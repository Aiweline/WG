package controlapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const maxRequestBytes = 64 << 10

var (
	ErrInvalidInput = errors.New("invalid input")
	ErrNotFound     = errors.New("not found")
	ErrConflict     = errors.New("conflict")
	ErrUnsupported  = errors.New("unsupported")
)

type Backend interface {
	Status(context.Context) (StatusResponse, error)
	ConnectionAction(context.Context, string, OperationRequest) (OperationResponse, error)
	ListRules(context.Context, RuleFilter) (RuleListResponse, error)
	SetRule(context.Context, SetRuleRequest) (RuleMutationResponse, error)
	DeleteRule(context.Context, string, DeleteRuleRequest) (RuleMutationResponse, error)
	ExplainRule(context.Context, string) (RuleExplanation, error)
	DNSStatus(context.Context) (DNSStatus, error)
	RefreshDNS(context.Context, OperationRequest) (DNSStatus, error)
	RunDoctor(context.Context) (DiagnosticReport, error)
	CheckUpdate(context.Context) (UpdateStatus, error)
	UpdateAction(context.Context, string, OperationRequest) (UpdateStatus, error)
	ValidatePairing(context.Context, PairingValidationRequest) (PairingValidation, error)
	Enroll(context.Context, EnrollRequest) (OperationResponse, error)
}

type Server struct {
	backend Backend
	log     *slog.Logger
	sem     chan struct{}
	mux     *http.ServeMux
}

func NewServer(backend Backend, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{backend: backend, log: logger, sem: make(chan struct{}, 32), mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler {
	return s.recoverer(s.limitConcurrency(s.securityHeaders(s.mux)))
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/v1/status", s.getStatus)
	s.mux.HandleFunc("POST /api/v1/connection/{action}", s.connectionAction)
	s.mux.HandleFunc("GET /api/v1/rules", s.listRules)
	s.mux.HandleFunc("POST /api/v1/rules", s.setRule)
	s.mux.HandleFunc("DELETE /api/v1/rules", s.deleteRule)
	s.mux.HandleFunc("DELETE /api/v1/rules/{id}", s.deleteRule)
	s.mux.HandleFunc("GET /api/v1/rules/explain", s.explainRule)
	s.mux.HandleFunc("GET /api/v1/dns", s.getDNS)
	s.mux.HandleFunc("POST /api/v1/dns/refresh", s.refreshDNS)
	s.mux.HandleFunc("POST /api/v1/diagnostics", s.runDoctor)
	s.mux.HandleFunc("POST /api/v1/updates/check", s.checkUpdate)
	s.mux.HandleFunc("POST /api/v1/updates/{action}", s.updateAction)
	s.mux.HandleFunc("POST /api/v1/pairing/validate", s.validatePairing)
	s.mux.HandleFunc("POST /api/v1/pairing/enroll", s.enroll)
	// Browser-only development preflight. Production access is still constrained by the Unix socket.
	s.mux.HandleFunc("OPTIONS /api/v1/{path...}", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
}

func (s *Server) getStatus(w http.ResponseWriter, r *http.Request) {
	value, err := s.backend.Status(r.Context())
	s.respond(w, value, err)
}

func (s *Server) connectionAction(w http.ResponseWriter, r *http.Request) {
	action := r.PathValue("action")
	if action != "connect" && action != "disconnect" && action != "reconnect" {
		s.respond(w, nil, fmt.Errorf("%w: unknown connection action", ErrInvalidInput))
		return
	}
	var req OperationRequest
	if err := decodeJSON(w, r, &req); err != nil {
		s.respond(w, nil, err)
		return
	}
	value, err := s.backend.ConnectionAction(r.Context(), action, req)
	s.respond(w, value, err)
}

func (s *Server) listRules(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	filter := RuleFilter{
		Query: r.URL.Query().Get("q"), Result: r.URL.Query().Get("result"),
		Source: r.URL.Query().Get("source"), TargetType: r.URL.Query().Get("target_type"), Limit: limit,
	}
	value, err := s.backend.ListRules(r.Context(), filter)
	s.respond(w, value, err)
}

func (s *Server) setRule(w http.ResponseWriter, r *http.Request) {
	var req SetRuleRequest
	if err := decodeJSON(w, r, &req); err != nil {
		s.respond(w, nil, err)
		return
	}
	value, err := s.backend.SetRule(r.Context(), req)
	s.respond(w, value, err)
}

func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request) {
	var req DeleteRuleRequest
	if err := decodeJSON(w, r, &req); err != nil {
		s.respond(w, nil, err)
		return
	}
	value, err := s.backend.DeleteRule(r.Context(), r.PathValue("id"), req)
	s.respond(w, value, err)
}

func (s *Server) explainRule(w http.ResponseWriter, r *http.Request) {
	value, err := s.backend.ExplainRule(r.Context(), r.URL.Query().Get("target"))
	s.respond(w, value, err)
}

func (s *Server) getDNS(w http.ResponseWriter, r *http.Request) {
	value, err := s.backend.DNSStatus(r.Context())
	s.respond(w, value, err)
}

func (s *Server) refreshDNS(w http.ResponseWriter, r *http.Request) {
	var req OperationRequest
	if err := decodeJSON(w, r, &req); err != nil {
		s.respond(w, nil, err)
		return
	}
	value, err := s.backend.RefreshDNS(r.Context(), req)
	s.respond(w, value, err)
}

func (s *Server) runDoctor(w http.ResponseWriter, r *http.Request) {
	value, err := s.backend.RunDoctor(r.Context())
	s.respond(w, value, err)
}

func (s *Server) checkUpdate(w http.ResponseWriter, r *http.Request) {
	value, err := s.backend.CheckUpdate(r.Context())
	s.respond(w, value, err)
}

func (s *Server) updateAction(w http.ResponseWriter, r *http.Request) {
	action := r.PathValue("action")
	if action != "upgrade" && action != "rollback" {
		s.respond(w, nil, fmt.Errorf("%w: unknown update action", ErrInvalidInput))
		return
	}
	var req OperationRequest
	if err := decodeJSON(w, r, &req); err != nil {
		s.respond(w, nil, err)
		return
	}
	value, err := s.backend.UpdateAction(r.Context(), action, req)
	s.respond(w, value, err)
}

func (s *Server) validatePairing(w http.ResponseWriter, r *http.Request) {
	var req PairingValidationRequest
	if err := decodeJSON(w, r, &req); err != nil {
		s.respond(w, nil, err)
		return
	}
	value, err := s.backend.ValidatePairing(r.Context(), req)
	s.respond(w, value, err)
}

func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	var req EnrollRequest
	if err := decodeJSON(w, r, &req); err != nil {
		s.respond(w, nil, err)
		return
	}
	value, err := s.backend.Enroll(r.Context(), req)
	s.respond(w, value, err)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("%w: malformed JSON: %v", ErrInvalidInput, err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: request must contain one JSON value", ErrInvalidInput)
	}
	return nil
}

func (s *Server) respond(w http.ResponseWriter, value any, err error) {
	if err != nil {
		status, code := statusFor(err)
		writeJSON(w, status, ErrorResponse{Error: APIError{Code: code, Message: err.Error()}})
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func statusFor(err error) (int, string) {
	switch {
	case errors.Is(err, ErrInvalidInput):
		return http.StatusBadRequest, "invalid_input"
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound, "not_found"
	case errors.Is(err, ErrConflict):
		return http.StatusConflict, "conflict"
	case errors.Is(err, ErrUnsupported):
		return http.StatusNotImplemented, "unsupported"
	default:
		return http.StatusInternalServerError, "internal_error"
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (s *Server) limitConcurrency(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case s.sem <- struct{}{}:
			defer func() { <-s.sem }()
			next.ServeHTTP(w, r)
		case <-r.Context().Done():
			writeJSON(w, http.StatusRequestTimeout, ErrorResponse{Error: APIError{Code: "timeout", Message: "request cancelled"}})
		default:
			writeJSON(w, http.StatusServiceUnavailable, ErrorResponse{Error: APIError{Code: "busy", Message: "too many concurrent requests"}})
		}
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if origin := r.Header.Get("Origin"); origin == "http://127.0.0.1:4173" || strings.HasPrefix(origin, "http://localhost:") {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		defer func() {
			if recovered := recover(); recovered != nil {
				s.log.Error("control API panic", "value", recovered)
				writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: APIError{Code: "internal_error", Message: "internal error"}})
			}
		}()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
