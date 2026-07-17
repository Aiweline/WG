package controlapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeBackend struct{}

func (fakeBackend) Status(context.Context) (StatusResponse, error) {
	return StatusResponse{APIVersion: Version, Mode: "client", BackendAvailable: true}, nil
}
func (fakeBackend) ConnectionAction(_ context.Context, action string, req OperationRequest) (OperationResponse, error) {
	return OperationResponse{OperationID: req.OperationID, Accepted: true, State: action}, nil
}
func (fakeBackend) ListRules(context.Context, RuleFilter) (RuleListResponse, error) {
	return RuleListResponse{Rules: []Rule{}}, nil
}
func (fakeBackend) SetRule(_ context.Context, req SetRuleRequest) (RuleMutationResponse, error) {
	return RuleMutationResponse{OperationID: req.OperationID, Rule: Rule{Target: req.Target, Result: req.Result}}, nil
}
func (fakeBackend) DeleteRule(context.Context, string, DeleteRuleRequest) (RuleMutationResponse, error) {
	return RuleMutationResponse{State: "AUTO"}, nil
}
func (fakeBackend) ExplainRule(context.Context, string) (RuleExplanation, error) {
	return RuleExplanation{ManagedState: "AUTO", FinalResult: "TUNNEL"}, nil
}
func (fakeBackend) DNSStatus(context.Context) (DNSStatus, error) { return DNSStatus{}, nil }
func (fakeBackend) RefreshDNS(context.Context, OperationRequest) (DNSStatus, error) {
	return DNSStatus{SystemDNSUnchanged: true}, nil
}
func (fakeBackend) RunDoctor(context.Context) (DiagnosticReport, error) {
	return DiagnosticReport{Redacted: true}, nil
}
func (fakeBackend) CheckUpdate(context.Context) (UpdateStatus, error) { return UpdateStatus{}, nil }
func (fakeBackend) UpdateAction(context.Context, string, OperationRequest) (UpdateStatus, error) {
	return UpdateStatus{}, ErrUnsupported
}
func (fakeBackend) ValidatePairing(context.Context, PairingValidationRequest) (PairingValidation, error) {
	return PairingValidation{Valid: true}, nil
}
func (fakeBackend) Enroll(context.Context, EnrollRequest) (OperationResponse, error) {
	return OperationResponse{Accepted: true}, nil
}

func TestStatusEndpoint(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	response := httptest.NewRecorder()
	NewServer(fakeBackend{}, nil).Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status code = %d, body = %s", response.Code, response.Body.String())
	}
	var got StatusResponse
	if err := json.NewDecoder(response.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.APIVersion != Version || !got.BackendAvailable {
		t.Fatalf("unexpected response: %+v", got)
	}
}

func TestRejectsUnknownJSONFields(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/connection/connect", strings.NewReader(`{"operation_id":"op-1","secret":"must-not-pass"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	NewServer(fakeBackend{}, nil).Handler().ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status code = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestDeleteReturnsAutoManagementState(t *testing.T) {
	request := httptest.NewRequest(http.MethodDelete, "/api/v1/rules/rule-1", strings.NewReader(`{"operation_id":"op-delete"}`))
	response := httptest.NewRecorder()
	NewServer(fakeBackend{}, nil).Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"AUTO"`) {
		t.Fatalf("unexpected response: %d %s", response.Code, response.Body.String())
	}
}
