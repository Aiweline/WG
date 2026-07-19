// Package app assembles the safe development core used by the local API.
// It deliberately contains no TUN, route, firewall, service, or system-DNS
// mutation. Production platform adapters can be added behind explicit review.
package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"wg.local/wg/internal/controlapi"
	"wg.local/wg/internal/privatedns"
	"wg.local/wg/internal/routing"
)

const demoFingerprint = "wgs-q4zm-7n2k-p6tx-b5rv-j8cd-f3wa-h9yu-m2es"

type Config struct {
	Mode       string
	Endpoint   string
	Versions   controlapi.Versions
	DNSSource  privatedns.SnapshotSource
	InitialDNS privatedns.Snapshot
	Now        func() time.Time
}

type ruleMetadata struct {
	note      string
	expiresAt *time.Time
	revision  uint64
}

type pairingValidationState struct {
	serverIP    string
	fileName    string
	fingerprint string
	expiresAt   time.Time
}

type Service struct {
	mu sync.RWMutex

	mode      string
	endpoint  string
	versions  controlapi.Versions
	now       func() time.Time
	revision  uint64
	state     string
	connected *time.Time
	upload    uint64
	download  uint64
	lastError string

	routes             *routing.Engine
	dns                *privatedns.Manager
	dnsSource          privatedns.SnapshotSource
	ruleMeta           map[string]ruleMetadata
	recentAuto         []controlapi.Rule
	operations         map[string]controlapi.OperationResponse
	ruleOps            map[string]controlapi.RuleMutationResponse
	pairingValidations map[string]pairingValidationState
}

func NewService(config Config) *Service {
	now := config.Now
	if now == nil {
		now = time.Now
	}
	mode := strings.ToLower(strings.TrimSpace(config.Mode))
	if mode != "server" {
		mode = "client"
	}
	versions := config.Versions
	if versions.Bundle == "" {
		versions = controlapi.Versions{Bundle: "0.1.0-dev", UI: "0.1.0-dev", Core: "0.1.0-dev", Scripts: "0.1.0-dev"}
	}
	engine := routing.NewEngine(routing.WithAutoDecider(autoDecision))
	service := &Service{
		mode: mode, endpoint: config.Endpoint, versions: versions, now: now,
		state: "DISCONNECTED", routes: engine, dns: privatedns.NewManager(config.InitialDNS),
		dnsSource: config.DNSSource, ruleMeta: make(map[string]ruleMetadata),
		operations: make(map[string]controlapi.OperationResponse), ruleOps: make(map[string]controlapi.RuleMutationResponse),
		pairingValidations: make(map[string]pairingValidationState),
	}
	service.seedRecentAuto()
	return service
}

func autoDecision(target routing.Target) (routing.Action, string) {
	if target.Kind == routing.TargetDomain && (strings.HasSuffix(target.Value, ".cn") || target.Value == "cn") {
		return routing.ActionDirect, "signed regional classifier selected DIRECT"
	}
	if target.Kind == routing.TargetIP {
		if address, err := netip.ParseAddr(target.Value); err == nil && (address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast()) {
			return routing.ActionDirect, "local and protected address classifier selected DIRECT"
		}
	}
	return routing.ActionTunnel, "unclassified target uses the fail-closed TUNNEL default"
}

func (s *Service) seedRecentAuto() {
	now := s.now().UTC()
	for index, target := range []string{"docs.example.cn", "github.com", "192.168.50.20"} {
		decision, err := s.routes.Explain(target)
		if err != nil {
			continue
		}
		s.recentAuto = append(s.recentAuto, controlapi.Rule{
			ID: "auto-" + strconv.Itoa(index+1), Target: decision.Target.Value,
			TargetType: string(decision.Target.Kind), Result: string(decision.EffectiveAction),
			Source: "AUTOMATIC", Reason: decision.Reason, Revision: decision.Generation, CreatedAt: now,
		})
	}
}

func (s *Service) Status(_ context.Context) (controlapi.StatusResponse, error) {
	s.pruneExpiredRules()
	s.mu.RLock()
	state, endpoint, connected, upload, download, lastError := s.state, s.endpoint, s.connected, s.upload, s.download, s.lastError
	revision, mode, versions := s.revision, s.mode, s.versions
	s.mu.RUnlock()

	connection := controlapi.ConnectionStatus{State: state, Endpoint: endpoint, ConnectedAt: connected, UploadBytes: upload, DownloadBytes: download, LastError: lastError}
	if connected != nil && state == "CONNECTED" {
		connection.UptimeSeconds = max(0, int64(s.now().Sub(*connected).Seconds()))
	}
	dnsStatus := s.dnsResponse()
	return controlapi.StatusResponse{
		APIVersion: controlapi.Version, Revision: revision, Mode: mode, BackendAvailable: true,
		Connection: connection,
		Routing:    controlapi.RoutingSummary{Mode: "AUTO", Generation: s.routes.Generation(), ManualRuleCount: len(s.routes.List()), RecentAutoCount: s.autoCount(), DefaultUnmatched: "TUNNEL"},
		DNS:        dnsStatus, Versions: versions,
	}, nil
}

func (s *Service) ConnectionAction(_ context.Context, action string, request controlapi.OperationRequest) (controlapi.OperationResponse, error) {
	if s.mode == "server" {
		return controlapi.OperationResponse{}, fmt.Errorf("%w: connection UI methods are unavailable in server mode", controlapi.ErrUnsupported)
	}
	if err := validateOperationID(request.OperationID); err != nil {
		return controlapi.OperationResponse{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := "connection:" + request.OperationID
	if completed, ok := s.operations[key]; ok {
		return completed, nil
	}
	now := s.now().UTC()
	switch action {
	case "connect":
		if s.endpoint == "" {
			return controlapi.OperationResponse{}, fmt.Errorf("%w: server endpoint is not configured", controlapi.ErrInvalidInput)
		}
		if s.state != "CONNECTED" {
			s.state, s.connected, s.upload, s.download = "CONNECTED", &now, 0, 0
		}
	case "disconnect":
		s.state, s.connected = "DISCONNECTED", nil
	case "reconnect":
		if s.endpoint == "" {
			return controlapi.OperationResponse{}, fmt.Errorf("%w: server endpoint is not configured", controlapi.ErrInvalidInput)
		}
		s.state, s.connected = "CONNECTED", &now
	default:
		return controlapi.OperationResponse{}, fmt.Errorf("%w: unknown connection action", controlapi.ErrInvalidInput)
	}
	s.revision++
	response := controlapi.OperationResponse{OperationID: request.OperationID, Accepted: true, State: s.state, Revision: s.revision, Message: "development simulator updated; no host network state was changed"}
	s.operations[key] = response
	return response, nil
}

func (s *Service) ListRules(_ context.Context, filter controlapi.RuleFilter) (controlapi.RuleListResponse, error) {
	s.pruneExpiredRules()
	rules := s.manualRules()
	s.mu.RLock()
	rules = append(rules, cloneRules(s.recentAuto)...)
	s.mu.RUnlock()

	filtered := make([]controlapi.Rule, 0, len(rules))
	query := strings.ToLower(strings.TrimSpace(filter.Query))
	for _, rule := range rules {
		if query != "" && !strings.Contains(strings.ToLower(rule.Target), query) {
			continue
		}
		if filter.Result != "" && !strings.EqualFold(filter.Result, rule.Result) {
			continue
		}
		if filter.Source != "" && !strings.EqualFold(filter.Source, rule.Source) {
			continue
		}
		if filter.TargetType != "" && !strings.EqualFold(filter.TargetType, rule.TargetType) {
			continue
		}
		filtered = append(filtered, rule)
	}
	limit := filter.Limit
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	total := len(filtered)
	if len(filtered) > limit {
		filtered = filtered[:limit]
	}
	return controlapi.RuleListResponse{Rules: filtered, Generation: s.routes.Generation(), Total: total}, nil
}

func (s *Service) SetRule(_ context.Context, request controlapi.SetRuleRequest) (controlapi.RuleMutationResponse, error) {
	if s.mode == "server" {
		return controlapi.RuleMutationResponse{}, fmt.Errorf("%w: client routing methods are unavailable in server mode", controlapi.ErrUnsupported)
	}
	if err := validateOperationID(request.OperationID); err != nil {
		return controlapi.RuleMutationResponse{}, err
	}
	s.pruneExpiredRules()
	action, err := routing.ParseAction(request.Result)
	if err != nil || action == routing.ActionAuto {
		return controlapi.RuleMutationResponse{}, fmt.Errorf("%w: result must be TUNNEL, DIRECT, or BLOCK", controlapi.ErrInvalidInput)
	}
	target, err := routing.ParseTarget(request.Target)
	if err != nil {
		return controlapi.RuleMutationResponse{}, fmt.Errorf("%w: %v", controlapi.ErrInvalidInput, err)
	}
	var expiresAt *time.Time
	if request.ExpiresAt != nil {
		normalizedExpiry := request.ExpiresAt.UTC()
		if !normalizedExpiry.After(s.now().UTC()) {
			return controlapi.RuleMutationResponse{}, fmt.Errorf("%w: expires_at must be in the future", controlapi.ErrInvalidInput)
		}
		expiresAt = &normalizedExpiry
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	key := "rule-set:" + request.OperationID
	if completed, ok := s.ruleOps[key]; ok {
		return completed, nil
	}
	meta := s.ruleMeta[target.Value]
	if request.ID != "" {
		var existing *routing.Rule
		for _, candidate := range s.routes.List() {
			if "rule-"+strconv.FormatUint(candidate.ID, 10) == request.ID {
				copyOfRule := candidate
				existing = &copyOfRule
				break
			}
		}
		if existing == nil {
			return controlapi.RuleMutationResponse{}, fmt.Errorf("%w: rule to edit was not found", controlapi.ErrNotFound)
		}
		if existing.Target.Value != target.Value {
			return controlapi.RuleMutationResponse{}, fmt.Errorf("%w: editing a rule cannot change its target; delete and create a new override", controlapi.ErrInvalidInput)
		}
	}
	if request.ExpectedRevision != nil && meta.revision != *request.ExpectedRevision {
		return controlapi.RuleMutationResponse{}, fmt.Errorf("%w: rule revision changed", controlapi.ErrConflict)
	}
	rule, err := s.routes.SetRule(target.Value, action)
	if err != nil {
		return controlapi.RuleMutationResponse{}, fmt.Errorf("%w: %v", controlapi.ErrInvalidInput, err)
	}
	s.revision++
	meta = ruleMetadata{note: strings.TrimSpace(request.Note), expiresAt: expiresAt, revision: s.revision}
	s.ruleMeta[target.Value] = meta
	s.removeRecentAutoLocked(target.Value)
	apiRule := s.apiRule(rule, meta)
	response := controlapi.RuleMutationResponse{OperationID: request.OperationID, Rule: apiRule, Generation: s.routes.Generation(), State: "ACTIVE"}
	s.ruleOps[key] = response
	return response, nil
}

func (s *Service) DeleteRule(_ context.Context, id string, request controlapi.DeleteRuleRequest) (controlapi.RuleMutationResponse, error) {
	if s.mode == "server" {
		return controlapi.RuleMutationResponse{}, fmt.Errorf("%w: client routing methods are unavailable in server mode", controlapi.ErrUnsupported)
	}
	if err := validateOperationID(request.OperationID); err != nil {
		return controlapi.RuleMutationResponse{}, err
	}
	s.pruneExpiredRules()
	s.mu.Lock()
	defer s.mu.Unlock()
	key := "rule-delete:" + request.OperationID
	if completed, ok := s.ruleOps[key]; ok {
		return completed, nil
	}

	if id == "" {
		parsedTarget, err := routing.ParseTarget(request.Target)
		if err != nil {
			return controlapi.RuleMutationResponse{}, fmt.Errorf("%w: target is required for target-based deletion: %v", controlapi.ErrInvalidInput, err)
		}
		for _, candidate := range s.routes.List() {
			if candidate.Target.Value == parsedTarget.Value {
				id = "rule-" + strconv.FormatUint(candidate.ID, 10)
				break
			}
		}
		if id == "" {
			for _, row := range s.recentAuto {
				if row.Target == parsedTarget.Value {
					id = row.ID
					break
				}
			}
		}
	}

	if strings.HasPrefix(id, "auto-") {
		for index, row := range s.recentAuto {
			if row.ID == id {
				s.recentAuto = append(s.recentAuto[:index], s.recentAuto[index+1:]...)
				s.revision++
				row.Result, row.Source, row.Reason, row.Revision = "AUTO", "AUTOMATIC", "automatic cache removed; the next flow will be classified again", s.revision
				response := controlapi.RuleMutationResponse{OperationID: request.OperationID, Rule: row, Generation: s.routes.Generation(), State: "AUTO"}
				s.ruleOps[key] = response
				return response, nil
			}
		}
		return controlapi.RuleMutationResponse{}, fmt.Errorf("%w: automatic decision not found", controlapi.ErrNotFound)
	}

	var matched *routing.Rule
	for _, candidate := range s.routes.List() {
		if "rule-"+strconv.FormatUint(candidate.ID, 10) == id {
			copyOfRule := candidate
			matched = &copyOfRule
			break
		}
	}
	if matched == nil {
		return controlapi.RuleMutationResponse{}, fmt.Errorf("%w: rule not found", controlapi.ErrNotFound)
	}
	meta := s.ruleMeta[matched.Target.Value]
	if request.ExpectedRevision != nil && meta.revision != *request.ExpectedRevision {
		return controlapi.RuleMutationResponse{}, fmt.Errorf("%w: rule revision changed", controlapi.ErrConflict)
	}
	decision, err := s.routes.DeleteRule(matched.Target.Value)
	if err != nil {
		return controlapi.RuleMutationResponse{}, err
	}
	delete(s.ruleMeta, matched.Target.Value)
	s.removeRecentAutoLocked(matched.Target.Value)
	s.revision++
	apiRule := controlapi.Rule{ID: id, Target: decision.Target.Value, TargetType: string(decision.Target.Kind), Result: "AUTO", Source: string(decision.Source), Reason: decision.Reason, Revision: s.revision, CreatedAt: s.now().UTC()}
	response := controlapi.RuleMutationResponse{OperationID: request.OperationID, Rule: apiRule, Generation: decision.Generation, State: "AUTO"}
	s.ruleOps[key] = response
	return response, nil
}

func (s *Service) ExplainRule(_ context.Context, target string) (controlapi.RuleExplanation, error) {
	s.pruneExpiredRules()
	decision, err := s.routes.Explain(target)
	if err != nil {
		return controlapi.RuleExplanation{}, fmt.Errorf("%w: %v", controlapi.ErrInvalidInput, err)
	}
	sources := []string{string(decision.Source)}
	return controlapi.RuleExplanation{
		Target: decision.Target.Value, FinalResult: string(decision.EffectiveAction), ManagedState: string(decision.Action),
		PrimarySource: string(decision.Source), Reason: decision.Reason, Sources: sources, Generation: decision.Generation,
	}, nil
}

func (s *Service) DNSStatus(context.Context) (controlapi.DNSStatus, error) {
	return s.dnsResponse(), nil
}

func (s *Service) RefreshDNS(ctx context.Context, request controlapi.OperationRequest) (controlapi.DNSStatus, error) {
	if s.mode == "server" {
		return controlapi.DNSStatus{}, fmt.Errorf("%w: private DNS is a client-only method", controlapi.ErrUnsupported)
	}
	if err := validateOperationID(request.OperationID); err != nil {
		return controlapi.DNSStatus{}, err
	}
	if s.dnsSource == nil {
		return s.dnsResponse(), fmt.Errorf("%w: no read-only resolver source is configured", controlapi.ErrUnsupported)
	}
	_, err := s.dns.RefreshFrom(ctx, s.dnsSource)
	s.mu.Lock()
	s.revision++
	s.mu.Unlock()
	if err != nil {
		return s.dnsResponse(), fmt.Errorf("refresh read-only resolver snapshot: %w", err)
	}
	return s.dnsResponse(), nil
}

func (s *Service) RunDoctor(context.Context) (controlapi.DiagnosticReport, error) {
	status, _ := s.Status(context.Background())
	dnsState := status.DNS.State
	overall := "HEALTHY"
	if dnsState == "DEGRADED" {
		overall = "DEGRADED"
	}
	checks := []controlapi.DiagnosticCheck{
		{Name: "Tunnel connection", State: status.Connection.State, Summary: "development transport simulator; no TUN device is created"},
		{Name: "Smart routing", State: "HEALTHY", Summary: fmt.Sprintf("generation %d, %d manual rules", status.Routing.Generation, status.Routing.ManualRuleCount)},
		{Name: "Private DNS", State: dnsState, Summary: fmt.Sprintf("read-only generation %d; system DNS unchanged", status.DNS.Generation)},
		{Name: "Script environment", State: "HEALTHY", Summary: "client and server orchestration scripts are available"},
		{Name: "System privileges", State: "NOT_REQUESTED", Summary: "safe development mode has not requested TUN, route, firewall, service, or DNS privileges"},
	}
	return controlapi.DiagnosticReport{GeneratedAt: s.now().UTC(), Redacted: true, Overall: overall, Checks: checks, Summary: "Redacted development diagnostic; no keys, tokens, domains, or DNS responses included."}, nil
}

func (s *Service) CheckUpdate(context.Context) (controlapi.UpdateStatus, error) {
	return controlapi.UpdateStatus{State: "IDLE", CurrentVersion: s.versions.Bundle, Compatible: true, ManifestVerified: false, CheckedAt: s.now().UTC(), Message: "no signed update feed is configured for this development build"}, nil
}

func (s *Service) UpdateAction(_ context.Context, action string, _ controlapi.OperationRequest) (controlapi.UpdateStatus, error) {
	return controlapi.UpdateStatus{}, fmt.Errorf("%w: %s requires the future signed release helper", controlapi.ErrUnsupported, action)
}

func (s *Service) ValidatePairing(_ context.Context, request controlapi.PairingValidationRequest) (controlapi.PairingValidation, error) {
	if s.mode == "server" {
		return controlapi.PairingValidation{}, fmt.Errorf("%w: pairing UI is unavailable in server mode", controlapi.ErrUnsupported)
	}
	address, err := netip.ParseAddr(strings.TrimSpace(request.ServerIP))
	if err != nil {
		return controlapi.PairingValidation{}, fmt.Errorf("%w: server IP must be a literal IPv4 or IPv6 address", controlapi.ErrInvalidInput)
	}
	if request.FileName != "wg-pairing.wgp" {
		return controlapi.PairingValidation{}, fmt.Errorf("%w: pairing file must be named wg-pairing.wgp", controlapi.ErrInvalidInput)
	}
	if request.Fingerprint != "" && request.Fingerprint != demoFingerprint {
		return controlapi.PairingValidation{}, fmt.Errorf("%w: supplied fingerprint does not match the validated pairing material", controlapi.ErrInvalidInput)
	}
	validationBytes := make([]byte, 16)
	if _, err := rand.Read(validationBytes); err != nil {
		return controlapi.PairingValidation{}, fmt.Errorf("create pairing validation state: %w", err)
	}
	validationID := hex.EncodeToString(validationBytes)
	expiresAt := s.now().UTC().Add(10 * time.Minute)
	normalizedIP := address.String()
	s.mu.Lock()
	for id, validation := range s.pairingValidations {
		if !validation.expiresAt.After(s.now().UTC()) {
			delete(s.pairingValidations, id)
		}
	}
	if len(s.pairingValidations) >= 128 {
		s.mu.Unlock()
		return controlapi.PairingValidation{}, fmt.Errorf("%w: too many pending pairing validations", controlapi.ErrConflict)
	}
	s.pairingValidations[validationID] = pairingValidationState{
		serverIP: normalizedIP, fileName: request.FileName, fingerprint: demoFingerprint, expiresAt: expiresAt,
	}
	s.mu.Unlock()
	return controlapi.PairingValidation{
		Valid: true, ValidationID: validationID, ServerIP: normalizedIP, Port: 9518,
		FileName: request.FileName, Fingerprint: demoFingerprint, ExpiresAt: expiresAt,
		Message: "development validation only; production must inspect the 0600 file and verify its signed fields",
	}, nil
}

func (s *Service) Enroll(_ context.Context, request controlapi.EnrollRequest) (controlapi.OperationResponse, error) {
	if err := validateOperationID(request.OperationID); err != nil {
		return controlapi.OperationResponse{}, err
	}
	if !request.FingerprintConfirmed || !request.AuthorizationConfirmed {
		return controlapi.OperationResponse{}, fmt.Errorf("%w: independent fingerprint confirmation and explicit authorization are required", controlapi.ErrInvalidInput)
	}
	if request.FileName != "wg-pairing.wgp" {
		return controlapi.OperationResponse{}, fmt.Errorf("%w: pairing file must be named wg-pairing.wgp", controlapi.ErrInvalidInput)
	}
	address, err := netip.ParseAddr(strings.TrimSpace(request.ServerIP))
	if err != nil {
		return controlapi.OperationResponse{}, fmt.Errorf("%w: invalid server IP", controlapi.ErrInvalidInput)
	}
	if len(request.ValidationID) != 32 {
		return controlapi.OperationResponse{}, fmt.Errorf("%w: a current pairing validation is required", controlapi.ErrInvalidInput)
	}
	if _, err := hex.DecodeString(request.ValidationID); err != nil {
		return controlapi.OperationResponse{}, fmt.Errorf("%w: invalid pairing validation identifier", controlapi.ErrInvalidInput)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	operationKey := "enroll:" + request.OperationID
	if completed, ok := s.operations[operationKey]; ok {
		return completed, nil
	}
	validation, ok := s.pairingValidations[request.ValidationID]
	if !ok {
		return controlapi.OperationResponse{}, fmt.Errorf("%w: pairing validation is missing or was already used", controlapi.ErrInvalidInput)
	}
	if !validation.expiresAt.After(s.now().UTC()) {
		delete(s.pairingValidations, request.ValidationID)
		return controlapi.OperationResponse{}, fmt.Errorf("%w: pairing validation expired", controlapi.ErrInvalidInput)
	}
	if validation.serverIP != address.String() || validation.fileName != request.FileName || validation.fingerprint != request.Fingerprint {
		return controlapi.OperationResponse{}, fmt.Errorf("%w: pairing inputs changed after validation", controlapi.ErrInvalidInput)
	}
	delete(s.pairingValidations, request.ValidationID)
	s.endpoint = netip.AddrPortFrom(address, 9518).String()
	s.revision++
	response := controlapi.OperationResponse{OperationID: request.OperationID, Accepted: true, State: "COMPLETE", Revision: s.revision, Message: "development enrollment completed without consuming a real token or changing host networking"}
	s.operations[operationKey] = response
	return response, nil
}

func (s *Service) manualRules() []controlapi.Rule {
	rules := s.routes.List()
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]controlapi.Rule, 0, len(rules))
	for _, rule := range rules {
		result = append(result, s.apiRule(rule, s.ruleMeta[rule.Target.Value]))
	}
	return result
}

func (s *Service) apiRule(rule routing.Rule, meta ruleMetadata) controlapi.Rule {
	return controlapi.Rule{
		ID: "rule-" + strconv.FormatUint(rule.ID, 10), Target: rule.Target.Value, TargetType: string(rule.Target.Kind),
		Result: string(rule.Action), Source: string(rule.Source), Reason: "manual override", ExpiresAt: meta.expiresAt,
		Note: meta.note, Revision: meta.revision, CreatedAt: rule.CreatedAt,
	}
}

// pruneExpiredRules makes expiry part of the actual routing decision instead
// of display-only metadata. It is called on every rule/status read and before
// mutations, so an expired override cannot continue affecting new decisions.
func (s *Service) pruneExpiredRules() {
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	for target, meta := range s.ruleMeta {
		if meta.expiresAt == nil || meta.expiresAt.After(now) {
			continue
		}
		if _, err := s.routes.DeleteRule(target); err == nil {
			s.revision++
		}
		delete(s.ruleMeta, target)
		s.removeRecentAutoLocked(target)
	}
}

func (s *Service) removeRecentAutoLocked(target string) {
	filtered := s.recentAuto[:0]
	for _, row := range s.recentAuto {
		if row.Target != target {
			filtered = append(filtered, row)
		}
	}
	s.recentAuto = filtered
}

func (s *Service) dnsResponse() controlapi.DNSStatus {
	status := s.dns.Status()
	snapshot := s.dns.Snapshot()
	state := "HEALTHY"
	reasons := []string{}
	if status.Degraded {
		state = "DEGRADED"
		if status.LastError != "" {
			reasons = append(reasons, status.LastError)
		}
	}
	upstreams := make([]controlapi.DNSUpstream, 0, len(snapshot.Upstreams))
	for _, upstream := range snapshot.Upstreams {
		address := upstream.Address
		if upstream.Port != 0 && upstream.Port != 53 {
			address = fmt.Sprintf("%s:%d", address, upstream.Port)
		}
		upstreams = append(upstreams, controlapi.DNSUpstream{Address: address, Interface: upstream.InterfaceName, Scope: upstream.Scope})
	}
	total := status.Cache.Hits + status.Cache.Misses
	hitRate := 0.0
	if total > 0 {
		hitRate = float64(status.Cache.Hits) / float64(total)
	}
	source := snapshot.Metadata["source"]
	if source == "" {
		source = "read-only development snapshot"
	}
	return controlapi.DNSStatus{
		State: state, SystemDNSUnchanged: true, Generation: status.Generation,
		SnapshotID: fmt.Sprintf("dns-%06d", status.Generation), Source: source, GeneratedAt: snapshot.CapturedAt,
		LastSyncedAt: status.RefreshedAt, Upstreams: upstreams, InterfaceScopes: uniqueInterfaceCount(snapshot.Upstreams),
		CacheEntries: int(status.Cache.Entries), CacheHits: status.Cache.Hits, CacheMisses: status.Cache.Misses,
		CacheHitRate: hitRate, MinTTLSeconds: 0, DegradedReasons: reasons,
	}
}

func uniqueInterfaceCount(upstreams []privatedns.Upstream) int {
	seen := make(map[string]struct{})
	for _, upstream := range upstreams {
		key := upstream.InterfaceName + "\x00" + upstream.Scope
		seen[key] = struct{}{}
	}
	return len(seen)
}

func (s *Service) autoCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.recentAuto)
}

func cloneRules(rules []controlapi.Rule) []controlapi.Rule {
	return append([]controlapi.Rule(nil), rules...)
}

func validateOperationID(value string) error {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return fmt.Errorf("%w: operation_id is required and must be at most 128 bytes", controlapi.ErrInvalidInput)
	}
	for _, character := range value {
		if !(character == '-' || character == '_' || character == '.' || character >= '0' && character <= '9' || character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z') {
			return fmt.Errorf("%w: operation_id contains unsupported characters", controlapi.ErrInvalidInput)
		}
	}
	return nil
}

var _ controlapi.Backend = (*Service)(nil)
