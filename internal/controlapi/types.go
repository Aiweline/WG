package controlapi

import "time"

const Version = "v1"

type Versions struct {
	Bundle  string `json:"bundle"`
	UI      string `json:"ui"`
	Core    string `json:"core"`
	Scripts string `json:"scripts"`
}

type ConnectionStatus struct {
	State         string     `json:"state"`
	Endpoint      string     `json:"endpoint"`
	ConnectedAt   *time.Time `json:"connected_at,omitempty"`
	UptimeSeconds int64      `json:"uptime_seconds"`
	UploadBytes   uint64     `json:"upload_bytes"`
	DownloadBytes uint64     `json:"download_bytes"`
	LastError     string     `json:"last_error,omitempty"`
}

type RoutingSummary struct {
	Mode             string `json:"mode"`
	Generation       uint64 `json:"generation"`
	ManualRuleCount  int    `json:"manual_rule_count"`
	RecentAutoCount  int    `json:"recent_auto_count"`
	DefaultUnmatched string `json:"default_unmatched"`
}

type DNSUpstream struct {
	Address   string `json:"address"`
	Interface string `json:"interface,omitempty"`
	Scope     string `json:"scope,omitempty"`
}

type DNSStatus struct {
	State              string        `json:"state"`
	SystemDNSUnchanged bool          `json:"system_dns_unchanged"`
	Generation         uint64        `json:"generation"`
	SnapshotID         string        `json:"snapshot_id"`
	Source             string        `json:"source"`
	GeneratedAt        time.Time     `json:"generated_at"`
	LastSyncedAt       time.Time     `json:"last_synced_at"`
	Upstreams          []DNSUpstream `json:"upstreams"`
	InterfaceScopes    int           `json:"interface_scopes"`
	CacheEntries       int           `json:"cache_entries"`
	CacheHits          uint64        `json:"cache_hits"`
	CacheMisses        uint64        `json:"cache_misses"`
	CacheHitRate       float64       `json:"cache_hit_rate"`
	MinTTLSeconds      int64         `json:"min_ttl_seconds"`
	DegradedReasons    []string      `json:"degraded_reasons"`
}

type StatusResponse struct {
	APIVersion       string           `json:"api_version"`
	Revision         uint64           `json:"revision"`
	Mode             string           `json:"mode"`
	BackendAvailable bool             `json:"backend_available"`
	Connection       ConnectionStatus `json:"connection"`
	Routing          RoutingSummary   `json:"routing"`
	DNS              DNSStatus        `json:"dns"`
	Versions         Versions         `json:"versions"`
}

type OperationRequest struct {
	OperationID string `json:"operation_id"`
}

type OperationResponse struct {
	OperationID string `json:"operation_id"`
	Accepted    bool   `json:"accepted"`
	State       string `json:"state"`
	Revision    uint64 `json:"revision"`
	Message     string `json:"message,omitempty"`
}

type Rule struct {
	ID         string     `json:"id"`
	Target     string     `json:"target"`
	TargetType string     `json:"target_type"`
	Result     string     `json:"result"`
	Source     string     `json:"source"`
	Reason     string     `json:"reason"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	Note       string     `json:"note,omitempty"`
	Revision   uint64     `json:"revision"`
	CreatedAt  time.Time  `json:"created_at"`
}

type RuleFilter struct {
	Query      string
	Result     string
	Source     string
	TargetType string
	Limit      int
}

type RuleListResponse struct {
	Rules      []Rule `json:"rules"`
	Generation uint64 `json:"routing_generation"`
	Total      int    `json:"total"`
}

type SetRuleRequest struct {
	OperationID      string     `json:"operation_id"`
	ID               string     `json:"id,omitempty"`
	Target           string     `json:"target"`
	TargetType       string     `json:"target_type,omitempty"`
	Result           string     `json:"result"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	Note             string     `json:"note,omitempty"`
	ExpectedRevision *uint64    `json:"expected_revision,omitempty"`
}

type DeleteRuleRequest struct {
	OperationID      string  `json:"operation_id"`
	Target           string  `json:"target,omitempty"`
	ExpectedRevision *uint64 `json:"expected_revision,omitempty"`
}

type RuleMutationResponse struct {
	OperationID string `json:"operation_id"`
	Rule        Rule   `json:"rule"`
	Generation  uint64 `json:"routing_generation"`
	State       string `json:"state"`
}

type RuleExplanation struct {
	Target        string   `json:"target"`
	FinalResult   string   `json:"final_result"`
	ManagedState  string   `json:"managed_state"`
	PrimarySource string   `json:"primary_source"`
	Reason        string   `json:"reason"`
	Sources       []string `json:"sources"`
	Generation    uint64   `json:"routing_generation"`
}

type DiagnosticCheck struct {
	Name    string `json:"name"`
	State   string `json:"state"`
	Summary string `json:"summary"`
}

type DiagnosticReport struct {
	GeneratedAt time.Time         `json:"generated_at"`
	Redacted    bool              `json:"redacted"`
	Overall     string            `json:"overall"`
	Checks      []DiagnosticCheck `json:"checks"`
	Summary     string            `json:"summary"`
}

type UpdateStatus struct {
	State            string    `json:"state"`
	CurrentVersion   string    `json:"current_version"`
	AvailableVersion string    `json:"available_version,omitempty"`
	Compatible       bool      `json:"compatible"`
	ManifestVerified bool      `json:"manifest_verified"`
	CheckedAt        time.Time `json:"checked_at"`
	Message          string    `json:"message,omitempty"`
}

type PairingValidationRequest struct {
	ServerIP    string `json:"server_ip"`
	FileName    string `json:"file_name"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type PairingValidation struct {
	Valid        bool      `json:"valid"`
	ValidationID string    `json:"validation_id"`
	ServerIP     string    `json:"server_ip"`
	Port         int       `json:"port"`
	FileName     string    `json:"file_name"`
	Fingerprint  string    `json:"fingerprint"`
	ExpiresAt    time.Time `json:"expires_at"`
	Message      string    `json:"message,omitempty"`
}

type EnrollRequest struct {
	OperationID            string `json:"operation_id"`
	ValidationID           string `json:"validation_id"`
	ServerIP               string `json:"server_ip"`
	FileName               string `json:"file_name"`
	Fingerprint            string `json:"fingerprint"`
	FingerprintConfirmed   bool   `json:"fingerprint_confirmed"`
	AuthorizationConfirmed bool   `json:"authorization_confirmed"`
}

type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type ErrorResponse struct {
	Error APIError `json:"error"`
}
