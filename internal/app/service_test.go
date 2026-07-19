package app

import (
	"context"
	"testing"
	"time"

	"wg.local/wg/internal/controlapi"
	"wg.local/wg/internal/privatedns"
)

func testService() *Service {
	return NewService(Config{
		Mode: "client", Endpoint: "203.0.113.10:9518",
		InitialDNS: privatedns.Snapshot{Upstreams: []privatedns.Upstream{{Address: "223.5.5.5", Port: 53}}},
	})
}

func TestConnectionOperationsAreIdempotent(t *testing.T) {
	service := testService()
	request := controlapi.OperationRequest{OperationID: "connect-1"}
	first, err := service.ConnectionAction(context.Background(), "connect", request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.ConnectionAction(context.Background(), "connect", request)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || first.State != "CONNECTED" {
		t.Fatalf("operation was not idempotent: first=%+v second=%+v", first, second)
	}
}

func TestDeleteManualRuleRestoresAuto(t *testing.T) {
	service := testService()
	created, err := service.SetRule(context.Background(), controlapi.SetRuleRequest{OperationID: "set-1", Target: "Example.COM.", Result: "DIRECT"})
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := service.DeleteRule(context.Background(), created.Rule.ID, controlapi.DeleteRuleRequest{OperationID: "delete-1", ExpectedRevision: &created.Rule.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if deleted.State != "AUTO" || deleted.Rule.Result != "AUTO" {
		t.Fatalf("delete should restore AUTO: %+v", deleted)
	}
	explanation, err := service.ExplainRule(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if explanation.ManagedState != "AUTO" || explanation.FinalResult != "TUNNEL" {
		t.Fatalf("unexpected automatic decision: %+v", explanation)
	}
}

func TestRuleExpiryRestoresAutoForActualDecisions(t *testing.T) {
	now := time.Date(2026, 7, 16, 8, 0, 0, 0, time.UTC)
	service := NewService(Config{
		Mode: "client", Endpoint: "203.0.113.10:9518", Now: func() time.Time { return now },
		InitialDNS: privatedns.Snapshot{Upstreams: []privatedns.Upstream{{Address: "223.5.5.5", Port: 53}}},
	})
	expires := now.Add(time.Minute)
	created, err := service.SetRule(context.Background(), controlapi.SetRuleRequest{OperationID: "expiring-set", Target: "example.com", Result: "DIRECT", ExpiresAt: &expires})
	if err != nil || created.Rule.ExpiresAt == nil {
		t.Fatalf("set expiring rule: response=%+v err=%v", created, err)
	}
	before, err := service.ExplainRule(context.Background(), "example.com")
	if err != nil || before.ManagedState != "DIRECT" {
		t.Fatalf("rule should be active before expiry: response=%+v err=%v", before, err)
	}
	now = expires
	after, err := service.ExplainRule(context.Background(), "example.com")
	if err != nil || after.ManagedState != "AUTO" || after.FinalResult != "TUNNEL" {
		t.Fatalf("expired rule must restore AUTO: response=%+v err=%v", after, err)
	}
	listed, err := service.ListRules(context.Background(), controlapi.RuleFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range listed.Rules {
		if rule.ID == created.Rule.ID {
			t.Fatalf("expired rule remained in list: %+v", rule)
		}
	}
}

func TestDeleteRuleByTargetAndEditIdentity(t *testing.T) {
	service := testService()
	created, err := service.SetRule(context.Background(), controlapi.SetRuleRequest{OperationID: "target-set", Target: "example.com", Result: "DIRECT"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.SetRule(context.Background(), controlapi.SetRuleRequest{
		OperationID: "target-edit-bad", ID: created.Rule.ID, ExpectedRevision: &created.Rule.Revision,
		Target: "other.example.com", Result: "BLOCK",
	})
	if err == nil {
		t.Fatal("editing a rule must not silently leave the old target behind")
	}
	deleted, err := service.DeleteRule(context.Background(), "", controlapi.DeleteRuleRequest{OperationID: "target-delete", Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if deleted.State != "AUTO" || deleted.Rule.Target != "example.com" {
		t.Fatalf("target deletion did not restore AUTO: %+v", deleted)
	}
}

func TestRejectsAlreadyExpiredRule(t *testing.T) {
	now := time.Date(2026, 7, 16, 8, 0, 0, 0, time.UTC)
	service := NewService(Config{Mode: "client", Now: func() time.Time { return now }})
	_, err := service.SetRule(context.Background(), controlapi.SetRuleRequest{OperationID: "past-expiry", Target: "example.com", Result: "DIRECT", ExpiresAt: &now})
	if err == nil {
		t.Fatal("expires_at at or before now must be rejected")
	}
}

func TestDNSStatusAlwaysReportsSystemUnchanged(t *testing.T) {
	service := testService()
	status, err := service.DNSStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !status.SystemDNSUnchanged || status.Source == "" {
		t.Fatalf("unexpected DNS status: %+v", status)
	}
}

func TestServerModeRejectsClientUIMethods(t *testing.T) {
	service := NewService(Config{Mode: "server"})
	_, err := service.SetRule(context.Background(), controlapi.SetRuleRequest{OperationID: "set-1", Target: "example.com", Result: "TUNNEL"})
	if err == nil {
		t.Fatal("server mode must reject client routing UI method")
	}
}

func TestPairingUsesNormativeFileAndFingerprint(t *testing.T) {
	service := testService()
	value, err := service.ValidatePairing(context.Background(), controlapi.PairingValidationRequest{ServerIP: "203.0.113.10", FileName: "wg-pairing.wgp"})
	if err != nil {
		t.Fatal(err)
	}
	if !value.Valid || value.Fingerprint[:4] != "wgs-" || len(value.ValidationID) != 32 {
		t.Fatalf("unexpected pairing validation: %+v", value)
	}
	enrolled, err := service.Enroll(context.Background(), controlapi.EnrollRequest{
		OperationID: "pair-enroll", ValidationID: value.ValidationID, ServerIP: value.ServerIP,
		FileName: value.FileName, Fingerprint: value.Fingerprint,
		FingerprintConfirmed: true, AuthorizationConfirmed: true,
	})
	if err != nil || !enrolled.Accepted {
		t.Fatalf("enroll validated pairing: response=%+v err=%v", enrolled, err)
	}
	_, err = service.Enroll(context.Background(), controlapi.EnrollRequest{
		OperationID: "pair-enroll-replay-with-new-id", ValidationID: value.ValidationID, ServerIP: value.ServerIP,
		FileName: value.FileName, Fingerprint: value.Fingerprint,
		FingerprintConfirmed: true, AuthorizationConfirmed: true,
	})
	if err == nil {
		t.Fatal("a consumed pairing validation must not be reusable with another operation")
	}
}

func TestPairingValidationBindsInputsAndExpires(t *testing.T) {
	now := time.Date(2026, 7, 16, 8, 0, 0, 0, time.UTC)
	service := NewService(Config{Mode: "client", Now: func() time.Time { return now }})
	validated, err := service.ValidatePairing(context.Background(), controlapi.PairingValidationRequest{ServerIP: "203.0.113.10", FileName: "wg-pairing.wgp"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Enroll(context.Background(), controlapi.EnrollRequest{
		OperationID: "pair-changed", ValidationID: validated.ValidationID, ServerIP: "203.0.113.11",
		FileName: validated.FileName, Fingerprint: validated.Fingerprint,
		FingerprintConfirmed: true, AuthorizationConfirmed: true,
	})
	if err == nil {
		t.Fatal("enrollment must reject inputs changed after validation")
	}

	now = validated.ExpiresAt
	_, err = service.Enroll(context.Background(), controlapi.EnrollRequest{
		OperationID: "pair-expired", ValidationID: validated.ValidationID, ServerIP: validated.ServerIP,
		FileName: validated.FileName, Fingerprint: validated.Fingerprint,
		FingerprintConfirmed: true, AuthorizationConfirmed: true,
	})
	if err == nil {
		t.Fatal("enrollment must reject an expired validation")
	}
}
