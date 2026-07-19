package integration_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"wg.local/wg/internal/app"
	"wg.local/wg/internal/controlapi"
	"wg.local/wg/internal/privatedns"
)

func TestRuleLifecycleReturnsToAuto(t *testing.T) {
	service := app.NewService(app.Config{
		Mode: "client", Endpoint: "203.0.113.10:9518",
		InitialDNS: privatedns.Snapshot{Upstreams: []privatedns.Upstream{{Address: "223.5.5.5", Port: 53}}},
	})
	server := httptest.NewServer(controlapi.NewServer(service, nil).Handler())
	defer server.Close()

	created := doJSON[controlapi.RuleMutationResponse](t, http.MethodPost, server.URL+"/api/v1/rules", map[string]any{
		"operation_id": "integration-set", "target": "api.example.com", "result": "TUNNEL",
	})
	if created.State != "ACTIVE" || created.Rule.Source != "MANUAL" {
		t.Fatalf("unexpected create response: %+v", created)
	}

	deleted := doJSON[controlapi.RuleMutationResponse](t, http.MethodDelete, server.URL+"/api/v1/rules", map[string]any{
		"operation_id": "integration-delete", "target": "api.example.com", "expected_revision": created.Rule.Revision,
	})
	if deleted.State != "AUTO" || deleted.Rule.Result != "AUTO" {
		t.Fatalf("delete did not restore AUTO: %+v", deleted)
	}
}

func TestDNSRefreshCannotBeUsedInServerMode(t *testing.T) {
	service := app.NewService(app.Config{Mode: "server"})
	server := httptest.NewServer(controlapi.NewServer(service, nil).Handler())
	defer server.Close()

	body, err := json.Marshal(map[string]string{"operation_id": "server-dns"})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/dns/refresh", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status code = %d, want %d", response.StatusCode, http.StatusNotImplemented)
	}
}

func doJSON[T any](t *testing.T, method, endpoint string, payload any) T {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(method, endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status code = %d", response.StatusCode)
	}
	var value T
	if err := json.NewDecoder(response.Body).Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}
