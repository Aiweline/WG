package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestManagedDirectHostMatchesExactAndSuffix(t *testing.T) {
	rules := splitCSV("example.com, internal.test")
	for _, host := range []string{"example.com", "api.example.com", "INTERNAL.TEST:443"} {
		if !matches(host, rules) {
			t.Fatalf("expected %q to match managed direct rules", host)
		}
	}
	if matches("notexample.com", rules) {
		t.Fatal("unrelated hostname matched direct rule")
	}
}

func TestEnsurePortUsesHTTPSDefault(t *testing.T) {
	if got := ensurePort("example.com"); got != "example.com:443" {
		t.Fatalf("ensurePort() = %q", got)
	}
	if got := ensurePort("example.com:8443"); got != "example.com:8443" {
		t.Fatalf("ensurePort() changed explicit port: %q", got)
	}
}

func TestServerRejectsMissingTokenBeforeForwarding(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()
	(proxyHandler{token: "expected"}).ServeHTTP(rec, req)
	if rec.Code != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusProxyAuthRequired)
	}
}
