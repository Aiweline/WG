package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func TestLoadToken(t *testing.T) {
	if got, err := loadToken(" literal-token ", ""); err != nil || got != "literal-token" {
		t.Fatalf("literal token = %q, %v", got, err)
	}

	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(" file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := loadToken("", path); err != nil || got != "file-token" {
		t.Fatalf("file token = %q, %v", got, err)
	}
	if _, err := loadToken("literal", path); err == nil {
		t.Fatal("expected an error when both token inputs are configured")
	}
}

func TestUDPPacketRoundTrip(t *testing.T) {
	aead, err := udpAEAD("test-token")
	if err != nil {
		t.Fatal(err)
	}
	request, err := makeUDPRequest("127.0.0.1:5353", []byte("dns-query"))
	if err != nil {
		t.Fatal(err)
	}
	packet, err := sealUDP(aead, request)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := openUDP(aead, packet)
	if err != nil {
		t.Fatal(err)
	}
	target, body, err := parseUDPRequest(plain)
	if err != nil {
		t.Fatal(err)
	}
	if target != "127.0.0.1:5353" || string(body) != "dns-query" {
		t.Fatalf("decoded UDP request = %q %q", target, body)
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
