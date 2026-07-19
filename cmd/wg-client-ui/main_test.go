package main

import (
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestSPAHandlerFallsBackToIndex(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("WG UI"), 0o600); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	newSPAHandler(root).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/routing", nil))
	if response.Code != http.StatusOK || response.Body.String() != "WG UI" {
		t.Fatalf("unexpected response: %d %q", response.Code, response.Body.String())
	}
}

func TestSPAHandlerServesRootWithoutRedirect(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("WG UI"), 0o600); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	newSPAHandler(root).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusOK || response.Body.String() != "WG UI" {
		t.Fatalf("unexpected root response: %d %q", response.Code, response.Body.String())
	}
}

func TestUIAddressMustBeLoopback(t *testing.T) {
	if err := requireLoopback("192.0.2.4:4173"); err == nil {
		t.Fatal("expected non-loopback UI listener to fail")
	}
}

func TestDNSQueryResponseValidation(t *testing.T) {
	query, id := dnsQuery("example.com")
	response := make([]byte, 12)
	binary.BigEndian.PutUint16(response[:2], id)
	response[2] = 0x81
	response[3] = 0x80
	binary.BigEndian.PutUint16(response[4:6], 1)
	binary.BigEndian.PutUint16(response[6:8], 1)
	if len(query) < 12 || !validDNSResponse(response, id) {
		t.Fatal("expected a valid DNS response")
	}
	if validDNSResponse(query, id) {
		t.Fatal("a DNS request must not be accepted as a response")
	}
}

func TestProxyTestHandlerRejectsGet(t *testing.T) {
	handler := newProxyTestHandler()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/proxy/test", nil))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", response.Code)
	}
}
