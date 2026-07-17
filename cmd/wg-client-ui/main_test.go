package main

import (
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
