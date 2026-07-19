package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func validTestProxyConfig() proxyClientConfig {
	return proxyClientConfig{
		Servers:          []proxyServerProfile{{Name: "Beijing", IP: "47.92.25.188", Port: 9518}},
		SelectedEndpoint: "47.92.25.188:9518",
		Transport:        "both",
		UDPTarget:        "1.1.1.1:53",
	}
}

func TestValidateProxyConfig(t *testing.T) {
	valid := validTestProxyConfig()
	if err := validateProxyConfig(valid, true); err != nil {
		t.Fatalf("valid config was rejected: %v", err)
	}

	tests := []struct {
		name             string
		mutate           func(*proxyClientConfig)
		requireSelection bool
	}{
		{name: "unknown transport", mutate: func(config *proxyClientConfig) { config.Transport = "quic" }, requireSelection: true},
		{name: "invalid IP", mutate: func(config *proxyClientConfig) { config.Servers[0].IP = "vpn.example.com" }, requireSelection: true},
		{name: "unspecified IP", mutate: func(config *proxyClientConfig) { config.Servers[0].IP = "0.0.0.0" }, requireSelection: true},
		{name: "invalid server port", mutate: func(config *proxyClientConfig) { config.Servers[0].Port = 65536 }, requireSelection: true},
		{name: "selection not in list", mutate: func(config *proxyClientConfig) { config.SelectedEndpoint = "192.0.2.1:9518" }},
		{name: "selection required", mutate: func(config *proxyClientConfig) { config.SelectedEndpoint = "" }, requireSelection: true},
		{name: "invalid UDP target port", mutate: func(config *proxyClientConfig) { config.UDPTarget = "1.1.1.1:70000" }, requireSelection: true},
		{name: "nonnumeric UDP target port", mutate: func(config *proxyClientConfig) { config.UDPTarget = "1.1.1.1:dns" }, requireSelection: true},
		{name: "duplicate server", mutate: func(config *proxyClientConfig) { config.Servers = append(config.Servers, config.Servers[0]) }, requireSelection: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validTestProxyConfig()
			test.mutate(&config)
			if err := validateProxyConfig(config, test.requireSelection); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestValidHostPort(t *testing.T) {
	tests := map[string]bool{
		"1.1.1.1:53":                true,
		"dns.google:53":             true,
		"[2606:4700:4700::1111]:53": true,
		"1.1.1.1:0":                 false,
		"1.1.1.1:65536":             false,
		"1.1.1.1:dns":               false,
		"missing-port":              false,
		"bad host:53":               false,
	}
	for value, expected := range tests {
		if actual := validHostPort(value); actual != expected {
			t.Errorf("validHostPort(%q) = %v, want %v", value, actual, expected)
		}
	}
}

func TestProxyConfigRoundTripUsesPrivatePermissions(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "client-state")
	controller := newProxyController(stateDir, filepath.Join(stateDir, "wg-proxy"))
	config := validTestProxyConfig()
	if err := controller.saveConfig(config); err != nil {
		t.Fatal(err)
	}

	directoryInfo, err := os.Stat(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if permission := directoryInfo.Mode().Perm(); permission != 0o700 {
		t.Fatalf("state directory permission = %o, want 700", permission)
	}
	configInfo, err := os.Stat(controller.configPath())
	if err != nil {
		t.Fatal(err)
	}
	if permission := configInfo.Mode().Perm(); permission != 0o600 {
		t.Fatalf("config permission = %o, want 600", permission)
	}
	loaded, err := controller.loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded, config) {
		t.Fatalf("loaded config = %#v, want %#v", loaded, config)
	}

	if err := os.Chmod(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := controller.saveConfig(config); err != nil {
		t.Fatal(err)
	}
	directoryInfo, err = os.Stat(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if permission := directoryInfo.Mode().Perm(); permission != 0o700 {
		t.Fatalf("state directory permission after save = %o, want 700", permission)
	}
}

func TestProxyConfigCanRemoveLastServer(t *testing.T) {
	controller := newProxyController(filepath.Join(t.TempDir(), "client-state"), "/missing/wg-proxy")
	if err := controller.saveConfig(defaultProxyConfig()); err != nil {
		t.Fatalf("save empty config: %v", err)
	}
	loaded, err := controller.loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Servers) != 0 || loaded.SelectedEndpoint != "" {
		t.Fatalf("loaded config = %#v, want no servers or selection", loaded)
	}
}

func TestProxyConfigAPIRejectsMalformedAndOversizedJSON(t *testing.T) {
	controller := newProxyController(filepath.Join(t.TempDir(), "state"), "/missing/wg-proxy")
	config := validTestProxyConfig()
	body, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}

	put := httptest.NewRecorder()
	controller.serveConfig(put, httptest.NewRequest(http.MethodPut, "/api/proxy/config", strings.NewReader(string(body))))
	if put.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, body = %s", put.Code, put.Body.String())
	}

	get := httptest.NewRecorder()
	controller.serveConfig(get, httptest.NewRequest(http.MethodGet, "/api/proxy/config", nil))
	if get.Code != http.StatusOK {
		t.Fatalf("GET status = %d, body = %s", get.Code, get.Body.String())
	}
	var loaded proxyClientConfig
	if err := json.Unmarshal(get.Body.Bytes(), &loaded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded, config) {
		t.Fatalf("GET config = %#v, want %#v", loaded, config)
	}

	for name, malformed := range map[string]string{
		"trailing object": string(body) + `{}`,
		"unknown field":   `{"servers":[],"selected_endpoint":"","transport":"tcp","udp_target":"1.1.1.1:53","extra":true}`,
		"oversized body":  string(body) + strings.Repeat(" ", int(maxProxyConfigBytes)+1),
	} {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			controller.serveConfig(response, httptest.NewRequest(http.MethodPut, "/api/proxy/config", strings.NewReader(malformed)))
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
		})
	}

	wrongMethod := httptest.NewRecorder()
	controller.serveConfig(wrongMethod, httptest.NewRequest(http.MethodPost, "/api/proxy/config", nil))
	if wrongMethod.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d", wrongMethod.Code)
	}
	if allow := wrongMethod.Header().Get("Allow"); allow != "GET, PUT" {
		t.Fatalf("Allow = %q, want %q", allow, "GET, PUT")
	}
}

func TestLoadProxyConfigRejectsOversizedFile(t *testing.T) {
	stateDir := t.TempDir()
	controller := newProxyController(stateDir, "/missing/wg-proxy")
	if err := os.WriteFile(controller.configPath(), []byte(strings.Repeat(" ", int(maxProxyConfigBytes)+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.loadConfig(); err == nil || !strings.Contains(err.Error(), "64 KiB") {
		t.Fatalf("expected size error, got %v", err)
	}
}

func TestProxyConnectRejectsInsecureTokenPermissions(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	controller := newProxyController(stateDir, filepath.Join(stateDir, "wg-proxy"))
	if err := controller.saveConfig(validTestProxyConfig()); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{controller.binary, filepath.Join(stateDir, "server-cert.pem"), filepath.Join(stateDir, "token")} {
		if err := os.WriteFile(file, []byte("test"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(stateDir, "token"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := controller.connect(); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("expected insecure token error, got %v", err)
	}
}

func TestProxyStatusRejectsMutation(t *testing.T) {
	controller := newProxyController(t.TempDir(), "/missing/wg-proxy")
	response := httptest.NewRecorder()
	controller.serveStatus(response, httptest.NewRequest(http.MethodPost, "/api/proxy/status", nil))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", response.Code)
	}
	if allow := response.Header().Get("Allow"); allow != http.MethodGet {
		t.Fatalf("Allow = %q, want GET", allow)
	}
}
