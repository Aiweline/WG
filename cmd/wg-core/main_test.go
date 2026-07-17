package main

import "testing"

func TestParseSafeClientOptions(t *testing.T) {
	options, err := parseOptions([]string{"client", "--dev-safe", "--no-host-network", "--management-address", "127.0.0.1:47003"})
	if err != nil {
		t.Fatal(err)
	}
	if options.mode != "client" || !options.devSafe || !options.noHostNetwork {
		t.Fatalf("unexpected options: %+v", options)
	}
}

func TestManagementAddressMustBeLoopback(t *testing.T) {
	if err := validateLoopback("0.0.0.0:47003"); err == nil {
		t.Fatal("expected non-loopback management address to fail")
	}
}
