package wgcrypto

import (
	"crypto/ecdh"
	"errors"
	"testing"
)

func TestX25519RFC7748Vector(t *testing.T) {
	privateBytes := mustHex(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	wantPublic := mustHex32(t, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	peerPublic := mustHex32(t, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	wantShared := mustHex32(t, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

	private, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		t.Fatalf("new private key: %v", err)
	}
	public, err := PublicBytes(private.PublicKey())
	if err != nil {
		t.Fatalf("public bytes: %v", err)
	}
	if public != wantPublic {
		t.Fatalf("public key mismatch: got %x", public)
	}
	shared, err := DH(private, peerPublic)
	if err != nil {
		t.Fatalf("dh: %v", err)
	}
	if shared != wantShared {
		t.Fatalf("shared secret mismatch: got %x", shared)
	}
}

func TestDHRejectsLowOrderResultWithoutSensitiveError(t *testing.T) {
	private, err := GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	var allZeroPublic [32]byte
	_, err = DH(private, allZeroPublic)
	if err == nil {
		t.Fatal("all-zero X25519 peer was accepted")
	}
	if !errors.Is(err, ErrDH) && !errors.Is(err, ErrZeroSharedSecret) {
		t.Fatalf("unexpected safe error class: %v", err)
	}
	if got := err.Error(); got != ErrDH.Error() && got != ErrZeroSharedSecret.Error() {
		t.Fatalf("error leaked implementation detail: %q", got)
	}
}

func TestKeyHelpersRejectNil(t *testing.T) {
	if _, err := PublicBytes(nil); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("public nil error = %v", err)
	}
	var peer [32]byte
	if _, err := DH(nil, peer); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("dh nil error = %v", err)
	}
	if _, err := GenerateKeyFrom(nil); !errors.Is(err, ErrRandomSource) {
		t.Fatalf("random nil error = %v", err)
	}
}

func TestFingerprintCanonicalKnownValues(t *testing.T) {
	public := mustHex32(t, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	server, err := Fingerprint(FingerprintServer, public)
	if err != nil {
		t.Fatalf("server fingerprint: %v", err)
	}
	if want := "wgs-gbtf-yd7v-blc2-rtmf-sd75-6mvx-vo62-cfx4"; server != want {
		t.Fatalf("server fingerprint = %q", server)
	}
	client, err := Fingerprint(FingerprintClient, public)
	if err != nil {
		t.Fatalf("client fingerprint: %v", err)
	}
	if want := "wgc-ubue-745y-rude-rfp7-htnd-l3hv-35ql-jsyg"; client != want {
		t.Fatalf("client fingerprint = %q", client)
	}
	if _, err := Fingerprint(0, public); !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("invalid role error = %v", err)
	}
}
