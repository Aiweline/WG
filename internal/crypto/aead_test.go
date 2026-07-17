package wgcrypto

import (
	"bytes"
	"errors"
	"testing"
)

func TestHandshakeSealOpenAndTamper(t *testing.T) {
	key := mustHex32(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	ad := []byte("canonical-m1-ad")
	plaintext := []byte("canonical TLV stream")
	ciphertext, err := SealHandshake(key, ad, plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	opened, err := OpenHandshake(key, ad, ciphertext)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatal("handshake plaintext mismatch")
	}

	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)-1] ^= 0x80
	if _, err := OpenHandshake(key, ad, tampered); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tamper error = %v", err)
	}
	if _, err := OpenHandshake(key, []byte("different-ad"), ciphertext); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("associated data tamper error = %v", err)
	}
	if _, err := OpenHandshake(key, ad, ciphertext[:15]); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("short ciphertext error = %v", err)
	}
}

func TestNonceLayout(t *testing.T) {
	got := Nonce(0x0102030405060708)
	want := [12]byte{0, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1}
	if got != want {
		t.Fatalf("nonce = %x, want %x", got, want)
	}
	if got := Nonce(0); got != [12]byte{} {
		t.Fatalf("PN zero nonce = %x", got)
	}
}
