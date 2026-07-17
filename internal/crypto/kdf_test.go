package wgcrypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestContextCanonical(t *testing.T) {
	var deploymentID [16]byte
	for index := range deploymentID {
		deploymentID[index] = byte(index)
	}
	got := Context(deploymentID)
	want := make([]byte, 0, len(got))
	want = append(want, 4)
	want = append(want, "WG/1"...)
	want = append(want, deploymentID[:]...)
	want = append(want, byte(len(SuiteID)))
	want = append(want, SuiteID...)
	if !bytes.Equal(got, want) {
		t.Fatalf("context does not use the canonical byte layout")
	}
}

func TestSum256BLAKE2sOfficialVector(t *testing.T) {
	// BLAKE2 specification vector for the empty message.
	want := mustHex32(t, "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9")
	if got := Sum256(nil); got != want {
		t.Fatalf("BLAKE2s-256 vector mismatch: got %x", got)
	}
}

func TestHKDFBLAKE2sIndependentVector(t *testing.T) {
	// Inputs mirror RFC 5869 test case 1. The expected values were generated
	// independently with Python's hmac and hashlib.blake2s implementations.
	ikm := mustHex(t, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt := mustHex(t, "000102030405060708090a0b0c")
	info := mustHex(t, "f0f1f2f3f4f5f6f7f8f9")
	wantPRK := mustHex32(t, "57e878130679f9ea85900980b52df2643d043b82f290eb7dd62175dbb04cca4e")
	wantOKM := mustHex(t, "1472c31f2ff768c71b19f8803683ee3b13c1a5fb3ea59c0c3bf0d44a4a40dcd4329d9cd85bbe35a1b3e7")

	prk := Extract(salt, ikm)
	if prk != wantPRK {
		t.Fatalf("extract mismatch: got %x", prk)
	}
	okm, err := Expand(prk[:], info, len(wantOKM))
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if !bytes.Equal(okm, wantOKM) {
		t.Fatalf("expand mismatch: got %x", okm)
	}
	if _, err := Expand(prk[:], nil, 255*hashSize+1); !errors.Is(err, ErrInvalidLength) {
		t.Fatalf("oversized expand error = %v", err)
	}
}

func TestWGKeyScheduleIndependentValuesAndDirections(t *testing.T) {
	var deploymentID [16]byte
	var es, ss, ee, se [32]byte
	for index := range deploymentID {
		deploymentID[index] = byte(index)
	}
	for index := range es {
		es[index] = byte(index + 1)
		ss[index] = byte(index + 33)
		ee[index] = byte(index + 65)
		se[index] = byte(index + 97)
	}

	prk1, k1, err := DeriveM1(Context(deploymentID), es)
	if err != nil {
		t.Fatalf("derive m1: %v", err)
	}
	if want := mustHex32(t, "26616c1b26e1289120863399f6527bdf3447600f1a00f9d76918fc7c1cf835b7"); prk1 != want {
		t.Fatalf("prk1 mismatch: got %x", prk1)
	}
	if want := mustHex32(t, "3d8f788d389cc5128fbc4752f9e82c456e56e33dbe0cf27a89d6fdbf5e1799af"); k1 != want {
		t.Fatalf("k1 mismatch: got %x", k1)
	}

	th1 := Sum256([]byte("transcript-one"))
	if want := mustHex32(t, "24d187f8628e1bd833b4280267b3af3b7091a0d8fb9870d721fdfafb4b1bbdce"); th1 != want {
		t.Fatal("test transcript th1 mismatch")
	}
	prk2, k2, err := DeriveM2(th1, es, ss, ee, se)
	if err != nil {
		t.Fatalf("derive m2: %v", err)
	}
	if want := mustHex32(t, "7f64faab051f1871e122c4c98dcf182b347a59b299b1728a45bd8a9f34bad9ed"); prk2 != want {
		t.Fatalf("prk2 mismatch: got %x", prk2)
	}
	if want := mustHex32(t, "71c9b58074abf69ccfae161c37c74913d8bce562a8c8a0a80dce48922acab00f"); k2 != want {
		t.Fatalf("k2 mismatch: got %x", k2)
	}

	th2 := Sum256([]byte("transcript-two"))
	c2s, s2c, err := DeriveTraffic(prk2, th2)
	if err != nil {
		t.Fatalf("derive traffic: %v", err)
	}
	if want := mustHex32(t, "3aa582e0b00dd5ab913dfc53850fcfa2dd094910a019b87acac46a7b2af07ccb"); c2s != want {
		t.Fatalf("c2s mismatch: got %x", c2s)
	}
	if want := mustHex32(t, "5d4e3641860062e213781d98bf9f5674ca27f4a1b8427b319f1a35c1d2f9c551"); s2c != want {
		t.Fatalf("s2c mismatch: got %x", s2c)
	}
	if c2s == s2c {
		t.Fatal("direction keys must be distinct")
	}
}

func TestKeyScheduleRejectsZeroDHInput(t *testing.T) {
	var zero, nonzero [32]byte
	nonzero[0] = 1
	if _, _, err := DeriveM1([]byte("context"), zero); !errors.Is(err, ErrZeroSharedSecret) {
		t.Fatalf("derive m1 zero secret error = %v", err)
	}
	if _, _, err := DeriveM2(nonzero, nonzero, zero, nonzero, nonzero); !errors.Is(err, ErrZeroSharedSecret) {
		t.Fatalf("derive m2 zero secret error = %v", err)
	}
}

func mustHex(t *testing.T, encoded string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode test vector: %v", err)
	}
	return decoded
}

func mustHex32(t *testing.T, encoded string) [32]byte {
	t.Helper()
	decoded := mustHex(t, encoded)
	if len(decoded) != 32 {
		t.Fatalf("test vector length = %d", len(decoded))
	}
	var result [32]byte
	copy(result[:], decoded)
	return result
}
