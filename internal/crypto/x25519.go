package wgcrypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"io"
)

// GenerateKey creates an X25519 private key using the operating system CSPRNG.
func GenerateKey() (*ecdh.PrivateKey, error) {
	return GenerateKeyFrom(rand.Reader)
}

// GenerateKeyFrom creates an X25519 private key using random. It exists for
// deterministic tests and dependency injection; production callers should use
// GenerateKey.
func GenerateKeyFrom(random io.Reader) (*ecdh.PrivateKey, error) {
	if random == nil {
		return nil, ErrRandomSource
	}
	private, err := ecdh.X25519().GenerateKey(random)
	if err != nil {
		return nil, ErrRandomSource
	}
	return private, nil
}

// PublicBytes returns the canonical raw 32-byte X25519 public key.
func PublicBytes(key *ecdh.PublicKey) ([32]byte, error) {
	var result [32]byte
	if key == nil {
		return result, ErrInvalidKey
	}
	encoded := key.Bytes()
	if len(encoded) != len(result) {
		return result, ErrInvalidKey
	}
	copy(result[:], encoded)
	return result, nil
}

// DH performs X25519 and rejects an all-zero shared secret. crypto/ecdh also
// rejects low-order X25519 results; the explicit postcondition check keeps the
// WG-HS/1 invariant at this package boundary.
func DH(private *ecdh.PrivateKey, peerPublic [32]byte) ([32]byte, error) {
	var result [32]byte
	if private == nil {
		return result, ErrInvalidKey
	}
	peer, err := ecdh.X25519().NewPublicKey(peerPublic[:])
	if err != nil {
		return result, ErrInvalidKey
	}
	shared, err := private.ECDH(peer)
	if err != nil {
		return result, ErrDH
	}
	if len(shared) != len(result) {
		return result, ErrDH
	}
	if isAllZero(shared) {
		return result, ErrZeroSharedSecret
	}
	copy(result[:], shared)
	return result, nil
}
