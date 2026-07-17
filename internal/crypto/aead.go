package wgcrypto

import (
	"encoding/binary"

	"golang.org/x/crypto/chacha20poly1305"
)

var handshakeNonce [chacha20poly1305.NonceSize]byte

// SealHandshake encrypts one WG-HS/1 handshake plaintext with the mandated
// all-zero 96-bit nonce. A derived handshake key is single-use by design.
func SealHandshake(key [chacha20poly1305.KeySize]byte, associatedData, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, ErrInvalidKey
	}
	return aead.Seal(nil, handshakeNonce[:], plaintext, associatedData), nil
}

// OpenHandshake authenticates and decrypts one WG-HS/1 handshake ciphertext.
func OpenHandshake(key [chacha20poly1305.KeySize]byte, associatedData, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < chacha20poly1305.Overhead {
		return nil, ErrAuthentication
	}
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, ErrInvalidKey
	}
	plaintext, err := aead.Open(nil, handshakeNonce[:], ciphertext, associatedData)
	if err != nil {
		return nil, ErrAuthentication
	}
	return plaintext, nil
}

// Nonce returns 0x00000000 || uint64_le(packetNumber).
func Nonce(packetNumber uint64) [chacha20poly1305.NonceSize]byte {
	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:], packetNumber)
	return nonce
}
