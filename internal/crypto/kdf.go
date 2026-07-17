package wgcrypto

import (
	"crypto/hmac"
	"crypto/subtle"
	"hash"

	"golang.org/x/crypto/blake2s"
)

const (
	// SuiteID is the only WG/1 cryptographic suite identifier. WG/1 does not
	// negotiate aliases or alternative suites.
	SuiteID = "WG-HS1-X25519-CHACHAPOLY-BLAKE2S"

	hashSize = blake2s.Size
)

var (
	protocolLabel = []byte("WG/1")
	m1Label       = []byte("WG-HS1/m1")
	m2Label       = []byte("WG-HS1/m2")
	c2sLabel      = []byte("WG-HS1/c2s")
	s2cLabel      = []byte("WG-HS1/s2c")
)

// Context returns the canonical WG-HS/1 context for a deployment identifier.
func Context(deploymentID [16]byte) []byte {
	context := make([]byte, 0, 1+len(protocolLabel)+len(deploymentID)+1+len(SuiteID))
	context = append(context, byte(len(protocolLabel)))
	context = append(context, protocolLabel...)
	context = append(context, deploymentID[:]...)
	context = append(context, byte(len(SuiteID)))
	context = append(context, SuiteID...)
	return context
}

// Sum256 computes BLAKE2s-256 over the exact concatenation of parts.
func Sum256(parts ...[]byte) [32]byte {
	h := newBLAKE2s()
	for _, part := range parts {
		_, _ = h.Write(part)
	}
	var sum [hashSize]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

// Extract implements RFC 5869 HKDF-Extract using HMAC-BLAKE2s-256. A missing
// salt is represented by HashLen zero bytes, as required by RFC 5869.
func Extract(salt, ikm []byte) [32]byte {
	if len(salt) == 0 {
		salt = make([]byte, hashSize)
	}
	mac := hmac.New(newBLAKE2s, salt)
	_, _ = mac.Write(ikm)
	var prk [hashSize]byte
	copy(prk[:], mac.Sum(nil))
	return prk
}

// Expand implements RFC 5869 HKDF-Expand using HMAC-BLAKE2s-256.
func Expand(prk, info []byte, length int) ([]byte, error) {
	if length < 0 || length > 255*hashSize {
		return nil, ErrInvalidLength
	}
	if length == 0 {
		return []byte{}, nil
	}

	output := make([]byte, 0, length)
	previous := make([]byte, 0, hashSize)
	for counter := byte(1); len(output) < length; counter++ {
		mac := hmac.New(newBLAKE2s, prk)
		_, _ = mac.Write(previous)
		_, _ = mac.Write(info)
		_, _ = mac.Write([]byte{counter})
		previous = mac.Sum(previous[:0])
		need := length - len(output)
		if need > len(previous) {
			need = len(previous)
		}
		output = append(output, previous[:need]...)
	}
	return output, nil
}

// DeriveM1 derives the INITIAL extraction key and AEAD key from es.
func DeriveM1(context []byte, es [32]byte) (prk1, k1 [32]byte, err error) {
	if isAllZero(es[:]) {
		return prk1, k1, ErrZeroSharedSecret
	}
	salt := Sum256(context)
	prk1 = Extract(salt[:], es[:])
	expanded, err := Expand(prk1[:], m1Label, hashSize)
	if err != nil {
		return [hashSize]byte{}, [hashSize]byte{}, err
	}
	copy(k1[:], expanded)
	return prk1, k1, nil
}

// DeriveM2 derives the HANDSHAKE extraction key and AEAD key. The IKM order is
// fixed as es || ss || ee || se.
func DeriveM2(th1, es, ss, ee, se [32]byte) (prk2, k2 [32]byte, err error) {
	for _, secret := range [...][32]byte{es, ss, ee, se} {
		if isAllZero(secret[:]) {
			return prk2, k2, ErrZeroSharedSecret
		}
	}
	var ikm [4 * hashSize]byte
	copy(ikm[0*hashSize:], es[:])
	copy(ikm[1*hashSize:], ss[:])
	copy(ikm[2*hashSize:], ee[:])
	copy(ikm[3*hashSize:], se[:])
	prk2 = Extract(th1[:], ikm[:])
	info := make([]byte, 0, len(m2Label)+len(th1))
	info = append(info, m2Label...)
	info = append(info, th1[:]...)
	expanded, err := Expand(prk2[:], info, hashSize)
	if err != nil {
		return [hashSize]byte{}, [hashSize]byte{}, err
	}
	copy(k2[:], expanded)
	return prk2, k2, nil
}

// DeriveTraffic derives independent client-to-server and server-to-client
// traffic keys from the completed handshake transcript.
func DeriveTraffic(prk2, th2 [32]byte) (clientToServer, serverToClient [32]byte, err error) {
	c2sInfo := make([]byte, 0, len(c2sLabel)+len(th2))
	c2sInfo = append(c2sInfo, c2sLabel...)
	c2sInfo = append(c2sInfo, th2[:]...)
	s2cInfo := make([]byte, 0, len(s2cLabel)+len(th2))
	s2cInfo = append(s2cInfo, s2cLabel...)
	s2cInfo = append(s2cInfo, th2[:]...)

	c2s, err := Expand(prk2[:], c2sInfo, hashSize)
	if err != nil {
		return clientToServer, serverToClient, err
	}
	s2c, err := Expand(prk2[:], s2cInfo, hashSize)
	if err != nil {
		return clientToServer, serverToClient, err
	}
	copy(clientToServer[:], c2s)
	copy(serverToClient[:], s2c)
	return clientToServer, serverToClient, nil
}

func newBLAKE2s() hash.Hash {
	h, err := blake2s.New256(nil)
	if err != nil {
		panic("wgcrypto: unavailable BLAKE2s-256")
	}
	return h
}

func isAllZero(value []byte) bool {
	zero := make([]byte, len(value))
	return subtle.ConstantTimeCompare(value, zero) == 1
}
