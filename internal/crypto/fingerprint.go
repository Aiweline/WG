package wgcrypto

import (
	"encoding/base32"
	"strings"
)

// FingerprintRole chooses the fixed WG/1 domain-separation label and display
// prefix for a static public key fingerprint.
type FingerprintRole uint8

const (
	FingerprintServer FingerprintRole = iota + 1
	FingerprintClient
)

var noPaddingBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// Fingerprint returns the canonical wgs-/wgc- lowercase, grouped fingerprint.
func Fingerprint(role FingerprintRole, publicKey [32]byte) (string, error) {
	var label, prefix string
	switch role {
	case FingerprintServer:
		label, prefix = "WG-FP/1/server", "wgs-"
	case FingerprintClient:
		label, prefix = "WG-FP/1/client", "wgc-"
	default:
		return "", ErrInvalidRole
	}

	digest := Sum256([]byte(label), publicKey[:])
	encoded := strings.ToLower(noPaddingBase32.EncodeToString(digest[:20]))
	var grouped strings.Builder
	grouped.Grow(len(prefix) + len(encoded) + 7)
	grouped.WriteString(prefix)
	for index := 0; index < len(encoded); index += 4 {
		if index > 0 {
			grouped.WriteByte('-')
		}
		grouped.WriteString(encoded[index : index+4])
	}
	return grouped.String(), nil
}
