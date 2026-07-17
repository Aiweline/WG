// Package wgcrypto implements the WG/1 cryptographic schedule by composing
// standard, reviewed Go cryptographic primitives. It does not implement any
// low-level primitive itself.
package wgcrypto

import "errors"

var (
	ErrInvalidLength    = errors.New("wgcrypto: invalid length")
	ErrInvalidRole      = errors.New("wgcrypto: invalid fingerprint role")
	ErrInvalidKey       = errors.New("wgcrypto: invalid key")
	ErrRandomSource     = errors.New("wgcrypto: random source failed")
	ErrDH               = errors.New("wgcrypto: key agreement failed")
	ErrZeroSharedSecret = errors.New("wgcrypto: invalid shared secret")
	ErrAuthentication   = errors.New("wgcrypto: authentication failed")
	ErrInvalidTransport = errors.New("wgcrypto: invalid transport packet")
	ErrFrameEncoding    = errors.New("wgcrypto: invalid transport frames")
)
