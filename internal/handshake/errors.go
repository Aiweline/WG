// Package handshake implements the in-memory WG-HS/1 handshake state machine.
// It deliberately contains no sockets, TUN handling, host routing, or enrollment.
package handshake

import "errors"

var (
	ErrState                 = errors.New("handshake: invalid state transition")
	ErrConfiguration         = errors.New("handshake: invalid configuration")
	ErrMessage               = errors.New("handshake: invalid message")
	ErrAuthentication        = errors.New("handshake: authentication failed")
	ErrUnregisteredClient    = errors.New("handshake: client is not registered")
	ErrEnrollmentUnsupported = errors.New("handshake: enrollment is not supported")
	ErrTranscript            = errors.New("handshake: transcript mismatch")
	ErrConnectionID          = errors.New("handshake: connection identifier mismatch")
	ErrParameters            = errors.New("handshake: unacceptable negotiated parameters")
	ErrAttemptCapacity       = errors.New("handshake: pending-attempt capacity reached")
	ErrAttemptExpired        = errors.New("handshake: attempt expired")
)
