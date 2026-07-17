// Package codec implements bounded parsing and canonical serialization for
// WG/1 public wire structures. It deliberately contains no cryptography or I/O.
package codec

import (
	"errors"
	"fmt"
)

var (
	ErrTruncated          = errors.New("codec: truncated input")
	ErrLength             = errors.New("codec: invalid length")
	ErrLimit              = errors.New("codec: configured limit exceeded")
	ErrTrailingData       = errors.New("codec: trailing data")
	ErrVersion            = errors.New("codec: unsupported version")
	ErrKind               = errors.New("codec: unknown packet kind")
	ErrFlags              = errors.New("codec: non-zero flags")
	ErrReserved           = errors.New("codec: non-zero reserved field")
	ErrCID                = errors.New("codec: invalid connection identifier")
	ErrPacketNumber       = errors.New("codec: invalid packet number")
	ErrTLVOrder           = errors.New("codec: TLV fields are not canonical")
	ErrDuplicateTLV       = errors.New("codec: duplicate TLV field")
	ErrUnknownCriticalTLV = errors.New("codec: unknown critical TLV field")
	ErrTLVLength          = errors.New("codec: invalid TLV field length")
	ErrTLVContext         = errors.New("codec: TLV field is invalid in this context")
	ErrMissingTLV         = errors.New("codec: required TLV field is missing")
	ErrUnknownFrameType   = errors.New("codec: unknown frame type")
	ErrFrameFlags         = errors.New("codec: non-zero frame flags")
	ErrFrameConstraint    = errors.New("codec: invalid frame combination")
	ErrIPPacket           = errors.New("codec: invalid inner IP packet")
	ErrUTF8               = errors.New("codec: invalid UTF-8")
)

// DecodeError adds a safe field and byte offset to a classifiable parse error.
// Detail must never contain secrets or packet contents.
type DecodeError struct {
	Kind   error
	Offset int
	Field  string
	Detail string
}

func (e *DecodeError) Error() string {
	message := e.Kind.Error()
	if e.Field != "" {
		message += " in " + e.Field
	}
	if e.Offset >= 0 {
		message += fmt.Sprintf(" at byte %d", e.Offset)
	}
	if e.Detail != "" {
		message += ": " + e.Detail
	}
	return message
}

// Unwrap enables errors.Is and errors.As.
func (e *DecodeError) Unwrap() error { return e.Kind }

func decodeError(kind error, offset int, field, detail string) error {
	return &DecodeError{Kind: kind, Offset: offset, Field: field, Detail: detail}
}
