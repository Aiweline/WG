package codec

import (
	"encoding/binary"
	"fmt"
	"math"
)

const (
	EphemeralPublicKeySize = 32
	MinRetryTokenSize      = 16
)

// Initial is the clear structure surrounding INITIAL's encrypted TLV stream.
type Initial struct {
	Token                 []byte
	ClientEphemeralPublic [EphemeralPublicKeySize]byte
	EncryptedPayload      []byte
}

// ParseInitial parses a complete INITIAL payload and rejects trailing bytes.
func ParseInitial(data []byte) (Initial, error) {
	const fixedAfterToken = EphemeralPublicKeySize + 2 + AEADTagSize
	if len(data) > math.MaxUint16 {
		return Initial{}, decodeError(ErrLimit, 0, "initial", "outer payload exceeds uint16")
	}
	if len(data) < 2 {
		return Initial{}, decodeError(ErrTruncated, len(data), "initial.token_length", "need uint16")
	}
	tokenLength := int(binary.BigEndian.Uint16(data[:2]))
	if tokenLength > len(data)-2 {
		return Initial{}, decodeError(ErrTruncated, 2, "initial.token", "declared token exceeds payload")
	}
	if len(data)-2-tokenLength < fixedAfterToken {
		return Initial{}, decodeError(ErrTruncated, 2+tokenLength, "initial", "missing public key or encrypted payload")
	}
	offset := 2
	result := Initial{Token: append([]byte(nil), data[offset:offset+tokenLength]...)}
	offset += tokenLength
	copy(result.ClientEphemeralPublic[:], data[offset:offset+EphemeralPublicKeySize])
	offset += EphemeralPublicKeySize
	encryptedLength := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if encryptedLength < AEADTagSize {
		return Initial{}, decodeError(ErrLength, offset-2, "initial.encrypted_length", "must include a 16-byte authentication tag")
	}
	remaining := len(data) - offset
	if remaining < encryptedLength {
		return Initial{}, decodeError(ErrTruncated, offset+remaining, "initial.encrypted_payload", "shorter than declared")
	}
	if remaining > encryptedLength {
		return Initial{}, decodeError(ErrTrailingData, offset+encryptedLength, "initial.encrypted_payload", "bytes follow declared ciphertext")
	}
	result.EncryptedPayload = append([]byte(nil), data[offset:]...)
	return result, nil
}

// MarshalBinary serializes INITIAL canonically.
func (p Initial) MarshalBinary() ([]byte, error) {
	if len(p.Token) > math.MaxUint16 {
		return nil, decodeError(ErrLength, 0, "initial.token", "does not fit uint16")
	}
	if len(p.EncryptedPayload) < AEADTagSize || len(p.EncryptedPayload) > math.MaxUint16 {
		return nil, decodeError(ErrLength, 0, "initial.encrypted_payload", "must be 16..65535 bytes")
	}
	total := 2 + len(p.Token) + EphemeralPublicKeySize + 2 + len(p.EncryptedPayload)
	if total > math.MaxUint16 {
		return nil, decodeError(ErrLength, 0, "initial", "outer payload does not fit uint16")
	}
	data := make([]byte, total)
	binary.BigEndian.PutUint16(data[:2], uint16(len(p.Token)))
	offset := 2
	copy(data[offset:], p.Token)
	offset += len(p.Token)
	copy(data[offset:], p.ClientEphemeralPublic[:])
	offset += EphemeralPublicKeySize
	binary.BigEndian.PutUint16(data[offset:offset+2], uint16(len(p.EncryptedPayload)))
	offset += 2
	copy(data[offset:], p.EncryptedPayload)
	return data, nil
}

// Retry is an opaque, authenticated address-validation token. Codec can only
// enforce the minimum length implied by 128-bit authentication strength.
type Retry struct {
	Token []byte
}

func ParseRetry(data []byte) (Retry, error) {
	if len(data) > math.MaxUint16 {
		return Retry{}, decodeError(ErrLimit, 0, "retry.token", "outer payload exceeds uint16")
	}
	if len(data) < MinRetryTokenSize {
		return Retry{}, decodeError(ErrLength, 0, "retry.token", fmt.Sprintf("need at least %d bytes", MinRetryTokenSize))
	}
	return Retry{Token: append([]byte(nil), data...)}, nil
}

func (p Retry) MarshalBinary() ([]byte, error) {
	if len(p.Token) < MinRetryTokenSize || len(p.Token) > math.MaxUint16 {
		return nil, decodeError(ErrLength, 0, "retry.token", "must be 16..65535 bytes")
	}
	return append([]byte(nil), p.Token...), nil
}

// Handshake is the clear structure surrounding HANDSHAKE's encrypted TLVs.
type Handshake struct {
	ServerEphemeralPublic [EphemeralPublicKeySize]byte
	EncryptedPayload      []byte
}

func ParseHandshake(data []byte) (Handshake, error) {
	const prefixSize = EphemeralPublicKeySize + 2
	if len(data) > math.MaxUint16 {
		return Handshake{}, decodeError(ErrLimit, 0, "handshake", "outer payload exceeds uint16")
	}
	if len(data) < prefixSize {
		return Handshake{}, decodeError(ErrTruncated, len(data), "handshake", "missing public key or encrypted length")
	}
	var result Handshake
	copy(result.ServerEphemeralPublic[:], data[:EphemeralPublicKeySize])
	encryptedLength := int(binary.BigEndian.Uint16(data[EphemeralPublicKeySize:prefixSize]))
	if encryptedLength < AEADTagSize {
		return Handshake{}, decodeError(ErrLength, EphemeralPublicKeySize, "handshake.encrypted_length", "must include a 16-byte authentication tag")
	}
	remaining := len(data) - prefixSize
	if remaining < encryptedLength {
		return Handshake{}, decodeError(ErrTruncated, len(data), "handshake.encrypted_payload", "shorter than declared")
	}
	if remaining > encryptedLength {
		return Handshake{}, decodeError(ErrTrailingData, prefixSize+encryptedLength, "handshake.encrypted_payload", "bytes follow declared ciphertext")
	}
	result.EncryptedPayload = append([]byte(nil), data[prefixSize:]...)
	return result, nil
}

func (p Handshake) MarshalBinary() ([]byte, error) {
	if len(p.EncryptedPayload) < AEADTagSize || len(p.EncryptedPayload) > math.MaxUint16 {
		return nil, decodeError(ErrLength, 0, "handshake.encrypted_payload", "must be 16..65535 bytes")
	}
	total := EphemeralPublicKeySize + 2 + len(p.EncryptedPayload)
	if total > math.MaxUint16 {
		return nil, decodeError(ErrLength, 0, "handshake", "outer payload does not fit uint16")
	}
	data := make([]byte, total)
	copy(data[:EphemeralPublicKeySize], p.ServerEphemeralPublic[:])
	binary.BigEndian.PutUint16(data[EphemeralPublicKeySize:EphemeralPublicKeySize+2], uint16(len(p.EncryptedPayload)))
	copy(data[EphemeralPublicKeySize+2:], p.EncryptedPayload)
	return data, nil
}

// Transport is an opaque AEAD ciphertext. Frame parsing happens only after a
// separate crypto layer authenticates and decrypts it.
type Transport struct {
	Ciphertext []byte
}

func ParseTransport(data []byte) (Transport, error) {
	if len(data) > math.MaxUint16 {
		return Transport{}, decodeError(ErrLimit, 0, "transport.ciphertext", "outer payload exceeds uint16")
	}
	if len(data) < AEADTagSize {
		return Transport{}, decodeError(ErrLength, 0, "transport.ciphertext", "must include a 16-byte authentication tag")
	}
	return Transport{Ciphertext: append([]byte(nil), data...)}, nil
}

func (p Transport) MarshalBinary() ([]byte, error) {
	if len(p.Ciphertext) < AEADTagSize || len(p.Ciphertext) > math.MaxUint16 {
		return nil, decodeError(ErrLength, 0, "transport.ciphertext", "must be 16..65535 bytes")
	}
	return append([]byte(nil), p.Ciphertext...), nil
}
