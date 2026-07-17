package wgcrypto

import (
	"errors"
	"math"

	"golang.org/x/crypto/chacha20poly1305"
	"wg.local/wg/internal/codec"
)

// SealTransport canonically encodes frames, derives the PN nonce, and seals
// the plaintext with the final complete 32-byte header as associated data.
func SealTransport(key [chacha20poly1305.KeySize]byte, header codec.Header, frames []codec.Frame, maxPlaintext int) (codec.Packet, error) {
	if header.Kind != codec.PacketTransport {
		return codec.Packet{}, ErrInvalidTransport
	}
	plaintext, err := codec.MarshalFrames(frames, maxPlaintext)
	if err != nil {
		return codec.Packet{}, errors.Join(ErrFrameEncoding, err)
	}
	return SealTransportPlaintext(key, header, plaintext)
}

// SealTransportPlaintext seals an already encoded TRANSPORT plaintext. Most
// callers must use SealTransport so that codec.MarshalFrames enforces the WG/1
// frame grammar. This lower-level boundary exists for protocol-layer tests and
// other callers that already own canonical frame encoding.
func SealTransportPlaintext(key [chacha20poly1305.KeySize]byte, header codec.Header, plaintext []byte) (codec.Packet, error) {
	if header.Kind != codec.PacketTransport {
		return codec.Packet{}, ErrInvalidTransport
	}
	if len(plaintext) > math.MaxUint16-chacha20poly1305.Overhead {
		return codec.Packet{}, ErrInvalidLength
	}
	header.PayloadLength = uint16(len(plaintext) + chacha20poly1305.Overhead)
	associatedData, err := header.MarshalBinary()
	if err != nil {
		return codec.Packet{}, ErrInvalidTransport
	}
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return codec.Packet{}, ErrInvalidKey
	}
	nonce := Nonce(header.PacketNumber)
	ciphertext := aead.Seal(nil, nonce[:], plaintext, associatedData)
	return codec.Packet{Header: header, Payload: ciphertext}, nil
}

// OpenTransport authenticates a complete header/ciphertext pair and then
// parses the inner frame stream. Callers that need to atomically claim a packet
// number after authentication but before frame parsing must use
// OpenTransportPlaintext instead.
func OpenTransport(key [chacha20poly1305.KeySize]byte, packet codec.Packet, maxPlaintext int) ([]codec.Frame, error) {
	plaintext, err := OpenTransportPlaintext(key, packet)
	if err != nil {
		return nil, err
	}
	frames, err := codec.ParseFrames(plaintext, maxPlaintext)
	if err != nil {
		return nil, errors.Join(ErrFrameEncoding, err)
	}
	return frames, nil
}

// OpenTransportPlaintext validates and authenticates a TRANSPORT packet but
// deliberately does not parse its frame plaintext. A replay-aware receiver
// must call this function first, atomically claim packet.Header.PacketNumber
// only after it succeeds, and only then call codec.ParseFrames. This ordering
// prevents authenticated malformed plaintext from leaving a PN reusable.
func OpenTransportPlaintext(key [chacha20poly1305.KeySize]byte, packet codec.Packet) ([]byte, error) {
	if packet.Header.Kind != codec.PacketTransport || len(packet.Payload) < chacha20poly1305.Overhead || len(packet.Payload) > math.MaxUint16 {
		return nil, ErrInvalidTransport
	}
	if int(packet.Header.PayloadLength) != len(packet.Payload) {
		return nil, ErrInvalidTransport
	}
	associatedData, err := packet.Header.MarshalBinary()
	if err != nil {
		return nil, ErrInvalidTransport
	}
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, ErrInvalidKey
	}
	nonce := Nonce(packet.Header.PacketNumber)
	plaintext, err := aead.Open(nil, nonce[:], packet.Payload, associatedData)
	if err != nil {
		return nil, ErrAuthentication
	}
	return plaintext, nil
}
