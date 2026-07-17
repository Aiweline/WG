package codec

import (
	"encoding/binary"
	"fmt"
	"math"
)

const (
	Version1               uint8 = 0x01
	HeaderSize                   = 32
	AEADTagSize                  = 16
	DefaultMaxDatagramSize       = 1400
	DefaultMaxPayloadSize        = DefaultMaxDatagramSize - HeaderSize
)

// PacketType is the outer WG/1 datagram kind.
type PacketType uint8

const (
	PacketInitial   PacketType = 0x01
	PacketRetry     PacketType = 0x02
	PacketHandshake PacketType = 0x03
	PacketTransport PacketType = 0x10
)

func (kind PacketType) valid() bool {
	return kind == PacketInitial || kind == PacketRetry || kind == PacketHandshake || kind == PacketTransport
}

// Header is the fixed 32-byte outer header.
type Header struct {
	Version       uint8
	Kind          PacketType
	Flags         uint16
	DCID          uint64
	SCID          uint64
	PacketNumber  uint64
	PayloadLength uint16
	Reserved      uint16
}

// ParseHeader parses exactly one header and rejects trailing bytes.
func ParseHeader(data []byte) (Header, error) {
	if len(data) < HeaderSize {
		return Header{}, decodeError(ErrTruncated, len(data), "header", "need 32 bytes")
	}
	if len(data) > HeaderSize {
		return Header{}, decodeError(ErrTrailingData, HeaderSize, "header", "header parser accepts exactly 32 bytes")
	}
	return parseHeaderPrefix(data)
}

func parseHeaderPrefix(data []byte) (Header, error) {
	if len(data) < HeaderSize {
		return Header{}, decodeError(ErrTruncated, len(data), "header", "need 32 bytes")
	}
	header := Header{
		Version:       data[0],
		Kind:          PacketType(data[1]),
		Flags:         binary.BigEndian.Uint16(data[2:4]),
		DCID:          binary.BigEndian.Uint64(data[4:12]),
		SCID:          binary.BigEndian.Uint64(data[12:20]),
		PacketNumber:  binary.BigEndian.Uint64(data[20:28]),
		PayloadLength: binary.BigEndian.Uint16(data[28:30]),
		Reserved:      binary.BigEndian.Uint16(data[30:32]),
	}
	if err := header.validate(); err != nil {
		return Header{}, err
	}
	return header, nil
}

// MarshalBinary serializes a validated header in canonical big-endian form.
func (h Header) MarshalBinary() ([]byte, error) {
	if err := h.validate(); err != nil {
		return nil, err
	}
	data := make([]byte, HeaderSize)
	data[0] = h.Version
	data[1] = byte(h.Kind)
	binary.BigEndian.PutUint16(data[2:4], h.Flags)
	binary.BigEndian.PutUint64(data[4:12], h.DCID)
	binary.BigEndian.PutUint64(data[12:20], h.SCID)
	binary.BigEndian.PutUint64(data[20:28], h.PacketNumber)
	binary.BigEndian.PutUint16(data[28:30], h.PayloadLength)
	binary.BigEndian.PutUint16(data[30:32], h.Reserved)
	return data, nil
}

func (h Header) validate() error {
	if h.Version != Version1 {
		return decodeError(ErrVersion, 0, "version", fmt.Sprintf("got 0x%02x", h.Version))
	}
	if !h.Kind.valid() {
		return decodeError(ErrKind, 1, "kind", fmt.Sprintf("got 0x%02x", uint8(h.Kind)))
	}
	if h.Flags != 0 {
		return decodeError(ErrFlags, 2, "flags", "version 1 requires zero")
	}
	if h.Reserved != 0 {
		return decodeError(ErrReserved, 30, "reserved", "version 1 requires zero")
	}

	switch h.Kind {
	case PacketInitial:
		if h.DCID != 0 || h.SCID == 0 {
			return decodeError(ErrCID, 4, "cid", "INITIAL requires dcid=0 and non-zero scid")
		}
		if h.PacketNumber != 0 {
			return decodeError(ErrPacketNumber, 20, "packet_number", "INITIAL requires zero")
		}
	case PacketRetry:
		if h.DCID == 0 || h.SCID != 0 {
			return decodeError(ErrCID, 4, "cid", "RETRY requires non-zero dcid and scid=0")
		}
		if h.PacketNumber != 0 {
			return decodeError(ErrPacketNumber, 20, "packet_number", "RETRY requires zero")
		}
	case PacketHandshake:
		if h.DCID == 0 || h.SCID == 0 {
			return decodeError(ErrCID, 4, "cid", "HANDSHAKE requires non-zero dcid and scid")
		}
		if h.PacketNumber != 0 {
			return decodeError(ErrPacketNumber, 20, "packet_number", "HANDSHAKE requires zero")
		}
	case PacketTransport:
		if h.DCID == 0 || h.SCID == 0 {
			return decodeError(ErrCID, 4, "cid", "TRANSPORT requires non-zero dcid and scid")
		}
	}
	return nil
}

// Packet contains a validated header and a detached outer payload.
type Packet struct {
	Header  Header
	Payload []byte
}

// NewPacket constructs a canonical version-1 packet. MarshalBinary performs
// all kind-specific payload and size validation.
func NewPacket(kind PacketType, dcid, scid, packetNumber uint64, payload []byte) Packet {
	return Packet{
		Header: Header{
			Version:      Version1,
			Kind:         kind,
			DCID:         dcid,
			SCID:         scid,
			PacketNumber: packetNumber,
		},
		Payload: append([]byte(nil), payload...),
	}
}

// ParsePacket validates a complete datagram. A non-positive limit selects the
// version-1 default of 1400 bytes.
func ParsePacket(data []byte, maxDatagramSize int) (Packet, error) {
	limit, err := normalizeDatagramLimit(maxDatagramSize)
	if err != nil {
		return Packet{}, err
	}
	if len(data) < HeaderSize {
		return Packet{}, decodeError(ErrTruncated, len(data), "datagram", "missing fixed header")
	}
	if len(data) > limit {
		return Packet{}, decodeError(ErrLimit, 0, "datagram", fmt.Sprintf("length %d exceeds %d", len(data), limit))
	}
	header, err := parseHeaderPrefix(data[:HeaderSize])
	if err != nil {
		return Packet{}, err
	}
	expected := HeaderSize + int(header.PayloadLength)
	if expected > limit {
		return Packet{}, decodeError(ErrLimit, 28, "payload_length", fmt.Sprintf("declared datagram length %d exceeds %d", expected, limit))
	}
	if len(data) < expected {
		return Packet{}, decodeError(ErrTruncated, len(data), "payload", fmt.Sprintf("declared datagram length %d", expected))
	}
	if len(data) > expected {
		return Packet{}, decodeError(ErrTrailingData, expected, "payload", "bytes follow declared payload")
	}
	payload := append([]byte(nil), data[HeaderSize:expected]...)
	if err := validateOuterPayload(header.Kind, payload); err != nil {
		return Packet{}, err
	}
	return Packet{Header: header, Payload: payload}, nil
}

// MarshalBinary validates and serializes a complete datagram. PayloadLength is
// derived from Payload and never trusted from the caller.
func (p Packet) MarshalBinary(maxDatagramSize int) ([]byte, error) {
	limit, err := normalizeDatagramLimit(maxDatagramSize)
	if err != nil {
		return nil, err
	}
	if len(p.Payload) > math.MaxUint16 {
		return nil, decodeError(ErrLength, 0, "payload", "does not fit uint16")
	}
	if HeaderSize+len(p.Payload) > limit {
		return nil, decodeError(ErrLimit, 0, "datagram", fmt.Sprintf("length %d exceeds %d", HeaderSize+len(p.Payload), limit))
	}
	if err := validateOuterPayload(p.Header.Kind, p.Payload); err != nil {
		return nil, err
	}
	header := p.Header
	header.PayloadLength = uint16(len(p.Payload))
	encodedHeader, err := header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	data := make([]byte, HeaderSize+len(p.Payload))
	copy(data, encodedHeader)
	copy(data[HeaderSize:], p.Payload)
	return data, nil
}

func normalizeDatagramLimit(limit int) (int, error) {
	if limit == 0 {
		return DefaultMaxDatagramSize, nil
	}
	if limit < HeaderSize || limit > HeaderSize+math.MaxUint16 {
		return 0, decodeError(ErrLimit, 0, "max_datagram_size", "must fit header plus uint16 payload")
	}
	return limit, nil
}

func validateOuterPayload(kind PacketType, payload []byte) error {
	switch kind {
	case PacketInitial:
		_, err := ParseInitial(payload)
		return err
	case PacketRetry:
		_, err := ParseRetry(payload)
		return err
	case PacketHandshake:
		_, err := ParseHandshake(payload)
		return err
	case PacketTransport:
		_, err := ParseTransport(payload)
		return err
	default:
		return decodeError(ErrKind, 1, "kind", fmt.Sprintf("got 0x%02x", uint8(kind)))
	}
}
