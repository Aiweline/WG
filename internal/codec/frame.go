package codec

import (
	"encoding/binary"
	"fmt"
	"math"
	"unicode/utf8"
)

const (
	FrameHeaderSize           = 4
	DefaultMaxFramePlaintext  = DefaultMaxDatagramSize - HeaderSize - AEADTagSize
	DefaultMaxCloseTextLength = 256
	ConfirmBodySize           = 32
	ChallengeBodySize         = 8
)

type FrameType uint8

const (
	FrameIPPacket      FrameType = 0x01
	FrameConfirm       FrameType = 0x02
	FramePing          FrameType = 0x03
	FramePong          FrameType = 0x04
	FramePathChallenge FrameType = 0x05
	FramePathResponse  FrameType = 0x06
	FrameLeaseUpdate   FrameType = 0x07
	FrameClose         FrameType = 0x08
)

func (frameType FrameType) valid() bool {
	return frameType >= FrameIPPacket && frameType <= FrameClose
}

// Frame is a detached inner frame. Flags must be zero in version 1.
type Frame struct {
	Type  FrameType
	Flags uint8
	Body  []byte
}

// ParseFrames parses a complete authenticated plaintext. maxPlaintext=0 uses
// the default derived from a 1400-byte datagram and a 16-byte AEAD tag.
func ParseFrames(data []byte, maxPlaintext int) ([]Frame, error) {
	limit, err := normalizeFrameLimit(maxPlaintext)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, decodeError(ErrLength, 0, "frames", "TRANSPORT plaintext requires at least one frame")
	}
	if len(data) > limit {
		return nil, decodeError(ErrLimit, 0, "frames", fmt.Sprintf("length %d exceeds %d", len(data), limit))
	}

	frames := make([]Frame, 0, 2)
	offset := 0
	for offset < len(data) {
		if len(data)-offset < FrameHeaderSize {
			return nil, decodeError(ErrTruncated, offset, "frame.header", "need 4 bytes")
		}
		frameType := FrameType(data[offset])
		flags := data[offset+1]
		length := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		if !frameType.valid() {
			return nil, decodeError(ErrUnknownFrameType, offset, "frame_type", fmt.Sprintf("0x%02x", uint8(frameType)))
		}
		if flags != 0 {
			return nil, decodeError(ErrFrameFlags, offset+1, "frame_flags", "version 1 requires zero")
		}
		bodyOffset := offset + FrameHeaderSize
		if length > len(data)-bodyOffset {
			return nil, decodeError(ErrTruncated, bodyOffset, "frame.body", fmt.Sprintf("declares %d bytes", length))
		}
		frame := Frame{Type: frameType, Body: append([]byte(nil), data[bodyOffset:bodyOffset+length]...)}
		if err := validateFrame(frame, offset); err != nil {
			return nil, err
		}
		frames = append(frames, frame)
		offset = bodyOffset + length
	}
	if err := validateFrameCombination(frames); err != nil {
		return nil, err
	}
	return frames, nil
}

// MarshalFrames emits one canonical plaintext and validates packet-level frame
// combination rules.
func MarshalFrames(frames []Frame, maxPlaintext int) ([]byte, error) {
	limit, err := normalizeFrameLimit(maxPlaintext)
	if err != nil {
		return nil, err
	}
	if len(frames) == 0 {
		return nil, decodeError(ErrLength, 0, "frames", "need at least one frame")
	}
	if err := validateFrameCombination(frames); err != nil {
		return nil, err
	}
	total := 0
	for _, frame := range frames {
		if err := validateFrame(frame, -1); err != nil {
			return nil, err
		}
		if len(frame.Body) > math.MaxUint16 {
			return nil, decodeError(ErrLength, -1, "frame.body", "does not fit uint16")
		}
		if total > limit-FrameHeaderSize-len(frame.Body) {
			return nil, decodeError(ErrLimit, -1, "frames", "encoded frames exceed configured plaintext limit")
		}
		total += FrameHeaderSize + len(frame.Body)
	}
	data := make([]byte, total)
	offset := 0
	for _, frame := range frames {
		data[offset] = byte(frame.Type)
		data[offset+1] = 0
		binary.BigEndian.PutUint16(data[offset+2:offset+4], uint16(len(frame.Body)))
		copy(data[offset+4:], frame.Body)
		offset += FrameHeaderSize + len(frame.Body)
	}
	return data, nil
}

// EncodeClose creates a validated CLOSE body.
func EncodeClose(reason uint16, diagnostic string) ([]byte, error) {
	if !utf8.ValidString(diagnostic) {
		return nil, decodeError(ErrUTF8, -1, "close.diagnostic", "invalid UTF-8")
	}
	if len([]byte(diagnostic)) > DefaultMaxCloseTextLength {
		return nil, decodeError(ErrLimit, -1, "close.diagnostic", "exceeds implementation limit")
	}
	body := make([]byte, 2+len(diagnostic))
	binary.BigEndian.PutUint16(body[:2], reason)
	copy(body[2:], diagnostic)
	return body, nil
}

// DecodeClose validates and returns the reason and diagnostic.
func DecodeClose(body []byte) (uint16, string, error) {
	if len(body) < 2 {
		return 0, "", decodeError(ErrTruncated, len(body), "close.reason", "need uint16")
	}
	if len(body)-2 > DefaultMaxCloseTextLength {
		return 0, "", decodeError(ErrLimit, 2, "close.diagnostic", "exceeds implementation limit")
	}
	if !utf8.Valid(body[2:]) {
		return 0, "", decodeError(ErrUTF8, 2, "close.diagnostic", "invalid UTF-8")
	}
	return binary.BigEndian.Uint16(body[:2]), string(body[2:]), nil
}

func validateFrame(frame Frame, offset int) error {
	if !frame.Type.valid() {
		return decodeError(ErrUnknownFrameType, offset, "frame_type", fmt.Sprintf("0x%02x", uint8(frame.Type)))
	}
	if frame.Flags != 0 {
		return decodeError(ErrFrameFlags, offset+1, "frame_flags", "version 1 requires zero")
	}
	switch frame.Type {
	case FrameIPPacket:
		return validateIPPacket(frame.Body, offset+FrameHeaderSize)
	case FrameConfirm:
		if len(frame.Body) != ConfirmBodySize {
			return decodeError(ErrLength, offset+FrameHeaderSize, "confirm", "requires 32-byte th2")
		}
	case FramePing, FramePong:
		if len(frame.Body) != ChallengeBodySize {
			return decodeError(ErrLength, offset+FrameHeaderSize, "challenge", "requires 8 bytes")
		}
	case FrameClose:
		_, _, err := DecodeClose(frame.Body)
		return err
	}
	// PATH_CHALLENGE, PATH_RESPONSE, and LEASE_UPDATE have no byte-level body
	// format in v0.2; the session layer validates their semantics.
	return nil
}

func validateFrameCombination(frames []Frame) error {
	ipPackets := 0
	confirmIndex := -1
	for _, frame := range frames {
		if frame.Type == FrameIPPacket {
			ipPackets++
		}
	}
	for index, frame := range frames {
		if frame.Type == FrameConfirm {
			if confirmIndex >= 0 {
				return decodeError(ErrFrameConstraint, -1, "frames", "CONFIRM cannot be duplicated")
			}
			confirmIndex = index
		}
	}
	if ipPackets > 1 {
		return decodeError(ErrFrameConstraint, -1, "frames", "at most one IP_PACKET is allowed")
	}
	if ipPackets == 1 && len(frames) != 1 {
		return decodeError(ErrFrameConstraint, -1, "frames", "IP_PACKET cannot be combined with control frames")
	}
	if confirmIndex >= 0 && (len(frames) != 2 || confirmIndex != 0 || frames[1].Type != FramePing) {
		return decodeError(ErrFrameConstraint, -1, "frames", "CONFIRM must be followed by PING in the same two-frame plaintext")
	}
	return nil
}

func validateIPPacket(packet []byte, offset int) error {
	if len(packet) == 0 {
		return decodeError(ErrIPPacket, offset, "ip_packet", "empty packet")
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return decodeError(ErrIPPacket, offset, "ipv4", "shorter than minimum header")
		}
		headerLength := int(packet[0]&0x0F) * 4
		if headerLength < 20 || headerLength > len(packet) {
			return decodeError(ErrIPPacket, offset, "ipv4.ihl", "invalid header length")
		}
		totalLength := int(binary.BigEndian.Uint16(packet[2:4]))
		if totalLength != len(packet) {
			return decodeError(ErrIPPacket, offset+2, "ipv4.total_length", fmt.Sprintf("declares %d, frame has %d", totalLength, len(packet)))
		}
	case 6:
		if len(packet) < 40 {
			return decodeError(ErrIPPacket, offset, "ipv6", "shorter than fixed header")
		}
		totalLength := 40 + int(binary.BigEndian.Uint16(packet[4:6]))
		if totalLength != len(packet) {
			return decodeError(ErrIPPacket, offset+4, "ipv6.payload_length", fmt.Sprintf("declares total %d, frame has %d", totalLength, len(packet)))
		}
	default:
		return decodeError(ErrIPPacket, offset, "ip.version", "only IPv4 and IPv6 are accepted")
	}
	return nil
}

func normalizeFrameLimit(limit int) (int, error) {
	if limit == 0 {
		return DefaultMaxFramePlaintext, nil
	}
	if limit < FrameHeaderSize || limit > math.MaxUint16 {
		return 0, decodeError(ErrLimit, -1, "max_frame_plaintext", "must be 4..65535")
	}
	return limit, nil
}
