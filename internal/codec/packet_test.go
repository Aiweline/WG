package codec

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestHeaderBigEndianRoundTrip(t *testing.T) {
	t.Parallel()

	header := Header{
		Version:       Version1,
		Kind:          PacketTransport,
		DCID:          0x0102030405060708,
		SCID:          0x1112131415161718,
		PacketNumber:  0x2122232425262728,
		PayloadLength: 0x3132,
	}
	data, err := header.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(data[4:12], []byte{1, 2, 3, 4, 5, 6, 7, 8}) || !bytes.Equal(data[28:30], []byte{0x31, 0x32}) {
		t.Fatalf("header is not big-endian: %x", data)
	}
	parsed, err := ParseHeader(data)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if parsed != header {
		t.Fatalf("parsed = %+v, want %+v", parsed, header)
	}
}

func TestPacketKindsRoundTrip(t *testing.T) {
	t.Parallel()

	initialPayload, err := (Initial{EncryptedPayload: bytes.Repeat([]byte{0xA1}, AEADTagSize)}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	handshakePayload, err := (Handshake{EncryptedPayload: bytes.Repeat([]byte{0xA2}, AEADTagSize)}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	tests := []Packet{
		NewPacket(PacketInitial, 0, 11, 0, initialPayload),
		NewPacket(PacketRetry, 11, 0, 0, bytes.Repeat([]byte{0xB1}, MinRetryTokenSize)),
		NewPacket(PacketHandshake, 11, 22, 0, handshakePayload),
		NewPacket(PacketTransport, 22, 11, 9, bytes.Repeat([]byte{0xC1}, AEADTagSize)),
	}

	for _, packet := range tests {
		packet := packet
		t.Run(string(rune(packet.Header.Kind)), func(t *testing.T) {
			t.Parallel()
			data, err := packet.MarshalBinary(0)
			if err != nil {
				t.Fatalf("MarshalBinary: %v", err)
			}
			parsed, err := ParsePacket(data, 0)
			if err != nil {
				t.Fatalf("ParsePacket: %v", err)
			}
			if parsed.Header.PayloadLength != uint16(len(packet.Payload)) || !bytes.Equal(parsed.Payload, packet.Payload) {
				t.Fatalf("parsed packet = %+v", parsed)
			}
			parsed.Payload[0] ^= 0xFF
			if bytes.Equal(parsed.Payload, packet.Payload) {
				t.Fatal("test mutation did not change parsed payload")
			}
		})
	}
}

func TestPacketRejectsHeaderAndLengthViolations(t *testing.T) {
	t.Parallel()

	base, err := NewPacket(PacketTransport, 1, 2, 3, bytes.Repeat([]byte{1}, AEADTagSize)).MarshalBinary(0)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		edit func([]byte) []byte
		want error
	}{
		{"short header", func(data []byte) []byte { return data[:HeaderSize-1] }, ErrTruncated},
		{"version", func(data []byte) []byte { data[0] = 2; return data }, ErrVersion},
		{"kind", func(data []byte) []byte { data[1] = 0xFF; return data }, ErrKind},
		{"flags", func(data []byte) []byte { data[3] = 1; return data }, ErrFlags},
		{"reserved", func(data []byte) []byte { data[31] = 1; return data }, ErrReserved},
		{"zero dcid", func(data []byte) []byte { clear(data[4:12]); return data }, ErrCID},
		{"zero scid", func(data []byte) []byte { clear(data[12:20]); return data }, ErrCID},
		{"truncated payload", func(data []byte) []byte { binary.BigEndian.PutUint16(data[28:30], AEADTagSize+1); return data }, ErrTruncated},
		{"trailing payload", func(data []byte) []byte { binary.BigEndian.PutUint16(data[28:30], AEADTagSize-1); return data }, ErrTrailingData},
		{"declared over limit", func(data []byte) []byte { binary.BigEndian.PutUint16(data[28:30], 1400); return data }, ErrLimit},
		{"actual over limit", func(data []byte) []byte { return append(data, bytes.Repeat([]byte{0}, 1400)...) }, ErrLimit},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			data := append([]byte(nil), base...)
			_, err := ParsePacket(test.edit(data), 0)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestHandshakeKindsRequireZeroPacketNumber(t *testing.T) {
	t.Parallel()

	initialPayload, _ := (Initial{EncryptedPayload: make([]byte, AEADTagSize)}).MarshalBinary()
	packet := NewPacket(PacketInitial, 0, 1, 7, initialPayload)
	if _, err := packet.MarshalBinary(0); !errors.Is(err, ErrPacketNumber) {
		t.Fatalf("error = %v, want ErrPacketNumber", err)
	}
}

func TestParseHeaderRejectsTrailingData(t *testing.T) {
	t.Parallel()

	header := Header{Version: Version1, Kind: PacketTransport, DCID: 1, SCID: 2}
	data, err := header.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseHeader(append(data, 0)); !errors.Is(err, ErrTrailingData) {
		t.Fatalf("error = %v, want ErrTrailingData", err)
	}
}

func TestOuterPayloadBoundaries(t *testing.T) {
	t.Parallel()

	initial := Initial{Token: []byte{1, 2}, EncryptedPayload: bytes.Repeat([]byte{3}, AEADTagSize)}
	encoded, err := initial.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseInitial(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.Token, initial.Token) || !bytes.Equal(parsed.EncryptedPayload, initial.EncryptedPayload) {
		t.Fatalf("parsed = %+v", parsed)
	}
	encoded[len(encoded)-1] ^= 0xFF
	if bytes.Equal(parsed.EncryptedPayload, encoded[len(encoded)-AEADTagSize:]) {
		t.Fatal("ParseInitial retained input memory")
	}

	trailing := append([]byte(nil), encoded...)
	trailing = append(trailing, 0)
	if _, err := ParseInitial(trailing); !errors.Is(err, ErrTrailingData) {
		t.Fatalf("initial trailing error = %v", err)
	}
	shortCipher := append([]byte(nil), encoded...)
	binary.BigEndian.PutUint16(shortCipher[2+len(initial.Token)+EphemeralPublicKeySize:], AEADTagSize-1)
	if _, err := ParseInitial(shortCipher); !errors.Is(err, ErrLength) {
		t.Fatalf("initial encrypted length error = %v", err)
	}

	handshake, err := (Handshake{EncryptedPayload: make([]byte, AEADTagSize)}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	handshake = append(handshake, 0)
	if _, err := ParseHandshake(handshake); !errors.Is(err, ErrTrailingData) {
		t.Fatalf("handshake trailing error = %v", err)
	}
	if _, err := ParseRetry(make([]byte, MinRetryTokenSize-1)); !errors.Is(err, ErrLength) {
		t.Fatalf("retry error = %v", err)
	}
	if _, err := ParseTransport(make([]byte, AEADTagSize-1)); !errors.Is(err, ErrLength) {
		t.Fatalf("transport error = %v", err)
	}
}
