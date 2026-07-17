package codec

import (
	"bytes"
	"testing"
)

func FuzzParsePacket(f *testing.F) {
	payload := make([]byte, AEADTagSize)
	seed, _ := NewPacket(PacketTransport, 1, 2, 3, payload).MarshalBinary(0)
	f.Add(seed)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		packet, err := ParsePacket(data, HeaderSize+65535)
		if err != nil {
			return
		}
		encoded, err := packet.MarshalBinary(HeaderSize + 65535)
		if err != nil {
			t.Fatalf("successful parse did not marshal: %v", err)
		}
		if !bytes.Equal(encoded, data) {
			t.Fatalf("non-canonical successful parse")
		}
	})
}

func FuzzParseTLVs(f *testing.F) {
	seed, _ := MarshalTLVs([]TLV{{Type: 0x01, Value: []byte("x")}, {Type: TLVVersion, Value: []byte{1}}})
	f.Add(seed)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		fields, err := ParseTLVs(data)
		if err != nil {
			return
		}
		encoded, err := MarshalTLVs(fields)
		if err != nil {
			t.Fatalf("successful parse did not marshal: %v", err)
		}
		if !bytes.Equal(encoded, data) {
			t.Fatal("TLV parse accepted non-canonical input")
		}
	})
}

func FuzzParseFrames(f *testing.F) {
	seed, _ := MarshalFrames([]Frame{{Type: FramePing, Body: make([]byte, ChallengeBodySize)}}, 65535)
	f.Add(seed)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		frames, err := ParseFrames(data, 65535)
		if err != nil {
			return
		}
		encoded, err := MarshalFrames(frames, 65535)
		if err != nil {
			t.Fatalf("successful parse did not marshal: %v", err)
		}
		if !bytes.Equal(encoded, data) {
			t.Fatal("frame parse accepted non-canonical input")
		}
	})
}

func FuzzParseOuterPayloads(f *testing.F) {
	initial, _ := (Initial{EncryptedPayload: make([]byte, AEADTagSize)}).MarshalBinary()
	f.Add(uint8(0), initial)
	f.Add(uint8(1), make([]byte, MinRetryTokenSize))
	f.Add(uint8(2), []byte{})
	f.Fuzz(func(t *testing.T, selector uint8, data []byte) {
		switch selector % 4 {
		case 0:
			value, err := ParseInitial(data)
			if err == nil {
				encoded, marshalErr := value.MarshalBinary()
				if marshalErr != nil || !bytes.Equal(encoded, data) {
					t.Fatalf("INITIAL round trip failed: %v", marshalErr)
				}
			}
		case 1:
			value, err := ParseRetry(data)
			if err == nil {
				encoded, marshalErr := value.MarshalBinary()
				if marshalErr != nil || !bytes.Equal(encoded, data) {
					t.Fatalf("RETRY round trip failed: %v", marshalErr)
				}
			}
		case 2:
			value, err := ParseHandshake(data)
			if err == nil {
				encoded, marshalErr := value.MarshalBinary()
				if marshalErr != nil || !bytes.Equal(encoded, data) {
					t.Fatalf("HANDSHAKE round trip failed: %v", marshalErr)
				}
			}
		case 3:
			value, err := ParseTransport(data)
			if err == nil {
				encoded, marshalErr := value.MarshalBinary()
				if marshalErr != nil || !bytes.Equal(encoded, data) {
					t.Fatalf("TRANSPORT round trip failed: %v", marshalErr)
				}
			}
		}
	})
}
