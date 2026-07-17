package wgcrypto

import (
	"bytes"
	"errors"
	"testing"

	"wg.local/wg/internal/codec"
)

func TestTransportBidirectionalRoundTrip(t *testing.T) {
	prk2 := mustHex32(t, "7f64faab051f1871e122c4c98dcf182b347a59b299b1728a45bd8a9f34bad9ed")
	th2 := mustHex32(t, "ad4c4e710cc7cbf4fb14abe1e25685d8da7f9833ff855740ff8170cd895225ab")
	c2s, s2c, err := DeriveTraffic(prk2, th2)
	if err != nil {
		t.Fatalf("derive traffic: %v", err)
	}

	c2sHeader := transportHeader(22, 11, 0)
	c2sFrames := []codec.Frame{{Type: codec.FramePing, Body: []byte("12345678")}}
	c2sPacket, err := SealTransport(c2s, c2sHeader, c2sFrames, 0)
	if err != nil {
		t.Fatalf("seal c2s: %v", err)
	}
	if c2sPacket.Header.PayloadLength != uint16(codec.FrameHeaderSize+8+codec.AEADTagSize) {
		t.Fatalf("derived payload length = %d", c2sPacket.Header.PayloadLength)
	}
	wire, err := c2sPacket.MarshalBinary(0)
	if err != nil {
		t.Fatalf("marshal c2s: %v", err)
	}
	parsed, err := codec.ParsePacket(wire, 0)
	if err != nil {
		t.Fatalf("parse c2s: %v", err)
	}
	openedC2S, err := OpenTransport(c2s, parsed, 0)
	if err != nil {
		t.Fatalf("open c2s: %v", err)
	}
	assertFramesEqual(t, openedC2S, c2sFrames)

	s2cHeader := transportHeader(11, 22, 0)
	s2cFrames := []codec.Frame{{Type: codec.FramePong, Body: []byte("abcdefgh")}}
	s2cPacket, err := SealTransport(s2c, s2cHeader, s2cFrames, 0)
	if err != nil {
		t.Fatalf("seal s2c: %v", err)
	}
	openedS2C, err := OpenTransport(s2c, s2cPacket, 0)
	if err != nil {
		t.Fatalf("open s2c: %v", err)
	}
	assertFramesEqual(t, openedS2C, s2cFrames)

	if _, err := OpenTransport(s2c, c2sPacket, 0); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong direction key error = %v", err)
	}
}

func TestTransportAuthenticatesFullHeaderAndCiphertext(t *testing.T) {
	key := mustHex32(t, "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f")
	frames := []codec.Frame{{Type: codec.FramePing, Body: []byte("12345678")}}
	packet, err := SealTransport(key, transportHeader(2, 1, 9), frames, 0)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	headerTamper := packet
	headerTamper.Header.DCID ^= 1
	if _, err := OpenTransport(key, headerTamper, 0); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("header tamper error = %v", err)
	}
	pnTamper := packet
	pnTamper.Header.PacketNumber++
	if _, err := OpenTransport(key, pnTamper, 0); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("PN tamper error = %v", err)
	}
	ciphertextTamper := packet
	ciphertextTamper.Payload = append([]byte(nil), packet.Payload...)
	ciphertextTamper.Payload[0] ^= 0x01
	if _, err := OpenTransport(key, ciphertextTamper, 0); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("ciphertext tamper error = %v", err)
	}
}

func TestTransportValidatesHeaderLengthAndFrames(t *testing.T) {
	key := [32]byte{1}
	header := transportHeader(2, 1, 0)
	header.Kind = codec.PacketHandshake
	if _, err := SealTransport(key, header, []codec.Frame{{Type: codec.FramePing, Body: []byte("12345678")}}, 0); !errors.Is(err, ErrInvalidTransport) {
		t.Fatalf("wrong kind seal error = %v", err)
	}

	packet, err := SealTransport(key, transportHeader(2, 1, 0), []codec.Frame{{Type: codec.FramePing, Body: []byte("12345678")}}, 0)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	packet.Header.PayloadLength--
	if _, err := OpenTransport(key, packet, 0); !errors.Is(err, ErrInvalidTransport) {
		t.Fatalf("length mismatch error = %v", err)
	}
	if _, err := SealTransport(key, transportHeader(2, 1, 0), []codec.Frame{{Type: codec.FramePing, Body: []byte("short")}}, 0); !errors.Is(err, ErrFrameEncoding) {
		t.Fatalf("invalid frame error = %v", err)
	}
}

func TestOpenTransportPlaintextSeparatesAuthenticationFromFrameParsing(t *testing.T) {
	key := mustHex32(t, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
	// This is authenticated plaintext, but 0xff is not a WG/1 frame type.
	malformedFrames := []byte{0xff, 0x00, 0x00, 0x00}
	packet, err := SealTransportPlaintext(key, transportHeader(9, 7, 42), malformedFrames)
	if err != nil {
		t.Fatalf("seal raw plaintext: %v", err)
	}

	plaintext, err := OpenTransportPlaintext(key, packet)
	if err != nil {
		t.Fatalf("authenticate plaintext: %v", err)
	}
	if !bytes.Equal(plaintext, malformedFrames) {
		t.Fatalf("plaintext = %x, want %x", plaintext, malformedFrames)
	}
	if _, err := OpenTransport(key, packet, 0); !errors.Is(err, ErrFrameEncoding) {
		t.Fatalf("compatibility frame parse error = %v", err)
	}

	tampered := packet
	tampered.Payload = append([]byte(nil), packet.Payload...)
	tampered.Payload[len(tampered.Payload)-1] ^= 0x80
	if _, err := OpenTransportPlaintext(key, tampered); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tampered auth-only error = %v", err)
	}
}

func transportHeader(dcid, scid, packetNumber uint64) codec.Header {
	return codec.Header{
		Version:      codec.Version1,
		Kind:         codec.PacketTransport,
		DCID:         dcid,
		SCID:         scid,
		PacketNumber: packetNumber,
	}
}

func assertFramesEqual(t *testing.T, got, want []codec.Frame) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("frame count = %d, want %d", len(got), len(want))
	}
	for index := range want {
		if got[index].Type != want[index].Type || got[index].Flags != want[index].Flags || !bytes.Equal(got[index].Body, want[index].Body) {
			t.Fatalf("frame %d mismatch", index)
		}
	}
}
