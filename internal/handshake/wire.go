package handshake

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"math"

	"wg.local/wg/internal/codec"
	wgcrypto "wg.local/wg/internal/crypto"
)

func makeInitialPrefix(token []byte, ephemeral [32]byte, encryptedLength int) ([]byte, error) {
	if len(token) > math.MaxUint16 || encryptedLength < codec.AEADTagSize || encryptedLength > math.MaxUint16 {
		return nil, fmt.Errorf("%w: invalid INITIAL length", ErrMessage)
	}
	prefix := make([]byte, 2+len(token)+32+2)
	binary.BigEndian.PutUint16(prefix[:2], uint16(len(token)))
	offset := 2
	copy(prefix[offset:], token)
	offset += len(token)
	copy(prefix[offset:], ephemeral[:])
	offset += 32
	binary.BigEndian.PutUint16(prefix[offset:], uint16(encryptedLength))
	return prefix, nil
}

func makeHandshakePrefix(ephemeral [32]byte, encryptedLength int) ([]byte, error) {
	if encryptedLength < codec.AEADTagSize || encryptedLength > math.MaxUint16 {
		return nil, fmt.Errorf("%w: invalid HANDSHAKE length", ErrMessage)
	}
	prefix := make([]byte, 32+2)
	copy(prefix, ephemeral[:])
	binary.BigEndian.PutUint16(prefix[32:], uint16(encryptedLength))
	return prefix, nil
}

func makeHeader(kind codec.PacketType, dcid, scid, packetNumber uint64, payloadLength int) (codec.Header, []byte, error) {
	if payloadLength < 0 || payloadLength > math.MaxUint16 {
		return codec.Header{}, nil, fmt.Errorf("%w: payload length out of range", ErrMessage)
	}
	header := codec.Header{
		Version: codec.Version1, Kind: kind, DCID: dcid, SCID: scid,
		PacketNumber: packetNumber, PayloadLength: uint16(payloadLength),
	}
	encoded, err := header.MarshalBinary()
	if err != nil {
		return codec.Header{}, nil, fmt.Errorf("%w: %v", ErrMessage, err)
	}
	return header, encoded, nil
}

func marshalWirePacket(header codec.Header, prefix, ciphertext []byte, maxDatagram int) ([]byte, error) {
	payload := make([]byte, 0, len(prefix)+len(ciphertext))
	payload = append(payload, prefix...)
	payload = append(payload, ciphertext...)
	encoded, err := (codec.Packet{Header: header, Payload: payload}).MarshalBinary(maxDatagram)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMessage, err)
	}
	return encoded, nil
}

func parseInitialWire(datagram []byte, maxDatagram int, context []byte) (codec.Packet, codec.Initial, []byte, [32]byte, error) {
	packet, err := codec.ParsePacket(datagram, maxDatagram)
	if err != nil {
		return codec.Packet{}, codec.Initial{}, nil, [32]byte{}, fmt.Errorf("%w: %v", ErrMessage, err)
	}
	if packet.Header.Kind != codec.PacketInitial {
		return codec.Packet{}, codec.Initial{}, nil, [32]byte{}, fmt.Errorf("%w: expected INITIAL", ErrMessage)
	}
	initial, err := codec.ParseInitial(packet.Payload)
	if err != nil {
		return codec.Packet{}, codec.Initial{}, nil, [32]byte{}, fmt.Errorf("%w: %v", ErrMessage, err)
	}
	prefixLength := len(packet.Payload) - len(initial.EncryptedPayload)
	adEnd := codec.HeaderSize + prefixLength
	if adEnd > len(datagram) {
		return codec.Packet{}, codec.Initial{}, nil, [32]byte{}, fmt.Errorf("%w: INITIAL prefix out of bounds", ErrMessage)
	}
	ad := join(context, datagram[:adEnd])
	th1 := wgcrypto.Sum256(ad, initial.EncryptedPayload)
	return packet, initial, ad, th1, nil
}

func parseHandshakeWire(datagram []byte, maxDatagram int, context []byte, th1 [32]byte) (codec.Packet, codec.Handshake, []byte, [32]byte, error) {
	packet, err := codec.ParsePacket(datagram, maxDatagram)
	if err != nil {
		return codec.Packet{}, codec.Handshake{}, nil, [32]byte{}, fmt.Errorf("%w: %v", ErrMessage, err)
	}
	if packet.Header.Kind != codec.PacketHandshake {
		return codec.Packet{}, codec.Handshake{}, nil, [32]byte{}, fmt.Errorf("%w: expected HANDSHAKE", ErrMessage)
	}
	handshake, err := codec.ParseHandshake(packet.Payload)
	if err != nil {
		return codec.Packet{}, codec.Handshake{}, nil, [32]byte{}, fmt.Errorf("%w: %v", ErrMessage, err)
	}
	prefixLength := len(packet.Payload) - len(handshake.EncryptedPayload)
	adEnd := codec.HeaderSize + prefixLength
	if adEnd > len(datagram) {
		return codec.Packet{}, codec.Handshake{}, nil, [32]byte{}, fmt.Errorf("%w: HANDSHAKE prefix out of bounds", ErrMessage)
	}
	ad := join(context, th1[:], datagram[:adEnd])
	th2 := wgcrypto.Sum256(ad, handshake.EncryptedPayload)
	return packet, handshake, ad, th2, nil
}

func join(parts ...[]byte) []byte {
	total := 0
	for _, part := range parts {
		total += len(part)
	}
	result := make([]byte, 0, total)
	for _, part := range parts {
		result = append(result, part...)
	}
	return result
}

func secureEqual(left, right []byte) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare(left, right) == 1
}

func nextNonZeroCID(random io.Reader) (uint64, error) {
	var raw [8]byte
	for attempt := 0; attempt < 32; attempt++ {
		if _, err := io.ReadFull(random, raw[:]); err != nil {
			return 0, fmt.Errorf("%w: read connection identifier: %v", ErrConfiguration, err)
		}
		if cid := binary.BigEndian.Uint64(raw[:]); cid != 0 {
			return cid, nil
		}
	}
	return 0, fmt.Errorf("%w: random source repeatedly produced a zero connection identifier", ErrConfiguration)
}

func zero32(value *[32]byte) {
	for index := range value {
		value[index] = 0
	}
}
