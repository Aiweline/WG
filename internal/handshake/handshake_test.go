package handshake

import (
	"bytes"
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"testing"

	"wg.local/wg/internal/codec"
	wgcrypto "wg.local/wg/internal/crypto"
)

type testFixture struct {
	client *Client
	server *Server
}

func TestWGHS1RoundTripAndTrafficKeys(t *testing.T) {
	fixture := newTestFixture(t)
	initial, err := fixture.client.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	initialPacket, err := codec.ParsePacket(initial, 0)
	if err != nil {
		t.Fatalf("parse INITIAL: %v", err)
	}
	if initialPacket.Header.SCID == 0 || fixture.client.ClientCID() == 0 {
		t.Fatal("client CID must be non-zero")
	}
	initialPayload, err := codec.ParseInitial(initialPacket.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if initialPayload.ClientEphemeralPublic == ([32]byte{}) {
		t.Fatal("client ephemeral public key must be non-zero")
	}

	session, response, err := fixture.server.HandleInitial(initial)
	if err != nil {
		t.Fatalf("HandleInitial: %v", err)
	}
	defer session.Close()
	if session.ServerCID() == 0 {
		t.Fatal("server CID must be non-zero")
	}
	handshakePacket, err := codec.ParsePacket(response, 0)
	if err != nil {
		t.Fatal(err)
	}
	handshakePayload, err := codec.ParseHandshake(handshakePacket.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if handshakePayload.ServerEphemeralPublic == ([32]byte{}) {
		t.Fatal("server ephemeral public key must be non-zero")
	}
	if session.State() != StatePendingConfirm {
		t.Fatalf("server state before CONFIRM = %s", session.State())
	}
	if _, err := session.Seal([]codec.Frame{{Type: codec.FramePing, Body: bytes.Repeat([]byte{1}, 8)}}); !errors.Is(err, ErrState) {
		t.Fatalf("PendingConfirm server unexpectedly sent traffic: %v", err)
	}

	if err := fixture.client.Finish(response); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if fixture.client.state != StatePendingConfirm {
		t.Fatalf("client state after Finish = %s", fixture.client.state)
	}
	if fixture.client.c2sKey != session.c2sKey || fixture.client.s2cKey != session.s2cKey {
		t.Fatal("client and server traffic keys differ")
	}
	if fixture.client.th2 != session.th2 {
		t.Fatal("client and server th2 differ")
	}

	confirm, challenge, err := fixture.client.BuildConfirm()
	if err != nil {
		t.Fatalf("BuildConfirm: %v", err)
	}
	if session.State() != StatePendingConfirm {
		t.Fatal("building CONFIRM must not establish the server")
	}
	pong, err := session.HandleConfirm(confirm)
	if err != nil {
		t.Fatalf("HandleConfirm: %v", err)
	}
	if session.State() != StateEstablished {
		t.Fatalf("server state after valid CONFIRM = %s", session.State())
	}
	if err := fixture.client.HandlePong(pong); err != nil {
		t.Fatalf("HandlePong: %v", err)
	}
	if fixture.client.State() != StateEstablished {
		t.Fatalf("client state after matching PONG = %s", fixture.client.State())
	}
	if challenge == [8]byte{} {
		t.Fatal("deterministic challenge unexpectedly all zero")
	}

	clientChallenge := [8]byte{1, 3, 3, 7, 9, 2, 4, 6}
	clientDatagram, err := fixture.client.Seal([]codec.Frame{{Type: codec.FramePing, Body: clientChallenge[:]}})
	if err != nil {
		t.Fatalf("client Seal: %v", err)
	}
	clientFrames, err := session.Open(clientDatagram)
	if err != nil {
		t.Fatalf("server Open: %v", err)
	}
	if len(clientFrames) != 1 || clientFrames[0].Type != codec.FramePing || !bytes.Equal(clientFrames[0].Body, clientChallenge[:]) {
		t.Fatalf("unexpected client frames: %+v", clientFrames)
	}

	serverChallenge := [8]byte{8, 6, 7, 5, 3, 0, 9, 1}
	serverDatagram, err := session.Seal([]codec.Frame{{Type: codec.FramePong, Body: serverChallenge[:]}})
	if err != nil {
		t.Fatalf("server Seal: %v", err)
	}
	serverFrames, err := fixture.client.Open(serverDatagram)
	if err != nil {
		t.Fatalf("client Open: %v", err)
	}
	if len(serverFrames) != 1 || serverFrames[0].Type != codec.FramePong || !bytes.Equal(serverFrames[0].Body, serverChallenge[:]) {
		t.Fatalf("unexpected server frames: %+v", serverFrames)
	}
}

func TestRejectsTamperedInitialHeaderAndCiphertext(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte)
	}{
		{
			name: "header",
			mutate: func(datagram []byte) {
				datagram[19] ^= 0x01 // Change the transmitted client SCID.
			},
		},
		{
			name: "ciphertext",
			mutate: func(datagram []byte) {
				datagram[len(datagram)-1] ^= 0x80
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestFixture(t)
			initial, err := fixture.client.Start()
			if err != nil {
				t.Fatal(err)
			}
			tampered := append([]byte(nil), initial...)
			test.mutate(tampered)
			if _, _, err := fixture.server.HandleInitial(tampered); err == nil {
				t.Fatal("tampered INITIAL was accepted")
			}
		})
	}
}

func TestRetryTokenPrefixIsBoundIntoM1(t *testing.T) {
	fixture := newTestFixture(t)
	fixture.client.options.retryToken = deterministicBytes(0x39, 24)
	initial, err := fixture.client.Start()
	if err != nil {
		t.Fatal(err)
	}
	packet, err := codec.ParsePacket(initial, 0)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := codec.ParseInitial(packet.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload.Token, fixture.client.options.retryToken) {
		t.Fatal("retry token did not round trip")
	}
	tampered := append([]byte(nil), initial...)
	tampered[codec.HeaderSize+2+7] ^= 0x01
	if _, _, err := fixture.server.HandleInitial(tampered); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("error = %v, want ErrAuthentication", err)
	}
}

func TestRejectsTamperedHandshakeHeaderAndCiphertext(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte)
	}{
		{
			name: "header",
			mutate: func(datagram []byte) {
				datagram[19] ^= 0x01 // Change the transmitted server SCID.
			},
		},
		{
			name: "ciphertext",
			mutate: func(datagram []byte) {
				datagram[len(datagram)-1] ^= 0x40
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestFixture(t)
			initial, err := fixture.client.Start()
			if err != nil {
				t.Fatal(err)
			}
			session, response, err := fixture.server.HandleInitial(initial)
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			tampered := append([]byte(nil), response...)
			test.mutate(tampered)
			if err := fixture.client.Finish(tampered); err == nil {
				t.Fatal("tampered HANDSHAKE was accepted")
			}
			if fixture.client.State() != StateRejected {
				t.Fatalf("client state after HANDSHAKE rejection = %s", fixture.client.State())
			}
			if session.State() != StatePendingConfirm {
				t.Fatalf("server state changed after client rejection: %s", session.State())
			}
		})
	}
}

func TestInitialBindsDeploymentVersionAndClientCID(t *testing.T) {
	tests := []struct {
		name     string
		field    codec.TLVType
		mutate   func([]byte)
		expected error
	}{
		{
			name: "deployment id", field: codec.TLVDeploymentID,
			mutate: func(value []byte) { value[0] ^= 0x01 }, expected: ErrParameters,
		},
		{
			name: "version", field: codec.TLVVersion,
			mutate: func(value []byte) { value[0] = 2 }, expected: ErrParameters,
		},
		{
			name: "client cid", field: codec.TLVClientCID,
			mutate: func(value []byte) { value[7] ^= 0x01 }, expected: ErrConnectionID,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestFixture(t)
			initial, err := fixture.client.Start()
			if err != nil {
				t.Fatal(err)
			}
			mutated := mutateInitialField(t, fixture.client, initial, test.field, test.mutate)
			if _, _, err := fixture.server.HandleInitial(mutated); !errors.Is(err, test.expected) {
				t.Fatalf("error = %v, want %v", err, test.expected)
			}
		})
	}
}

func TestDeploymentContextMismatchIsRejected(t *testing.T) {
	fixture := newTestFixture(t)
	initial, err := fixture.client.Start()
	if err != nil {
		t.Fatal(err)
	}
	otherDeployment := fixture.server.deploymentID
	otherDeployment[15] ^= 0x55
	otherServer, err := NewServer(ServerConfig{
		DeploymentID: otherDeployment, StaticPrivate: fixture.server.staticPrivate,
		RegisteredClients: fixture.server.registeredClients,
		Random:            bytes.NewReader(deterministicBytes(0x51, 128)),
		AddressFamilies:   0x01, MaxDatagramSize: 1400, TunnelMTU: 1280,
		IPv4Lease: []byte{10, 77, 0, 2, 32},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := otherServer.HandleInitial(initial); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("error = %v, want authentication failure", err)
	}
}

func TestUnregisteredStaticPublicKeyIsRejected(t *testing.T) {
	fixture := newTestFixture(t)
	unregistered := deterministicPrivateKey(t, 0xD3)
	unregisteredPublic, err := wgcrypto.PublicBytes(unregistered.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(ServerConfig{
		DeploymentID:      fixture.server.deploymentID,
		StaticPrivate:     fixture.server.staticPrivate,
		RegisteredClients: [][32]byte{unregisteredPublic},
		Random:            bytes.NewReader(deterministicBytes(0x61, 128)),
		AddressFamilies:   0x01, MaxDatagramSize: 1400, TunnelMTU: 1280,
		IPv4Lease: []byte{10, 77, 0, 2, 32},
	})
	if err != nil {
		t.Fatal(err)
	}
	initial, err := fixture.client.Start()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.HandleInitial(initial); !errors.Is(err, ErrUnregisteredClient) {
		t.Fatalf("error = %v, want ErrUnregisteredClient", err)
	}
}

func TestWrongConfirmTranscriptRejectsSession(t *testing.T) {
	fixture := newTestFixture(t)
	initial, err := fixture.client.Start()
	if err != nil {
		t.Fatal(err)
	}
	session, response, err := fixture.server.HandleInitial(initial)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.client.Finish(response); err != nil {
		t.Fatal(err)
	}
	if session.State() != StatePendingConfirm {
		t.Fatalf("state before CONFIRM = %s", session.State())
	}
	wrongTH2 := fixture.client.th2
	wrongTH2[0] ^= 0x01
	challenge := [8]byte{9, 8, 7, 6, 5, 4, 3, 2}
	header := codec.Header{
		Version: codec.Version1, Kind: codec.PacketTransport,
		DCID: fixture.client.serverCID, SCID: fixture.client.clientCID, PacketNumber: 0,
	}
	packet, err := wgcrypto.SealTransport(fixture.client.c2sKey, header, []codec.Frame{
		{Type: codec.FrameConfirm, Body: wrongTH2[:]},
		{Type: codec.FramePing, Body: challenge[:]},
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	datagram, err := packet.MarshalBinary(0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.HandleConfirm(datagram); !errors.Is(err, ErrTranscript) {
		t.Fatalf("error = %v, want ErrTranscript", err)
	}
	if session.State() != StateRejected {
		t.Fatalf("server state after wrong th2 = %s", session.State())
	}
	if activeCIDCount(fixture.server) != 0 || fixture.server.activeAttempts != 0 {
		t.Fatalf("rejected session leaked CID/cache capacity: cids=%d attempts=%d", activeCIDCount(fixture.server), fixture.server.activeAttempts)
	}
	entry := onlyAttemptEntry(t, fixture.server)
	if entry.phase != attemptTombstone || entry.response != nil || entry.session != nil {
		t.Fatal("rejected session retained its HANDSHAKE cache")
	}
	if _, _, err := fixture.server.HandleInitial(initial); !errors.Is(err, ErrTranscript) {
		t.Fatalf("rejected-attempt replay error = %v, want ErrTranscript", err)
	}
}

func TestTransportHeaderAndCiphertextTampering(t *testing.T) {
	fixture, session := establishTestSession(t)
	defer session.Close()
	tests := []struct {
		name   string
		mutate func([]byte)
	}{
		{name: "header", mutate: func(data []byte) { data[19] ^= 1 }},
		{name: "ciphertext", mutate: func(data []byte) { data[len(data)-1] ^= 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Use the current expected PN but do not consume it because rejected
			// packets never enter the receive window.
			snapshot := session.receiveWindow.Snapshot()
			packetNumber := uint64(0)
			if snapshot.Initialized {
				packetNumber = snapshot.Highest + 1
			}
			header := codec.Header{
				Version: codec.Version1, Kind: codec.PacketTransport,
				DCID: session.serverCID, SCID: session.clientCID, PacketNumber: packetNumber,
			}
			body := [8]byte{2, 4, 6, 8, 1, 3, 5, 7}
			packet, err := wgcrypto.SealTransport(fixture.client.c2sKey, header, []codec.Frame{{Type: codec.FramePing, Body: body[:]}}, 0)
			if err != nil {
				t.Fatal(err)
			}
			datagram, err := packet.MarshalBinary(0)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(datagram)
			if _, err := session.Open(datagram); err == nil {
				t.Fatal("tampered TRANSPORT was accepted")
			}
		})
	}
}

func TestTransportAllowsOutOfOrderAndRejectsReplay(t *testing.T) {
	fixture, session := establishTestSession(t)
	defer session.Close()
	firstBody := [8]byte{1, 1, 1, 1, 1, 1, 1, 1}
	secondBody := [8]byte{2, 2, 2, 2, 2, 2, 2, 2}
	first, err := fixture.client.Seal([]codec.Frame{{Type: codec.FramePing, Body: firstBody[:]}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := fixture.client.Seal([]codec.Frame{{Type: codec.FramePing, Body: secondBody[:]}})
	if err != nil {
		t.Fatal(err)
	}
	frames, err := session.Open(second)
	if err != nil {
		t.Fatalf("open newer client PN first: %v", err)
	}
	if !bytes.Equal(frames[0].Body, secondBody[:]) {
		t.Fatal("wrong newer client frame")
	}
	frames, err = session.Open(first)
	if err != nil {
		t.Fatalf("open older in-window client PN: %v", err)
	}
	if !bytes.Equal(frames[0].Body, firstBody[:]) {
		t.Fatal("wrong older client frame")
	}
	if _, err := session.Open(first); err == nil {
		t.Fatal("replayed client packet was accepted")
	}

	serverFirst, err := session.Seal([]codec.Frame{{Type: codec.FramePong, Body: firstBody[:]}})
	if err != nil {
		t.Fatal(err)
	}
	serverSecond, err := session.Seal([]codec.Frame{{Type: codec.FramePong, Body: secondBody[:]}})
	if err != nil {
		t.Fatal(err)
	}
	frames, err = fixture.client.Open(serverSecond)
	if err != nil {
		t.Fatalf("open newer server PN first: %v", err)
	}
	if !bytes.Equal(frames[0].Body, secondBody[:]) {
		t.Fatal("wrong newer server frame")
	}
	frames, err = fixture.client.Open(serverFirst)
	if err != nil {
		t.Fatalf("open older in-window server PN: %v", err)
	}
	if !bytes.Equal(frames[0].Body, firstBody[:]) {
		t.Fatal("wrong older server frame")
	}
	if _, err := fixture.client.Open(serverFirst); err == nil {
		t.Fatal("replayed server packet was accepted")
	}
}

func TestAuthenticationFailureDoesNotConsumeReplayNumber(t *testing.T) {
	fixture, session := establishTestSession(t)
	defer session.Close()
	body := [8]byte{7, 0, 7, 0, 7, 0, 7, 0}
	valid, err := fixture.client.Seal([]codec.Frame{{Type: codec.FramePing, Body: body[:]}})
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), valid...)
	tampered[len(tampered)-1] ^= 0x80
	if _, err := session.Open(tampered); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tamper error = %v, want ErrAuthentication", err)
	}
	frames, err := session.Open(valid)
	if err != nil {
		t.Fatalf("valid packet after auth failure: %v", err)
	}
	if len(frames) != 1 || !bytes.Equal(frames[0].Body, body[:]) {
		t.Fatalf("unexpected frames: %+v", frames)
	}
}

func TestAuthenticatedMalformedFramesConsumeReplayNumber(t *testing.T) {
	fixture, session := establishTestSession(t)
	defer session.Close()
	header := codec.Header{
		Version: codec.Version1, Kind: codec.PacketTransport,
		DCID: session.serverCID, SCID: session.clientCID, PacketNumber: 1,
	}
	malformedPacket, err := wgcrypto.SealTransportPlaintext(fixture.client.c2sKey, header, []byte{0xFF, 0, 0, 0})
	if err != nil {
		t.Fatal(err)
	}
	malformedDatagram, err := malformedPacket.MarshalBinary(0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Open(malformedDatagram); !errors.Is(err, ErrMessage) {
		t.Fatalf("malformed-frame error = %v, want ErrMessage", err)
	}
	body := [8]byte{5, 5, 5, 5, 5, 5, 5, 5}
	validPacket, err := wgcrypto.SealTransport(fixture.client.c2sKey, header, []codec.Frame{{Type: codec.FramePing, Body: body[:]}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	validDatagram, err := validPacket.MarshalBinary(0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Open(validDatagram); !errors.Is(err, ErrMessage) {
		t.Fatalf("same-PN error = %v, want replay rejection", err)
	}
}

func TestTransportUsesNegotiatedDatagramLimit(t *testing.T) {
	fixture := newTestFixture(t)
	fixture.server.options.maxDatagramSize = 1200
	fixture.server.options.tunnelMTU = 1100
	initial, err := fixture.client.Start()
	if err != nil {
		t.Fatal(err)
	}
	session, response, err := fixture.server.HandleInitial(initial)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := fixture.client.Finish(response); err != nil {
		t.Fatal(err)
	}
	confirm, _, err := fixture.client.BuildConfirm()
	if err != nil {
		t.Fatal(err)
	}
	pong, err := session.HandleConfirm(confirm)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.client.HandlePong(pong); err != nil {
		t.Fatal(err)
	}
	negotiated, ok := fixture.client.Negotiated()
	if !ok || negotiated.MaxDatagramSize != 1200 || fixture.client.transportMaxSize != 1200 || session.maxDatagram != 1200 {
		t.Fatalf("negotiated limits not installed: %+v client=%d server=%d", negotiated, fixture.client.transportMaxSize, session.maxDatagram)
	}

	oversizedIP := makeIPv4Packet(1160)
	if _, err := fixture.client.Seal([]codec.Frame{{Type: codec.FrameIPPacket, Body: oversizedIP}}); err == nil {
		t.Fatal("client sealed frames beyond negotiated datagram limit")
	}
	header := codec.Header{
		Version: codec.Version1, Kind: codec.PacketTransport,
		DCID: fixture.client.clientCID, SCID: fixture.client.serverCID, PacketNumber: 1,
	}
	packet, err := wgcrypto.SealTransport(session.s2cKey, header, []codec.Frame{{Type: codec.FrameIPPacket, Body: oversizedIP}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	datagram, err := packet.MarshalBinary(1400)
	if err != nil {
		t.Fatal(err)
	}
	if len(datagram) <= 1200 {
		t.Fatalf("test packet length = %d, want >1200", len(datagram))
	}
	if _, err := fixture.client.Open(datagram); err == nil {
		t.Fatal("client accepted packet beyond negotiated datagram limit")
	}
}

func TestSendPacketNumberFailsClosedAtRehandshakeBoundary(t *testing.T) {
	fixture, session := establishTestSession(t)
	defer session.Close()
	body := [8]byte{4, 2, 4, 2, 4, 2, 4, 2}
	fixture.client.sendPN = rehandshakePacketNumber - 1
	datagram, err := fixture.client.Seal([]codec.Frame{{Type: codec.FramePing, Body: body[:]}})
	if err != nil {
		t.Fatalf("client final permitted PN: %v", err)
	}
	packet, err := codec.ParsePacket(datagram, 0)
	if err != nil {
		t.Fatal(err)
	}
	if packet.Header.PacketNumber != rehandshakePacketNumber-1 {
		t.Fatalf("client PN = %d", packet.Header.PacketNumber)
	}
	if _, err := fixture.client.Seal([]codec.Frame{{Type: codec.FramePing, Body: body[:]}}); !errors.Is(err, ErrState) {
		t.Fatalf("client boundary error = %v", err)
	}
	if fixture.client.State() != StateClosed {
		t.Fatalf("client state at PN boundary = %s", fixture.client.State())
	}

	session.sendPN = rehandshakePacketNumber - 1
	datagram, err = session.Seal([]codec.Frame{{Type: codec.FramePong, Body: body[:]}})
	if err != nil {
		t.Fatalf("server final permitted PN: %v", err)
	}
	packet, err = codec.ParsePacket(datagram, 0)
	if err != nil {
		t.Fatal(err)
	}
	if packet.Header.PacketNumber != rehandshakePacketNumber-1 {
		t.Fatalf("server PN = %d", packet.Header.PacketNumber)
	}
	if _, err := session.Seal([]codec.Frame{{Type: codec.FramePong, Body: body[:]}}); !errors.Is(err, ErrState) {
		t.Fatalf("server boundary error = %v", err)
	}
	if session.State() != StateClosed {
		t.Fatalf("server state at PN boundary = %s", session.State())
	}
}

func makeIPv4Packet(length int) []byte {
	packet := make([]byte, length)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(length))
	packet[8] = 64
	packet[9] = 17
	copy(packet[12:16], []byte{10, 77, 0, 2})
	copy(packet[16:20], []byte{198, 51, 100, 8})
	return packet
}

func establishTestSession(t *testing.T) (*testFixture, *ServerSession) {
	t.Helper()
	fixture := newTestFixture(t)
	initial, err := fixture.client.Start()
	if err != nil {
		t.Fatal(err)
	}
	session, response, err := fixture.server.HandleInitial(initial)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.client.Finish(response); err != nil {
		t.Fatal(err)
	}
	confirm, _, err := fixture.client.BuildConfirm()
	if err != nil {
		t.Fatal(err)
	}
	pong, err := session.HandleConfirm(confirm)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.client.HandlePong(pong); err != nil {
		t.Fatal(err)
	}
	return fixture, session
}

func newTestFixture(t *testing.T) *testFixture {
	t.Helper()
	clientStatic := deterministicPrivateKey(t, 0x11)
	serverStatic := deterministicPrivateKey(t, 0x72)
	clientPublic, err := wgcrypto.PublicBytes(clientStatic.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	serverPublic, err := wgcrypto.PublicBytes(serverStatic.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	var deployment [16]byte
	copy(deployment[:], deterministicBytes(0xA0, len(deployment)))
	client, err := NewClient(ClientConfig{
		DeploymentID: deployment, StaticPrivate: clientStatic,
		ServerStaticPublic: serverPublic,
		Random:             bytes.NewReader(deterministicBytes(0x21, 256)),
		Capabilities:       0x1020, AddressFamilies: 0x01,
		MaxDatagramSize: 1400, MinTunnelMTU: 576, MaxTunnelMTU: 1348,
	})
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(ServerConfig{
		DeploymentID: deployment, StaticPrivate: serverStatic,
		RegisteredClients: [][32]byte{clientPublic},
		Random:            bytes.NewReader(deterministicBytes(0x51, 256)),
		Capabilities:      0x2040, AddressFamilies: 0x01,
		MaxDatagramSize: 1400, TunnelMTU: 1280, LeaseSeconds: 600,
		IPv4Lease: []byte{10, 77, 0, 2, 32}, EgressPolicy: 7,
		DNSParameters: []byte{1, 2, 3, 4},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &testFixture{client: client, server: server}
}

func deterministicPrivateKey(t *testing.T, seed byte) *ecdh.PrivateKey {
	t.Helper()
	raw := deterministicBytes(seed, 32)
	privateKey, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		t.Fatalf("deterministic private key: %v", err)
	}
	return privateKey
}

func deterministicBytes(seed byte, length int) []byte {
	data := make([]byte, length)
	for index := range data {
		data[index] = seed + byte(index*29+1)
	}
	return data
}

func mutateInitialField(t *testing.T, client *Client, datagram []byte, fieldType codec.TLVType, mutate func([]byte)) []byte {
	t.Helper()
	packet, initial, ad, _, err := parseInitialWire(datagram, int(client.options.maxDatagramSize), client.context)
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := wgcrypto.DeriveM1(client.context, client.es)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := wgcrypto.OpenHandshake(key, ad, initial.EncryptedPayload)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := codec.ParseTLVsFor(plaintext, codec.TLVContextInitial)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for index := range fields {
		if fields[index].Type == fieldType {
			mutate(fields[index].Value)
			found = true
		}
	}
	if !found {
		t.Fatalf("field 0x%02x not found", fieldType)
	}
	mutatedPlaintext, err := codec.MarshalTLVsFor(fields, codec.TLVContextInitial)
	if err != nil {
		t.Fatal(err)
	}
	mutatedCiphertext, err := wgcrypto.SealHandshake(key, ad, mutatedPlaintext)
	if err != nil {
		t.Fatal(err)
	}
	prefixLength := len(packet.Payload) - len(initial.EncryptedPayload)
	mutated, err := marshalWirePacket(packet.Header, packet.Payload[:prefixLength], mutatedCiphertext, int(client.options.maxDatagramSize))
	if err != nil {
		t.Fatal(err)
	}
	return mutated
}

func TestWireUsesNetworkByteOrderForCIDFields(t *testing.T) {
	fixture := newTestFixture(t)
	initial, err := fixture.client.Start()
	if err != nil {
		t.Fatal(err)
	}
	packet, err := codec.ParsePacket(initial, 0)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint64(initial[12:20]) != packet.Header.SCID {
		t.Fatal("outer client CID is not network byte order")
	}
}

func TestClientRejectsRepeatedZeroCIDSource(t *testing.T) {
	fixture := newTestFixture(t)
	fixture.client.options.random = bytes.NewReader(make([]byte, 32*8))
	if _, err := fixture.client.Start(); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("error = %v, want ErrConfiguration", err)
	}
	if fixture.client.ClientCID() != 0 || fixture.client.State() != StateIdle {
		t.Fatal("failed CID generation changed client state")
	}
}
