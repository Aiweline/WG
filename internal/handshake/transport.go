package handshake

import (
	"fmt"
	"io"

	"wg.local/wg/internal/codec"
	wgcrypto "wg.local/wg/internal/crypto"
)

const rehandshakePacketNumber = uint64(1) << 32

// BuildConfirm creates the mandatory first TRANSPORT datagram containing
// CONFIRM(th2) followed by PING(random challenge).
func (client *Client) BuildConfirm() ([]byte, [8]byte, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.state != StatePendingConfirm {
		return nil, [8]byte{}, fmt.Errorf("%w: BuildConfirm from %s", ErrState, client.state)
	}
	var challenge [8]byte
	if _, err := io.ReadFull(client.options.random, challenge[:]); err != nil {
		return nil, [8]byte{}, fmt.Errorf("%w: generate PING challenge: %v", ErrConfiguration, err)
	}
	frames := []codec.Frame{
		{Type: codec.FrameConfirm, Body: append([]byte(nil), client.th2[:]...)},
		{Type: codec.FramePing, Body: append([]byte(nil), challenge[:]...)},
	}
	datagram, err := client.sealLocked(frames)
	if err != nil {
		return nil, [8]byte{}, err
	}
	client.pendingChallenge = challenge
	client.haveChallenge = true
	client.state = StatePendingPong
	return datagram, challenge, nil
}

// RetransmitConfirm reuses the original th2 and PING challenge while
// allocating a fresh TRANSPORT PN. It is available only while awaiting PONG.
func (client *Client) RetransmitConfirm() ([]byte, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.state != StatePendingPong || !client.haveChallenge {
		return nil, fmt.Errorf("%w: RetransmitConfirm from %s", ErrState, client.state)
	}
	frames := []codec.Frame{
		{Type: codec.FrameConfirm, Body: append([]byte(nil), client.th2[:]...)},
		{Type: codec.FramePing, Body: append([]byte(nil), client.pendingChallenge[:]...)},
	}
	return client.sealLocked(frames)
}

// HandlePong authenticates the server's first TRANSPORT datagram and only
// marks the client Established when it contains the matching PONG.
func (client *Client) HandlePong(datagram []byte) error {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.state != StatePendingPong || !client.haveChallenge {
		return fmt.Errorf("%w: HandlePong from %s", ErrState, client.state)
	}
	frames, err := client.openLocked(datagram)
	if err != nil {
		return err
	}
	if len(frames) != 1 || frames[0].Type != codec.FramePong || !secureEqual(frames[0].Body, client.pendingChallenge[:]) {
		return fmt.Errorf("%w: expected matching PONG", ErrMessage)
	}
	client.haveChallenge = false
	client.pendingChallenge = [8]byte{}
	client.state = StateEstablished
	return nil
}

// Seal encrypts authenticated client-to-server frames after establishment.
func (client *Client) Seal(frames []codec.Frame) ([]byte, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.state != StateEstablished {
		return nil, fmt.Errorf("%w: client Seal from %s", ErrState, client.state)
	}
	return client.sealLocked(frames)
}

// Open authenticates and decrypts one server-to-client datagram after
// establishment.
func (client *Client) Open(datagram []byte) ([]codec.Frame, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.state != StateEstablished {
		return nil, fmt.Errorf("%w: client Open from %s", ErrState, client.state)
	}
	return client.openLocked(datagram)
}

func (client *Client) sealLocked(frames []codec.Frame) ([]byte, error) {
	if client.sendPN >= rehandshakePacketNumber {
		client.closeLocked(StateClosed)
		return nil, fmt.Errorf("%w: client packet-number limit reached", ErrState)
	}
	pn := client.sendPN
	client.sendPN++ // Allocated packet numbers are never rolled back or reused.
	header := codec.Header{
		Version: codec.Version1, Kind: codec.PacketTransport,
		DCID: client.serverCID, SCID: client.clientCID, PacketNumber: pn,
	}
	packet, err := wgcrypto.SealTransport(client.c2sKey, header, frames, maxPlaintextForDatagram(client.transportMaxSize))
	if err != nil {
		return nil, fmt.Errorf("%w: seal client TRANSPORT", ErrMessage)
	}
	datagram, err := packet.MarshalBinary(client.transportMaxSize)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal client TRANSPORT: %v", ErrMessage, err)
	}
	return datagram, nil
}

func (client *Client) openLocked(datagram []byte) ([]codec.Frame, error) {
	packet, err := parseTransportDatagram(datagram, client.transportMaxSize)
	if err != nil {
		return nil, err
	}
	if packet.Header.DCID != client.clientCID || packet.Header.SCID != client.serverCID {
		return nil, fmt.Errorf("%w: server TRANSPORT CID", ErrConnectionID)
	}
	if packet.Header.PacketNumber >= rehandshakePacketNumber || !client.receiveWindow.Precheck(packet.Header.PacketNumber) {
		return nil, fmt.Errorf("%w: unacceptable server packet number", ErrMessage)
	}
	plaintext, err := wgcrypto.OpenTransportPlaintext(client.s2cKey, packet)
	if err != nil {
		return nil, fmt.Errorf("%w: open server TRANSPORT", ErrAuthentication)
	}
	if err := client.receiveWindow.AcceptAuthenticated(packet.Header.PacketNumber); err != nil {
		return nil, fmt.Errorf("%w: replayed server packet", ErrMessage)
	}
	frames, err := codec.ParseFrames(plaintext, maxPlaintextForDatagram(client.transportMaxSize))
	if err != nil {
		return nil, fmt.Errorf("%w: parse server frames: %v", ErrMessage, err)
	}
	return frames, nil
}

// HandleConfirm authenticates CONFIRM+PING. The server remains
// PendingConfirm until the authenticated th2 comparison succeeds.
func (session *ServerSession) HandleConfirm(datagram []byte) ([]byte, error) {
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.state != StatePendingConfirm && session.state != StateEstablished {
		return nil, fmt.Errorf("%w: HandleConfirm from %s", ErrState, session.state)
	}
	wasEstablished := session.state == StateEstablished
	frames, err := session.openLocked(datagram)
	if err != nil {
		return nil, err
	}
	if len(frames) != 2 || frames[0].Type != codec.FrameConfirm || frames[1].Type != codec.FramePing {
		return nil, fmt.Errorf("%w: expected CONFIRM followed by PING", ErrMessage)
	}
	if !secureEqual(frames[0].Body, session.th2[:]) {
		if !wasEstablished {
			session.closeLocked(StateRejected)
		}
		return nil, ErrTranscript
	}
	challenge := append([]byte(nil), frames[1].Body...)
	if wasEstablished {
		if !session.haveConfirmChallenge || !secureEqual(challenge, session.confirmChallenge[:]) {
			return nil, fmt.Errorf("%w: CONFIRM retry challenge mismatch", ErrMessage)
		}
		if !session.hasAttempt || session.owner == nil || !session.owner.confirmGraceActive(session.attemptKey, session) {
			return nil, ErrAttemptExpired
		}
	} else {
		if !session.hasAttempt || session.owner == nil || !session.owner.promoteAttempt(session.attemptKey, session) {
			session.closeLocked(StateClosed)
			return nil, ErrAttemptExpired
		}
		copy(session.confirmChallenge[:], challenge)
		session.haveConfirmChallenge = true
		session.state = StateEstablished
	}
	response, err := session.sealLocked([]codec.Frame{{Type: codec.FramePong, Body: challenge}})
	if err != nil {
		session.closeLocked(StateClosed)
		return nil, err
	}
	return response, nil
}

// Open authenticates and decrypts client-to-server frames after confirmation.
func (session *ServerSession) Open(datagram []byte) ([]codec.Frame, error) {
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.state != StateEstablished {
		return nil, fmt.Errorf("%w: server Open from %s", ErrState, session.state)
	}
	return session.openLocked(datagram)
}

// Seal encrypts server-to-client frames after confirmation.
func (session *ServerSession) Seal(frames []codec.Frame) ([]byte, error) {
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.state != StateEstablished {
		return nil, fmt.Errorf("%w: server Seal from %s", ErrState, session.state)
	}
	return session.sealLocked(frames)
}

func (session *ServerSession) openLocked(datagram []byte) ([]codec.Frame, error) {
	packet, err := parseTransportDatagram(datagram, session.maxDatagram)
	if err != nil {
		return nil, err
	}
	if packet.Header.DCID != session.serverCID || packet.Header.SCID != session.clientCID {
		return nil, fmt.Errorf("%w: client TRANSPORT CID", ErrConnectionID)
	}
	if packet.Header.PacketNumber >= rehandshakePacketNumber || !session.receiveWindow.Precheck(packet.Header.PacketNumber) {
		return nil, fmt.Errorf("%w: unacceptable client packet number", ErrMessage)
	}
	plaintext, err := wgcrypto.OpenTransportPlaintext(session.c2sKey, packet)
	if err != nil {
		return nil, fmt.Errorf("%w: open client TRANSPORT", ErrAuthentication)
	}
	if err := session.receiveWindow.AcceptAuthenticated(packet.Header.PacketNumber); err != nil {
		return nil, fmt.Errorf("%w: replayed client packet", ErrMessage)
	}
	frames, err := codec.ParseFrames(plaintext, maxPlaintextForDatagram(session.maxDatagram))
	if err != nil {
		return nil, fmt.Errorf("%w: parse client frames: %v", ErrMessage, err)
	}
	return frames, nil
}

func (session *ServerSession) sealLocked(frames []codec.Frame) ([]byte, error) {
	if session.sendPN >= rehandshakePacketNumber {
		session.closeLocked(StateClosed)
		return nil, fmt.Errorf("%w: server packet-number limit reached", ErrState)
	}
	pn := session.sendPN
	session.sendPN++ // Allocated packet numbers are never rolled back or reused.
	header := codec.Header{
		Version: codec.Version1, Kind: codec.PacketTransport,
		DCID: session.clientCID, SCID: session.serverCID, PacketNumber: pn,
	}
	packet, err := wgcrypto.SealTransport(session.s2cKey, header, frames, maxPlaintextForDatagram(session.maxDatagram))
	if err != nil {
		return nil, fmt.Errorf("%w: seal server TRANSPORT", ErrMessage)
	}
	datagram, err := packet.MarshalBinary(session.maxDatagram)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal server TRANSPORT: %v", ErrMessage, err)
	}
	return datagram, nil
}

func parseTransportDatagram(datagram []byte, maxDatagram int) (codec.Packet, error) {
	packet, err := codec.ParsePacket(datagram, maxDatagram)
	if err != nil {
		return codec.Packet{}, fmt.Errorf("%w: TRANSPORT packet: %v", ErrMessage, err)
	}
	if packet.Header.Kind != codec.PacketTransport {
		return codec.Packet{}, fmt.Errorf("%w: expected TRANSPORT", ErrMessage)
	}
	return packet, nil
}

func maxPlaintextForDatagram(maxDatagram int) int {
	return maxDatagram - codec.HeaderSize - codec.AEADTagSize
}
