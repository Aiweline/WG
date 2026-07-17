package handshake

import (
	"crypto/ecdh"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"sync"

	"wg.local/wg/internal/codec"
	wgcrypto "wg.local/wg/internal/crypto"
	"wg.local/wg/internal/session"
)

// Server handles normal WG-HS/1 INITIAL messages for pre-registered clients.
type Server struct {
	deploymentID      [16]byte
	staticPrivate     *ecdh.PrivateKey
	registeredClients [][32]byte
	options           serverOptions
	context           []byte

	randomMu   sync.Mutex
	activeMu   sync.Mutex
	activeCIDs map[uint64]struct{}

	attemptMu      sync.Mutex
	attempts       map[[32]byte]*attemptEntry
	activeAttempts int
}

// ServerSession is created after INITIAL decrypts and claims an enabled,
// registered client public key. Possession of that client's private key is
// accepted only after a valid CONFIRM; the initial state is PendingConfirm.
type ServerSession struct {
	mu sync.Mutex

	owner                *Server
	state                State
	clientCID            uint64
	serverCID            uint64
	clientStatic         [32]byte
	th2                  [32]byte
	c2sKey               [32]byte
	s2cKey               [32]byte
	sendPN               uint64
	receiveWindow        session.ReplayWindow
	maxDatagram          int
	closedCID            bool
	attemptKey           [32]byte
	hasAttempt           bool
	confirmChallenge     [8]byte
	haveConfirmChallenge bool
}

// NewServer validates its static identity, lease, and pre-registration set.
func NewServer(config ServerConfig) (*Server, error) {
	options, err := normalizeServerConfig(config)
	if err != nil {
		return nil, err
	}
	registered := make([][32]byte, len(config.RegisteredClients))
	copy(registered, config.RegisteredClients)
	return &Server{
		deploymentID: config.DeploymentID, staticPrivate: config.StaticPrivate,
		registeredClients: registered, options: options,
		context: wgcrypto.Context(config.DeploymentID), activeCIDs: make(map[uint64]struct{}),
		attempts: make(map[[32]byte]*attemptEntry),
	}, nil
}

// HandleInitial validates one raw INITIAL datagram and returns the HANDSHAKE
// response plus a PendingConfirm session. Client private-key possession is
// proven only by the later CONFIRM. The raw datagram is used directly for
// m1_ad and th1; no equivalent header is reconstructed.
func (server *Server) HandleInitial(datagram []byte) (resultSession *ServerSession, resultResponse []byte, resultErr error) {
	packet, initial, m1AD, th1, err := parseInitialWire(datagram, int(server.options.maxDatagramSize), server.context)
	if err != nil {
		return nil, nil, err
	}
	if packet.Header.DCID != 0 || packet.Header.SCID == 0 {
		return nil, nil, fmt.Errorf("%w: INITIAL outer CID", ErrConnectionID)
	}
	lease, err := server.acquireAttempt(th1, datagram)
	if err != nil {
		return nil, nil, err
	}
	if !lease.builder {
		return lease.session, lease.response, nil
	}
	attemptCompleted := false
	defer func() {
		if attemptCompleted {
			return
		}
		failure := resultErr
		if failure == nil {
			failure = ErrMessage
		}
		server.failAttempt(lease.entry, failure)
	}()

	es, err := wgcrypto.DH(server.staticPrivate, initial.ClientEphemeralPublic)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: server static/client ephemeral DH", ErrAuthentication)
	}
	prk1, k1, err := wgcrypto.DeriveM1(server.context, es)
	if err != nil {
		zero32(&prk1)
		zero32(&k1)
		zero32(&es)
		return nil, nil, fmt.Errorf("%w: derive INITIAL keys", ErrAuthentication)
	}
	plaintext, err := wgcrypto.OpenHandshake(k1, m1AD, initial.EncryptedPayload)
	zero32(&prk1)
	zero32(&k1)
	if err != nil {
		zero32(&es)
		return nil, nil, fmt.Errorf("%w: decrypt INITIAL", ErrAuthentication)
	}
	fields, err := codec.ParseTLVsFor(plaintext, codec.TLVContextInitial)
	if err != nil {
		zero32(&es)
		return nil, nil, fmt.Errorf("%w: INITIAL fields: %v", ErrMessage, err)
	}
	clientStatic, requestedFamilies, clientMaxDatagram, err := server.validateInitialFields(fields, packet.Header.SCID)
	if err != nil {
		zero32(&es)
		return nil, nil, err
	}

	server.randomMu.Lock()
	serverCID, err := server.reserveServerCIDLocked()
	if err != nil {
		server.randomMu.Unlock()
		zero32(&es)
		return nil, nil, err
	}
	ephemeralPrivate, err := wgcrypto.GenerateKeyFrom(server.options.random)
	server.randomMu.Unlock()
	if err != nil {
		server.releaseCID(serverCID)
		zero32(&es)
		return nil, nil, fmt.Errorf("%w: generate server ephemeral key: %v", ErrConfiguration, err)
	}
	keepCID := false
	defer func() {
		if !keepCID {
			server.releaseCID(serverCID)
		}
	}()
	ephemeralPublic, err := wgcrypto.PublicBytes(ephemeralPrivate.PublicKey())
	if err != nil {
		zero32(&es)
		return nil, nil, fmt.Errorf("%w: encode server ephemeral key", ErrConfiguration)
	}

	ss, err := wgcrypto.DH(server.staticPrivate, clientStatic)
	if err != nil {
		zero32(&es)
		return nil, nil, fmt.Errorf("%w: static/static DH", ErrAuthentication)
	}
	ee, err := wgcrypto.DH(ephemeralPrivate, initial.ClientEphemeralPublic)
	if err != nil {
		zero32(&es)
		zero32(&ss)
		return nil, nil, fmt.Errorf("%w: ephemeral/ephemeral DH", ErrAuthentication)
	}
	se, err := wgcrypto.DH(ephemeralPrivate, clientStatic)
	if err != nil {
		zero32(&es)
		zero32(&ss)
		zero32(&ee)
		return nil, nil, fmt.Errorf("%w: ephemeral/static DH", ErrAuthentication)
	}
	prk2, k2, err := wgcrypto.DeriveM2(th1, es, ss, ee, se)
	zero32(&es)
	zero32(&ss)
	zero32(&ee)
	zero32(&se)
	if err != nil {
		zero32(&prk2)
		zero32(&k2)
		return nil, nil, fmt.Errorf("%w: derive HANDSHAKE keys", ErrAuthentication)
	}

	availableFamilies := server.options.addressFamilies
	if len(server.options.ipv4Lease) == 0 {
		availableFamilies &^= 0x01
	}
	if len(server.options.ipv6Lease) == 0 {
		availableFamilies &^= 0x02
	}
	selectedFamilies := requestedFamilies & availableFamilies
	if selectedFamilies == 0 {
		zero32(&prk2)
		zero32(&k2)
		return nil, nil, fmt.Errorf("%w: no shared address family", ErrParameters)
	}
	selectedMaxDatagram := minUint16(clientMaxDatagram, server.options.maxDatagramSize)
	maxTunnelMTU := selectedMaxDatagram - codec.HeaderSize - codec.AEADTagSize - codec.FrameHeaderSize
	selectedTunnelMTU := minUint16(server.options.tunnelMTU, maxTunnelMTU)
	if selectedTunnelMTU < 576 {
		zero32(&prk2)
		zero32(&k2)
		return nil, nil, fmt.Errorf("%w: negotiated tunnel MTU is too small", ErrParameters)
	}
	handshakeFields := server.handshakeFields(packet.Header.SCID, serverCID, selectedFamilies, selectedMaxDatagram, selectedTunnelMTU)
	encodedFields, err := codec.MarshalTLVsFor(handshakeFields, codec.TLVContextHandshake)
	if err != nil {
		zero32(&prk2)
		zero32(&k2)
		return nil, nil, fmt.Errorf("%w: encode HANDSHAKE fields: %v", ErrMessage, err)
	}
	ciphertextLength := len(encodedFields) + codec.AEADTagSize
	prefix, err := makeHandshakePrefix(ephemeralPublic, ciphertextLength)
	if err != nil {
		zero32(&prk2)
		zero32(&k2)
		return nil, nil, err
	}
	header, encodedHeader, err := makeHeader(codec.PacketHandshake, packet.Header.SCID, serverCID, 0, len(prefix)+ciphertextLength)
	if err != nil {
		zero32(&prk2)
		zero32(&k2)
		return nil, nil, err
	}
	m2AD := join(server.context, th1[:], encodedHeader, prefix)
	ciphertext, err := wgcrypto.SealHandshake(k2, m2AD, encodedFields)
	zero32(&k2)
	if err != nil {
		zero32(&prk2)
		return nil, nil, fmt.Errorf("%w: encrypt HANDSHAKE", ErrAuthentication)
	}
	if len(ciphertext) != ciphertextLength {
		zero32(&prk2)
		return nil, nil, fmt.Errorf("%w: unexpected HANDSHAKE ciphertext length", ErrMessage)
	}
	response, err := marshalWirePacket(header, prefix, ciphertext, int(selectedMaxDatagram))
	if err != nil {
		zero32(&prk2)
		return nil, nil, err
	}
	th2 := wgcrypto.Sum256(m2AD, ciphertext)
	c2s, s2c, err := wgcrypto.DeriveTraffic(prk2, th2)
	zero32(&prk2)
	if err != nil {
		zero32(&c2s)
		zero32(&s2c)
		return nil, nil, fmt.Errorf("%w: derive traffic keys", ErrAuthentication)
	}

	session := &ServerSession{
		owner: server, state: StatePendingConfirm,
		clientCID: packet.Header.SCID, serverCID: serverCID,
		clientStatic: clientStatic, th2: th2, c2sKey: c2s, s2cKey: s2c,
		maxDatagram: int(selectedMaxDatagram),
	}
	if err := server.publishAttempt(lease.entry, session, response); err != nil {
		session.Close()
		keepCID = true
		return nil, nil, err
	}
	attemptCompleted = true
	keepCID = true
	return session, response, nil
}

func (server *Server) validateInitialFields(fields []codec.TLV, outerClientCID uint64) ([32]byte, uint8, uint16, error) {
	if _, present := codec.FindTLV(fields, codec.TLVEnrollmentTokenID); present {
		return [32]byte{}, 0, 0, ErrEnrollmentUnsupported
	}
	if _, present := codec.FindTLV(fields, codec.TLVEnrollmentProof); present {
		return [32]byte{}, 0, 0, ErrEnrollmentUnsupported
	}
	version, _ := codec.FindTLV(fields, codec.TLVVersion)
	deployment, _ := codec.FindTLV(fields, codec.TLVDeploymentID)
	clientCID, _ := codec.FindTLV(fields, codec.TLVClientCID)
	addressFamilies, _ := codec.FindTLV(fields, codec.TLVAddressFamilies)
	maxDatagram, _ := codec.FindTLV(fields, codec.TLVMaxDatagramSize)
	clientStaticValue, _ := codec.FindTLV(fields, codec.TLVClientStaticKey)
	if version[0] != codec.Version1 {
		return [32]byte{}, 0, 0, fmt.Errorf("%w: VERSION", ErrParameters)
	}
	if !secureEqual(deployment, server.deploymentID[:]) {
		return [32]byte{}, 0, 0, fmt.Errorf("%w: DEPLOYMENT_ID", ErrParameters)
	}
	if binary.BigEndian.Uint64(clientCID) != outerClientCID {
		return [32]byte{}, 0, 0, fmt.Errorf("%w: CLIENT_CID", ErrConnectionID)
	}
	requestedFamilies := addressFamilies[0]
	if requestedFamilies == 0 || requestedFamilies&^uint8(0x03) != 0 {
		return [32]byte{}, 0, 0, fmt.Errorf("%w: ADDRESS_FAMILIES", ErrParameters)
	}
	clientMaxDatagram := binary.BigEndian.Uint16(maxDatagram)
	if clientMaxDatagram < codec.HeaderSize+codec.AEADTagSize+codec.FrameHeaderSize {
		return [32]byte{}, 0, 0, fmt.Errorf("%w: MAX_DATAGRAM_SIZE", ErrParameters)
	}
	var clientStatic [32]byte
	copy(clientStatic[:], clientStaticValue)
	if !server.isRegistered(clientStatic) {
		return [32]byte{}, 0, 0, ErrUnregisteredClient
	}
	return clientStatic, requestedFamilies, clientMaxDatagram, nil
}

func (server *Server) handshakeFields(clientCID, serverCID uint64, families uint8, maxDatagram, tunnelMTU uint16) []codec.TLV {
	fields := []codec.TLV{
		{Type: codec.TLVEgressPolicyVersion, Value: encodeUint64(server.options.egressPolicy)},
		{Type: codec.TLVVersion, Value: []byte{codec.Version1}},
		{Type: codec.TLVDeploymentID, Value: server.deploymentID[:]},
		{Type: codec.TLVClientCID, Value: encodeUint64(clientCID)},
		{Type: codec.TLVServerCID, Value: encodeUint64(serverCID)},
		{Type: codec.TLVCapabilities, Value: encodeUint64(server.options.capabilities)},
		{Type: codec.TLVAddressFamilies, Value: []byte{families}},
		{Type: codec.TLVMaxDatagramSize, Value: encodeUint16(maxDatagram)},
		{Type: codec.TLVTunnelMTU, Value: encodeUint16(tunnelMTU)},
		{Type: codec.TLVLeaseSeconds, Value: encodeUint32(server.options.leaseSeconds)},
	}
	if len(server.options.dnsParameters) != 0 {
		fields = append(fields, codec.TLV{Type: codec.TLVDNSParameters, Value: server.options.dnsParameters})
	}
	if families&0x01 != 0 && len(server.options.ipv4Lease) != 0 {
		fields = append(fields, codec.TLV{Type: codec.TLVIPv4Lease, Value: server.options.ipv4Lease})
	}
	if families&0x02 != 0 && len(server.options.ipv6Lease) != 0 {
		fields = append(fields, codec.TLV{Type: codec.TLVIPv6Lease, Value: server.options.ipv6Lease})
	}
	return fields
}

func (server *Server) isRegistered(candidate [32]byte) bool {
	matched := 0
	for _, registered := range server.registeredClients {
		matched |= subtle.ConstantTimeCompare(candidate[:], registered[:])
	}
	return matched == 1
}

func (server *Server) reserveServerCIDLocked() (uint64, error) {
	for attempt := 0; attempt < 32; attempt++ {
		cid, err := nextNonZeroCID(server.options.random)
		if err != nil {
			return 0, err
		}
		server.activeMu.Lock()
		_, exists := server.activeCIDs[cid]
		if !exists {
			server.activeCIDs[cid] = struct{}{}
		}
		server.activeMu.Unlock()
		if !exists {
			return cid, nil
		}
	}
	return 0, fmt.Errorf("%w: unable to allocate a unique server CID", ErrConfiguration)
}

func (server *Server) releaseCID(cid uint64) {
	server.activeMu.Lock()
	delete(server.activeCIDs, cid)
	server.activeMu.Unlock()
}

func (session *ServerSession) State() State { return stateValue(&session.mu, &session.state) }

func (session *ServerSession) ClientCID() uint64 {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.clientCID
}

func (session *ServerSession) ServerCID() uint64 {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.serverCID
}

func (session *ServerSession) Close() {
	session.mu.Lock()
	defer session.mu.Unlock()
	session.closeLocked(StateClosed)
}

func (session *ServerSession) closeLocked(state State) {
	session.state = state
	zero32(&session.c2sKey)
	zero32(&session.s2cKey)
	session.confirmChallenge = [8]byte{}
	session.haveConfirmChallenge = false
	if session.hasAttempt && session.owner != nil {
		reason := error(ErrState)
		if state == StateRejected {
			reason = ErrTranscript
		}
		session.owner.removeAttempt(session.attemptKey, session, reason)
		session.hasAttempt = false
	}
	if !session.closedCID && session.owner != nil {
		session.owner.releaseCID(session.serverCID)
		session.closedCID = true
	}
}

func minUint16(left, right uint16) uint16 {
	if left < right {
		return left
	}
	return right
}
