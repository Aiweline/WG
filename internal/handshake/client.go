package handshake

import (
	"crypto/ecdh"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"

	"wg.local/wg/internal/codec"
	wgcrypto "wg.local/wg/internal/crypto"
	"wg.local/wg/internal/session"
)

// Client implements one normal pre-enrolled WG-HS/1 attempt.
type Client struct {
	mu sync.Mutex

	state              State
	deploymentID       [16]byte
	staticPrivate      *ecdh.PrivateKey
	staticPublic       [32]byte
	serverStaticPublic [32]byte
	options            clientOptions
	context            []byte

	clientCID        uint64
	serverCID        uint64
	ephemeralPrivate *ecdh.PrivateKey
	es               [32]byte
	th1              [32]byte
	th2              [32]byte
	c2sKey           [32]byte
	s2cKey           [32]byte
	sendPN           uint64
	receiveWindow    session.ReplayWindow
	transportMaxSize int
	pendingChallenge [8]byte
	haveChallenge    bool
	negotiated       Negotiated
}

// NewClient validates the pinned server identity and creates an idle attempt.
func NewClient(config ClientConfig) (*Client, error) {
	options, err := normalizeClientConfig(config)
	if err != nil {
		return nil, err
	}
	staticPublic, err := wgcrypto.PublicBytes(config.StaticPrivate.PublicKey())
	if err != nil {
		return nil, fmt.Errorf("%w: client static public key: %v", ErrConfiguration, err)
	}
	client := &Client{
		state: StateIdle, deploymentID: config.DeploymentID,
		staticPrivate: config.StaticPrivate, staticPublic: staticPublic,
		serverStaticPublic: config.ServerStaticPublic, options: options,
		transportMaxSize: int(options.maxDatagramSize),
	}
	client.context = wgcrypto.Context(config.DeploymentID)
	return client, nil
}

// State returns the current client state.
func (client *Client) State() State { return stateValue(&client.mu, &client.state) }

// ClientCID returns the CID selected by Start, or zero before Start.
func (client *Client) ClientCID() uint64 {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.clientCID
}

// ServerCID returns the authenticated server CID after Finish.
func (client *Client) ServerCID() uint64 {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.serverCID
}

// Close discards ephemeral and traffic key material. It is idempotent.
func (client *Client) Close() {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.closeLocked(StateClosed)
}

func (client *Client) closeLocked(state State) {
	client.ephemeralPrivate = nil
	zero32(&client.es)
	zero32(&client.c2sKey)
	zero32(&client.s2cKey)
	client.haveChallenge = false
	client.pendingChallenge = [8]byte{}
	client.state = state
}

// Negotiated returns a detached copy of authenticated server parameters.
func (client *Client) Negotiated() (Negotiated, bool) {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.state < StatePendingConfirm || client.state == StateRejected || client.state == StateClosed {
		return Negotiated{}, false
	}
	result := client.negotiated
	result.IPv4Lease = append([]byte(nil), result.IPv4Lease...)
	result.IPv6Lease = append([]byte(nil), result.IPv6Lease...)
	result.DNSParameters = append([]byte(nil), result.DNSParameters...)
	return result, true
}

// Start creates a canonical INITIAL datagram using a fresh X25519 key and a
// fresh non-zero client CID.
func (client *Client) Start() ([]byte, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.state != StateIdle {
		return nil, fmt.Errorf("%w: Start from %s", ErrState, client.state)
	}

	clientCID, err := nextNonZeroCID(client.options.random)
	if err != nil {
		return nil, err
	}
	ephemeralPrivate, err := wgcrypto.GenerateKeyFrom(client.options.random)
	if err != nil {
		return nil, fmt.Errorf("%w: generate client ephemeral key: %v", ErrConfiguration, err)
	}
	ephemeralPublic, err := wgcrypto.PublicBytes(ephemeralPrivate.PublicKey())
	if err != nil {
		return nil, fmt.Errorf("%w: encode client ephemeral key: %v", ErrConfiguration, err)
	}
	es, err := wgcrypto.DH(ephemeralPrivate, client.serverStaticPublic)
	if err != nil {
		return nil, fmt.Errorf("%w: client ephemeral/server static DH", ErrAuthentication)
	}
	prk1, k1, err := wgcrypto.DeriveM1(client.context, es)
	if err != nil {
		zero32(&prk1)
		zero32(&k1)
		zero32(&es)
		return nil, fmt.Errorf("%w: derive INITIAL keys", ErrAuthentication)
	}

	fields := []codec.TLV{
		{Type: codec.TLVVersion, Value: []byte{codec.Version1}},
		{Type: codec.TLVDeploymentID, Value: client.deploymentID[:]},
		{Type: codec.TLVClientCID, Value: encodeUint64(clientCID)},
		{Type: codec.TLVCapabilities, Value: encodeUint64(client.options.capabilities)},
		{Type: codec.TLVAddressFamilies, Value: []byte{client.options.addressFamilies}},
		{Type: codec.TLVMaxDatagramSize, Value: encodeUint16(client.options.maxDatagramSize)},
		{Type: codec.TLVClientStaticKey, Value: client.staticPublic[:]},
	}
	plaintext, err := codec.MarshalTLVsFor(fields, codec.TLVContextInitial)
	if err != nil {
		zero32(&prk1)
		zero32(&k1)
		zero32(&es)
		return nil, fmt.Errorf("%w: encode INITIAL fields: %v", ErrMessage, err)
	}
	ciphertextLength := len(plaintext) + codec.AEADTagSize
	prefix, err := makeInitialPrefix(client.options.retryToken, ephemeralPublic, ciphertextLength)
	if err != nil {
		zero32(&prk1)
		zero32(&k1)
		zero32(&es)
		return nil, err
	}
	header, encodedHeader, err := makeHeader(codec.PacketInitial, 0, clientCID, 0, len(prefix)+ciphertextLength)
	if err != nil {
		zero32(&prk1)
		zero32(&k1)
		zero32(&es)
		return nil, err
	}
	m1AD := join(client.context, encodedHeader, prefix)
	ciphertext, err := wgcrypto.SealHandshake(k1, m1AD, plaintext)
	zero32(&prk1)
	zero32(&k1)
	if err != nil {
		zero32(&es)
		return nil, fmt.Errorf("%w: encrypt INITIAL", ErrAuthentication)
	}
	if len(ciphertext) != ciphertextLength {
		zero32(&es)
		return nil, fmt.Errorf("%w: unexpected INITIAL ciphertext length", ErrMessage)
	}
	datagram, err := marshalWirePacket(header, prefix, ciphertext, int(client.options.maxDatagramSize))
	if err != nil {
		zero32(&es)
		return nil, err
	}

	client.clientCID = clientCID
	client.ephemeralPrivate = ephemeralPrivate
	client.es = es
	client.th1 = wgcrypto.Sum256(m1AD, ciphertext)
	client.state = StateInitialSent
	return datagram, nil
}

// Finish authenticates and processes a HANDSHAKE datagram, then derives both
// direction-specific traffic keys. It does not establish the session yet.
func (client *Client) Finish(datagram []byte) (err error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.state != StateInitialSent || client.ephemeralPrivate == nil {
		return fmt.Errorf("%w: Finish from %s", ErrState, client.state)
	}
	completed := false
	defer func() {
		if !completed {
			client.closeLocked(StateRejected)
		}
	}()

	packet, message, m2AD, th2, err := parseHandshakeWire(datagram, int(client.options.maxDatagramSize), client.context, client.th1)
	if err != nil {
		return err
	}
	if packet.Header.DCID != client.clientCID || packet.Header.SCID == 0 {
		return fmt.Errorf("%w: HANDSHAKE outer CID", ErrConnectionID)
	}

	ss, err := wgcrypto.DH(client.staticPrivate, client.serverStaticPublic)
	if err != nil {
		return fmt.Errorf("%w: static/static DH", ErrAuthentication)
	}
	ee, err := wgcrypto.DH(client.ephemeralPrivate, message.ServerEphemeralPublic)
	if err != nil {
		zero32(&ss)
		return fmt.Errorf("%w: ephemeral/ephemeral DH", ErrAuthentication)
	}
	se, err := wgcrypto.DH(client.staticPrivate, message.ServerEphemeralPublic)
	if err != nil {
		zero32(&ss)
		zero32(&ee)
		return fmt.Errorf("%w: static/ephemeral DH", ErrAuthentication)
	}
	prk2, k2, err := wgcrypto.DeriveM2(client.th1, client.es, ss, ee, se)
	zero32(&ss)
	zero32(&ee)
	zero32(&se)
	if err != nil {
		zero32(&prk2)
		zero32(&k2)
		return fmt.Errorf("%w: derive HANDSHAKE keys", ErrAuthentication)
	}
	plaintext, err := wgcrypto.OpenHandshake(k2, m2AD, message.EncryptedPayload)
	zero32(&k2)
	if err != nil {
		zero32(&prk2)
		return fmt.Errorf("%w: decrypt HANDSHAKE", ErrAuthentication)
	}
	fields, err := codec.ParseTLVsFor(plaintext, codec.TLVContextHandshake)
	if err != nil {
		zero32(&prk2)
		return fmt.Errorf("%w: HANDSHAKE fields: %v", ErrMessage, err)
	}
	negotiated, serverCID, err := client.validateHandshakeFields(fields, packet.Header.SCID)
	if err != nil {
		zero32(&prk2)
		return err
	}
	c2s, s2c, err := wgcrypto.DeriveTraffic(prk2, th2)
	zero32(&prk2)
	if err != nil {
		zero32(&c2s)
		zero32(&s2c)
		return fmt.Errorf("%w: derive traffic keys", ErrAuthentication)
	}

	client.serverCID = serverCID
	client.th2 = th2
	client.c2sKey = c2s
	client.s2cKey = s2c
	client.negotiated = negotiated
	client.transportMaxSize = int(negotiated.MaxDatagramSize)
	client.ephemeralPrivate = nil
	zero32(&client.es)
	client.state = StatePendingConfirm
	completed = true
	return nil
}

func (client *Client) validateHandshakeFields(fields []codec.TLV, outerServerCID uint64) (Negotiated, uint64, error) {
	version, _ := codec.FindTLV(fields, codec.TLVVersion)
	deployment, _ := codec.FindTLV(fields, codec.TLVDeploymentID)
	clientCIDValue, _ := codec.FindTLV(fields, codec.TLVClientCID)
	serverCIDValue, _ := codec.FindTLV(fields, codec.TLVServerCID)
	capabilities, _ := codec.FindTLV(fields, codec.TLVCapabilities)
	addressFamilies, _ := codec.FindTLV(fields, codec.TLVAddressFamilies)
	maxDatagram, _ := codec.FindTLV(fields, codec.TLVMaxDatagramSize)
	tunnelMTU, _ := codec.FindTLV(fields, codec.TLVTunnelMTU)
	leaseSeconds, _ := codec.FindTLV(fields, codec.TLVLeaseSeconds)

	if len(version) != 1 || version[0] != codec.Version1 {
		return Negotiated{}, 0, fmt.Errorf("%w: VERSION", ErrParameters)
	}
	if !secureEqual(deployment, client.deploymentID[:]) {
		return Negotiated{}, 0, fmt.Errorf("%w: DEPLOYMENT_ID", ErrParameters)
	}
	if binary.BigEndian.Uint64(clientCIDValue) != client.clientCID {
		return Negotiated{}, 0, fmt.Errorf("%w: CLIENT_CID", ErrConnectionID)
	}
	serverCID := binary.BigEndian.Uint64(serverCIDValue)
	if serverCID == 0 || serverCID != outerServerCID {
		return Negotiated{}, 0, fmt.Errorf("%w: SERVER_CID", ErrConnectionID)
	}
	returnedFamilies := addressFamilies[0]
	if returnedFamilies == 0 || returnedFamilies&^client.options.addressFamilies != 0 {
		return Negotiated{}, 0, fmt.Errorf("%w: ADDRESS_FAMILIES", ErrParameters)
	}
	returnedMaxDatagram := binary.BigEndian.Uint16(maxDatagram)
	if returnedMaxDatagram < codec.HeaderSize+codec.AEADTagSize+codec.FrameHeaderSize || returnedMaxDatagram > client.options.maxDatagramSize {
		return Negotiated{}, 0, fmt.Errorf("%w: MAX_DATAGRAM_SIZE", ErrParameters)
	}
	returnedMTU := binary.BigEndian.Uint16(tunnelMTU)
	if returnedMTU < client.options.minTunnelMTU || returnedMTU > client.options.maxTunnelMTU ||
		returnedMTU > returnedMaxDatagram-codec.HeaderSize-codec.AEADTagSize-codec.FrameHeaderSize {
		return Negotiated{}, 0, fmt.Errorf("%w: TUNNEL_MTU", ErrParameters)
	}
	returnedLeaseSeconds := binary.BigEndian.Uint32(leaseSeconds)
	if returnedLeaseSeconds == 0 {
		return Negotiated{}, 0, fmt.Errorf("%w: LEASE_SECONDS", ErrParameters)
	}
	ipv4Lease, hasIPv4 := codec.FindTLV(fields, codec.TLVIPv4Lease)
	ipv6Lease, hasIPv6 := codec.FindTLV(fields, codec.TLVIPv6Lease)
	if hasIPv4 != (returnedFamilies&0x01 != 0) || hasIPv6 != (returnedFamilies&0x02 != 0) {
		return Negotiated{}, 0, fmt.Errorf("%w: lease/address-family mismatch", ErrParameters)
	}
	if hasIPv4 {
		address := netip.AddrFrom4([4]byte(ipv4Lease[:4]))
		if !address.IsGlobalUnicast() || address.IsLoopback() {
			return Negotiated{}, 0, fmt.Errorf("%w: unacceptable IPv4 lease", ErrParameters)
		}
	}
	if hasIPv6 {
		address := netip.AddrFrom16([16]byte(ipv6Lease[:16]))
		if !address.IsGlobalUnicast() || address.IsLoopback() {
			return Negotiated{}, 0, fmt.Errorf("%w: unacceptable IPv6 lease", ErrParameters)
		}
	}
	egressPolicyValue, hasEgressPolicy := codec.FindTLV(fields, codec.TLVEgressPolicyVersion)
	var egressPolicy uint64
	if hasEgressPolicy {
		egressPolicy = binary.BigEndian.Uint64(egressPolicyValue)
	}
	dnsParameters, _ := codec.FindTLV(fields, codec.TLVDNSParameters)
	return Negotiated{
		Capabilities:    binary.BigEndian.Uint64(capabilities),
		AddressFamilies: returnedFamilies, MaxDatagramSize: returnedMaxDatagram,
		TunnelMTU: returnedMTU, LeaseSeconds: returnedLeaseSeconds,
		IPv4Lease: ipv4Lease, IPv6Lease: ipv6Lease,
		EgressPolicy: egressPolicy, DNSParameters: dnsParameters,
	}, serverCID, nil
}
