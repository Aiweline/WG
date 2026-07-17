package handshake

import (
	"crypto/ecdh"
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"

	"wg.local/wg/internal/codec"
)

// State is the externally observable handshake/session state.
type State uint8

const (
	StateIdle State = iota
	StateInitialSent
	StatePendingConfirm
	StatePendingPong
	StateEstablished
	StateRejected
	StateClosed
)

func (s State) String() string {
	switch s {
	case StateIdle:
		return "Idle"
	case StateInitialSent:
		return "InitialSent"
	case StatePendingConfirm:
		return "PendingConfirm"
	case StatePendingPong:
		return "PendingPong"
	case StateEstablished:
		return "Established"
	case StateRejected:
		return "Rejected"
	case StateClosed:
		return "Closed"
	default:
		return "Unknown"
	}
}

// ClientConfig contains only the material needed for a normal, pre-enrolled
// client handshake. Random defaults to crypto/rand.Reader.
type ClientConfig struct {
	DeploymentID       [16]byte
	StaticPrivate      *ecdh.PrivateKey
	ServerStaticPublic [32]byte
	Random             io.Reader
	// RetryToken is an opaque address-validation token carried in the clear
	// INITIAL prefix and bound into m1_ad. It is not an enrollment credential.
	RetryToken      []byte
	Capabilities    uint64
	AddressFamilies uint8
	MaxDatagramSize uint16
	MinTunnelMTU    uint16
	MaxTunnelMTU    uint16
}

// ServerConfig describes one in-memory server and its pre-registered clients.
// Enrollment credentials are intentionally absent from this M1 API.
type ServerConfig struct {
	DeploymentID  [16]byte
	StaticPrivate *ecdh.PrivateKey
	// RegisteredClients contains only enabled, pre-registered public keys.
	// Disabled keys must not appear in this slice.
	RegisteredClients [][32]byte
	Random            io.Reader
	Capabilities      uint64
	AddressFamilies   uint8
	MaxDatagramSize   uint16
	TunnelMTU         uint16
	LeaseSeconds      uint32
	IPv4Lease         []byte
	IPv6Lease         []byte
	EgressPolicy      uint64
	DNSParameters     []byte
	// Now is injectable for deterministic expiry tests. Production defaults to
	// time.Now. Cleanup never depends on a background goroutine.
	Now                    func() time.Time
	PendingAttemptTimeout  time.Duration
	ConfirmGracePeriod     time.Duration
	AttemptReplayRetention time.Duration
	MaxPendingAttempts     int
	MaxAttemptRecords      int
}

// Negotiated contains the authenticated HANDSHAKE parameters accepted by the
// client. Slices are detached from packet storage.
type Negotiated struct {
	Capabilities    uint64
	AddressFamilies uint8
	MaxDatagramSize uint16
	TunnelMTU       uint16
	LeaseSeconds    uint32
	IPv4Lease       []byte
	IPv6Lease       []byte
	EgressPolicy    uint64
	DNSParameters   []byte
}

type clientOptions struct {
	random          io.Reader
	addressFamilies uint8
	maxDatagramSize uint16
	minTunnelMTU    uint16
	maxTunnelMTU    uint16
	capabilities    uint64
	retryToken      []byte
}

type serverOptions struct {
	random                 io.Reader
	addressFamilies        uint8
	maxDatagramSize        uint16
	tunnelMTU              uint16
	leaseSeconds           uint32
	capabilities           uint64
	ipv4Lease              []byte
	ipv6Lease              []byte
	egressPolicy           uint64
	dnsParameters          []byte
	now                    func() time.Time
	pendingAttemptTimeout  time.Duration
	confirmGracePeriod     time.Duration
	attemptReplayRetention time.Duration
	maxPendingAttempts     int
	maxAttemptRecords      int
}

func normalizeClientConfig(config ClientConfig) (clientOptions, error) {
	if config.StaticPrivate == nil {
		return clientOptions{}, fmt.Errorf("%w: missing client static private key", ErrConfiguration)
	}
	if config.DeploymentID == ([16]byte{}) {
		return clientOptions{}, fmt.Errorf("%w: deployment ID must be non-zero", ErrConfiguration)
	}
	random := config.Random
	if random == nil {
		random = cryptorand.Reader
	}
	addressFamilies := config.AddressFamilies
	if addressFamilies == 0 {
		addressFamilies = 0x03
	}
	if addressFamilies&^uint8(0x03) != 0 {
		return clientOptions{}, fmt.Errorf("%w: unsupported address-family bits", ErrConfiguration)
	}
	maxDatagramSize := config.MaxDatagramSize
	if maxDatagramSize == 0 {
		maxDatagramSize = codec.DefaultMaxDatagramSize
	}
	if maxDatagramSize < codec.HeaderSize+codec.AEADTagSize+codec.FrameHeaderSize+576 {
		return clientOptions{}, fmt.Errorf("%w: max datagram size is too small", ErrConfiguration)
	}
	minTunnelMTU := config.MinTunnelMTU
	if minTunnelMTU == 0 {
		minTunnelMTU = 576
	}
	maxTunnelMTU := config.MaxTunnelMTU
	if maxTunnelMTU == 0 {
		maxTunnelMTU = maxDatagramSize - codec.HeaderSize - codec.AEADTagSize - codec.FrameHeaderSize
	}
	if minTunnelMTU > maxTunnelMTU {
		return clientOptions{}, fmt.Errorf("%w: invalid tunnel MTU interval", ErrConfiguration)
	}
	return clientOptions{
		random: random, addressFamilies: addressFamilies,
		maxDatagramSize: maxDatagramSize, minTunnelMTU: minTunnelMTU,
		maxTunnelMTU: maxTunnelMTU, capabilities: config.Capabilities,
		retryToken: append([]byte(nil), config.RetryToken...),
	}, nil
}

func normalizeServerConfig(config ServerConfig) (serverOptions, error) {
	if config.StaticPrivate == nil {
		return serverOptions{}, fmt.Errorf("%w: missing server static private key", ErrConfiguration)
	}
	if config.DeploymentID == ([16]byte{}) {
		return serverOptions{}, fmt.Errorf("%w: deployment ID must be non-zero", ErrConfiguration)
	}
	if len(config.RegisteredClients) == 0 {
		return serverOptions{}, fmt.Errorf("%w: no registered clients", ErrConfiguration)
	}
	random := config.Random
	if random == nil {
		random = cryptorand.Reader
	}
	addressFamilies := config.AddressFamilies
	if addressFamilies == 0 {
		addressFamilies = 0x01
	}
	if addressFamilies&^uint8(0x03) != 0 {
		return serverOptions{}, fmt.Errorf("%w: unsupported address-family bits", ErrConfiguration)
	}
	maxDatagramSize := config.MaxDatagramSize
	if maxDatagramSize == 0 {
		maxDatagramSize = codec.DefaultMaxDatagramSize
	}
	if maxDatagramSize < codec.HeaderSize+codec.AEADTagSize+codec.FrameHeaderSize+576 {
		return serverOptions{}, fmt.Errorf("%w: max datagram size is too small", ErrConfiguration)
	}
	tunnelMTU := config.TunnelMTU
	if tunnelMTU == 0 {
		tunnelMTU = maxDatagramSize - codec.HeaderSize - codec.AEADTagSize - codec.FrameHeaderSize
	}
	if tunnelMTU < 576 || tunnelMTU > maxDatagramSize-codec.HeaderSize-codec.AEADTagSize-codec.FrameHeaderSize {
		return serverOptions{}, fmt.Errorf("%w: invalid tunnel MTU", ErrConfiguration)
	}
	leaseSeconds := config.LeaseSeconds
	if leaseSeconds == 0 {
		leaseSeconds = 600
	}
	ipv4Lease := append([]byte(nil), config.IPv4Lease...)
	ipv6Lease := append([]byte(nil), config.IPv6Lease...)
	if len(ipv4Lease) == 0 && len(ipv6Lease) == 0 {
		return serverOptions{}, fmt.Errorf("%w: at least one lease is required", ErrConfiguration)
	}
	if len(ipv4Lease) != 0 && (len(ipv4Lease) != 5 || ipv4Lease[4] > 32) {
		return serverOptions{}, fmt.Errorf("%w: invalid IPv4 lease", ErrConfiguration)
	}
	if len(ipv6Lease) != 0 && (len(ipv6Lease) != 17 || ipv6Lease[16] > 128) {
		return serverOptions{}, fmt.Errorf("%w: invalid IPv6 lease", ErrConfiguration)
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	pendingAttemptTimeout := config.PendingAttemptTimeout
	if pendingAttemptTimeout == 0 {
		pendingAttemptTimeout = 5 * time.Second
	}
	confirmGracePeriod := config.ConfirmGracePeriod
	if confirmGracePeriod == 0 {
		confirmGracePeriod = 10 * time.Second
	}
	attemptReplayRetention := config.AttemptReplayRetention
	if attemptReplayRetention == 0 {
		attemptReplayRetention = 30 * time.Second
	}
	if pendingAttemptTimeout < 0 || confirmGracePeriod < 0 || attemptReplayRetention < 0 {
		return serverOptions{}, fmt.Errorf("%w: attempt timeouts must be positive", ErrConfiguration)
	}
	maxPendingAttempts := config.MaxPendingAttempts
	if maxPendingAttempts == 0 {
		maxPendingAttempts = 1024
	}
	if maxPendingAttempts < 0 {
		return serverOptions{}, fmt.Errorf("%w: pending-attempt limit must be positive", ErrConfiguration)
	}
	maxAttemptRecords := config.MaxAttemptRecords
	if maxAttemptRecords == 0 {
		if maxPendingAttempts > int(^uint(0)>>1)/4 {
			return serverOptions{}, fmt.Errorf("%w: pending-attempt limit is too large", ErrConfiguration)
		}
		maxAttemptRecords = maxPendingAttempts * 4
	}
	if maxAttemptRecords < maxPendingAttempts {
		return serverOptions{}, fmt.Errorf("%w: attempt-record limit is below pending-attempt limit", ErrConfiguration)
	}
	return serverOptions{
		random: random, addressFamilies: addressFamilies,
		maxDatagramSize: maxDatagramSize, tunnelMTU: tunnelMTU,
		leaseSeconds: leaseSeconds, capabilities: config.Capabilities,
		ipv4Lease: ipv4Lease, ipv6Lease: ipv6Lease,
		egressPolicy:  config.EgressPolicy,
		dnsParameters: append([]byte(nil), config.DNSParameters...),
		now:           now, pendingAttemptTimeout: pendingAttemptTimeout,
		confirmGracePeriod:     confirmGracePeriod,
		attemptReplayRetention: attemptReplayRetention,
		maxPendingAttempts:     maxPendingAttempts, maxAttemptRecords: maxAttemptRecords,
	}, nil
}

func encodeUint16(value uint16) []byte {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, value)
	return data
}

func encodeUint32(value uint32) []byte {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, value)
	return data
}

func encodeUint64(value uint64) []byte {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, value)
	return data
}

func stateValue(mu *sync.Mutex, state *State) State {
	mu.Lock()
	defer mu.Unlock()
	return *state
}
