package session

import (
	"fmt"
	"sync"
	"time"
)

// Snapshot is an immutable view of Machine state.
type Snapshot struct {
	Role                Role
	State               State
	EnteredAt           time.Time
	LastEventAt         time.Time
	Deadline            time.Time
	InitialRetries      uint8
	ControlRetries      uint8
	HasOutstandingPing  bool
	OutstandingPingID   uint64
	RekeyHandshakeReady bool
	HasLastConfirmID    bool
	LastConfirmID       uint64
	ConfirmGraceUntil   time.Time
}

// Machine is a role-specific, in-memory session state machine. Every read and
// transition is protected by the same mutex so state and retry accounting are
// observed atomically.
type Machine struct {
	mu sync.RWMutex

	role   Role
	state  State
	policy TimeoutPolicy

	enteredAt   time.Time
	lastEventAt time.Time
	deadline    time.Time

	initialRetries uint8
	controlRetries uint8

	hasOutstandingPing bool
	outstandingPingID  uint64

	rekeyHandshakeReady bool

	hasLastConfirmID  bool
	lastConfirmID     uint64
	confirmGraceUntil time.Time
}

// NewMachine creates an Idle machine with caller-controlled time.
func NewMachine(role Role, policy TimeoutPolicy, now time.Time) (*Machine, error) {
	if !role.valid() {
		return nil, fmt.Errorf("invalid session role: %d", role)
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	return &Machine{
		role:        role,
		state:       StateIdle,
		policy:      policy,
		enteredAt:   now,
		lastEventAt: now,
	}, nil
}

// NewDefaultMachine uses DefaultTimeoutPolicy.
func NewDefaultMachine(role Role, now time.Time) (*Machine, error) {
	return NewMachine(role, DefaultTimeoutPolicy(), now)
}

// Snapshot returns a race-free state view.
func (m *Machine) Snapshot() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return Snapshot{
		Role:                m.role,
		State:               m.state,
		EnteredAt:           m.enteredAt,
		LastEventAt:         m.lastEventAt,
		Deadline:            m.deadline,
		InitialRetries:      m.initialRetries,
		ControlRetries:      m.controlRetries,
		HasOutstandingPing:  m.hasOutstandingPing,
		OutstandingPingID:   m.outstandingPingID,
		RekeyHandshakeReady: m.rekeyHandshakeReady,
		HasLastConfirmID:    m.hasLastConfirmID,
		LastConfirmID:       m.lastConfirmID,
		ConfirmGraceUntil:   m.confirmGraceUntil,
	}
}

func (m *Machine) requireTimeLocked(now time.Time) error {
	if now.Before(m.lastEventAt) {
		return fmt.Errorf("%w: last=%s received=%s", ErrTimeRegression, m.lastEventAt, now)
	}
	return nil
}

func (m *Machine) requireBeforeDeadlineLocked(now time.Time) error {
	if !m.deadline.IsZero() && !now.Before(m.deadline) {
		return fmt.Errorf("%w: state=%s deadline=%s", ErrStateTimedOut, m.state, m.deadline)
	}
	return nil
}

func (m *Machine) requireEventLocked(event Event) (State, error) {
	next, ok := nextState(m.role, m.state, event)
	if !ok {
		return 0, &TransitionError{Role: m.role, From: m.state, Event: event}
	}
	return next, nil
}

func (m *Machine) setStateLocked(next State, now time.Time) {
	m.state = next
	m.enteredAt = now
	m.lastEventAt = now

	switch next {
	case StateIdle:
		m.deadline = time.Time{}
	case StateInitialSent:
		m.deadline = now.Add(m.policy.InitialSent)
		m.initialRetries = 0
		m.clearPingLocked()
	case StatePendingConfirm:
		m.deadline = now.Add(m.policy.PendingConfirm)
		m.controlRetries = 0
		m.clearPingLocked()
	case StateEstablished:
		m.deadline = now.Add(m.policy.EstablishedIdle)
		m.rekeyHandshakeReady = false
	case StateRekeying:
		m.deadline = now.Add(m.policy.PendingConfirm)
		m.rekeyHandshakeReady = false
		m.controlRetries = 0
		m.clearPingLocked()
	case StateDraining:
		m.deadline = now.Add(m.policy.Draining)
		m.rekeyHandshakeReady = false
		m.clearPingLocked()
	case StateClosed:
		m.deadline = time.Time{}
		m.rekeyHandshakeReady = false
		m.clearPingLocked()
	}
}

func (m *Machine) clearPingLocked() {
	m.hasOutstandingPing = false
	m.outstandingPingID = 0
	m.controlRetries = 0
}

// BeginHandshake moves a client from Idle to InitialSent.
func (m *Machine) BeginHandshake(now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.requireTimeLocked(now); err != nil {
		return err
	}
	next, err := m.requireEventLocked(EventBeginHandshake)
	if err != nil {
		return err
	}
	m.setStateLocked(next, now)
	return nil
}

// HandleRetry records a valid RETRY association. The caller is responsible for
// generating a new temporary key and new INITIAL bytes. The hard InitialSent
// deadline is intentionally not extended.
func (m *Machine) HandleRetry(now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.requireTimeLocked(now); err != nil {
		return err
	}
	if err := m.requireBeforeDeadlineLocked(now); err != nil {
		return err
	}
	if _, err := m.requireEventLocked(EventRetryReceived); err != nil {
		return err
	}
	m.initialRetries = 0
	m.lastEventAt = now
	return nil
}

// RecordInitialRetransmission reserves one of the three default INITIAL retry
// slots and returns its bounded exponential-backoff delay. The session package
// does not rebuild or transmit bytes.
func (m *Machine) RecordInitialRetransmission(now time.Time) (time.Duration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.requireTimeLocked(now); err != nil {
		return 0, err
	}
	if err := m.requireBeforeDeadlineLocked(now); err != nil {
		return 0, err
	}
	if _, err := m.requireEventLocked(EventRetransmitInitial); err != nil {
		return 0, err
	}
	if m.initialRetries >= m.policy.MaxInitialRetries {
		return 0, fmt.Errorf("%w: INITIAL maximum=%d", ErrRetriesExhausted, m.policy.MaxInitialRetries)
	}
	delay := m.policy.initialBackoff(m.initialRetries)
	m.initialRetries++
	m.lastEventAt = now
	return delay, nil
}

// HandshakeComplete records authenticated handshake completion. For an initial
// handshake it enters PendingConfirm, never Established. During rekey it marks
// the new handshake ready while remaining in Rekeying.
func (m *Machine) HandshakeComplete(now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.requireTimeLocked(now); err != nil {
		return err
	}
	if err := m.requireBeforeDeadlineLocked(now); err != nil {
		return err
	}
	next, err := m.requireEventLocked(EventHandshakeComplete)
	if err != nil {
		return err
	}
	if m.state == StateRekeying {
		m.rekeyHandshakeReady = true
		m.clearPingLocked()
		m.deadline = now.Add(m.policy.PendingConfirm)
		m.lastEventAt = now
		return nil
	}
	m.setStateLocked(next, now)
	return nil
}

// IssuePing records the client's CONFIRM/PING operation. Establishment still
// requires AcceptPong with this exact operation ID.
func (m *Machine) IssuePing(operationID uint64, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.requireTimeLocked(now); err != nil {
		return err
	}
	if err := m.requireBeforeDeadlineLocked(now); err != nil {
		return err
	}
	if _, err := m.requireEventLocked(EventIssuePing); err != nil {
		return err
	}
	if m.state == StateRekeying && !m.rekeyHandshakeReady {
		return &TransitionError{Role: m.role, From: m.state, Event: EventIssuePing}
	}
	if m.hasOutstandingPing {
		return ErrPingOutstanding
	}
	m.hasOutstandingPing = true
	m.outstandingPingID = operationID
	m.controlRetries = 0
	m.lastEventAt = now
	return nil
}

// RecordPingRetransmission reserves a control retry. The caller must allocate a
// new transport packet number while retaining the same idempotent operation ID.
func (m *Machine) RecordPingRetransmission(operationID uint64, now time.Time) (time.Duration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.requireTimeLocked(now); err != nil {
		return 0, err
	}
	if err := m.requireBeforeDeadlineLocked(now); err != nil {
		return 0, err
	}
	if _, err := m.requireEventLocked(EventRetransmitPing); err != nil {
		return 0, err
	}
	if !m.hasOutstandingPing {
		return 0, ErrNoOutstandingPing
	}
	if operationID != m.outstandingPingID {
		return 0, &PongMismatchError{Expected: m.outstandingPingID, Received: operationID}
	}
	if m.controlRetries >= m.policy.MaxControlRetries {
		return 0, fmt.Errorf("%w: CONFIRM/PING maximum=%d", ErrRetriesExhausted, m.policy.MaxControlRetries)
	}
	delay := m.policy.controlBackoff(m.controlRetries)
	m.controlRetries++
	m.lastEventAt = now
	return delay, nil
}

// AcceptPong establishes a client session only when the PONG matches the
// currently outstanding PING. A mismatch does not mutate state or counters.
func (m *Machine) AcceptPong(operationID uint64, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.requireTimeLocked(now); err != nil {
		return err
	}
	if err := m.requireBeforeDeadlineLocked(now); err != nil {
		return err
	}
	next, err := m.requireEventLocked(EventPong)
	if err != nil {
		return err
	}
	if !m.hasOutstandingPing {
		return ErrNoOutstandingPing
	}
	if operationID != m.outstandingPingID {
		return &PongMismatchError{Expected: m.outstandingPingID, Received: operationID}
	}
	m.clearPingLocked()
	m.setStateLocked(next, now)
	return nil
}

// AcceptConfirmPing handles a server-side authenticated CONFIRM/PING. The first
// valid operation enters Established and returns duplicate=false. A matching
// retransmission in the confirmation grace period returns duplicate=true so the
// caller can resend PONG without reactivating state or leases.
func (m *Machine) AcceptConfirmPing(operationID uint64, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.requireTimeLocked(now); err != nil {
		return false, err
	}
	if err := m.requireBeforeDeadlineLocked(now); err != nil {
		return false, err
	}
	next, err := m.requireEventLocked(EventConfirmPing)
	if err != nil {
		return false, err
	}
	if m.state == StateRekeying && !m.rekeyHandshakeReady {
		return false, &TransitionError{Role: m.role, From: m.state, Event: EventConfirmPing}
	}
	if m.state == StateEstablished {
		if !m.hasLastConfirmID || operationID != m.lastConfirmID {
			return false, &ConfirmMismatchError{Expected: m.lastConfirmID, Received: operationID}
		}
		if now.After(m.confirmGraceUntil) {
			return false, ErrConfirmGraceExpired
		}
		m.lastEventAt = now
		m.deadline = now.Add(m.policy.EstablishedIdle)
		return true, nil
	}
	m.hasLastConfirmID = true
	m.lastConfirmID = operationID
	m.confirmGraceUntil = now.Add(m.policy.ConfirmGrace)
	m.setStateLocked(next, now)
	return false, nil
}

// BeginRekey starts a parallel replacement handshake while the current session
// remains represented by the Rekeying state.
func (m *Machine) BeginRekey(now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.requireTimeLocked(now); err != nil {
		return err
	}
	if err := m.requireBeforeDeadlineLocked(now); err != nil {
		return err
	}
	next, err := m.requireEventLocked(EventBeginRekey)
	if err != nil {
		return err
	}
	m.setStateLocked(next, now)
	return nil
}

// Touch records authenticated Established activity and refreshes the idle
// deadline. It is safe to call concurrently.
func (m *Machine) Touch(now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.requireTimeLocked(now); err != nil {
		return err
	}
	if err := m.requireBeforeDeadlineLocked(now); err != nil {
		return err
	}
	if _, err := m.requireEventLocked(EventActivity); err != nil {
		return err
	}
	m.lastEventAt = now
	m.deadline = now.Add(m.policy.EstablishedIdle)
	return nil
}

// BeginDrain starts the bounded draining period.
func (m *Machine) BeginDrain(now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.requireTimeLocked(now); err != nil {
		return err
	}
	next, err := m.requireEventLocked(EventBeginDrain)
	if err != nil {
		return err
	}
	m.setStateLocked(next, now)
	return nil
}

// CheckTimeout applies a due state deadline without sleeping. Established and
// Rekeying enter Draining; handshake states close; Draining closes.
func (m *Machine) CheckTimeout(now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.requireTimeLocked(now); err != nil {
		return false, err
	}
	if m.deadline.IsZero() || now.Before(m.deadline) {
		return false, nil
	}
	next, err := m.requireEventLocked(EventTimeout)
	if err != nil {
		return false, err
	}
	m.setStateLocked(next, now)
	return true, nil
}

// Close is an idempotent in-memory close.
func (m *Machine) Close(now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.requireTimeLocked(now); err != nil {
		return err
	}
	if m.state == StateClosed {
		return nil
	}
	next, err := m.requireEventLocked(EventClose)
	if err != nil {
		return err
	}
	m.setStateLocked(next, now)
	return nil
}
