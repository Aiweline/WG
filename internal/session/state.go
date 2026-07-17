// Package session implements the pure-memory control-plane state that sits
// between the WG handshake and transport layers. It performs no network,
// cryptographic, disk, or operating-system work.
package session

import (
	"errors"
	"fmt"
	"time"
)

// Role identifies which side of a session owns a Machine.
type Role uint8

const (
	RoleClient Role = iota + 1
	RoleServer
)

func (r Role) String() string {
	switch r {
	case RoleClient:
		return "client"
	case RoleServer:
		return "server"
	default:
		return fmt.Sprintf("role(%d)", uint8(r))
	}
}

func (r Role) valid() bool { return r == RoleClient || r == RoleServer }

// State is a discrete session-control state. A role-specific transition table
// determines which events are legal from each state.
type State uint8

const (
	StateIdle State = iota
	StateInitialSent
	StatePendingConfirm
	StateEstablished
	StateRekeying
	StateDraining
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
	case StateEstablished:
		return "Established"
	case StateRekeying:
		return "Rekeying"
	case StateDraining:
		return "Draining"
	case StateClosed:
		return "Closed"
	default:
		return fmt.Sprintf("State(%d)", uint8(s))
	}
}

// Event names state-machine operations. Events that carry data, such as PING,
// PONG, and server CONFIRM/PING, are exposed through typed Machine methods.
type Event uint8

const (
	EventBeginHandshake Event = iota + 1
	EventRetryReceived
	EventRetransmitInitial
	EventHandshakeComplete
	EventIssuePing
	EventRetransmitPing
	EventPong
	EventConfirmPing
	EventActivity
	EventBeginRekey
	EventBeginDrain
	EventTimeout
	EventClose
)

func (e Event) String() string {
	switch e {
	case EventBeginHandshake:
		return "BeginHandshake"
	case EventRetryReceived:
		return "RetryReceived"
	case EventRetransmitInitial:
		return "RetransmitInitial"
	case EventHandshakeComplete:
		return "HandshakeComplete"
	case EventIssuePing:
		return "IssuePing"
	case EventRetransmitPing:
		return "RetransmitPing"
	case EventPong:
		return "Pong"
	case EventConfirmPing:
		return "ConfirmPing"
	case EventActivity:
		return "Activity"
	case EventBeginRekey:
		return "BeginRekey"
	case EventBeginDrain:
		return "BeginDrain"
	case EventTimeout:
		return "Timeout"
	case EventClose:
		return "Close"
	default:
		return fmt.Sprintf("Event(%d)", uint8(e))
	}
}

var (
	ErrIllegalTransition   = errors.New("illegal session transition")
	ErrInvalidPolicy       = errors.New("invalid timeout policy")
	ErrTimeRegression      = errors.New("session event time regressed")
	ErrStateTimedOut       = errors.New("session state deadline reached")
	ErrRetriesExhausted    = errors.New("retransmission limit exhausted")
	ErrPingOutstanding     = errors.New("a ping is already outstanding")
	ErrNoOutstandingPing   = errors.New("no ping is outstanding")
	ErrPongMismatch        = errors.New("pong does not match outstanding ping")
	ErrConfirmMismatch     = errors.New("confirm operation does not match")
	ErrConfirmGraceExpired = errors.New("confirm retransmission grace expired")
)

// TransitionError describes an event that is invalid for a role and state.
// The machine is unchanged when this error is returned.
type TransitionError struct {
	Role  Role
	From  State
	Event Event
}

func (e *TransitionError) Error() string {
	return fmt.Sprintf("%v: role=%s from=%s event=%s", ErrIllegalTransition, e.Role, e.From, e.Event)
}

func (e *TransitionError) Unwrap() error { return ErrIllegalTransition }

// PongMismatchError preserves the expected and received operation IDs.
type PongMismatchError struct {
	Expected uint64
	Received uint64
}

func (e *PongMismatchError) Error() string {
	return fmt.Sprintf("%v: expected=%d received=%d", ErrPongMismatch, e.Expected, e.Received)
}

func (e *PongMismatchError) Unwrap() error { return ErrPongMismatch }

// ConfirmMismatchError preserves the active and received server operation IDs.
type ConfirmMismatchError struct {
	Expected uint64
	Received uint64
}

func (e *ConfirmMismatchError) Error() string {
	return fmt.Sprintf("%v: expected=%d received=%d", ErrConfirmMismatch, e.Expected, e.Received)
}

func (e *ConfirmMismatchError) Unwrap() error { return ErrConfirmMismatch }

// TimeoutPolicy contains the design defaults and retransmission bounds. Time
// is supplied by the caller, so tests and callers never need to sleep.
type TimeoutPolicy struct {
	InitialSent       time.Duration
	PendingConfirm    time.Duration
	EstablishedIdle   time.Duration
	PathValidation    time.Duration
	Draining          time.Duration
	RetryToken        time.Duration
	ConfirmGrace      time.Duration
	InitialRetryBase  time.Duration
	ControlRetryBase  time.Duration
	MaxRetryBackoff   time.Duration
	MaxInitialRetries uint8
	MaxControlRetries uint8
}

// DefaultTimeoutPolicy returns the section 9 defaults. Retry bases are local
// scheduling defaults; the state deadlines remain the hard upper bounds.
func DefaultTimeoutPolicy() TimeoutPolicy {
	return TimeoutPolicy{
		InitialSent:       10 * time.Second,
		PendingConfirm:    5 * time.Second,
		EstablishedIdle:   5 * time.Minute,
		PathValidation:    3 * time.Second,
		Draining:          30 * time.Second,
		RetryToken:        30 * time.Second,
		ConfirmGrace:      10 * time.Second,
		InitialRetryBase:  500 * time.Millisecond,
		ControlRetryBase:  500 * time.Millisecond,
		MaxRetryBackoff:   4 * time.Second,
		MaxInitialRetries: 3,
		MaxControlRetries: 3,
	}
}

// Validate rejects zero, negative, or internally inconsistent policies.
func (p TimeoutPolicy) Validate() error {
	durations := []struct {
		name  string
		value time.Duration
	}{
		{"InitialSent", p.InitialSent},
		{"PendingConfirm", p.PendingConfirm},
		{"EstablishedIdle", p.EstablishedIdle},
		{"PathValidation", p.PathValidation},
		{"Draining", p.Draining},
		{"RetryToken", p.RetryToken},
		{"ConfirmGrace", p.ConfirmGrace},
		{"InitialRetryBase", p.InitialRetryBase},
		{"ControlRetryBase", p.ControlRetryBase},
		{"MaxRetryBackoff", p.MaxRetryBackoff},
	}
	for _, item := range durations {
		if item.value <= 0 {
			return fmt.Errorf("%w: %s must be positive", ErrInvalidPolicy, item.name)
		}
	}
	if p.MaxInitialRetries == 0 || p.MaxControlRetries == 0 {
		return fmt.Errorf("%w: retry limits must be positive", ErrInvalidPolicy)
	}
	if p.InitialRetryBase > p.MaxRetryBackoff || p.ControlRetryBase > p.MaxRetryBackoff {
		return fmt.Errorf("%w: retry base exceeds maximum backoff", ErrInvalidPolicy)
	}
	return nil
}

func (p TimeoutPolicy) initialBackoff(retry uint8) time.Duration {
	return boundedBackoff(p.InitialRetryBase, retry, p.MaxRetryBackoff)
}

func (p TimeoutPolicy) controlBackoff(retry uint8) time.Duration {
	return boundedBackoff(p.ControlRetryBase, retry, p.MaxRetryBackoff)
}

func boundedBackoff(base time.Duration, retry uint8, maximum time.Duration) time.Duration {
	delay := base
	for step := uint8(0); step < retry; step++ {
		if delay >= maximum || delay > maximum/2 {
			return maximum
		}
		delay *= 2
	}
	if delay > maximum {
		return maximum
	}
	return delay
}

// nextState is the single role-specific legal-transition table.
func nextState(role Role, from State, event Event) (State, bool) {
	if event == EventClose {
		return StateClosed, true
	}

	if role == RoleClient {
		switch from {
		case StateIdle:
			if event == EventBeginHandshake {
				return StateInitialSent, true
			}
		case StateInitialSent:
			switch event {
			case EventRetryReceived, EventRetransmitInitial:
				return StateInitialSent, true
			case EventHandshakeComplete:
				return StatePendingConfirm, true
			case EventTimeout:
				return StateClosed, true
			}
		case StatePendingConfirm:
			switch event {
			case EventIssuePing, EventRetransmitPing:
				return StatePendingConfirm, true
			case EventPong:
				return StateEstablished, true
			case EventTimeout:
				return StateClosed, true
			}
		case StateEstablished:
			switch event {
			case EventActivity:
				return StateEstablished, true
			case EventBeginRekey:
				return StateRekeying, true
			case EventBeginDrain, EventTimeout:
				return StateDraining, true
			}
		case StateRekeying:
			switch event {
			case EventHandshakeComplete, EventIssuePing, EventRetransmitPing:
				return StateRekeying, true
			case EventPong:
				return StateEstablished, true
			case EventBeginDrain, EventTimeout:
				return StateDraining, true
			}
		case StateDraining:
			if event == EventTimeout {
				return StateClosed, true
			}
		case StateClosed:
			// Close is handled as an idempotent event above.
		}
		return 0, false
	}

	if role == RoleServer {
		switch from {
		case StateIdle:
			if event == EventHandshakeComplete {
				return StatePendingConfirm, true
			}
		case StatePendingConfirm:
			switch event {
			case EventConfirmPing:
				return StateEstablished, true
			case EventTimeout:
				return StateClosed, true
			}
		case StateEstablished:
			switch event {
			case EventActivity, EventConfirmPing:
				return StateEstablished, true
			case EventBeginRekey:
				return StateRekeying, true
			case EventBeginDrain, EventTimeout:
				return StateDraining, true
			}
		case StateRekeying:
			switch event {
			case EventHandshakeComplete:
				return StateRekeying, true
			case EventConfirmPing:
				return StateEstablished, true
			case EventBeginDrain, EventTimeout:
				return StateDraining, true
			}
		case StateDraining:
			if event == EventTimeout {
				return StateClosed, true
			}
		case StateInitialSent, StateClosed:
			// InitialSent is client-only. Close is handled above.
		}
	}
	return 0, false
}
