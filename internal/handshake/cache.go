package handshake

import (
	"fmt"
	"sync"
	"time"
)

type attemptPhase uint8

const (
	attemptBuilding attemptPhase = iota
	attemptReady
	attemptTombstone
	attemptFailed
)

type attemptEntry struct {
	key      [32]byte
	initial  []byte
	phase    attemptPhase
	done     chan struct{}
	doneOnce sync.Once

	response  []byte
	session   *ServerSession
	expiresAt time.Time
	forgetAt  time.Time
	confirmed bool
	err       error
}

type attemptLease struct {
	entry    *attemptEntry
	builder  bool
	session  *ServerSession
	response []byte
}

func (server *Server) acquireAttempt(key [32]byte, initial []byte) (attemptLease, error) {
	server.attemptMu.Lock()
	now := server.options.now()
	expiredSessions, _ := server.cleanupAttemptsLocked(now)
	if existing, ok := server.attempts[key]; ok {
		if !secureEqual(existing.initial, initial) {
			server.attemptMu.Unlock()
			closeExpiredSessions(expiredSessions)
			return attemptLease{}, fmt.Errorf("%w: transcript key collision", ErrTranscript)
		}
		switch existing.phase {
		case attemptBuilding:
			done := existing.done
			server.attemptMu.Unlock()
			closeExpiredSessions(expiredSessions)
			<-done
			return server.resultOfAttempt(existing)
		case attemptReady:
			lease := attemptLease{
				entry: existing, session: existing.session,
				response: append([]byte(nil), existing.response...),
			}
			server.attemptMu.Unlock()
			closeExpiredSessions(expiredSessions)
			return lease, nil
		case attemptTombstone:
			err := existing.err
			if err == nil {
				err = ErrAttemptExpired
			}
			server.attemptMu.Unlock()
			closeExpiredSessions(expiredSessions)
			return attemptLease{}, err
		case attemptFailed:
			err := existing.err
			server.attemptMu.Unlock()
			closeExpiredSessions(expiredSessions)
			return attemptLease{}, err
		}
	}
	if server.activeAttempts >= server.options.maxPendingAttempts || len(server.attempts) >= server.options.maxAttemptRecords {
		server.attemptMu.Unlock()
		closeExpiredSessions(expiredSessions)
		return attemptLease{}, ErrAttemptCapacity
	}
	entry := &attemptEntry{
		key: key, initial: append([]byte(nil), initial...), phase: attemptBuilding,
		done: make(chan struct{}), expiresAt: now.Add(server.options.pendingAttemptTimeout),
	}
	server.attempts[key] = entry
	server.activeAttempts++
	server.attemptMu.Unlock()
	closeExpiredSessions(expiredSessions)
	return attemptLease{entry: entry, builder: true}, nil
}

func (server *Server) resultOfAttempt(entry *attemptEntry) (attemptLease, error) {
	server.attemptMu.Lock()
	defer server.attemptMu.Unlock()
	switch entry.phase {
	case attemptReady:
		return attemptLease{
			entry: entry, session: entry.session,
			response: append([]byte(nil), entry.response...),
		}, nil
	case attemptTombstone, attemptFailed:
		if entry.err != nil {
			return attemptLease{}, entry.err
		}
		return attemptLease{}, ErrAttemptExpired
	default:
		return attemptLease{}, fmt.Errorf("%w: attempt did not complete", ErrState)
	}
}

func (server *Server) publishAttempt(entry *attemptEntry, session *ServerSession, response []byte) error {
	server.attemptMu.Lock()
	defer server.attemptMu.Unlock()
	current, ok := server.attempts[entry.key]
	if !ok || current != entry || entry.phase != attemptBuilding {
		if entry.err != nil {
			return entry.err
		}
		return ErrAttemptExpired
	}
	entry.phase = attemptReady
	entry.session = session
	entry.response = append([]byte(nil), response...)
	entry.expiresAt = server.options.now().Add(server.options.pendingAttemptTimeout)
	session.attemptKey = entry.key
	session.hasAttempt = true
	entry.doneOnce.Do(func() { close(entry.done) })
	return nil
}

func (server *Server) failAttempt(entry *attemptEntry, failure error) {
	server.attemptMu.Lock()
	defer server.attemptMu.Unlock()
	current, ok := server.attempts[entry.key]
	if ok && current == entry && entry.phase == attemptBuilding {
		delete(server.attempts, entry.key)
		server.activeAttempts--
		entry.phase = attemptFailed
		entry.err = failure
		entry.doneOnce.Do(func() { close(entry.done) })
	}
}

func (server *Server) promoteAttempt(key [32]byte, session *ServerSession) bool {
	server.attemptMu.Lock()
	defer server.attemptMu.Unlock()
	now := server.options.now()
	entry, ok := server.attempts[key]
	if !ok || entry.phase != attemptReady || entry.session != session || !now.Before(entry.expiresAt) {
		if ok && entry.phase == attemptReady && entry.session == session {
			server.tombstoneAttemptLocked(entry, ErrAttemptExpired, now)
		}
		return false
	}
	entry.confirmed = true
	entry.expiresAt = now.Add(server.options.confirmGracePeriod)
	return true
}

func (server *Server) confirmGraceActive(key [32]byte, session *ServerSession) bool {
	server.attemptMu.Lock()
	defer server.attemptMu.Unlock()
	entry, ok := server.attempts[key]
	if !ok || entry.phase != attemptReady || entry.session != session || !entry.confirmed {
		return false
	}
	now := server.options.now()
	if !now.Before(entry.expiresAt) {
		server.tombstoneAttemptLocked(entry, ErrAttemptExpired, now)
		return false
	}
	return true
}

func (server *Server) removeAttempt(key [32]byte, session *ServerSession, reason error) {
	server.attemptMu.Lock()
	defer server.attemptMu.Unlock()
	entry, ok := server.attempts[key]
	if !ok || entry.phase != attemptReady || entry.session != session {
		return
	}
	server.tombstoneAttemptLocked(entry, reason, server.options.now())
}

func (server *Server) tombstoneAttemptLocked(entry *attemptEntry, reason error, now time.Time) {
	if entry.phase == attemptBuilding || entry.phase == attemptReady {
		server.activeAttempts--
	}
	entry.phase = attemptTombstone
	entry.response = nil
	entry.session = nil
	entry.err = reason
	entry.confirmed = false
	entry.expiresAt = time.Time{}
	entry.forgetAt = now.Add(server.options.attemptReplayRetention)
	entry.doneOnce.Do(func() { close(entry.done) })
}

// CleanupExpired deterministically expires pending attempts, releases their
// sessions/CIDs, drops expired response caches after the confirmation grace,
// and eventually forgets bounded replay tombstones.
func (server *Server) CleanupExpired() int {
	server.attemptMu.Lock()
	expiredSessions, changed := server.cleanupAttemptsLocked(server.options.now())
	server.attemptMu.Unlock()
	closeExpiredSessions(expiredSessions)
	return changed
}

func (server *Server) cleanupAttemptsLocked(now time.Time) ([]*ServerSession, int) {
	var expiredSessions []*ServerSession
	changed := 0
	for key, entry := range server.attempts {
		switch entry.phase {
		case attemptBuilding, attemptReady:
			if now.Before(entry.expiresAt) {
				continue
			}
			if entry.phase == attemptReady && !entry.confirmed && entry.session != nil {
				expiredSessions = append(expiredSessions, entry.session)
			}
			server.tombstoneAttemptLocked(entry, ErrAttemptExpired, now)
			changed++
		case attemptTombstone:
			if !now.Before(entry.forgetAt) {
				delete(server.attempts, key)
				changed++
			}
		case attemptFailed:
			delete(server.attempts, key)
			changed++
		}
	}
	return expiredSessions, changed
}

func closeExpiredSessions(sessions []*ServerSession) {
	for _, session := range sessions {
		session.Close()
	}
}
