// Package privatedns maintains WG's private, in-memory copy of system resolver
// configuration and a generation-scoped private cache.
//
// The package intentionally exposes only a read-side SnapshotSource. It has no
// API capable of changing resolver files, interfaces, system caches, or OS DNS
// settings.
package privatedns

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Upstream is one resolver endpoint observed through a platform read-only API.
type Upstream struct {
	Address        string
	Port           uint16
	Transport      string
	InterfaceName  string
	InterfaceIndex int
	Scope          string
}

// Snapshot is a detached copy of system resolver configuration. Metadata is
// intended for non-secret platform facts such as adapter or provider names.
type Snapshot struct {
	CapturedAt        time.Time
	NetworkGeneration uint64
	Upstreams         []Upstream
	SearchDomains     []string
	RoutingDomains    []string
	Metadata          map[string]string
}

// SnapshotSource can only read the current system resolver state.
type SnapshotSource interface {
	ReadSnapshot(context.Context) (Snapshot, error)
}

// SnapshotSourceFunc adapts a function to SnapshotSource.
type SnapshotSourceFunc func(context.Context) (Snapshot, error)

// ReadSnapshot calls f.
func (f SnapshotSourceFunc) ReadSnapshot(ctx context.Context) (Snapshot, error) {
	return f(ctx)
}

// CacheKey identifies a private DNS cache entry. Class defaults to IN (1).
type CacheKey struct {
	Name  string
	Type  uint16
	Class uint16
}

// CacheRecord is a detached cache result.
type CacheRecord struct {
	Values     []string
	StoredAt   time.Time
	ExpiresAt  time.Time
	Generation uint64
}

// CacheStats contains lifetime counters and the current entry count.
type CacheStats struct {
	Entries uint64
	Stores  uint64
	Hits    uint64
	Misses  uint64
	Expired uint64
}

// Status summarizes the private snapshot and cache without exposing queries.
type Status struct {
	Generation         uint64
	NetworkGeneration  uint64
	RefreshedAt        time.Time
	UpstreamCount      int
	SearchDomainCount  int
	RoutingDomainCount int
	Degraded           bool
	LastError          string
	Cache              CacheStats
}

type cacheEntry struct {
	record CacheRecord
}

// Manager owns a concurrency-safe private copy and private cache.
type Manager struct {
	mu          sync.RWMutex
	snapshot    Snapshot
	generation  uint64
	refreshedAt time.Time
	degraded    bool
	lastError   string
	cache       map[CacheKey]cacheEntry
	stores      uint64
	hits        uint64
	misses      uint64
	expired     uint64
	now         func() time.Time
}

// NewManager deep-copies initial and starts at private generation 1.
func NewManager(initial Snapshot) *Manager {
	return newManager(initial, time.Now)
}

func newManager(initial Snapshot, now func() time.Time) *Manager {
	if now == nil {
		now = time.Now
	}
	currentTime := now().UTC()
	manager := &Manager{
		snapshot:    cloneSnapshot(initial),
		generation:  1,
		refreshedAt: currentTime,
		cache:       make(map[CacheKey]cacheEntry),
		now:         now,
	}
	if manager.snapshot.CapturedAt.IsZero() {
		manager.snapshot.CapturedAt = currentTime
	}
	manager.updateHealthLocked("")
	return manager
}

// Refresh atomically replaces the private copy, advances its generation, and
// drops private cache entries from the old generation. It does not write to the
// system resolver that produced next.
func (m *Manager) Refresh(next Snapshot) Status {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.snapshot = cloneSnapshot(next)
	m.generation++
	m.refreshedAt = m.now().UTC()
	if m.snapshot.CapturedAt.IsZero() {
		m.snapshot.CapturedAt = m.refreshedAt
	}
	m.cache = make(map[CacheKey]cacheEntry)
	m.updateHealthLocked("")
	return m.statusLocked()
}

// RefreshFrom reads a source outside the Manager lock, then atomically copies
// it. A source failure preserves the last usable snapshot and cache while
// exposing a DEGRADED status.
func (m *Manager) RefreshFrom(ctx context.Context, source SnapshotSource) (Status, error) {
	if source == nil {
		err := errors.New("privatedns: nil snapshot source")
		return m.recordRefreshError(err), err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	next, err := source.ReadSnapshot(ctx)
	if err != nil {
		return m.recordRefreshError(err), err
	}
	return m.Refresh(next), nil
}

func (m *Manager) recordRefreshError(err error) Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.degraded = true
	m.lastError = err.Error()
	return m.statusLocked()
}

// Snapshot returns a deep copy. Mutating it cannot change Manager state.
func (m *Manager) Snapshot() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return cloneSnapshot(m.snapshot)
}

// Status returns a detached status snapshot.
func (m *Manager) Status() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.statusLocked()
}

// Put stores a private cache record in the current snapshot generation.
func (m *Manager) Put(key CacheKey, values []string, ttl time.Duration) error {
	normalized, err := normalizeCacheKey(key)
	if err != nil {
		return err
	}
	if ttl <= 0 {
		return errors.New("privatedns: TTL must be positive")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now().UTC()
	m.cache[normalized] = cacheEntry{record: CacheRecord{
		Values:     append([]string(nil), values...),
		StoredAt:   now,
		ExpiresAt:  now.Add(ttl),
		Generation: m.generation,
	}}
	m.stores++
	return nil
}

// Lookup returns an unexpired detached private record.
func (m *Manager) Lookup(key CacheKey) (CacheRecord, bool) {
	normalized, err := normalizeCacheKey(key)
	if err != nil {
		m.mu.Lock()
		m.misses++
		m.mu.Unlock()
		return CacheRecord{}, false
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.cache[normalized]
	if !ok || entry.record.Generation != m.generation {
		m.misses++
		return CacheRecord{}, false
	}
	if !m.now().UTC().Before(entry.record.ExpiresAt) {
		delete(m.cache, normalized)
		m.expired++
		m.misses++
		return CacheRecord{}, false
	}
	m.hits++
	return cloneRecord(entry.record), true
}

// PurgeExpired deletes expired entries from the private cache.
func (m *Manager) PurgeExpired() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now().UTC()
	removed := 0
	for key, entry := range m.cache {
		if entry.record.Generation != m.generation || !now.Before(entry.record.ExpiresAt) {
			delete(m.cache, key)
			removed++
			m.expired++
		}
	}
	return removed
}

// ClearCache clears only WG's private cache, never the system DNS cache.
func (m *Manager) ClearCache() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cache = make(map[CacheKey]cacheEntry)
}

// CacheStats returns private-cache counters without query names or values.
func (m *Manager) CacheStats() CacheStats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cacheStatsLocked()
}

func (m *Manager) updateHealthLocked(lastError string) {
	m.lastError = lastError
	m.degraded = len(m.snapshot.Upstreams) == 0
	if m.degraded && m.lastError == "" {
		m.lastError = "no resolver upstreams available in the copied snapshot"
	}
}

func (m *Manager) statusLocked() Status {
	return Status{
		Generation:         m.generation,
		NetworkGeneration:  m.snapshot.NetworkGeneration,
		RefreshedAt:        m.refreshedAt,
		UpstreamCount:      len(m.snapshot.Upstreams),
		SearchDomainCount:  len(m.snapshot.SearchDomains),
		RoutingDomainCount: len(m.snapshot.RoutingDomains),
		Degraded:           m.degraded,
		LastError:          m.lastError,
		Cache:              m.cacheStatsLocked(),
	}
}

func (m *Manager) cacheStatsLocked() CacheStats {
	return CacheStats{
		Entries: uint64(len(m.cache)),
		Stores:  m.stores,
		Hits:    m.hits,
		Misses:  m.misses,
		Expired: m.expired,
	}
}

func normalizeCacheKey(key CacheKey) (CacheKey, error) {
	name := strings.ToLower(strings.TrimSpace(key.Name))
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return CacheKey{}, fmt.Errorf("privatedns: empty cache name")
	}
	if key.Class == 0 {
		key.Class = 1
	}
	key.Name = name
	return key, nil
}

func cloneSnapshot(snapshot Snapshot) Snapshot {
	copyOfSnapshot := snapshot
	copyOfSnapshot.Upstreams = append([]Upstream(nil), snapshot.Upstreams...)
	copyOfSnapshot.SearchDomains = append([]string(nil), snapshot.SearchDomains...)
	copyOfSnapshot.RoutingDomains = append([]string(nil), snapshot.RoutingDomains...)
	if snapshot.Metadata != nil {
		copyOfSnapshot.Metadata = make(map[string]string, len(snapshot.Metadata))
		for key, value := range snapshot.Metadata {
			copyOfSnapshot.Metadata[key] = value
		}
	}
	return copyOfSnapshot
}

func cloneRecord(record CacheRecord) CacheRecord {
	copyOfRecord := record
	copyOfRecord.Values = append([]string(nil), record.Values...)
	return copyOfRecord
}
