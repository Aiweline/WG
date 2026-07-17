package privatedns

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestManagerDeepCopiesSnapshots(t *testing.T) {
	t.Parallel()

	initial := Snapshot{
		NetworkGeneration: 7,
		Upstreams: []Upstream{{
			Address:       "192.0.2.53",
			Port:          53,
			Transport:     "udp",
			InterfaceName: "eth0",
		}},
		SearchDomains:  []string{"corp.example"},
		RoutingDomains: []string{"~internal.example"},
		Metadata:       map[string]string{"provider": "network-manager"},
	}
	manager := NewManager(initial)

	initial.Upstreams[0].Address = "203.0.113.53"
	initial.SearchDomains[0] = "mutated.example"
	initial.Metadata["provider"] = "mutated"

	first := manager.Snapshot()
	if first.Upstreams[0].Address != "192.0.2.53" || first.SearchDomains[0] != "corp.example" || first.Metadata["provider"] != "network-manager" {
		t.Fatalf("manager retained caller-owned memory: %+v", first)
	}
	first.Upstreams[0].Address = "198.51.100.53"
	first.Metadata["provider"] = "again"
	second := manager.Snapshot()
	if second.Upstreams[0].Address != "192.0.2.53" || second.Metadata["provider"] != "network-manager" {
		t.Fatalf("Snapshot returned mutable manager state: %+v", second)
	}
}

func TestRefreshAdvancesGenerationAndIsolatesCache(t *testing.T) {
	t.Parallel()

	manager := NewManager(Snapshot{
		NetworkGeneration: 1,
		Upstreams:         []Upstream{{Address: "192.0.2.53", Port: 53}},
	})
	key := CacheKey{Name: "Example.COM.", Type: 1}
	if err := manager.Put(key, []string{"192.0.2.10"}, time.Minute); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, ok := manager.Lookup(CacheKey{Name: "example.com", Type: 1, Class: 1}); !ok {
		t.Fatal("normalized cache lookup missed")
	}

	status := manager.Refresh(Snapshot{
		NetworkGeneration: 2,
		Upstreams:         []Upstream{{Address: "198.51.100.53", Port: 53}},
		SearchDomains:     []string{"new.example"},
	})
	if status.Generation != 2 || status.NetworkGeneration != 2 || status.Degraded {
		t.Fatalf("unexpected refresh status: %+v", status)
	}
	if status.Cache.Entries != 0 {
		t.Fatalf("old-generation cache survived refresh: %+v", status.Cache)
	}
	if _, ok := manager.Lookup(key); ok {
		t.Fatal("old-generation lookup succeeded")
	}
}

func TestRefreshFromFailurePreservesSnapshotAndMarksDegraded(t *testing.T) {
	t.Parallel()

	manager := NewManager(Snapshot{
		NetworkGeneration: 10,
		Upstreams:         []Upstream{{Address: "192.0.2.53"}},
	})
	wantErr := errors.New("platform resolver unavailable")
	status, err := manager.RefreshFrom(context.Background(), SnapshotSourceFunc(func(context.Context) (Snapshot, error) {
		return Snapshot{}, wantErr
	}))
	if !errors.Is(err, wantErr) {
		t.Fatalf("RefreshFrom error = %v, want %v", err, wantErr)
	}
	if !status.Degraded || status.LastError == "" || status.Generation != 1 {
		t.Fatalf("unexpected degraded status: %+v", status)
	}
	if manager.Snapshot().NetworkGeneration != 10 {
		t.Fatal("failed refresh replaced the last usable snapshot")
	}
}

func TestEmptySnapshotIsDegraded(t *testing.T) {
	t.Parallel()

	manager := NewManager(Snapshot{})
	status := manager.Status()
	if !status.Degraded || status.LastError == "" || status.UpstreamCount != 0 {
		t.Fatalf("empty snapshot status = %+v", status)
	}
}

func TestPrivateCacheStatisticsExpiryAndCopies(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	manager := newManager(Snapshot{Upstreams: []Upstream{{Address: "192.0.2.53"}}}, func() time.Time {
		return now
	})
	key := CacheKey{Name: "cache.example.", Type: 28}
	values := []string{"2001:db8::10"}
	if err := manager.Put(key, values, 30*time.Second); err != nil {
		t.Fatalf("Put: %v", err)
	}
	values[0] = "2001:db8::bad"

	record, ok := manager.Lookup(CacheKey{Name: "CACHE.EXAMPLE", Type: 28, Class: 1})
	if !ok || record.Values[0] != "2001:db8::10" {
		t.Fatalf("Lookup = (%+v, %v)", record, ok)
	}
	record.Values[0] = "2001:db8::changed"
	recordAgain, ok := manager.Lookup(key)
	if !ok || recordAgain.Values[0] != "2001:db8::10" {
		t.Fatal("Lookup returned mutable cache storage")
	}

	now = now.Add(31 * time.Second)
	if _, ok := manager.Lookup(key); ok {
		t.Fatal("expired record was returned")
	}
	stats := manager.CacheStats()
	if stats.Entries != 0 || stats.Stores != 1 || stats.Hits != 2 || stats.Misses != 1 || stats.Expired != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestPurgeExpiredAndClearAffectOnlyPrivateCache(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	manager := newManager(Snapshot{Upstreams: []Upstream{{Address: "192.0.2.53"}}}, func() time.Time {
		return now
	})
	if err := manager.Put(CacheKey{Name: "short.example", Type: 1}, []string{"192.0.2.1"}, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := manager.Put(CacheKey{Name: "long.example", Type: 1}, []string{"192.0.2.2"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if removed := manager.PurgeExpired(); removed != 1 {
		t.Fatalf("PurgeExpired removed %d, want 1", removed)
	}
	if manager.CacheStats().Entries != 1 {
		t.Fatalf("entries after purge = %d", manager.CacheStats().Entries)
	}
	manager.ClearCache()
	if manager.CacheStats().Entries != 0 {
		t.Fatal("ClearCache did not clear private entries")
	}
	if manager.Snapshot().Upstreams[0].Address != "192.0.2.53" {
		t.Fatal("private cache maintenance changed resolver snapshot")
	}
}

func TestManagerConcurrentAccess(t *testing.T) {
	manager := NewManager(Snapshot{Upstreams: []Upstream{{Address: "192.0.2.53"}}})

	var wait sync.WaitGroup
	for worker := 0; worker < 20; worker++ {
		worker := worker
		wait.Add(1)
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < 100; iteration++ {
				key := CacheKey{Name: fmt.Sprintf("host-%d-%d.example", worker, iteration%10), Type: 1}
				if err := manager.Put(key, []string{"192.0.2.1"}, time.Minute); err != nil {
					t.Errorf("Put: %v", err)
					return
				}
				manager.Lookup(key)
				_ = manager.Status()
				_ = manager.Snapshot()
				if iteration%25 == 0 {
					manager.Refresh(Snapshot{
						NetworkGeneration: uint64(iteration + 1),
						Upstreams:         []Upstream{{Address: "198.51.100.53"}},
					})
				}
			}
		}()
	}
	wait.Wait()
}
