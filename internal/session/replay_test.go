package session

import (
	"errors"
	"sync"
	"testing"
)

func TestPacketNumbersMonotonicAndExhaustion(t *testing.T) {
	allocator := NewPacketNumbers(^uint64(0) - 1)
	first, err := allocator.Next()
	if err != nil || first != ^uint64(0)-1 {
		t.Fatalf("first=%d err=%v", first, err)
	}
	last, err := allocator.Next()
	if err != nil || last != ^uint64(0) {
		t.Fatalf("last=%d err=%v", last, err)
	}
	if _, err := allocator.Next(); !errors.Is(err, ErrPacketNumberExhausted) {
		t.Fatalf("post-exhaustion error=%v", err)
	}
}

func TestPacketNumbersConcurrentUnique(t *testing.T) {
	const count = 2000
	allocator := NewPacketNumbers(100)
	values := make(chan uint64, count)
	errorsSeen := make(chan error, count)

	var wait sync.WaitGroup
	for worker := 0; worker < count; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			value, err := allocator.Next()
			if err != nil {
				errorsSeen <- err
				return
			}
			values <- value
		}()
	}
	wait.Wait()
	close(values)
	close(errorsSeen)
	for err := range errorsSeen {
		t.Fatalf("Next: %v", err)
	}

	seen := make(map[uint64]struct{}, count)
	for value := range values {
		if _, exists := seen[value]; exists {
			t.Fatalf("duplicate packet number %d", value)
		}
		seen[value] = struct{}{}
	}
	if len(seen) != count {
		t.Fatalf("allocated %d unique values, want %d", len(seen), count)
	}
}

func TestReplayWindowFreshOutOfOrderDuplicateAndOld(t *testing.T) {
	var window ReplayWindow
	if !window.Precheck(100) {
		t.Fatal("uninitialized Precheck rejected packet")
	}
	if snapshot := window.Snapshot(); snapshot.Initialized {
		t.Fatal("Precheck mutated uninitialized window")
	}

	if err := window.AcceptAuthenticated(100); err != nil {
		t.Fatal(err)
	}
	if err := window.AcceptAuthenticated(99); err != nil {
		t.Fatalf("out-of-order packet: %v", err)
	}
	if err := window.AcceptAuthenticated(101); err != nil {
		t.Fatalf("new highest packet: %v", err)
	}
	if err := window.AcceptAuthenticated(99); !errors.Is(err, ErrReplayDuplicate) {
		t.Fatalf("duplicate error=%v, want ErrReplayDuplicate", err)
	}

	if err := window.AcceptAuthenticated(3000); err != nil {
		t.Fatalf("large advance: %v", err)
	}
	if window.Precheck(952) {
		t.Fatal("Precheck accepted delta=2048 packet")
	}
	if !window.Precheck(953) {
		t.Fatal("Precheck rejected delta=2047 packet")
	}
	if err := window.AcceptAuthenticated(952); !errors.Is(err, ErrReplayTooOld) {
		t.Fatalf("old packet error=%v, want ErrReplayTooOld", err)
	}
	if err := window.AcceptAuthenticated(953); err != nil {
		t.Fatalf("window-edge packet: %v", err)
	}
	if !window.Precheck(953) {
		t.Fatal("Precheck must not reject possible duplicate before authentication")
	}
	if err := window.AcceptAuthenticated(953); !errors.Is(err, ErrReplayDuplicate) {
		t.Fatalf("edge duplicate error=%v, want ErrReplayDuplicate", err)
	}
}

func TestReplayWindowShiftAcrossWords(t *testing.T) {
	var window ReplayWindow
	for _, packetNumber := range []uint64{64, 63, 1, 0} {
		if err := window.AcceptAuthenticated(packetNumber); err != nil {
			t.Fatalf("accept %d: %v", packetNumber, err)
		}
	}
	if err := window.AcceptAuthenticated(129); err != nil {
		t.Fatalf("advance across words: %v", err)
	}
	for _, packetNumber := range []uint64{64, 63, 1, 0} {
		if err := window.AcceptAuthenticated(packetNumber); !errors.Is(err, ErrReplayDuplicate) {
			t.Fatalf("packet %d after shift error=%v, want duplicate", packetNumber, err)
		}
	}
}

func TestReplayWindowConcurrentSingleWinner(t *testing.T) {
	var window ReplayWindow
	const workers = 128
	results := make(chan error, workers)
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results <- window.AcceptAuthenticated(500)
		}()
	}
	wait.Wait()
	close(results)

	accepted := 0
	duplicates := 0
	for err := range results {
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, ErrReplayDuplicate):
			duplicates++
		default:
			t.Fatalf("unexpected result: %v", err)
		}
	}
	if accepted != 1 || duplicates != workers-1 {
		t.Fatalf("accepted=%d duplicates=%d, want 1/%d", accepted, duplicates, workers-1)
	}
}

func TestReplayWindowConcurrentDistinctPackets(t *testing.T) {
	var window ReplayWindow
	const workers = 1024
	results := make(chan error, workers)
	var wait sync.WaitGroup
	for packetNumber := uint64(0); packetNumber < workers; packetNumber++ {
		packetNumber := packetNumber
		wait.Add(1)
		go func() {
			defer wait.Done()
			results <- window.AcceptAuthenticated(packetNumber)
		}()
	}
	wait.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("distinct packet rejected: %v", err)
		}
	}
	if snapshot := window.Snapshot(); !snapshot.Initialized || snapshot.Highest != workers-1 {
		t.Fatalf("snapshot=%+v, want initialized highest=%d", snapshot, workers-1)
	}
}
