package session

import (
	"errors"
	"fmt"
	"sync"
)

const (
	// ReplayWindowSize is the design-mandated number of authenticated packet
	// numbers tracked independently for each receive direction.
	ReplayWindowSize = 2048
	replayWordBits   = 64
	replayWordCount  = ReplayWindowSize / replayWordBits
)

var (
	ErrPacketNumberExhausted = errors.New("packet-number space exhausted")
	ErrReplayDuplicate       = errors.New("authenticated packet number is a duplicate")
	ErrReplayTooOld          = errors.New("authenticated packet number is outside replay window")
)

// PacketNumbers allocates monotonically increasing transport packet numbers.
// It emits MaxUint64 once, then permanently refuses further allocation.
type PacketNumbers struct {
	mu        sync.Mutex
	next      uint64
	exhausted bool
}

func NewPacketNumbers(first uint64) *PacketNumbers {
	return &PacketNumbers{next: first}
}

func (p *PacketNumbers) Next() (uint64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.exhausted {
		return 0, ErrPacketNumberExhausted
	}
	packetNumber := p.next
	if p.next == ^uint64(0) {
		p.exhausted = true
	} else {
		p.next++
	}
	return packetNumber, nil
}

// PacketNumberSnapshot is a race-free allocator view.
type PacketNumberSnapshot struct {
	Next      uint64
	Exhausted bool
}

func (p *PacketNumbers) Snapshot() PacketNumberSnapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	return PacketNumberSnapshot{Next: p.next, Exhausted: p.exhausted}
}

// ReplayError records why a post-authentication packet number was rejected.
type ReplayError struct {
	Kind         error
	PacketNumber uint64
	Highest      uint64
}

func (e *ReplayError) Error() string {
	return fmt.Sprintf("%v: pn=%d highest=%d", e.Kind, e.PacketNumber, e.Highest)
}

func (e *ReplayError) Unwrap() error { return e.Kind }

// ReplaySnapshot is an immutable replay-window view. Bitmap is intentionally
// not exposed; callers need only initialization and the authenticated high PN.
type ReplaySnapshot struct {
	Initialized bool
	Highest     uint64
}

// ReplayWindow tracks authenticated packet numbers. Callers may use Precheck
// before authentication only to reject obviously too-old packets. They must
// call AcceptAuthenticated after successful authentication to claim a PN.
type ReplayWindow struct {
	mu          sync.Mutex
	initialized bool
	highest     uint64
	bitmap      [replayWordCount]uint64
}

// Precheck performs a non-mutating, cheap age check. It intentionally returns
// true for possible duplicates; only authenticated callers may inspect/update
// the bitmap through AcceptAuthenticated.
func (w *ReplayWindow) Precheck(packetNumber uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.initialized || packetNumber > w.highest {
		return true
	}
	delta := w.highest - packetNumber
	return delta < ReplayWindowSize
}

// AcceptAuthenticated atomically claims an authenticated packet number. Only
// the unique caller receiving nil may parse frames or deliver a packet.
func (w *ReplayWindow) AcceptAuthenticated(packetNumber uint64) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.initialized {
		w.initialized = true
		w.highest = packetNumber
		w.bitmap[0] = 1
		return nil
	}

	if packetNumber > w.highest {
		advance := packetNumber - w.highest
		w.shiftLocked(advance)
		w.highest = packetNumber
		w.bitmap[0] |= 1
		return nil
	}

	delta := w.highest - packetNumber
	if delta >= ReplayWindowSize {
		return &ReplayError{Kind: ErrReplayTooOld, PacketNumber: packetNumber, Highest: w.highest}
	}
	word := int(delta / replayWordBits)
	bit := uint(delta % replayWordBits)
	mask := uint64(1) << bit
	if w.bitmap[word]&mask != 0 {
		return &ReplayError{Kind: ErrReplayDuplicate, PacketNumber: packetNumber, Highest: w.highest}
	}
	w.bitmap[word] |= mask
	return nil
}

func (w *ReplayWindow) shiftLocked(advance uint64) {
	if advance >= ReplayWindowSize {
		w.bitmap = [replayWordCount]uint64{}
		return
	}

	previous := w.bitmap
	w.bitmap = [replayWordCount]uint64{}
	wholeWords := int(advance / replayWordBits)
	partialBits := uint(advance % replayWordBits)

	for destination := replayWordCount - 1; destination >= 0; destination-- {
		source := destination - wholeWords
		if source < 0 {
			continue
		}
		value := previous[source] << partialBits
		if partialBits != 0 && source > 0 {
			value |= previous[source-1] >> (replayWordBits - partialBits)
		}
		w.bitmap[destination] = value
	}
}

func (w *ReplayWindow) Snapshot() ReplaySnapshot {
	w.mu.Lock()
	defer w.mu.Unlock()
	return ReplaySnapshot{Initialized: w.initialized, Highest: w.highest}
}
