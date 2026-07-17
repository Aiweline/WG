package handshake

import (
	"bytes"
	"crypto/ecdh"
	"errors"
	"sync"
	"testing"
	"time"

	"wg.local/wg/internal/codec"
	wgcrypto "wg.local/wg/internal/crypto"
)

func TestIdenticalInitialReturnsCachedHandshakeAndSession(t *testing.T) {
	fixture := newTestFixture(t)
	initial, err := fixture.client.Start()
	if err != nil {
		t.Fatal(err)
	}
	random := fixture.server.options.random.(*bytes.Reader)
	before := random.Len()
	firstSession, firstResponse, err := fixture.server.HandleInitial(initial)
	if err != nil {
		t.Fatal(err)
	}
	defer firstSession.Close()
	afterFirst := random.Len()
	secondSession, secondResponse, err := fixture.server.HandleInitial(initial)
	if err != nil {
		t.Fatal(err)
	}
	if secondSession != firstSession {
		t.Fatal("duplicate INITIAL created a second session")
	}
	if !bytes.Equal(secondResponse, firstResponse) {
		t.Fatal("duplicate INITIAL did not return byte-identical HANDSHAKE")
	}
	if random.Len() != afterFirst || before-afterFirst <= 0 {
		t.Fatalf("server randomness consumption before=%d first=%d duplicate=%d", before, afterFirst, random.Len())
	}
	if got := activeCIDCount(fixture.server); got != 1 {
		t.Fatalf("active CID count = %d, want 1", got)
	}
	if fixture.server.activeAttempts != 1 || len(fixture.server.attempts) != 1 {
		t.Fatalf("attempt counts active=%d records=%d", fixture.server.activeAttempts, len(fixture.server.attempts))
	}
}

func TestIdenticalInitialDuringConfirmGraceUsesCache(t *testing.T) {
	clock := newFakeClock(time.Unix(1_000, 0))
	fixture := newTestFixture(t)
	fixture.server.options.now = clock.Now
	fixture.server.options.pendingAttemptTimeout = 5 * time.Second
	fixture.server.options.confirmGracePeriod = 10 * time.Second
	initial, err := fixture.client.Start()
	if err != nil {
		t.Fatal(err)
	}
	session, response, err := fixture.server.HandleInitial(initial)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := fixture.client.Finish(response); err != nil {
		t.Fatal(err)
	}
	confirm, _, err := fixture.client.BuildConfirm()
	if err != nil {
		t.Fatal(err)
	}
	pong, err := session.HandleConfirm(confirm)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.client.HandlePong(pong); err != nil {
		t.Fatal(err)
	}
	clock.Advance(9 * time.Second)
	cachedSession, cachedResponse, err := fixture.server.HandleInitial(initial)
	if err != nil {
		t.Fatal(err)
	}
	if cachedSession != session || !bytes.Equal(cachedResponse, response) {
		t.Fatal("confirm-grace replay did not return the cached attempt")
	}
	if session.State() != StateEstablished || activeCIDCount(fixture.server) != 1 {
		t.Fatal("cache replay changed established session activation")
	}
}

func TestConfirmPingRetransmissionIsIdempotentDuringGrace(t *testing.T) {
	clock := newFakeClock(time.Unix(1_200, 0))
	fixture := newTestFixture(t)
	fixture.server.options.now = clock.Now
	fixture.server.options.confirmGracePeriod = 10 * time.Second
	initial, err := fixture.client.Start()
	if err != nil {
		t.Fatal(err)
	}
	session, response, err := fixture.server.HandleInitial(initial)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := fixture.client.Finish(response); err != nil {
		t.Fatal(err)
	}
	confirm, challenge, err := fixture.client.BuildConfirm()
	if err != nil {
		t.Fatal(err)
	}
	retry, err := fixture.client.RetransmitConfirm()
	if err != nil {
		t.Fatal(err)
	}
	lateRetry, err := fixture.client.RetransmitConfirm()
	if err != nil {
		t.Fatal(err)
	}
	confirmPacket, err := codec.ParsePacket(confirm, 0)
	if err != nil {
		t.Fatal(err)
	}
	retryPacket, err := codec.ParsePacket(retry, 0)
	if err != nil {
		t.Fatal(err)
	}
	if confirmPacket.Header.PacketNumber != 0 || retryPacket.Header.PacketNumber != 1 {
		t.Fatalf("CONFIRM PNs first=%d retry=%d", confirmPacket.Header.PacketNumber, retryPacket.Header.PacketNumber)
	}
	pong, err := session.HandleConfirm(confirm)
	if err != nil {
		t.Fatal(err)
	}
	if session.State() != StateEstablished {
		t.Fatalf("state after first CONFIRM = %s", session.State())
	}
	if _, err := session.HandleConfirm(confirm); err == nil {
		t.Fatal("same-PN CONFIRM replay was accepted")
	}
	retryPong, err := session.HandleConfirm(retry)
	if err != nil {
		t.Fatalf("fresh-PN CONFIRM retry: %v", err)
	}
	if session.State() != StateEstablished || activeCIDCount(fixture.server) != 1 || fixture.server.activeAttempts != 1 {
		t.Fatal("CONFIRM retry reactivated or duplicated session state")
	}
	if err := fixture.client.HandlePong(pong); err != nil {
		t.Fatal(err)
	}
	frames, err := fixture.client.Open(retryPong)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 || frames[0].Type != codec.FramePong || !bytes.Equal(frames[0].Body, challenge[:]) {
		t.Fatalf("retry PONG mismatch: %+v", frames)
	}
	clock.Advance(10 * time.Second)
	if _, err := session.HandleConfirm(lateRetry); !errors.Is(err, ErrAttemptExpired) {
		t.Fatalf("post-grace CONFIRM retry error = %v", err)
	}
	if session.State() != StateEstablished || fixture.server.activeAttempts != 0 {
		t.Fatal("post-grace retry changed established state or retained cache capacity")
	}
}

func TestConcurrentIdenticalInitialSingleflight(t *testing.T) {
	fixture := newTestFixture(t)
	initial, err := fixture.client.Start()
	if err != nil {
		t.Fatal(err)
	}
	gatedRandom := newGateReader(deterministicBytes(0x51, 256))
	fixture.server.options.random = gatedRandom
	before := gatedRandom.Remaining()
	const workers = 64
	type result struct {
		session  *ServerSession
		response []byte
		err      error
	}
	results := make(chan result, workers)
	var start sync.WaitGroup
	start.Add(1)
	var started sync.WaitGroup
	started.Add(workers)
	var workersDone sync.WaitGroup
	workersDone.Add(workers)
	for index := 0; index < workers; index++ {
		go func() {
			defer workersDone.Done()
			start.Wait()
			started.Done()
			session, response, err := fixture.server.HandleInitial(initial)
			results <- result{session: session, response: response, err: err}
		}()
	}
	start.Done()
	started.Wait()
	<-gatedRandom.entered
	close(gatedRandom.release)
	workersDone.Wait()
	close(results)
	var expectedSession *ServerSession
	var expectedResponse []byte
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent HandleInitial: %v", result.err)
		}
		if expectedSession == nil {
			expectedSession = result.session
			expectedResponse = result.response
			continue
		}
		if result.session != expectedSession || !bytes.Equal(result.response, expectedResponse) {
			t.Fatal("concurrent duplicate returned a different session or response")
		}
	}
	defer expectedSession.Close()
	if consumed := before - gatedRandom.Remaining(); consumed <= 0 {
		t.Fatalf("server randomness consumed %d bytes, want one attempt allocation", consumed)
	}
	if activeCIDCount(fixture.server) != 1 || fixture.server.activeAttempts != 1 {
		t.Fatalf("duplicate growth: cids=%d attempts=%d", activeCIDCount(fixture.server), fixture.server.activeAttempts)
	}
}

func TestPendingAttemptCapacityAndCloseRelease(t *testing.T) {
	fixture := newTestFixture(t)
	fixture.server.options.maxPendingAttempts = 2
	fixture.server.options.maxAttemptRecords = 8
	clients := []*Client{
		fixture.client,
		newAttemptClient(t, fixture.server, fixture.client.staticPrivate, 0x31),
		newAttemptClient(t, fixture.server, fixture.client.staticPrivate, 0x41),
	}
	initials := make([][]byte, len(clients))
	for index, client := range clients {
		var err error
		initials[index], err = client.Start()
		if err != nil {
			t.Fatal(err)
		}
	}
	first, _, err := fixture.server.HandleInitial(initials[0])
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := fixture.server.HandleInitial(initials[1])
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if _, _, err := fixture.server.HandleInitial(initials[2]); !errors.Is(err, ErrAttemptCapacity) {
		t.Fatalf("capacity error = %v", err)
	}
	if activeCIDCount(fixture.server) != 2 || fixture.server.activeAttempts != 2 {
		t.Fatal("capacity rejection mutated active state")
	}
	first.Close()
	if activeCIDCount(fixture.server) != 1 || fixture.server.activeAttempts != 1 {
		t.Fatal("Close did not release CID and pending capacity")
	}
	third, _, err := fixture.server.HandleInitial(initials[2])
	if err != nil {
		t.Fatalf("capacity was not reusable after Close: %v", err)
	}
	defer third.Close()
}

func TestAttemptRecordLimitBoundsReplayTombstones(t *testing.T) {
	clock := newFakeClock(time.Unix(1_500, 0))
	fixture := newTestFixture(t)
	fixture.server.options.now = clock.Now
	fixture.server.options.maxPendingAttempts = 2
	fixture.server.options.maxAttemptRecords = 2
	fixture.server.options.attemptReplayRetention = 15 * time.Second
	clients := []*Client{
		fixture.client,
		newAttemptClient(t, fixture.server, fixture.client.staticPrivate, 0x32),
		newAttemptClient(t, fixture.server, fixture.client.staticPrivate, 0x42),
	}
	initials := make([][]byte, len(clients))
	for index, client := range clients {
		var err error
		initials[index], err = client.Start()
		if err != nil {
			t.Fatal(err)
		}
	}
	for index := 0; index < 2; index++ {
		session, _, err := fixture.server.HandleInitial(initials[index])
		if err != nil {
			t.Fatal(err)
		}
		session.Close()
	}
	if fixture.server.activeAttempts != 0 || len(fixture.server.attempts) != 2 {
		t.Fatalf("tombstone counts active=%d records=%d", fixture.server.activeAttempts, len(fixture.server.attempts))
	}
	if _, _, err := fixture.server.HandleInitial(initials[2]); !errors.Is(err, ErrAttemptCapacity) {
		t.Fatalf("record-capacity error = %v", err)
	}
	clock.Advance(15 * time.Second)
	if changed := fixture.server.CleanupExpired(); changed != 2 || len(fixture.server.attempts) != 0 {
		t.Fatalf("record cleanup changed=%d records=%d", changed, len(fixture.server.attempts))
	}
	session, _, err := fixture.server.HandleInitial(initials[2])
	if err != nil {
		t.Fatalf("record capacity was not reusable after cleanup: %v", err)
	}
	session.Close()
}

func TestPendingExpiryClosesSessionAndKeepsReplayTombstone(t *testing.T) {
	clock := newFakeClock(time.Unix(2_000, 0))
	fixture := newTestFixture(t)
	fixture.server.options.now = clock.Now
	fixture.server.options.pendingAttemptTimeout = 5 * time.Second
	fixture.server.options.attemptReplayRetention = 20 * time.Second
	initial, err := fixture.client.Start()
	if err != nil {
		t.Fatal(err)
	}
	session, _, err := fixture.server.HandleInitial(initial)
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(5 * time.Second)
	if changed := fixture.server.CleanupExpired(); changed != 1 {
		t.Fatalf("cleanup changed %d records, want 1", changed)
	}
	if session.State() != StateClosed || activeCIDCount(fixture.server) != 0 || fixture.server.activeAttempts != 0 {
		t.Fatalf("pending expiry leaked state: state=%s cids=%d attempts=%d", session.State(), activeCIDCount(fixture.server), fixture.server.activeAttempts)
	}
	if _, _, err := fixture.server.HandleInitial(initial); !errors.Is(err, ErrAttemptExpired) {
		t.Fatalf("expired INITIAL replay error = %v", err)
	}
	entry := onlyAttemptEntry(t, fixture.server)
	if entry.response != nil || entry.session != nil || entry.phase != attemptTombstone {
		t.Fatal("expired entry retained response/session cache")
	}
	clock.Advance(20 * time.Second)
	if changed := fixture.server.CleanupExpired(); changed != 1 || len(fixture.server.attempts) != 0 {
		t.Fatalf("tombstone cleanup changed=%d records=%d", changed, len(fixture.server.attempts))
	}
}

func TestConfirmGraceExpiryDropsCacheButKeepsEstablishedCID(t *testing.T) {
	clock := newFakeClock(time.Unix(3_000, 0))
	fixture := newTestFixture(t)
	fixture.server.options.now = clock.Now
	fixture.server.options.confirmGracePeriod = 10 * time.Second
	initial, err := fixture.client.Start()
	if err != nil {
		t.Fatal(err)
	}
	session, response, err := fixture.server.HandleInitial(initial)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.client.Finish(response); err != nil {
		t.Fatal(err)
	}
	confirm, _, err := fixture.client.BuildConfirm()
	if err != nil {
		t.Fatal(err)
	}
	pong, err := session.HandleConfirm(confirm)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.client.HandlePong(pong); err != nil {
		t.Fatal(err)
	}
	clock.Advance(10 * time.Second)
	if changed := fixture.server.CleanupExpired(); changed != 1 {
		t.Fatalf("grace cleanup changed %d records", changed)
	}
	if session.State() != StateEstablished || activeCIDCount(fixture.server) != 1 || fixture.server.activeAttempts != 0 {
		t.Fatalf("grace cleanup disturbed established session: state=%s cids=%d attempts=%d", session.State(), activeCIDCount(fixture.server), fixture.server.activeAttempts)
	}
	if _, _, err := fixture.server.HandleInitial(initial); !errors.Is(err, ErrAttemptExpired) {
		t.Fatalf("post-grace replay error = %v", err)
	}
	session.Close()
	if activeCIDCount(fixture.server) != 0 {
		t.Fatal("established Close leaked CID")
	}
}

func activeCIDCount(server *Server) int {
	server.activeMu.Lock()
	defer server.activeMu.Unlock()
	return len(server.activeCIDs)
}

func onlyAttemptEntry(t *testing.T, server *Server) *attemptEntry {
	t.Helper()
	server.attemptMu.Lock()
	defer server.attemptMu.Unlock()
	if len(server.attempts) != 1 {
		t.Fatalf("attempt record count = %d, want 1", len(server.attempts))
	}
	for _, entry := range server.attempts {
		return entry
	}
	return nil
}

func newAttemptClient(t *testing.T, server *Server, staticPrivate *ecdh.PrivateKey, seed byte) *Client {
	t.Helper()
	serverPublic, err := wgcrypto.PublicBytes(server.staticPrivate.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(ClientConfig{
		DeploymentID: server.deploymentID, StaticPrivate: staticPrivate,
		ServerStaticPublic: serverPublic,
		Random:             bytes.NewReader(deterministicBytes(seed, 256)),
		AddressFamilies:    0x01, MaxDatagramSize: codec.DefaultMaxDatagramSize,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

type gateReader struct {
	mu      sync.Mutex
	reader  *bytes.Reader
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func newGateReader(data []byte) *gateReader {
	return &gateReader{
		reader: bytes.NewReader(data), entered: make(chan struct{}), release: make(chan struct{}),
	}
}

func (reader *gateReader) Read(data []byte) (int, error) {
	reader.once.Do(func() {
		close(reader.entered)
		<-reader.release
	})
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return reader.reader.Read(data)
}

func (reader *gateReader) Remaining() int {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return reader.reader.Len()
}

func newFakeClock(now time.Time) *fakeClock { return &fakeClock{now: now} }

func (clock *fakeClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *fakeClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(duration)
	clock.mu.Unlock()
}
