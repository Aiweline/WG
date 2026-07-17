package session

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func testTime() time.Time {
	return time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
}

func mustMachine(t *testing.T, role Role, now time.Time) *Machine {
	t.Helper()
	machine, err := NewDefaultMachine(role, now)
	if err != nil {
		t.Fatalf("NewDefaultMachine: %v", err)
	}
	return machine
}

func establishClient(t *testing.T, machine *Machine, now time.Time, operationID uint64) time.Time {
	t.Helper()
	if err := machine.BeginHandshake(now); err != nil {
		t.Fatalf("BeginHandshake: %v", err)
	}
	now = now.Add(time.Second)
	if err := machine.HandshakeComplete(now); err != nil {
		t.Fatalf("HandshakeComplete: %v", err)
	}
	if got := machine.Snapshot().State; got != StatePendingConfirm {
		t.Fatalf("handshake entered %s, want PendingConfirm", got)
	}
	now = now.Add(time.Second)
	if err := machine.IssuePing(operationID, now); err != nil {
		t.Fatalf("IssuePing: %v", err)
	}
	now = now.Add(time.Second)
	if err := machine.AcceptPong(operationID, now); err != nil {
		t.Fatalf("AcceptPong: %v", err)
	}
	return now
}

func TestClientRequiresMatchingPong(t *testing.T) {
	now := testTime()
	machine := mustMachine(t, RoleClient, now)

	if err := machine.BeginHandshake(now); err != nil {
		t.Fatal(err)
	}
	if err := machine.HandshakeComplete(now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if got := machine.Snapshot().State; got != StatePendingConfirm {
		t.Fatalf("state=%s, want PendingConfirm", got)
	}
	if err := machine.IssuePing(41, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}

	before := machine.Snapshot()
	err := machine.AcceptPong(42, now.Add(3*time.Second))
	if !errors.Is(err, ErrPongMismatch) {
		t.Fatalf("mismatched PONG error=%v, want ErrPongMismatch", err)
	}
	after := machine.Snapshot()
	if after.State != before.State || after.OutstandingPingID != before.OutstandingPingID || after.LastEventAt != before.LastEventAt {
		t.Fatalf("mismatched PONG mutated state: before=%+v after=%+v", before, after)
	}

	if err := machine.AcceptPong(41, now.Add(3*time.Second)); err != nil {
		t.Fatalf("matching PONG: %v", err)
	}
	if got := machine.Snapshot().State; got != StateEstablished {
		t.Fatalf("state=%s, want Established", got)
	}
}

func TestServerConfirmIsAtomicAndIdempotentDuringGrace(t *testing.T) {
	now := testTime()
	machine := mustMachine(t, RoleServer, now)
	if err := machine.HandshakeComplete(now); err != nil {
		t.Fatal(err)
	}
	if got := machine.Snapshot().State; got != StatePendingConfirm {
		t.Fatalf("state=%s, want PendingConfirm", got)
	}

	duplicate, err := machine.AcceptConfirmPing(77, now.Add(time.Second))
	if err != nil || duplicate {
		t.Fatalf("first confirm duplicate=%v err=%v", duplicate, err)
	}
	duplicate, err = machine.AcceptConfirmPing(77, now.Add(2*time.Second))
	if err != nil || !duplicate {
		t.Fatalf("retransmit duplicate=%v err=%v", duplicate, err)
	}

	before := machine.Snapshot()
	_, err = machine.AcceptConfirmPing(78, now.Add(3*time.Second))
	if !errors.Is(err, ErrConfirmMismatch) {
		t.Fatalf("different confirm error=%v, want ErrConfirmMismatch", err)
	}
	if after := machine.Snapshot(); after.LastEventAt != before.LastEventAt || after.LastConfirmID != before.LastConfirmID {
		t.Fatalf("different confirm mutated state: before=%+v after=%+v", before, after)
	}

	_, err = machine.AcceptConfirmPing(77, now.Add(12*time.Second))
	if !errors.Is(err, ErrConfirmGraceExpired) {
		t.Fatalf("late confirm error=%v, want ErrConfirmGraceExpired", err)
	}
}

func TestIllegalTransitionsDoNotMutate(t *testing.T) {
	now := testTime()
	client := mustMachine(t, RoleClient, now)
	before := client.Snapshot()
	err := client.AcceptPong(1, now)
	if !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("AcceptPong from Idle error=%v, want ErrIllegalTransition", err)
	}
	if after := client.Snapshot(); after != before {
		t.Fatalf("illegal transition mutated machine: before=%+v after=%+v", before, after)
	}

	server := mustMachine(t, RoleServer, now)
	serverBefore := server.Snapshot()
	err = server.BeginHandshake(now)
	if !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("server BeginHandshake error=%v, want ErrIllegalTransition", err)
	}
	if after := server.Snapshot(); after != serverBefore {
		t.Fatalf("illegal server transition mutated machine: before=%+v after=%+v", serverBefore, after)
	}
}

func TestRetriesAndHandshakeTimeout(t *testing.T) {
	now := testTime()
	machine := mustMachine(t, RoleClient, now)
	if err := machine.BeginHandshake(now); err != nil {
		t.Fatal(err)
	}
	wantDelays := []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second}
	for index, want := range wantDelays {
		delay, err := machine.RecordInitialRetransmission(now.Add(time.Duration(index) * time.Second))
		if err != nil {
			t.Fatalf("retry %d: %v", index, err)
		}
		if delay != want {
			t.Fatalf("retry %d delay=%s, want %s", index, delay, want)
		}
	}
	if _, err := machine.RecordInitialRetransmission(now.Add(4 * time.Second)); !errors.Is(err, ErrRetriesExhausted) {
		t.Fatalf("extra retry error=%v, want ErrRetriesExhausted", err)
	}

	timedOut, err := machine.CheckTimeout(now.Add(9 * time.Second))
	if err != nil || timedOut {
		t.Fatalf("early CheckTimeout timedOut=%v err=%v", timedOut, err)
	}
	timedOut, err = machine.CheckTimeout(now.Add(10 * time.Second))
	if err != nil || !timedOut {
		t.Fatalf("due CheckTimeout timedOut=%v err=%v", timedOut, err)
	}
	if got := machine.Snapshot().State; got != StateClosed {
		t.Fatalf("state=%s, want Closed", got)
	}
}

func TestControlRetriesAndTimeouts(t *testing.T) {
	now := testTime()
	machine := mustMachine(t, RoleClient, now)
	if err := machine.BeginHandshake(now); err != nil {
		t.Fatal(err)
	}
	if err := machine.HandshakeComplete(now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := machine.IssuePing(9, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	for retry := 0; retry < 3; retry++ {
		if _, err := machine.RecordPingRetransmission(9, now.Add(time.Duration(retry+2)*time.Second)); err != nil {
			t.Fatalf("control retry %d: %v", retry, err)
		}
	}
	if _, err := machine.RecordPingRetransmission(9, now.Add(4*time.Second)); !errors.Is(err, ErrRetriesExhausted) {
		t.Fatalf("extra control retry error=%v, want ErrRetriesExhausted", err)
	}

	// PendingConfirm is measured from handshake completion and expires at +6s.
	timedOut, err := machine.CheckTimeout(now.Add(6 * time.Second))
	if err != nil || !timedOut {
		t.Fatalf("pending timeout timedOut=%v err=%v", timedOut, err)
	}
	if got := machine.Snapshot().State; got != StateClosed {
		t.Fatalf("state=%s, want Closed", got)
	}
}

func TestEstablishedIdleDrainsThenCloses(t *testing.T) {
	now := testTime()
	machine := mustMachine(t, RoleClient, now)
	establishedAt := establishClient(t, machine, now, 7)

	timedOut, err := machine.CheckTimeout(establishedAt.Add(5 * time.Minute))
	if err != nil || !timedOut {
		t.Fatalf("idle timeout timedOut=%v err=%v", timedOut, err)
	}
	if got := machine.Snapshot().State; got != StateDraining {
		t.Fatalf("state=%s, want Draining", got)
	}
	timedOut, err = machine.CheckTimeout(establishedAt.Add(5*time.Minute + 30*time.Second))
	if err != nil || !timedOut {
		t.Fatalf("drain timeout timedOut=%v err=%v", timedOut, err)
	}
	if got := machine.Snapshot().State; got != StateClosed {
		t.Fatalf("state=%s, want Closed", got)
	}
}

func TestRekeyAlsoRequiresMatchingPong(t *testing.T) {
	now := testTime()
	machine := mustMachine(t, RoleClient, now)
	now = establishClient(t, machine, now, 1)
	if err := machine.BeginRekey(now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := machine.IssuePing(2, now.Add(2*time.Second)); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("PING before rekey handshake error=%v, want illegal transition", err)
	}
	if err := machine.HandshakeComplete(now.Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := machine.IssuePing(2, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := machine.AcceptPong(2, now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	if got := machine.Snapshot().State; got != StateEstablished {
		t.Fatalf("state=%s, want Established", got)
	}
}

func TestMachineConcurrentTouchAndSnapshot(t *testing.T) {
	now := testTime()
	machine := mustMachine(t, RoleClient, now)
	now = establishClient(t, machine, now, 99)
	touchAt := now.Add(time.Second)

	var wait sync.WaitGroup
	for worker := 0; worker < 32; worker++ {
		wait.Add(2)
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < 200; iteration++ {
				if err := machine.Touch(touchAt); err != nil {
					t.Errorf("Touch: %v", err)
					return
				}
			}
		}()
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < 200; iteration++ {
				if got := machine.Snapshot().State; got != StateEstablished {
					t.Errorf("Snapshot state=%s, want Established", got)
					return
				}
			}
		}()
	}
	wait.Wait()
}

func TestPolicyValidation(t *testing.T) {
	policy := DefaultTimeoutPolicy()
	policy.PendingConfirm = 0
	if _, err := NewMachine(RoleClient, policy, testTime()); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("NewMachine policy error=%v, want ErrInvalidPolicy", err)
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	now := testTime()
	machine := mustMachine(t, RoleClient, now)
	if err := machine.Close(now); err != nil {
		t.Fatal(err)
	}
	before := machine.Snapshot()
	if err := machine.Close(now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if after := machine.Snapshot(); after != before {
		t.Fatalf("second Close mutated machine: before=%+v after=%+v", before, after)
	}
}
