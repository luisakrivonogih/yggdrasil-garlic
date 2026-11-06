package garlic

import (
	"net"
	"sync"
	"testing"
	"time"
)

type fakeAddr string

func (a fakeAddr) Network() string { return "fake" }
func (a fakeAddr) String() string  { return string(a) }

type recordedSend struct {
	data []byte
	addr net.Addr
	at   time.Time
}

func newRecordingSender() (send func([]byte, net.Addr) error, calls chan recordedSend) {
	calls = make(chan recordedSend, 16)
	send = func(data []byte, addr net.Addr) error {
		calls <- recordedSend{data: append([]byte(nil), data...), addr: addr, at: time.Now()}
		return nil
	}
	return send, calls
}

func TestJitterSchedulerSendsAfterDelay(t *testing.T) {
	send, calls := newRecordingSender()
	s := newJitterScheduler(send, 16, 4)
	defer s.Stop()

	start := time.Now()
	if !s.enqueue([]byte("payload"), fakeAddr("bob"), 50*time.Millisecond) {
		t.Fatal("enqueue returned false, want true")
	}

	select {
	case got := <-calls:
		if elapsed := got.at.Sub(start); elapsed < 40*time.Millisecond {
			t.Fatalf("send happened after %s, want at least ~50ms delay", elapsed)
		}
		if string(got.data) != "payload" {
			t.Errorf("data = %q, want %q", got.data, "payload")
		}
		if got.addr != fakeAddr("bob") {
			t.Errorf("addr = %v, want %v", got.addr, fakeAddr("bob"))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for scheduled send")
	}
}

func TestJitterSchedulerZeroDelaySendsPromptly(t *testing.T) {
	send, calls := newRecordingSender()
	s := newJitterScheduler(send, 16, 4)
	defer s.Stop()

	if !s.enqueue([]byte("payload"), fakeAddr("bob"), 0) {
		t.Fatal("enqueue returned false, want true")
	}

	select {
	case <-calls:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for zero-delay send")
	}
}

func TestJitterSchedulerEnqueueFailsWhenQueueFull(t *testing.T) {
	send, _ := newRecordingSender()
	s := newJitterScheduler(send, 1, 0) // capacity 1, no workers draining it
	defer s.Stop()

	if !s.enqueue([]byte("a"), fakeAddr("x"), time.Hour) {
		t.Fatal("first enqueue returned false, want true (queue has room)")
	}
	if s.enqueue([]byte("b"), fakeAddr("x"), time.Hour) {
		t.Fatal("second enqueue returned true, want false (queue at capacity)")
	}
}

func TestJitterSchedulerStopPreventsFurtherSends(t *testing.T) {
	send, calls := newRecordingSender()
	s := newJitterScheduler(send, 16, 4)

	s.Stop()
	s.enqueue([]byte("payload"), fakeAddr("bob"), 0)

	select {
	case <-calls:
		t.Fatal("send happened after Stop, want none")
	case <-time.After(200 * time.Millisecond):
		// expected: nothing sent
	}
}

func TestRandomJitterStaysWithinBounds(t *testing.T) {
	for range 50 {
		d, err := randomJitter(10*time.Millisecond, 50*time.Millisecond)
		if err != nil {
			t.Fatalf("randomJitter returned error: %v", err)
		}
		if d < 10*time.Millisecond || d > 50*time.Millisecond {
			t.Fatalf("d = %s, want in [10ms, 50ms]", d)
		}
	}
}

func TestRandomJitterProducesVariety(t *testing.T) {
	seen := map[time.Duration]bool{}
	for range 50 {
		d, err := randomJitter(0, 100*time.Millisecond)
		if err != nil {
			t.Fatalf("randomJitter returned error: %v", err)
		}
		seen[d] = true
	}
	if len(seen) < 2 {
		t.Fatalf("got %d distinct value(s) across 50 calls, want variety", len(seen))
	}
}

func TestRandomJitterRejectsInvertedRange(t *testing.T) {
	if _, err := randomJitter(100*time.Millisecond, 10*time.Millisecond); err == nil {
		t.Fatal("expected error for maxDelay < minDelay, got nil")
	}
}

func TestRandomJitterHandlesEqualBounds(t *testing.T) {
	d, err := randomJitter(20*time.Millisecond, 20*time.Millisecond)
	if err != nil {
		t.Fatalf("randomJitter returned error: %v", err)
	}
	if d != 20*time.Millisecond {
		t.Fatalf("d = %s, want exactly 20ms", d)
	}
}

func TestJitterSchedulerHandlesConcurrentEnqueues(t *testing.T) {
	send, calls := newRecordingSender()
	s := newJitterScheduler(send, 64, 8)
	defer s.Stop()

	const n = 20
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s.enqueue([]byte{byte(i)}, fakeAddr("bob"), 0)
		}(i)
	}
	wg.Wait()

	received := 0
	deadline := time.After(2 * time.Second)
	for received < n {
		select {
		case <-calls:
			received++
		case <-deadline:
			t.Fatalf("received %d/%d sends before timeout", received, n)
		}
	}
}

// Packets to one destination must leave in the order they were enqueued,
// whatever their random delays: reordering makes QUIC (site traffic) see
// loss and collapse its sending rate.
func TestJitterSchedulerKeepsOrderPerDestination(t *testing.T) {
	var mu sync.Mutex
	got := map[string][]byte{}
	done := make(chan struct{}, 400)
	s := newJitterScheduler(func(data []byte, addr net.Addr) error {
		mu.Lock()
		got[addr.String()] = append(got[addr.String()], data[0])
		mu.Unlock()
		done <- struct{}{}
		return nil
	}, 256, 16)
	defer s.Stop()
	for i := range 200 {
		for _, dst := range []string{"alice", "bob"} {
			d, err := randomJitter(0, 20*time.Millisecond)
			if err != nil {
				t.Fatal(err)
			}
			if !s.enqueue([]byte{byte(i)}, fakeAddr(dst), d) {
				t.Fatal("queue full")
			}
		}
	}
	for range 400 {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out")
		}
	}
	for dst, seq := range got {
		for i, b := range seq {
			if b != byte(i) {
				t.Fatalf("%s: packet %d sent in position %d", dst, b, i)
			}
		}
	}
}
