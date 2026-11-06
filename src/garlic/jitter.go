package garlic

// Jitter: a bounded, delayed-send scheduler used to add random delay
// before actually transmitting a circuitData packet (origin send or
// relay forward), so an observer can't line up exact send timestamps
// across hops - a defense against the timing half of "traffic
// correlation" (docs/garlic-threat-model.md), complementing the
// per-packet size randomization in envelope.go/protocol.go.
//
// It must never block its caller: Garlic.handleIncoming's forwarding
// path calls enqueue synchronously from within core.Core.ReadFrom's read
// loop (see core.GarlicHandler's doc comment on why that must not
// block), so this is a fixed-size worker pool pulling from a bounded
// channel - enqueue either succeeds immediately or fails immediately
// (queue full), never waits.

import (
	"crypto/rand"
	"errors"
	"hash/fnv"
	"math/big"
	"net"
	"time"
)

var ErrInvalidJitterRange = errors.New("garlic: invalid jitter delay range")

type jitterJob struct {
	data   []byte
	addr   net.Addr
	sendAt time.Time
}

// jitterScheduler delays calls to send by a caller-specified duration,
// bounded by fixed-capacity queues and a fixed number of goroutines - so a
// burst of enqueues can never grow memory or goroutine count without limit.
//
// Packets to the same destination always go through the same lane and
// leave in the order they were enqueued: each waits for its own delay and
// for the packets ahead of it. Independent delays used to let packets of
// one stream overtake each other, and QUIC (site traffic) takes such
// reordering for loss and collapses its sending rate.
type jitterScheduler struct {
	send  func(data []byte, addr net.Addr) error
	lanes []chan jitterJob
	stop  chan struct{}
}

// newJitterScheduler starts a scheduler with workers lanes, each a
// goroutine draining a FIFO queue of capacity queueSize. workers may be 0
// (one lane that nothing drains; useful for testing enqueue's
// bounded-capacity behavior in isolation).
func newJitterScheduler(send func(data []byte, addr net.Addr) error, queueSize, workers int) *jitterScheduler {
	s := &jitterScheduler{send: send, stop: make(chan struct{})}
	for range max(workers, 1) {
		s.lanes = append(s.lanes, make(chan jitterJob, max(queueSize, 1)))
	}
	for i := range workers {
		go s.worker(s.lanes[i])
	}
	return s
}

func (s *jitterScheduler) worker(lane chan jitterJob) {
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	for {
		select {
		case job := <-lane:
			if d := time.Until(job.sendAt); d > 0 {
				timer.Reset(d)
				select {
				case <-timer.C:
				case <-s.stop:
					return
				}
			}
			_ = s.send(job.data, job.addr)
		case <-s.stop:
			return
		}
	}
}

func (s *jitterScheduler) lane(addr net.Addr) chan jitterJob {
	if len(s.lanes) == 1 {
		return s.lanes[0]
	}
	h := fnv.New32a()
	h.Write([]byte(addr.String()))
	return s.lanes[h.Sum32()%uint32(len(s.lanes))]
}

func (s *jitterScheduler) enqueue(data []byte, addr net.Addr, delay time.Duration) bool {
	select {
	case <-s.stop:
		return false
	default:
	}
	select {
	case s.lane(addr) <- jitterJob{data: data, addr: addr, sendAt: time.Now().Add(delay)}:
		return true
	default:
		return false
	}
}

func (s *jitterScheduler) Stop() {
	close(s.stop)
}

// randomJitter returns a uniformly random duration in [minDelay,
// maxDelay].
func randomJitter(minDelay, maxDelay time.Duration) (time.Duration, error) {
	if maxDelay < minDelay {
		return 0, ErrInvalidJitterRange
	}
	if maxDelay == minDelay {
		return minDelay, nil
	}
	span := big.NewInt(int64(maxDelay-minDelay) + 1)
	n, err := rand.Int(rand.Reader, span)
	if err != nil {
		return 0, err
	}
	return minDelay + time.Duration(n.Int64()), nil
}
