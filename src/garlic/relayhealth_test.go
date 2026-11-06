package garlic

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"
	"time"
)

func TestRelayWeightsDeprioritiseFailuresAndPreferFastWithinBounds(t *testing.T) {
	h := newRelayHealth()
	ok, failing, fast, slow, unknown := []byte("ok"), []byte("failing"), []byte("fast"), []byte("slow"), []byte("unknown")
	h.success([][]byte{ok}, 200*time.Millisecond)
	h.success([][]byte{fast}, 20*time.Millisecond)
	h.success([][]byte{slow}, 5*time.Second)
	h.failure([][]byte{failing})
	h.failure([][]byte{failing})
	w := h.weights([][]byte{ok, failing, fast, slow, unknown})
	if !(w[1] < w[0] && w[1] >= relayMinWeight) {
		t.Fatalf("failing relay weight %v (ok %v): must be lower but never below the floor", w[1], w[0])
	}
	if !(w[2] > w[0] && w[2] <= w[0]*relayLatencyBoost+1e-9) {
		t.Fatalf("fast relay weight %v vs %v: must be higher, at most %vx", w[2], w[0], relayLatencyBoost)
	}
	if !(w[3] < w[0] && w[3] >= w[0]/relayLatencyBoost-1e-9) {
		t.Fatalf("slow relay weight %v vs %v: must be lower, at most %vx", w[3], w[0], relayLatencyBoost)
	}
	if w[4] != 1 {
		t.Fatalf("unknown relay weight %v, want neutral 1", w[4])
	}
	// A success after failures restores trust quickly.
	h.success([][]byte{failing}, 0)
	h.success([][]byte{failing}, 0)
	if h.get(failing).FailScore >= 1 {
		t.Fatalf("fail score %v after successes", h.get(failing).FailScore)
	}
}

func TestWeightedOrderFavoursHeavierButKeepsEveryone(t *testing.T) {
	first := make([]int, 3)
	for range 3000 {
		first[weightedOrder([]float64{1, 1, 0.1})[0]]++
	}
	if first[2] == 0 || first[2] > first[0]/4 || first[2] > first[1]/4 {
		t.Fatalf("first picks %v: light entry must come first rarely, but sometimes", first)
	}
}

// Middle hops vary from circuit to circuit, and a relay that keeps failing
// is chosen less often - but still chosen sometimes.
func TestBuildPathVariesMiddlesAndDeprioritisesFailing(t *testing.T) {
	g := newTestGarlic(t)
	g.health = newRelayHealth()
	g.cfg.MinHopCount = 0
	guard, terminal := newTestRelay(t), newTestRelay(t)
	middles := []*testRelay{newTestRelay(t), newTestRelay(t), newTestRelay(t)}
	for _, r := range append([]*testRelay{guard, terminal}, middles...) {
		if _, err := g.learnRelayInfo(r.info(t, nil, 3*time.Hour), r.nodePub); err != nil {
			t.Fatal(err)
		}
	}
	g.trusted[string(guard.nodePub)] = bytes.Clone(guard.nodePub)
	for range 3 {
		g.health.failure([][]byte{middles[0].nodePub})
	}
	count := make([]int, len(middles))
	for range 600 {
		_, keys, err := g.buildPath(context.Background(), 3, terminal.nodePub, needSites)
		if err != nil {
			t.Fatal(err)
		}
		for i, m := range middles {
			if bytes.Equal(keys[1], m.nodePub) {
				count[i]++
			}
		}
	}
	if count[1] == 0 || count[2] == 0 {
		t.Fatalf("middle hops %v: healthy relays must all be used", count)
	}
	if count[0] == 0 || count[0]*3 > count[1] || count[0]*3 > count[2] {
		t.Fatalf("middle hops %v: a failing relay must be chosen much less often, but not never", count)
	}
}

// The guard survives restarts: a persisted guard that is still trusted is
// used from the start, and a newly chosen guard is reported once.
func TestGuardIsRestoredAndChangesAreReported(t *testing.T) {
	c := newLinkedCoreForAutoCircuitTest(t)
	defer c.Stop()
	a, b, stranger := newTestRelay(t), newTestRelay(t), newTestRelay(t)
	cfg := DefaultConfig()
	cfg.TrustedPeers = []string{hex.EncodeToString(a.nodePub), hex.EncodeToString(b.nodePub)}
	cfg.Guard = b.nodePub
	id, _ := NewIdentity()
	g := New(c, id, cfg, NewStaticRendezvous())
	defer g.Close()
	if !bytes.Equal(g.CurrentGuard(), b.nodePub) {
		t.Fatal("persisted guard not restored")
	}
	cfg.Guard = stranger.nodePub
	id2, _ := NewIdentity()
	g2 := New(c, id2, cfg, NewStaticRendezvous())
	if g2.CurrentGuard() != nil {
		t.Fatal("a persisted guard that is no longer trusted was used")
	}
	g2.Close()

	u := newTestGarlic(t)
	u.cfg.MinHopCount = 0
	reported := make(chan []byte, 4)
	u.cfg.OnGuardChange = func(k []byte) { reported <- k }
	if _, err := u.learnRelayInfo(a.info(t, nil, time.Hour), a.nodePub); err != nil {
		t.Fatal(err)
	}
	u.trusted[string(a.nodePub)] = bytes.Clone(a.nodePub)
	for range 3 {
		if _, _, err := u.buildPath(context.Background(), 1, nil, needSites); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case k := <-reported:
		if !bytes.Equal(k, a.nodePub) {
			t.Fatal("wrong guard reported")
		}
	case <-time.After(time.Second):
		t.Fatal("new guard not reported")
	}
	select {
	case <-reported:
		t.Fatal("an unchanged guard was reported again")
	case <-time.After(100 * time.Millisecond):
	}
}
