package garlic

import "time"

// SetLinkDelayForTest makes g delay every circuit packet it sends by d, to
// emulate link latency on a local test mesh.
func SetLinkDelayForTest(g *Garlic, d time.Duration) { g.testLinkDelay = d }

// FSCountsForTest reports how many of g's own circuits switched to
// per-circuit keys, and how many relayed duplex legs did.
func FSCountsForTest(g *Garlic) (origin, relayed int) {
	for _, c := range g.circuits.List() {
		if c.FSUpgraded() {
			origin++
		}
	}
	g.duplex.mu.Lock()
	defer g.duplex.mu.Unlock()
	for _, r := range g.duplex.routes {
		if r.fsActive {
			relayed++
		}
	}
	return origin, relayed
}
