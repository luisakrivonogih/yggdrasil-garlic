package garlic

import "time"

// SetLinkDelayForTest makes g delay every circuit packet it sends by d, to
// emulate link latency on a local test mesh.
func SetLinkDelayForTest(g *Garlic, d time.Duration) { g.testLinkDelay = d }
