package garlic_test

import (
	"bytes"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/yggdrasil-network/yggdrasil-go/src/core"
	"github.com/yggdrasil-network/yggdrasil-go/src/garlic"
	"github.com/yggdrasil-network/yggdrasil-go/src/garlicproxy"
)

// siteDownload measures one site download over a 5-node mesh (hidden host,
// three relays, hidden client) with the default jitter settings.
func siteDownload(t *testing.T, jitter bool, size int) time.Duration {
	cfg := garlic.DefaultConfig()
	cfg.PathLength = 3
	cfg.MinHopCount = 0
	cfg.AutoPoolEnabled = false
	cfg.CapabilityTimeout = 2 * time.Second
	cfg.JitterEnabled = jitter
	var nodes []*core.Core
	var overlays []*garlic.Garlic
	cores := make([]*core.Core, 5)
	for i := range cores {
		cores[i] = newLinkedTestNode(t)
	}
	connectChain(t, cores[:4])
	connectChain(t, []*core.Core{cores[1], cores[4]})
	pumpAll(cores)
	for i, n := range cores {
		id, _ := garlic.NewIdentity()
		c := cfg
		if i == 0 || i == 4 {
			c.Hidden = true
			c.TrustedPeers = []string{hex.EncodeToString(cores[1].PublicKey())}
		}
		nodes = append(nodes, n)
		overlays = append(overlays, garlic.New(n, id, c, nil))
	}
	t.Cleanup(func() {
		for _, g := range overlays {
			g.Close()
		}
		for _, n := range nodes {
			n.Stop()
		}
	})
	for i := 1; i < 4; i++ {
		for j := 1; j < 4; j++ {
			if i != j {
				waitForCapability(t, overlays[i], nodes[j].PublicKey(), 60*time.Second)
			}
		}
	}
	for _, i := range []int{0, 4} {
		waitForCapability(t, overlays[i], nodes[1].PublicKey(), 60*time.Second)
		waitForKnownRelays(t, overlays[i], 3, nodes[1].PublicKey())
	}
	payload := bytes.Repeat([]byte("x"), size)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(payload) }))
	defer backend.Close()
	u, _ := url.Parse(backend.URL)
	service, err := overlays[0].StartService(garlic.ServiceConfig{LocalAddr: u.Host})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-service.Ready():
	case <-time.After(60 * time.Second):
		t.Fatalf("not published: %v", service.LastError())
	}
	proxy, err := garlicproxy.Start(overlays[4], "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	proxyURL, _ := url.Parse("http://" + proxy.Addr().String())
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	browser := &http.Client{Transport: transport, Timeout: 5 * time.Minute}
	// Warm up: lookup and connection setup are not part of the measurement.
	if r, err := browser.Get("http://" + service.Domain() + "/"); err == nil {
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
	}
	start := time.Now()
	r, err := browser.Get("http://" + service.Domain() + "/")
	if err != nil {
		t.Fatal(err)
	}
	n, err := io.Copy(io.Discard, r.Body)
	r.Body.Close()
	if err != nil || n != int64(size) {
		t.Fatalf("download: %d bytes, %v", n, err)
	}
	return time.Since(start)
}

// Opt-in measurement (GARLIC_SPEED=1): site throughput with and without
// relay jitter.
func TestSiteSpeed(t *testing.T) {
	if os.Getenv("GARLIC_SPEED") == "" {
		t.Skip("set GARLIC_SPEED=1 to measure site throughput")
	}
	const size = 2 << 20
	for _, jitter := range []bool{false, true} {
		t.Run(map[bool]string{false: "jitter-off", true: "jitter-on"}[jitter], func(t *testing.T) {
			d := siteDownload(t, jitter, size)
			t.Logf("%d KiB in %v = %.0f KiB/s", size>>10, d.Round(time.Millisecond), float64(size>>10)/d.Seconds())
		})
	}
}
