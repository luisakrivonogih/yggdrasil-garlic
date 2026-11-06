package garlic_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yggdrasil-network/yggdrasil-go/src/core"
	"github.com/yggdrasil-network/yggdrasil-go/src/garlic"
	"github.com/yggdrasil-network/yggdrasil-go/src/garlicproxy"
)

// waitForKnownRelays pulls gossip from a trusted relay until g knows at
// least n relays.
func waitForKnownRelays(t *testing.T, g *garlic.Garlic, n int, from []byte) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for len(g.KnownPeers()) < n {
		if time.Now().After(deadline) {
			t.Fatalf("only %d relays known after gossip, want %d", len(g.KnownPeers()), n)
		}
		_ = g.RequestGossip(from)
		time.Sleep(200 * time.Millisecond)
	}
}

func TestSiteBrowserAcrossDistributedMesh(t *testing.T) {
	if testing.Short() {
		t.Skip("five-node network integration")
	}
	var nodes []*core.Core
	var overlays []*garlic.Garlic
	cfg := garlic.DefaultConfig()
	cfg.PathLength = 3
	cfg.MinHopCount = 0
	cfg.JitterEnabled = false
	cfg.AutoPoolEnabled = false
	cfg.CircuitLifetime = 12 * time.Second
	cfg.CapabilityTimeout = 2 * time.Second
	// Nodes 1-3 are public relays. Node 0 hosts the site in hidden mode and
	// trusts relay 1 as its guard; it is never contacted by anyone else.
	newNode := func(hidden bool, trusted ...[]byte) (*core.Core, *garlic.Garlic) {
		n := newLinkedTestNode(t)
		id, err := garlic.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		c := cfg
		c.Hidden = hidden
		for _, k := range trusted {
			c.TrustedPeers = append(c.TrustedPeers, hex.EncodeToString(k))
		}
		g := garlic.New(n, id, c, nil)
		nodes = append(nodes, n)
		overlays = append(overlays, g)
		return n, g
	}
	cores := make([]*core.Core, 4)
	for i := range cores {
		cores[i] = newLinkedTestNode(t)
	}
	connectChain(t, cores)
	pumpAll(cores)
	for i, n := range cores {
		id, err := garlic.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		c := cfg
		if i == 0 {
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
	waitForCapability(t, overlays[0], nodes[1].PublicKey(), 60*time.Second)
	waitForKnownRelays(t, overlays[0], 3, nodes[1].PublicKey())
	for i := 1; i < 4; i++ {
		if _, err := overlays[i].QueryCapability(nodes[0].PublicKey()); err == nil {
			t.Fatal("the hidden site host answered a capability query")
		}
	}
	payload := bytes.Repeat([]byte("garlic website data\n"), 110000)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Forwarded") != "" || r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("Referer") != "" {
			t.Error("proxy leaked identifying headers")
		}
		http.SetCookie(w, &http.Cookie{Name: "site", Value: "one", Domain: "domains.yggg", Path: "/"})
		if r.Method == "POST" {
			body, _ := io.ReadAll(r.Body)
			w.Write(body)
			return
		}
		if r.URL.Path == "/rotate" {
			w.Write([]byte("before rotation\n"))
			w.(http.Flusher).Flush()
			time.Sleep(12 * time.Second)
			w.Write([]byte("after rotation\n"))
			return
		}
		w.Write(payload)
	}))
	defer backend.Close()
	u, _ := url.Parse(backend.URL)
	service, err := overlays[0].StartService(garlic.ServiceConfig{LocalAddr: u.Host})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-service.Ready():
	case <-time.After(40 * time.Second):
		t.Fatalf("publication not ready: %v", service.LastError())
	}
	// A second, named site on the same hidden host: its own key and domain.
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("second site"))
	}))
	defer second.Close()
	u2, _ := url.Parse(second.URL)
	service2, err := overlays[0].StartService(garlic.ServiceConfig{Name: "second", LocalAddr: u2.Host})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-service2.Ready():
	case <-time.After(40 * time.Second):
		t.Fatalf("second site not ready: %v", service2.LastError())
	}
	if service2.Domain() == service.Domain() {
		t.Fatal("two sites of one node got the same domain")
	}
	// This hidden client joins only after publication. Its directory starts
	// empty, and it knows only one trusted relay, never the service
	// descriptor.
	fresh, client := newNode(true, nodes[1].PublicKey())
	connectChain(t, []*core.Core{nodes[1], fresh})
	pumpAll([]*core.Core{fresh})
	waitForCapability(t, client, nodes[1].PublicKey(), 30*time.Second)
	waitForKnownRelays(t, client, 3, nodes[1].PublicKey())
	proxy, err := garlicproxy.Start(client, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	proxyURL, _ := url.Parse("http://" + proxy.Addr().String())
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	browser := &http.Client{Transport: transport, Timeout: 60 * time.Second}
	request, err := http.NewRequest("GET", "http://"+service.Domain()+"/index.html", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Forwarded", "for=192.0.2.1")
	request.Header.Set("X-Forwarded-For", "192.0.2.1")
	request.Header.Set("Referer", "http://external.example/private")
	response, err := browser.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != 200 || !bytes.Equal(body, payload) {
		if len(body) > 200 {
			body = body[:200]
		}
		t.Fatalf("browser GET: status=%d error=%v body=%q", response.StatusCode, err, body)
	}
	for _, cookie := range response.Cookies() {
		if cookie.Domain != "" {
			t.Fatalf("cookie not host-only: %v", cookie)
		}
	}
	response, err = browser.Get("http://" + service2.Domain() + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(body) != "second site" {
		t.Fatalf("second site: %v %q", err, body)
	}
	response, err = browser.Get("http://" + service.Domain() + "/rotate")
	if err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(body) != "before rotation\nafter rotation\n" {
		t.Fatalf("stream did not survive circuit rotation: %v %q", err, body)
	}
	post := strings.Repeat("POST through Garlic\n", 12000)
	response, err = browser.Post("http://"+service.Domain()+"/submit", "text/plain", strings.NewReader(post))
	if err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(body) != post {
		t.Fatalf("POST response mismatch: %v (%d bytes)", err, len(body))
	}
	response, err = browser.Get("http://external.example/")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("external host was not rejected: %d", response.StatusCode)
	}
	// Every published introduction point is a relay, never the service
	// node, and never the host's own guard.
	points, err := client.LookupDomain(service.Domain())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range points {
		if bytes.Equal(p.NodeKey, nodes[0].PublicKey()) {
			t.Fatal("directory disclosed the service node")
		}
		if bytes.Equal(p.NodeKey, nodes[1].PublicKey()) {
			t.Fatal("the host's guard doubled as its site relay")
		}
	}
	// No relay other than the host's trusted guard ever learned that the
	// hidden host runs Garlic.
	for i := 2; i < 4; i++ {
		for _, p := range overlays[i].KnownPeers() {
			if bytes.Equal(p.NodeKey, nodes[0].PublicKey()) || bytes.Equal(p.NodeKey, fresh.PublicKey()) {
				t.Fatalf("relay %d learned about a hidden node", i)
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.DialService(ctx, service.Domain(), 443)
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatal("unconfigured virtual port 443 was accepted")
	}
}
