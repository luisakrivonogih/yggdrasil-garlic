package garlic_test

import (
	"bytes"
	"context"
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
	newNode := func() (*core.Core, *garlic.Garlic) {
		n := newLinkedTestNode(t)
		id, err := garlic.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		g := garlic.New(n, id, cfg, nil)
		nodes = append(nodes, n)
		overlays = append(overlays, g)
		return n, g
	}
	for range 4 {
		newNode()
	}
	connectChain(t, nodes)
	pumpAll(nodes)
	t.Cleanup(func() {
		for _, g := range overlays {
			g.Close()
		}
		for _, n := range nodes {
			n.Stop()
		}
	})
	for i, g := range overlays {
		for j, n := range nodes {
			if i != j {
				t.Logf("resolving capabilities %d -> %d", i, j)
				waitForCapability(t, g, n.PublicKey(), 60*time.Second)
			}
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
	// This node joins only after publication. Its directory starts empty,
	// and it receives only one bootstrap peer, never the service descriptor.
	fresh, client := newNode()
	connectChain(t, []*core.Core{nodes[1], fresh})
	pumpAll([]*core.Core{fresh})
	waitForCapability(t, client, nodes[1].PublicKey(), 30*time.Second)
	if err := client.RequestGossip(nodes[1].PublicKey()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for len(client.KnownPeers()) < 3 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
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
	// Every published introduction point is a relay, not the service node.
	points, err := client.LookupDomain(service.Domain())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range points {
		if bytes.Equal(p.NodeKey, nodes[0].PublicKey()) {
			t.Fatal("directory disclosed the service node")
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
