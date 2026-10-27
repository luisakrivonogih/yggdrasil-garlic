package garlicproxy

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/yggdrasil-network/yggdrasil-go/src/garlic"
)

func TestProxyTargetsAreStrictlyConfinedToHashDomains(t *testing.T) {
	domain := garlic.ComputeGID([]byte("key"), nil).Domain()
	for _, target := range []string{"127.0.0.1:80", "[::1]:80", "example.com:80", "name.yggg:80", domain + ".evil:80", "sub." + domain + ":80", domain + ":notaport"} {
		if _, _, err := parseTarget(target, 80); err == nil {
			t.Errorf("accepted %q", target)
		}
	}
	got, port, err := parseTarget(strings.ToUpper(domain)+".:443", 80)
	if err != nil || got != domain || port != 443 {
		t.Fatalf("canonical target: %q %d %v", got, port, err)
	}
}

func TestProxyRemovesCrossSiteAndNetworkIdentityHeaders(t *testing.T) {
	domain := garlic.ComputeGID([]byte("key"), nil).Domain()
	h := http.Header{"Forwarded": {"for=192.0.2.1"}, "X-Forwarded-For": {"192.0.2.1"}, "X-Forwarded-Custom": {"private"}, "Proxy-Authorization": {"secret"}, "Referer": {"http://external.example/private"}, "Origin": {"http://" + domain}, "Cookie": {"session=123"}, "Authorization": {"Bearer site-token"}}
	sanitizeHeaders(h, domain)
	for _, key := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Custom", "Proxy-Authorization", "Referer"} {
		if h.Get(key) != "" {
			t.Errorf("leaked %s", key)
		}
	}
	if h.Get("Origin") == "" || h.Get("Cookie") == "" || h.Get("Authorization") == "" {
		t.Fatal("same-site application headers removed")
	}
}

func TestProxyPACAndFailClosedPolicy(t *testing.T) {
	for _, listen := range []string{"0.0.0.0:0", "[::]:0", "192.0.2.1:0"} {
		if p, err := Start(nil, listen); err == nil {
			p.Close()
			t.Fatalf("non-loopback listener allowed: %s", listen)
		}
	}
	p, err := Start(nil, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	res, err := http.Get("http://" + p.Addr().String() + "/proxy.pac")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(body), "PROXY "+p.Addr().String()) || !strings.Contains(string(body), "'.yggg'") || strings.Contains(string(body), "; DIRECT") {
		t.Fatalf("invalid PAC: %q", body)
	}
	proxyURL, _ := url.Parse("http://" + p.Addr().String())
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	// A nil Garlic instance ensures forbidden targets fail before dialing.
	res, err = client.Get("http://127.0.0.1:1/")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("external destination was allowed: %d", res.StatusCode)
	}
	if _, err = client.Get("https://external.example/"); err == nil {
		t.Fatal("external CONNECT was allowed")
	}
}
