// Package garlicproxy connects ordinary browsers to .domains.yggg sites
// through a loopback HTTP proxy. All site traffic uses Garlic.DialService;
// there is no DNS lookup or direct-network fallback for a site hostname.
package garlicproxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yggdrasil-network/yggdrasil-go/src/garlic"
)

type Proxy struct {
	server      *http.Server
	listener    net.Listener
	transport   *http.Transport
	mu          sync.Mutex
	connections map[net.Conn]struct{}
	closing     bool
}

func Start(g *garlic.Garlic, listen string) (*Proxy, error) {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return nil, err
	}
	if host == "localhost" {
		listen = strings.Replace(listen, "localhost", "127.0.0.1", 1)
	} else if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("garlic proxy must listen on a loopback IP")
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	p := &Proxy{listener: ln, connections: make(map[net.Conn]struct{}), transport: &http.Transport{Proxy: nil, DisableCompression: true, MaxIdleConns: 32, MaxIdleConnsPerHost: 4, MaxConnsPerHost: 8, IdleConnTimeout: 60 * time.Second, ResponseHeaderTimeout: 60 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			domain, port, err := parseTarget(addr, 80)
			if err != nil {
				return nil, err
			}
			return g.DialService(ctx, domain, port)
		}}}
	reverse := &httputil.ReverseProxy{Transport: p.transport,
		Rewrite: func(req *httputil.ProxyRequest) {
			req.Out.Host = req.In.Host
			sanitizeHeaders(req.Out.Header, req.In.URL.Hostname())
			req.Out.Header.Del("X-Forwarded-For")
			req.Out.Header.Del("X-Forwarded-Host")
			req.Out.Header.Del("X-Forwarded-Proto")
		},
		ModifyResponse: func(res *http.Response) error {
			// The public suffix list does not know our private namespace.
			// Force host-only cookies so one site cannot set domains.yggg
			// cookies which a browser would send to every other site.
			cookies := res.Cookies()
			res.Header.Del("Set-Cookie")
			for _, cookie := range cookies {
				cookie.Domain = ""
				res.Header.Add("Set-Cookie", cookie.String())
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "Garlic site unavailable: "+err.Error(), http.StatusBadGateway)
		}}
	p.server = &http.Server{ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && !r.URL.IsAbs() && r.URL.Path == "/proxy.pac" {
			w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
			w.Header().Set("Cache-Control", "no-store")
			fmt.Fprintf(w, "function FindProxyForURL(url, host) { host = host.toLowerCase().replace(/\\.$/, ''); if (host === 'yggg' || dnsDomainIs(host, '.yggg')) return 'PROXY %s'; return 'DIRECT'; }\n", ln.Addr().String())
			return
		}
		if r.Method == http.MethodConnect {
			domain, port, err := parseTarget(r.Host, 443)
			if err != nil || port != 443 {
				http.Error(w, "CONNECT requires a .domains.yggg host on port 443", http.StatusForbidden)
				return
			}
			conn, err := g.DialService(r.Context(), domain, port)
			if err != nil {
				http.Error(w, "Garlic site unavailable: "+err.Error(), http.StatusBadGateway)
				return
			}
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				conn.Close()
				http.Error(w, "hijacking unavailable", 500)
				return
			}
			browser, rw, err := hijacker.Hijack()
			if err != nil {
				conn.Close()
				return
			}
			defer browser.Close()
			defer conn.Close()
			p.mu.Lock()
			if p.closing {
				p.mu.Unlock()
				return
			}
			p.connections[browser] = struct{}{}
			p.mu.Unlock()
			defer func() { p.mu.Lock(); delete(p.connections, browser); p.mu.Unlock() }()
			_, _ = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
			if rw.Flush() != nil {
				return
			}
			finished := make(chan struct{})
			go func() { _, _ = io.Copy(browser, conn); browser.Close(); close(finished) }()
			_, _ = io.Copy(conn, rw)
			conn.Close()
			<-finished
			return
		}
		if !r.URL.IsAbs() || r.URL.Scheme != "http" || r.URL.User != nil {
			http.Error(w, "Use this listener as an HTTP proxy for http://<hash>.domains.yggg/", 400)
			return
		}
		domain, port, err := parseTarget(r.URL.Host, 80)
		if err != nil || port != 80 {
			http.Error(w, "Only .domains.yggg sites on port 80 are accepted", http.StatusForbidden)
			return
		}
		r.URL.Host = domain
		r.Host = domain
		reverse.ServeHTTP(w, r)
	})}
	go func() { _ = p.server.Serve(ln) }()
	return p, nil
}

func parseTarget(hostport string, def uint16) (string, uint16, error) {
	host := hostport
	port := def
	if strings.Contains(hostport, ":") {
		h, p, err := net.SplitHostPort(hostport)
		if err != nil {
			return "", 0, err
		}
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return "", 0, err
		}
		host = h
		port = uint16(n)
	}
	gid, err := garlic.ParseDomain(host)
	if err != nil {
		return "", 0, err
	}
	return gid.Domain(), port, nil
}

func sanitizeHeaders(h http.Header, domain string) {
	for key := range h {
		lower := strings.ToLower(key)
		if lower == "forwarded" || lower == "via" || strings.HasPrefix(lower, "x-forwarded-") || strings.HasPrefix(lower, "proxy-") {
			h.Del(key)
		}
	}
	for _, key := range []string{"Referer", "Origin"} {
		if raw := h.Get(key); raw != "" {
			u, err := url.Parse(raw)
			if err != nil || !strings.EqualFold(u.Hostname(), domain) {
				h.Del(key)
			}
		}
	}
}

func (p *Proxy) Addr() net.Addr { return p.listener.Addr() }
func (p *Proxy) Close() error {
	p.mu.Lock()
	p.closing = true
	for conn := range p.connections {
		_ = conn.Close()
	}
	p.mu.Unlock()
	p.transport.CloseIdleConnections()
	return p.server.Close()
}
