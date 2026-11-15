// Package garlicproxy connects applications to .domains.yggg hidden services
// through a loopback proxy that speaks both SOCKS5 and HTTP on one port
// (told apart by the first byte). Any TCP port may be requested; the
// service decides which ports it offers. All traffic uses
// Garlic.DialService; there is no DNS lookup or direct-network fallback for
// a service hostname.
package garlicproxy

import (
	"bufio"
	"context"
	"errors"
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

// dialer is what the proxy needs from Garlic.
type dialer interface {
	DialService(ctx context.Context, domain string, port uint16) (net.Conn, error)
}

type Proxy struct {
	server      *http.Server
	listener    net.Listener
	httpConns   chan net.Conn
	done        chan struct{}
	ctx         context.Context
	cancel      context.CancelFunc
	dial        dialer
	transport   *http.Transport
	mu          sync.Mutex
	connections map[net.Conn]struct{}
	closing     bool
}

func Start(g *garlic.Garlic, listen string) (*Proxy, error) { return start(g, listen) }

func start(g dialer, listen string) (*Proxy, error) {
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
	ctx, cancel := context.WithCancel(context.Background())
	p := &Proxy{listener: ln, httpConns: make(chan net.Conn), done: make(chan struct{}), ctx: ctx, cancel: cancel, dial: g, connections: make(map[net.Conn]struct{}), transport: &http.Transport{Proxy: nil, DisableCompression: true, MaxIdleConns: 32, MaxIdleConnsPerHost: 4, MaxConnsPerHost: 8, IdleConnTimeout: 60 * time.Second, ResponseHeaderTimeout: 60 * time.Second,
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
			http.Error(w, "Garlic service unavailable: "+err.Error(), dialStatus(err))
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
			if err != nil {
				http.Error(w, "CONNECT requires a .domains.yggg host", http.StatusForbidden)
				return
			}
			if port == 0 {
				http.Error(w, "invalid port", http.StatusBadRequest)
				return
			}
			conn, err := g.DialService(r.Context(), domain, port)
			if err != nil {
				http.Error(w, "Garlic service unavailable: "+err.Error(), dialStatus(err))
				return
			}
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				conn.Close()
				http.Error(w, "hijacking unavailable", 500)
				return
			}
			client, rw, err := hijacker.Hijack()
			if err != nil {
				conn.Close()
				return
			}
			defer client.Close()
			defer conn.Close()
			if !p.track(client) {
				return
			}
			defer p.untrack(client)
			_, _ = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
			if rw.Flush() != nil {
				return
			}
			relay(client, rw, conn)
			return
		}
		if !r.URL.IsAbs() || r.URL.Scheme != "http" || r.URL.User != nil {
			http.Error(w, "Use this listener as an HTTP proxy for http://<hash>.domains.yggg/", 400)
			return
		}
		domain, port, err := parseTarget(r.URL.Host, 80)
		if err != nil {
			http.Error(w, "Only .domains.yggg services are accepted", http.StatusForbidden)
			return
		}
		if port == 0 {
			http.Error(w, "invalid port", http.StatusBadRequest)
			return
		}
		r.URL.Host = domain
		if port != 80 {
			r.URL.Host = net.JoinHostPort(domain, strconv.Itoa(int(port)))
		}
		r.Host = r.URL.Host
		reverse.ServeHTTP(w, r)
	})}
	go func() { _ = p.server.Serve(&muxListener{p}) }()
	go p.acceptLoop()
	return p, nil
}

// track registers a client connection so Close can end it.
func (p *Proxy) track(c net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing {
		return false
	}
	p.connections[c] = struct{}{}
	return true
}

func (p *Proxy) untrack(c net.Conn) { p.mu.Lock(); delete(p.connections, c); p.mu.Unlock() }

// relay copies both ways between a client and a service until both
// directions end. clientIn may hold bytes the client already sent.
func relay(client net.Conn, clientIn io.Reader, site net.Conn) {
	finished := make(chan struct{})
	go func() { _, _ = io.Copy(client, site); client.Close(); close(finished) }()
	_, _ = io.Copy(site, clientIn)
	site.Close()
	<-finished
}

// dialStatus maps a DialService error to an HTTP status.
func dialStatus(err error) int {
	if isTimeout(err) {
		return http.StatusGatewayTimeout
	}
	return http.StatusBadGateway
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
}

const handshakeTimeout = 10 * time.Second

// acceptLoop hands each connection to the SOCKS5 handler or, for anything
// else, to the HTTP server, depending on the first byte. The handshake slots
// are bounded so idle connections cannot pile up goroutines.
func (p *Proxy) acceptLoop() {
	defer close(p.done)
	slots := make(chan struct{}, 256)
	for {
		c, err := p.listener.Accept()
		if err != nil {
			return
		}
		select {
		case slots <- struct{}{}:
		default:
			c.Close()
			continue
		}
		go func() {
			release := func() { <-slots }
			p.route(c, release)
		}()
	}
}

func (p *Proxy) route(c net.Conn, release func()) {
	if !p.track(c) {
		release()
		c.Close()
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(handshakeTimeout))
	br := bufio.NewReaderSize(c, 4096)
	first, err := br.Peek(1)
	if err != nil || first[0] == 0x04 { // gone, or SOCKS4/4a: not supported
		release()
		p.untrack(c)
		c.Close()
		return
	}
	if first[0] == 0x05 {
		p.serveSOCKS(c, br, release)
		p.untrack(c)
		c.Close()
		return
	}
	release()
	_ = c.SetReadDeadline(time.Time{})
	p.untrack(c) // the HTTP server's own bookkeeping takes over
	select {
	case p.httpConns <- &peekConn{Conn: c, r: br}:
	case <-p.ctx.Done():
		c.Close()
	}
}

// peekConn replays bytes already buffered while sniffing the protocol.
type peekConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *peekConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// muxListener feeds the HTTP server the connections that are not SOCKS5.
type muxListener struct{ p *Proxy }

func (l *muxListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.p.httpConns:
		return c, nil
	case <-l.p.ctx.Done():
		return nil, net.ErrClosed
	}
}
func (l *muxListener) Close() error   { l.p.cancel(); return l.p.listener.Close() }
func (l *muxListener) Addr() net.Addr { return l.p.listener.Addr() }

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
	p.cancel()
	p.mu.Lock()
	p.closing = true
	for conn := range p.connections {
		_ = conn.Close()
	}
	p.mu.Unlock()
	p.transport.CloseIdleConnections()
	err := p.server.Close()
	_ = p.listener.Close()
	<-p.done
	return err
}
