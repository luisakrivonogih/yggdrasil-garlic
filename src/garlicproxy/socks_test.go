package garlicproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yggdrasil-network/yggdrasil-go/src/garlic"
)

// fakeDialer stands in for Garlic: port 7000 reaches a raw echo server, the
// others return the errors DialService does.
type fakeDialer struct {
	echo  string
	calls chan string
}

func (f *fakeDialer) DialService(ctx context.Context, domain string, port uint16) (net.Conn, error) {
	if f.calls != nil {
		f.calls <- domain + ":" + string(rune('0'+port%10))
	}
	switch port {
	case 7000, 80, 8081:
		return net.Dial("tcp", f.echo)
	case 7001:
		return nil, garlic.ErrPortNotOffered
	case 7002:
		return nil, garlic.ErrBackendUnavailable
	case 7003:
		return nil, garlic.ErrGIDNotFound
	case 7004:
		return nil, context.DeadlineExceeded
	}
	return nil, io.ErrUnexpectedEOF
}

func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

func testProxy(t *testing.T, d dialer) *Proxy {
	t.Helper()
	p, err := start(d, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

func testDomain() string { return garlic.ComputeGID([]byte("key"), nil).Domain() }

func socksConnect(t *testing.T, addr string, atyp byte, host []byte, port uint16, cmd byte, methods ...byte) (net.Conn, byte) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if len(methods) == 0 {
		methods = []byte{0}
	}
	c.Write(append([]byte{5, byte(len(methods))}, methods...))
	var sel [2]byte
	if _, err := io.ReadFull(c, sel[:]); err != nil {
		t.Fatal(err)
	}
	if sel[1] == 0x02 {
		c.Write([]byte{1, 1, 'u', 1, 'p'})
		var ok [2]byte
		if _, err := io.ReadFull(c, ok[:]); err != nil || ok[1] != 0 {
			t.Fatalf("auth: %v %v", ok, err)
		}
	}
	req := []byte{5, cmd, 0, atyp}
	if atyp == 3 {
		req = append(req, byte(len(host)))
	}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, port)
	c.Write(req)
	var rep [10]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		t.Fatalf("reply: %v", err)
	}
	if rep[0] != 5 || rep[3] != 1 || !bytes.Equal(rep[4:], make([]byte, 6)) {
		t.Fatalf("bad reply %v", rep)
	}
	return c, rep[1]
}

func TestSOCKS5ConnectRawProtocol(t *testing.T) {
	p := testProxy(t, &fakeDialer{echo: startEcho(t)})
	for _, methods := range [][]byte{{0}, {2}, {2, 0}} {
		c, code := socksConnect(t, p.Addr().String(), 3, []byte(strings.ToUpper(testDomain())), 7000, 1, methods...)
		if code != 0 {
			t.Fatalf("methods %v: code %d", methods, code)
		}
		msg := []byte{0, 1, 2, 3, 0xff, 0xfe, 'x'}
		c.Write(msg)
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("echo: %v %v", got, err)
		}
		c.Close()
	}
}

func TestSOCKS5ReplyCodes(t *testing.T) {
	p := testProxy(t, &fakeDialer{echo: startEcho(t)})
	addr := p.Addr().String()
	dom := []byte(testDomain())
	for port, want := range map[uint16]byte{7001: 5, 7002: 5, 7003: 4, 7004: 4, 7005: 1, 0: 1} {
		c, code := socksConnect(t, addr, 3, dom, port, 1)
		c.Close()
		if code != want {
			t.Errorf("port %d: code %d, want %d", port, code, want)
		}
	}
	for name, tc := range map[string]struct {
		atyp byte
		host []byte
	}{
		"ipv4":      {1, []byte{127, 0, 0, 1}},
		"ipv6":      {4, net.IPv6loopback},
		"foreign":   {3, []byte("example.com")},
		"suffix":    {3, []byte(testDomain() + ".evil")},
		"ip string": {3, []byte("127.0.0.1")},
	} {
		c, code := socksConnect(t, addr, tc.atyp, tc.host, 80, 1)
		c.Close()
		if code != 2 {
			t.Errorf("%s: code %d, want 2", name, code)
		}
	}
	for _, cmd := range []byte{2, 3} { // BIND, UDP ASSOCIATE
		c, code := socksConnect(t, addr, 3, dom, 80, cmd)
		c.Close()
		if code != 7 {
			t.Errorf("cmd %d: code %d, want 7", cmd, code)
		}
	}
}

func TestSOCKS5NoAcceptableMethodAndSOCKS4(t *testing.T) {
	p := testProxy(t, &fakeDialer{echo: startEcho(t)})
	c, _ := net.Dial("tcp", p.Addr().String())
	defer c.Close()
	c.Write([]byte{5, 1, 0x01}) // GSSAPI only
	var sel [2]byte
	if _, err := io.ReadFull(c, sel[:]); err != nil || sel[1] != 0xff {
		t.Fatalf("selection %v %v", sel, err)
	}
	c4, _ := net.Dial("tcp", p.Addr().String())
	defer c4.Close()
	c4.Write([]byte{4, 1, 0, 80, 1, 2, 3, 4, 0})
	_ = c4.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := c4.Read(make([]byte, 8)); n != 0 || err == nil {
		t.Fatalf("SOCKS4 not closed: %d %v", n, err)
	}
}

func TestSOCKS5AbortedHandshakeDoesNotLeak(t *testing.T) {
	p := testProxy(t, &fakeDialer{echo: startEcho(t)})
	for _, partial := range [][]byte{{5}, {5, 2, 0}, {5, 1, 0, 5, 1, 0, 3, 40, 'a'}} {
		c, _ := net.Dial("tcp", p.Addr().String())
		c.Write(partial)
		c.Close()
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		p.mu.Lock()
		n := len(p.connections)
		p.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d connections leaked", n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestSOCKS5HandshakeTimeoutAndClose(t *testing.T) {
	p := testProxy(t, &fakeDialer{echo: startEcho(t)})
	c, _ := net.Dial("tcp", p.Addr().String())
	defer c.Close()
	c.Write([]byte{5}) // then silence
	time.Sleep(100 * time.Millisecond)
	// An established tunnel is closed by Proxy.Close.
	tun, code := socksConnect(t, p.Addr().String(), 3, []byte(testDomain()), 7000, 1)
	if code != 0 {
		t.Fatal(code)
	}
	defer tun.Close()
	p.Close()
	_ = tun.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := tun.Read(make([]byte, 1)); err == nil {
		t.Fatal("tunnel survived Proxy.Close")
	}
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("pending handshake survived Proxy.Close")
	}
}

func TestSOCKSAndHTTPShareOnePort(t *testing.T) {
	echo := startEcho(t)
	calls := make(chan string, 8)
	p := testProxy(t, &fakeDialer{echo: echo, calls: calls})
	dom := testDomain()
	// SOCKS5 and a plain HTTP request on the same listener.
	c, code := socksConnect(t, p.Addr().String(), 3, []byte(dom), 7000, 1)
	if code != 0 {
		t.Fatal(code)
	}
	c.Close()
	res, err := http.Get("http://" + p.Addr().String() + "/proxy.pac")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(body), "PROXY ") {
		t.Fatalf("PAC: %q", body)
	}
}

func TestHTTPConnectAnyPort(t *testing.T) {
	echo := startEcho(t)
	p := testProxy(t, &fakeDialer{echo: echo})
	dom := testDomain()
	connect := func(target string) (int, *bufio.Reader, net.Conn) {
		c, err := net.Dial("tcp", p.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		io.WriteString(c, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
		br := bufio.NewReader(c)
		res, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		return res.StatusCode, br, c
	}
	status, br, c := connect(dom + ":7000")
	if status != 200 {
		t.Fatalf("status %d", status)
	}
	io.WriteString(c, "raw\x00bytes")
	got := make([]byte, 9)
	if _, err := io.ReadFull(br, got); err != nil || string(got) != "raw\x00bytes" {
		t.Fatalf("echo %q %v", got, err)
	}
	c.Close()
	for target, want := range map[string]int{"example.com:443": 403, "127.0.0.1:22": 403, dom + ":7001": 502, dom + ":7002": 502, dom + ":7004": 504, dom + ":0": 400} {
		status, _, c := connect(target)
		c.Close()
		if status != want {
			t.Errorf("%s: status %d, want %d", target, status, want)
		}
	}
}

func TestHTTPAbsoluteURIOnNonDefaultPort(t *testing.T) {
	var seen chan string = make(chan string, 4)
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				seen <- req.Host
				io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
			}()
		}
	}()
	p := testProxy(t, &fakeDialer{echo: backend.Addr().String()})
	proxyURL, _ := url.Parse("http://" + p.Addr().String())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 10 * time.Second}
	dom := testDomain()
	res, err := client.Get("http://" + dom + ":8081/x")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || string(body) != "ok" {
		t.Fatalf("%d %q", res.StatusCode, body)
	}
	if host := <-seen; host != dom+":8081" {
		t.Fatalf("backend saw Host %q", host)
	}
	res, err = client.Get("http://" + dom + "/")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if host := <-seen; host != dom {
		t.Fatalf("default port Host %q", host)
	}
}
