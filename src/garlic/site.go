package garlic

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand/v2"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// ServiceConfig exposes only explicitly configured virtual ports. An HTTP
// service requires just LocalAddr, e.g. 127.0.0.1:8080. TLSLocalAddr is an
// optional existing HTTPS backend for browser CONNECT requests on port 443.
// Name selects the site's own signing key (see SiteSigningKey): sites with
// different names cannot be linked to each other.
type ServiceConfig struct {
	Name         string `json:",omitempty"`
	ServiceID    string
	LocalAddr    string
	TLSLocalAddr string `json:",omitempty"`
}

type HostedService struct {
	g                    *Garlic
	cfg                  ServiceConfig
	key                  ed25519.PrivateKey // this site's own signing key
	gid                  GID
	serviceID            []byte
	pc                   *sitePacketConn
	routes               []*siteRoute // one per intro point (siteIntroPoints)
	introPoints          int          // relays in the last published descriptor
	transport            *quic.Transport
	listener             *quic.Listener
	ctx                  context.Context
	cancel               context.CancelFunc
	ready                chan struct{}
	wake                 chan struct{}
	readyOnce, closeOnce sync.Once
	mu                   sync.Mutex
	lastError            error
	lastPublished        time.Time
	connections, streams chan struct{}
}

// siteQUICConfig: site packets carry up to 2048 bytes of QUIC (see the
// site router), so 1400-byte packets fit with room for headers. Receive
// windows bound throughput to window/RTT, and a site path crosses six
// relays: 256 KiB per stream allowed only ~0.5 MiB/s at a 0.5 s RTT.
// quic-go grows a window from its initial size only as far as the
// application needs it, so the larger maximum costs memory only while a
// reader falls behind.
func siteQUICConfig() *quic.Config {
	return &quic.Config{HandshakeIdleTimeout: 15 * time.Second, MaxIdleTimeout: 60 * time.Second, KeepAlivePeriod: 15 * time.Second, MaxIncomingStreams: 32, MaxIncomingUniStreams: -1, InitialPacketSize: 1400, DisablePathMTUDiscovery: true, MaxStreamReceiveWindow: 4 << 20, MaxConnectionReceiveWindow: 8 << 20}
}

// siteCertificate is the site's self-signed TLS certificate. Clients check
// its key against the GID, not its dates; the dates are fixed so that a
// certificate does not reveal when the node started (which would link all
// sites started together).
var (
	siteCertNotBefore = time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)
	siteCertNotAfter  = time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC)
)

func siteCertificate(key ed25519.PrivateKey, domain string) (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain}, NotBefore: siteCertNotBefore, NotAfter: siteCertNotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// StartService hosts a site in any mode. In relay mode the site is still
// reached only through circuits and its descriptor names a different relay,
// but a public relay's uptime is visible to everyone and can be compared
// with the site's (see docs/garlic-quickstart.md).
func (g *Garlic) StartService(cfg ServiceConfig) (*HostedService, error) {
	serviceID, err := hex.DecodeString(cfg.ServiceID)
	if err != nil {
		return nil, fmt.Errorf("invalid serviceId: %w", err)
	}
	key, err := SiteSigningKey(g.identity.SigningPrivateKey, cfg.Name, serviceID)
	if err != nil {
		return nil, err
	}
	if cfg.LocalAddr == "" && cfg.TLSLocalAddr == "" {
		return nil, errors.New("garlic: a service needs LocalAddr or TLSLocalAddr")
	}
	for _, addr := range []string{cfg.LocalAddr, cfg.TLSLocalAddr} {
		if addr != "" {
			if _, _, err := net.SplitHostPort(addr); err != nil {
				return nil, fmt.Errorf("invalid local service address: %w", err)
			}
		}
	}
	gid := ComputeGID(key.Public().(ed25519.PublicKey), serviceID)
	cert, err := siteCertificate(key, gid.Domain())
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(g.sites.ctx)
	h := &HostedService{g: g, cfg: cfg, key: key, gid: gid, serviceID: serviceID, ctx: ctx, cancel: cancel, ready: make(chan struct{}), wake: make(chan struct{}, 1), connections: make(chan struct{}, 64), streams: make(chan struct{}, 128)}
	for range siteIntroPoints {
		h.routes = append(h.routes, &siteRoute{g: g})
	}
	h.pc, err = newSitePacketConn(g, gid, true, nil)
	if err == nil {
		h.pc.hostRoutes = &hostRouting{routes: h.routes, flows: make(map[CircuitID]flowRoute)}
		h.pc.startCover()
	}
	if err != nil {
		cancel()
		return nil, err
	}
	h.transport = &quic.Transport{Conn: h.pc}
	h.listener, err = h.transport.Listen(&tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"yggg-site-v1"}, MinVersion: tls.VersionTLS13}, siteQUICConfig())
	if err != nil {
		cancel()
		h.pc.Close()
		h.transport.Close()
		return nil, err
	}
	g.sites.mu.Lock()
	if _, exists := g.sites.hosts[gid]; exists || len(g.sites.hosts) >= 64 {
		g.sites.mu.Unlock()
		h.Close()
		return nil, errors.New("garlic: duplicate service or hosting capacity reached")
	}
	g.sites.hosts[gid] = h
	g.sites.mu.Unlock()
	go h.accept()
	go h.maintain()
	return h, nil
}

func (h *HostedService) Domain() string         { return h.gid.Domain() }
func (h *HostedService) Ready() <-chan struct{} { return h.ready }
func (h *HostedService) LastError() error       { h.mu.Lock(); defer h.mu.Unlock(); return h.lastError }

// siteJitter spreads d over [d/2, 3d/2). A node hosting several sites must
// not publish them in lockstep: matching publication times would link the
// sites to each other.
func siteJitter(d time.Duration) time.Duration {
	return d/2 + time.Duration(mrand.Int64N(int64(d)+1))
}

func (h *HostedService) maintain() {
	// Sites started together (at boot) begin publishing at independent
	// random moments.
	start := time.NewTimer(time.Duration(mrand.Int64N(int64(5 * time.Second))))
	select {
	case <-h.ctx.Done():
		start.Stop()
		return
	case <-start.C:
	}
	for {
		err := h.refresh()
		h.mu.Lock()
		h.lastError = err
		if err == nil {
			h.lastPublished = time.Now()
		}
		h.mu.Unlock()
		if err == nil {
			h.readyOnce.Do(func() { close(h.ready) })
		}
		delay := siteJitter(max(250*time.Millisecond, min(45*time.Second, h.routes[0].rotationInterval()/2)))
		if err != nil {
			delay = siteJitter(2 * time.Second)
		}
		t := time.NewTimer(delay)
		select {
		case <-h.ctx.Done():
			t.Stop()
			return
		case <-t.C:
		case <-h.wake:
			t.Stop()
		}
	}
}

// siteIntroPoints is how many different site relays a host keeps: each
// slot has its own circuit, and the descriptor lists all of them, so
// clients reach the site over several independent routes.
const siteIntroPoints = 2

func (h *HostedService) refresh() error {
	ctx, cancel := context.WithTimeout(h.ctx, 20*time.Second)
	defer cancel()
	select {
	case <-h.ctx.Done():
		return h.ctx.Err()
	default:
	}
	// 1. Every slot gets a working circuit to its own relay. Route locks
	// are held only while a slot's circuit changes, never during the
	// registration and directory round trips below, so site traffic keeps
	// flowing while the site is republished.
	var slotErr error
	for _, r := range h.routes {
		if err := h.ensureSlot(ctx, r); err != nil {
			slotErr = err
		}
	}
	type slot struct {
		route   *siteRoute
		gateway []byte
		circuit CircuitID
		point   IntroPoint
	}
	var live []slot
	for _, r := range h.routes {
		r.mu.Lock()
		gateway, circuit := bytes.Clone(r.gateway), r.circuit
		r.mu.Unlock()
		if len(gateway) == 0 || circuit == (CircuitID{}) {
			continue
		}
		relayInfo := h.g.relayInfoRaw(gateway)
		if relayInfo == nil {
			h.resetSlot(r, circuit)
			slotErr = ErrUnknownRelay
			continue
		}
		live = append(live, slot{r, gateway, circuit, IntroPoint{NodeKey: gateway, RelayInfo: relayInfo}})
	}
	if len(live) == 0 {
		return slotErr
	}
	// 2. One descriptor listing every relay; each relay registers it.
	now := uint64(time.Now().Unix())
	pub := h.key.Public().(ed25519.PublicKey)
	points := make([]IntroPoint, len(live))
	for i, l := range live {
		points[i] = l.point
	}
	d, err := SignServiceDescriptor(pub, h.key, h.serviceID, points, now, now+180)
	if err != nil {
		return err
	}
	var registered []IntroPoint
	var regErr error
	for _, l := range live {
		if err := h.g.sites.register(ctx, l.circuit, l.gateway, d, h.key); err != nil {
			h.resetSlot(l.route, l.circuit)
			regErr = err
			continue
		}
		registered = append(registered, l.point)
	}
	if len(registered) == 0 {
		return regErr
	}
	if len(registered) < len(points) {
		// Publish only the relays that accepted the registration.
		if d, err = SignServiceDescriptor(pub, h.key, h.serviceID, registered, now, now+180); err != nil {
			return err
		}
	}
	h.mu.Lock()
	h.introPoints = len(registered)
	h.mu.Unlock()
	// Directory RPCs construct independent circuits, avoiding publication
	// over the service's data circuits. The relays remain stable while
	// their circuits rotate, so live QUIC streams retain their endpoints.
	return h.g.rendezvous.Publish(h.gid, d)
}

// ensureSlot gives route a working circuit: to a relay of its own if it has
// none yet (never the guard, which already knows this node, and never
// another slot's relay), otherwise by rotating its circuit when due.
func (h *HostedService) ensureSlot(ctx context.Context, route *siteRoute) error {
	taken := map[string]bool{}
	if guard := h.g.CurrentGuard(); guard != nil {
		taken[string(guard)] = true
	}
	for _, other := range h.routes {
		if other == route {
			continue
		}
		other.mu.Lock()
		if len(other.gateway) > 0 {
			taken[string(other.gateway)] = true
		}
		other.mu.Unlock()
	}
	route.mu.Lock()
	defer route.mu.Unlock()
	if len(route.gateway) > 0 {
		return route.ensureLocked(ctx)
	}
	// Candidate relays come only from verified relay information held
	// locally; none of them is contacted before the circuit is built. The
	// order is random per slot, weighted towards relays that have been
	// working (recent failures push a relay back).
	var keys [][]byte
	for _, p := range h.g.KnownPeers() {
		if taken[string(p.NodeKey)] {
			continue
		}
		if c, ok := h.g.knownRelay(p.NodeKey); ok && needSites(c) {
			keys = append(keys, p.NodeKey)
		}
	}
	var circuitErr error
	for _, key := range h.g.orderByHealth(keys) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		id, err := h.g.createSiteCircuitContext(ctx, key)
		if err != nil {
			circuitErr = err
			continue
		}
		route.gateway = bytes.Clone(key)
		route.circuit = id
		route.current.Store(&id)
		route.created = time.Now()
		return nil
	}
	switch {
	case len(h.g.trustedPeerKeys()) == 0:
		return ErrNoTrustedPeers
	case len(keys) == 0:
		return errors.New("garlic: no usable relay known yet besides the trusted guard (waiting for gossip from trusted peers)")
	case circuitErr != nil:
		return fmt.Errorf("garlic: could not build a circuit to any site relay: %w", circuitErr)
	default:
		return ErrDirectoryUnavailable
	}
}

// resetSlot drops route's relay if it still uses circuit, so the next
// refresh picks a relay again.
func (h *HostedService) resetSlot(route *siteRoute, circuit CircuitID) {
	route.mu.Lock()
	defer route.mu.Unlock()
	if route.circuit != circuit {
		return
	}
	h.g.CloseCircuit(route.circuit)
	route.circuit = CircuitID{}
	route.current.Store(nil)
	route.gateway = nil
}

func (h *HostedService) accept() {
	for {
		conn, err := h.listener.Accept(h.ctx)
		if err != nil {
			return
		}
		select {
		case h.connections <- struct{}{}:
			go func() {
				defer func() { <-h.connections }()
				defer conn.CloseWithError(0, "")
				for {
					stream, err := conn.AcceptStream(h.ctx)
					if err != nil {
						return
					}
					select {
					case h.streams <- struct{}{}:
						go func() { defer func() { <-h.streams }(); h.serveStream(conn, stream) }()
					default:
						stream.CancelRead(1)
						stream.CancelWrite(1)
					}
				}
			}()
		default:
			conn.CloseWithError(1, "busy")
		}
	}
}

func (h *HostedService) serveStream(conn *quic.Conn, stream *quic.Stream) {
	defer stream.Close()
	defer stream.CancelRead(0)
	_ = stream.SetReadDeadline(time.Now().Add(15 * time.Second))
	var port [2]byte
	if _, err := io.ReadFull(stream, port[:]); err != nil {
		return
	}
	addr := ""
	switch binary.BigEndian.Uint16(port[:]) {
	case 80:
		addr = h.cfg.LocalAddr
	case 443:
		addr = h.cfg.TLSLocalAddr
	}
	if addr == "" {
		_, _ = stream.Write([]byte{0})
		return
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	backend, err := dialer.DialContext(h.ctx, "tcp", addr)
	if err != nil {
		_, _ = stream.Write([]byte{0})
		return
	}
	defer backend.Close()
	stop := context.AfterFunc(conn.Context(), func() { backend.Close() })
	defer stop()
	_ = stream.SetReadDeadline(time.Time{})
	if _, err := stream.Write([]byte{1}); err != nil {
		return
	}
	done := make(chan struct{})
	go func() { _, _ = io.Copy(stream, backend); _ = stream.Close(); close(done) }()
	_, _ = io.Copy(backend, stream)
	if tcp, ok := backend.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	<-done
}

func (h *HostedService) Close() error {
	h.closeOnce.Do(func() {
		h.cancel()
		h.listener.Close()
		h.pc.Close()
		h.transport.Close()
		for _, r := range h.routes {
			r.close()
		}
		h.g.sites.mu.Lock()
		if h.g.sites.hosts[h.gid] == h {
			delete(h.g.sites.hosts, h.gid)
		}
		h.g.sites.mu.Unlock()
	})
	return nil
}

type ServiceStatus struct {
	Name          string `json:"name,omitempty"`
	Domain        string `json:"domain"`
	IntroPoints   int    `json:"introPoints"`
	Published     bool   `json:"published"`
	LastPublished string `json:"lastPublished,omitempty"`
	Error         string `json:"error,omitempty"`
}

func (g *Garlic) HostedServices() []ServiceStatus {
	g.sites.mu.Lock()
	hosts := make([]*HostedService, 0, len(g.sites.hosts))
	for _, h := range g.sites.hosts {
		hosts = append(hosts, h)
	}
	g.sites.mu.Unlock()
	status := make([]ServiceStatus, 0, len(hosts))
	for _, h := range hosts {
		h.mu.Lock()
		s := ServiceStatus{Name: h.cfg.Name, Domain: h.Domain(), IntroPoints: h.introPoints, Published: !h.lastPublished.IsZero() && time.Since(h.lastPublished) < 180*time.Second}
		if !h.lastPublished.IsZero() {
			s.LastPublished = h.lastPublished.UTC().Format(time.RFC3339)
		}
		if h.lastError != nil {
			s.Error = h.lastError.Error()
		}
		h.mu.Unlock()
		status = append(status, s)
	}
	slices.SortFunc(status, func(a, b ServiceStatus) int { return bytes.Compare([]byte(a.Domain), []byte(b.Domain)) })
	return status
}
