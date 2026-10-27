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
	"net"
	"slices"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// ServiceConfig exposes only explicitly configured virtual ports. An HTTP
// service requires just LocalAddr, e.g. 127.0.0.1:8080. TLSLocalAddr is an
// optional existing HTTPS backend for browser CONNECT requests on port 443.
type ServiceConfig struct {
	ServiceID    string
	LocalAddr    string
	TLSLocalAddr string `json:",omitempty"`
}

type HostedService struct {
	g                    *Garlic
	cfg                  ServiceConfig
	gid                  GID
	serviceID            []byte
	pc                   *sitePacketConn
	route                *siteRoute
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

func siteQUICConfig() *quic.Config {
	return &quic.Config{HandshakeIdleTimeout: 15 * time.Second, MaxIdleTimeout: 60 * time.Second, KeepAlivePeriod: 15 * time.Second, MaxIncomingStreams: 4, MaxIncomingUniStreams: -1, InitialPacketSize: 1200, DisablePathMTUDiscovery: true, MaxStreamReceiveWindow: 256 << 10, MaxConnectionReceiveWindow: 1 << 20}
}

func siteCertificate(id *Identity, domain string) (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, id.SigningPublicKey, id.SigningPrivateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: id.SigningPrivateKey}, nil
}

func (g *Garlic) StartService(cfg ServiceConfig) (*HostedService, error) {
	serviceID, err := hex.DecodeString(cfg.ServiceID)
	if err != nil {
		return nil, fmt.Errorf("invalid serviceId: %w", err)
	}
	if len(serviceID) > maxServiceIDSize {
		return nil, ErrServiceIDTooLarge
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
	gid := ComputeGID(g.identity.SigningPublicKey, serviceID)
	cert, err := siteCertificate(g.identity, gid.Domain())
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(g.sites.ctx)
	h := &HostedService{g: g, cfg: cfg, gid: gid, serviceID: serviceID, ctx: ctx, cancel: cancel, ready: make(chan struct{}), wake: make(chan struct{}, 1), connections: make(chan struct{}, 64), streams: make(chan struct{}, 128), route: &siteRoute{g: g}}
	h.pc, err = newSitePacketConn(g, gid, true, h.route)
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

func (h *HostedService) maintain() {
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
		delay := max(250*time.Millisecond, min(45*time.Second, h.route.rotationInterval()/2))
		if err != nil {
			delay = 2 * time.Second
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

func (h *HostedService) refresh() error {
	ctx, cancel := context.WithTimeout(h.ctx, 20*time.Second)
	defer cancel()
	h.route.mu.Lock()
	defer h.route.mu.Unlock()
	select {
	case <-h.ctx.Done():
		return h.ctx.Err()
	default:
	}
	if len(h.route.gateway) == 0 {
		peers := h.g.KnownPeers()
		// Independent cryptographic random order per service; no global guard
		// or fixed relay is shared by all services on a physical node.
		for i := len(peers) - 1; i > 0; i-- {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
			if err != nil {
				return err
			}
			j := int(n.Int64())
			peers[i], peers[j] = peers[j], peers[i]
		}
		for _, p := range peers {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			cap, err := h.g.queryCapabilityContext(ctx, p.NodeKey)
			if err != nil || !slices.Contains(cap.Versions, CapabilitySites) {
				continue
			}
			id, err := h.g.createSiteCircuitContext(ctx, p.NodeKey)
			if err != nil {
				continue
			}
			h.route.gateway = bytes.Clone(p.NodeKey)
			h.route.circuit = id
			h.route.current.Store(&id)
			h.route.created = time.Now()
			break
		}
		if len(h.route.gateway) == 0 {
			return ErrDirectoryUnavailable
		}
	} else if err := h.route.ensureLocked(ctx); err != nil {
		return err
	}
	now := uint64(time.Now().Unix())
	d, err := SignServiceDescriptor(h.g.identity.SigningPublicKey, h.g.identity.SigningPrivateKey, h.serviceID, []IntroPoint{{NodeKey: h.route.gateway}}, now, now+180)
	if err != nil {
		return err
	}
	if err := h.g.sites.register(ctx, h.route.circuit, h.route.gateway, d); err != nil {
		h.g.CloseCircuit(h.route.circuit)
		h.route.circuit = CircuitID{}
		h.route.current.Store(nil)
		h.route.gateway = nil
		return err
	}
	// Directory RPCs construct independent circuits, avoiding publication
	// over the service's data circuit. The fixed relay remains stable while
	// that circuit rotates, so live QUIC streams retain their endpoint.
	return h.g.rendezvous.Publish(h.gid, d)
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
		h.route.close()
		h.g.sites.mu.Lock()
		if h.g.sites.hosts[h.gid] == h {
			delete(h.g.sites.hosts, h.gid)
		}
		h.g.sites.mu.Unlock()
	})
	return nil
}

type ServiceStatus struct {
	Domain        string `json:"domain"`
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
		s := ServiceStatus{Domain: h.Domain(), Published: !h.lastPublished.IsZero() && time.Since(h.lastPublished) < 180*time.Second}
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

type siteConn struct {
	*quic.Stream
	conn      *quic.Conn
	transport *quic.Transport
	pc        *sitePacketConn
	once      sync.Once
}

func (c *siteConn) LocalAddr() net.Addr  { return c.pc.LocalAddr() }
func (c *siteConn) RemoteAddr() net.Addr { return flowAddr(c.pc.id) }
func (c *siteConn) Close() error {
	c.once.Do(func() {
		c.Stream.CancelRead(0)
		c.Stream.Close()
		c.conn.CloseWithError(0, "")
		c.pc.Close()
		c.transport.Close()
	})
	return nil
}

// DialService authenticates the site's end-to-end TLS key against its GID,
// then opens a reliable stream to an explicitly hosted virtual port.
func (g *Garlic) DialService(ctx context.Context, domain string, port uint16) (net.Conn, error) {
	if port != 80 && port != 443 {
		return nil, errors.New("garlic: unsupported virtual port")
	}
	gid, err := ParseDomain(domain)
	if err != nil {
		return nil, err
	}
	var d *ServiceDescriptor
	if directory, ok := g.rendezvous.(*NetworkRendezvous); ok {
		d, err = directory.LookupContext(ctx, gid)
	} else {
		d, err = g.rendezvous.Lookup(gid)
	}
	if err != nil {
		return nil, err
	}
	if err := VerifyServiceDescriptor(d, gid, uint64(time.Now().Unix())); err != nil {
		return nil, err
	}
	if len(d.IntroPoints) == 0 {
		return nil, ErrGIDNotFound
	}
	var last error
	for i, p := range d.IntroPoints {
		if i >= 3 {
			break
		}
		conn, err := g.dialSiteRelay(ctx, gid, d, p.NodeKey, port)
		if err == nil {
			return conn, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, last
}

func (g *Garlic) dialSiteRelay(ctx context.Context, gid GID, d *ServiceDescriptor, gateway []byte, port uint16) (net.Conn, error) {
	if len(gateway) != ed25519.PublicKeySize {
		return nil, ErrInvalidPath
	}
	route := &siteRoute{g: g, gateway: bytes.Clone(gateway)}
	pc, err := newSitePacketConn(g, gid, false, route)
	if err != nil {
		return nil, err
	}
	g.sites.mu.Lock()
	if len(g.sites.clients) >= 64 {
		g.sites.mu.Unlock()
		pc.Close()
		return nil, errors.New("garlic: client capacity reached")
	}
	g.sites.clients[pc.id] = pc
	g.sites.mu.Unlock()
	tr := &quic.Transport{Conn: pc}
	ok := false
	defer func() {
		if !ok {
			pc.Close()
			tr.Close()
		}
	}()
	tlsConf := &tls.Config{ServerName: gid.Domain(), NextProtos: []string{"yggg-site-v1"}, MinVersion: tls.VersionTLS13, InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) != 1 {
				return errors.New("garlic: invalid site certificate")
			}
			cert := state.PeerCertificates[0]
			key, ok := cert.PublicKey.(ed25519.PublicKey)
			if !ok || !bytes.Equal(key, d.ServicePublicKey) || ComputeGID(key, d.ServiceID) != gid {
				return ErrDescriptorGIDMismatch
			}
			roots := x509.NewCertPool()
			roots.AddCert(cert)
			if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
				return err
			}
			_, err := cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: gid.Domain(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
			return err
		}}
	conn, err := tr.Dial(ctx, flowAddr(pc.id), tlsConf, siteQUICConfig())
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		conn.CloseWithError(0, "")
		return nil, err
	}
	site := &siteConn{Stream: stream, conn: conn, transport: tr, pc: pc}
	deadline := time.Now().Add(15 * time.Second)
	if t, ok := ctx.Deadline(); ok {
		deadline = minTime(deadline, t)
	}
	_ = stream.SetDeadline(deadline)
	var header [2]byte
	binary.BigEndian.PutUint16(header[:], port)
	if _, err = stream.Write(header[:]); err == nil {
		var status [1]byte
		_, err = io.ReadFull(stream, status[:])
		if err == nil && status[0] != 1 {
			err = errors.New("garlic: service backend unavailable")
		}
	}
	if err != nil {
		site.Close()
		return nil, err
	}
	_ = stream.SetDeadline(time.Time{})
	ok = true
	return site, nil
}
