package garlic

// Client side of site connections: one pool per site.
//
// A site's descriptor is cached until it expires, and streams share a few
// QUIC connections instead of every browser connection doing its own
// directory lookup, circuit and QUIC handshake. Each pooled connection runs
// over its own circuit - built independently, so usually through a
// different middle relay - and connections are spread over the site's
// intro points, so a site is reached over several different routes at
// once. While a site is in use a second connection is kept ready, so a new
// request rarely waits for a handshake.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	sitePoolConns   = 3  // QUIC connections per site, each on its own circuit
	sitePoolWarm    = 2  // connections kept ready while the site is in use
	sitePoolStreams = 16 // streams on a connection before another is preferred
	sitePoolIdle    = time.Minute
	maxSitePools    = 256
)

var errSiteBackend = errors.New("garlic: service backend unavailable")

type sitePool struct {
	g       *Garlic
	gid     GID
	mu      sync.Mutex
	desc    *ServiceDescriptor
	conns   []*pooledConn
	dialing int
	lookup  sync.Mutex // one directory lookup at a time per site
}

type pooledConn struct {
	pool    *sitePool
	conn    *quic.Conn
	tr      *quic.Transport
	pc      *sitePacketConn
	gateway []byte
	streams int
	idle    *time.Timer
	closed  bool
}

// pool returns the connection pool for gid.
func (r *siteRouter) pool(gid GID) *sitePool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p := r.pools[gid]; p != nil {
		return p
	}
	if len(r.pools) >= maxSitePools {
		for k, p := range r.pools {
			p.mu.Lock()
			empty := len(p.conns) == 0 && p.dialing == 0
			p.mu.Unlock()
			if empty {
				delete(r.pools, k)
			}
		}
	}
	p := &sitePool{g: r.g, gid: gid}
	r.pools[gid] = p
	return p
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
	return g.sites.pool(gid).dial(ctx, port)
}

func (p *sitePool) dial(ctx context.Context, port uint16) (net.Conn, error) {
	var last error
	for range 2 {
		c, err := p.conn(ctx)
		if err != nil {
			return nil, err
		}
		s, err := c.open(ctx, port)
		if err == nil {
			p.warm()
			return s, nil
		}
		last = err
		if errors.Is(err, errSiteBackend) || ctx.Err() != nil {
			break
		}
		// The connection is broken (its circuit died, the relay went
		// away): drop it and try another.
		p.drop(c)
	}
	return nil, last
}

// conn returns a connection with one stream reserved on it: an idle one if
// there is one, otherwise a new connection while the pool has room,
// otherwise the least loaded one.
func (p *sitePool) conn(ctx context.Context) (*pooledConn, error) {
	p.mu.Lock()
	best := p.leastLoadedLocked()
	if best != nil && (best.streams == 0 || len(p.conns)+p.dialing >= sitePoolConns) {
		p.reserveLocked(best)
		p.mu.Unlock()
		return best, nil
	}
	p.dialing++
	p.mu.Unlock()
	c, err := p.dialNew(ctx)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dialing--
	if err != nil {
		if best = p.leastLoadedLocked(); best != nil {
			p.reserveLocked(best)
			return best, nil
		}
		return nil, err
	}
	p.addLocked(c)
	p.reserveLocked(c)
	return c, nil
}

func (p *sitePool) leastLoadedLocked() *pooledConn {
	var best *pooledConn
	for _, c := range p.conns {
		if !c.closed && (best == nil || c.streams < best.streams) {
			best = c
		}
	}
	return best
}

func (p *sitePool) reserveLocked(c *pooledConn) {
	c.streams++
	if c.idle != nil {
		c.idle.Stop()
		c.idle = nil
	}
}

func (p *sitePool) addLocked(c *pooledConn) {
	c.pool = p
	p.conns = append(p.conns, c)
	go func() {
		<-c.conn.Context().Done()
		p.drop(c)
	}()
}

// warm keeps a second connection, over another route, ready while the
// site is in use.
func (p *sitePool) warm() {
	p.mu.Lock()
	live := 0
	for _, c := range p.conns {
		if !c.closed {
			live++
		}
	}
	if live+p.dialing >= sitePoolWarm {
		p.mu.Unlock()
		return
	}
	p.dialing++
	p.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(p.g.sites.ctx, 30*time.Second)
		defer cancel()
		c, err := p.dialNew(ctx)
		p.mu.Lock()
		defer p.mu.Unlock()
		p.dialing--
		if err != nil {
			return
		}
		p.addLocked(c)
		p.idleLocked(c)
	}()
}

func (p *sitePool) release(c *pooledConn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c.streams--
	if c.streams <= 0 {
		c.streams = 0
		p.idleLocked(c)
	}
}

func (p *sitePool) idleLocked(c *pooledConn) {
	if c.closed || c.idle != nil {
		return
	}
	c.idle = time.AfterFunc(sitePoolIdle, func() {
		p.mu.Lock()
		idle := c.streams == 0 && !c.closed
		p.mu.Unlock()
		if idle {
			p.drop(c)
		}
	})
}

// drop closes c and removes it from the pool.
func (p *sitePool) drop(c *pooledConn) {
	p.mu.Lock()
	if c.closed {
		p.mu.Unlock()
		return
	}
	c.closed = true
	if c.idle != nil {
		c.idle.Stop()
	}
	for i, x := range p.conns {
		if x == c {
			p.conns = append(p.conns[:i], p.conns[i+1:]...)
			break
		}
	}
	p.mu.Unlock()
	c.conn.CloseWithError(0, "")
	c.tr.Close()
	c.pc.Close()
}

func (p *sitePool) closeAll() {
	p.mu.Lock()
	conns := append([]*pooledConn(nil), p.conns...)
	p.mu.Unlock()
	for _, c := range conns {
		p.drop(c)
	}
}

// descriptor returns the site's descriptor, from the cache while it is
// valid, otherwise from the directory.
func (p *sitePool) descriptor(ctx context.Context) (*ServiceDescriptor, error) {
	cached := func() *ServiceDescriptor {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.desc != nil && VerifyServiceDescriptor(p.desc, p.gid, uint64(time.Now().Unix())) == nil {
			return p.desc
		}
		p.desc = nil
		return nil
	}
	if d := cached(); d != nil {
		return d, nil
	}
	p.lookup.Lock()
	defer p.lookup.Unlock()
	if d := cached(); d != nil {
		return d, nil
	}
	var d *ServiceDescriptor
	var err error
	if directory, ok := p.g.rendezvous.(*NetworkRendezvous); ok {
		d, err = directory.LookupContext(ctx, p.gid)
	} else {
		d, err = p.g.rendezvous.Lookup(p.gid)
	}
	if err != nil {
		return nil, err
	}
	if err := VerifyServiceDescriptor(d, p.gid, uint64(time.Now().Unix())); err != nil {
		return nil, err
	}
	if len(d.IntroPoints) == 0 {
		return nil, ErrGIDNotFound
	}
	p.mu.Lock()
	p.desc = d
	p.mu.Unlock()
	return d, nil
}

// dialNew opens a new connection over a new circuit, preferring the intro
// point this pool uses least (and, among those, healthier relays).
func (p *sitePool) dialNew(ctx context.Context) (*pooledConn, error) {
	d, err := p.descriptor(ctx)
	if err != nil {
		return nil, err
	}
	points := d.IntroPoints
	if len(points) > 3 {
		points = points[:3]
	}
	p.mu.Lock()
	use := map[string]int{}
	for _, c := range p.conns {
		if !c.closed {
			use[string(c.gateway)]++
		}
	}
	p.mu.Unlock()
	keys := make([][]byte, len(points))
	for i, ip := range points {
		keys[i] = ip.NodeKey
	}
	order := weightedOrder(p.g.health.weights(keys))
	// Least used intro points first; the weighted order breaks ties.
	for i := 1; i < len(order); i++ {
		for j := i; j > 0 && use[string(keys[order[j]])] < use[string(keys[order[j-1]])]; j-- {
			order[j], order[j-1] = order[j-1], order[j]
		}
	}
	var last error = ErrGIDNotFound
	for _, i := range order {
		ip := points[i]
		if _, err := p.g.learnRelayInfo(ip.RelayInfo, ip.NodeKey); err != nil {
			last = err
			continue
		}
		c, err := p.g.dialSiteConn(ctx, p.gid, d, ip.NodeKey)
		if err == nil {
			return c, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	// Nothing in this descriptor worked: look it up again next time.
	p.mu.Lock()
	if p.desc == d {
		p.desc = nil
	}
	p.mu.Unlock()
	return nil, last
}

// dialSiteConn establishes a QUIC connection to the site through gateway,
// over a new circuit, and authenticates the site's key against its GID.
func (g *Garlic) dialSiteConn(ctx context.Context, gid GID, d *ServiceDescriptor, gateway []byte) (*pooledConn, error) {
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
	pc.startCover()
	tr := &quic.Transport{Conn: pc}
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
	dialStart := time.Now()
	conn, err := tr.Dial(ctx, flowAddr(pc.id), tlsConf, siteQUICConfig())
	// The QUIC handshake takes about one round trip over the whole path.
	if cur := route.current.Load(); cur != nil && (err == nil || ctx.Err() == nil) {
		g.pathOutcome(*cur, err == nil, time.Since(dialStart))
	}
	if err != nil {
		pc.Close()
		tr.Close()
		return nil, err
	}
	return &pooledConn{conn: conn, tr: tr, pc: pc, gateway: bytes.Clone(gateway)}, nil
}

// open opens a stream on c (one stream must already be reserved on it) and
// asks the host for the virtual port.
func (c *pooledConn) open(ctx context.Context, port uint16) (net.Conn, error) {
	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		c.pool.release(c)
		return nil, err
	}
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
			err = errSiteBackend
		}
	}
	if err != nil {
		stream.CancelRead(0)
		stream.Close()
		c.pool.release(c)
		return nil, err
	}
	_ = stream.SetDeadline(time.Time{})
	return &siteConn{Stream: stream, c: c}, nil
}

// siteConn is one stream of a pooled connection; closing it frees the
// stream, not the connection.
type siteConn struct {
	*quic.Stream
	c    *pooledConn
	once sync.Once
}

func (s *siteConn) LocalAddr() net.Addr  { return s.c.pc.LocalAddr() }
func (s *siteConn) RemoteAddr() net.Addr { return flowAddr(s.c.pc.id) }
func (s *siteConn) Close() error {
	s.once.Do(func() {
		s.Stream.CancelRead(0)
		s.Stream.Close()
		s.c.pool.release(s.c)
	})
	return nil
}
