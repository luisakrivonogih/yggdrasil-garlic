package garlic

import (
	"context"
	"crypto/rand"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type sitePacket struct {
	peer CircuitID
	body []byte
}

// These synthetic IPv6 addresses exist only inside QUIC's PacketConn. They
// are random flow tokens, never OS-routed sockets or actual node addresses.
func flowAddr(id CircuitID) net.Addr {
	return &net.UDPAddr{IP: net.IP(append([]byte(nil), id[:]...)), Port: 1}
}

type siteRoute struct {
	g       *Garlic
	mu      sync.Mutex
	gateway []byte
	circuit CircuitID
	created time.Time
	current atomic.Pointer[CircuitID]
	ctx     context.Context
}

func (r *siteRoute) ensureLocked(ctx context.Context) error {
	if r.circuit != (CircuitID{}) && time.Since(r.created) < r.rotationInterval() {
		if c, ok := r.g.circuits.Get(r.circuit); ok && !c.IsClosed() && time.Now().Before(c.ExpiresAt) {
			packets, bytes := c.TrafficStats()
			if packets < c.MaxPackets*4/5 && bytes < c.MaxBytes*4/5 {
				return nil
			}
		}
	}
	id, err := r.g.createSiteCircuitContext(ctx, r.gateway)
	if err != nil {
		return err
	}
	old := r.circuit
	r.circuit = id
	r.current.Store(&id)
	r.created = time.Now()
	if old != (CircuitID{}) {
		r.g.CloseCircuit(old)
	}
	return nil
}

func (r *siteRoute) rotationInterval() time.Duration {
	return min(90*time.Second, r.g.cfg.CircuitLifetime*2/3)
}

func (r *siteRoute) send(body []byte, host bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if host {
		if r.circuit == (CircuitID{}) {
			return ErrCircuitNotFound
		}
	} else {
		ctx := r.ctx
		if ctx == nil {
			ctx = r.g.sites.ctx
		}
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		if err := r.ensureLocked(ctx); err != nil {
			return err
		}
	}
	err := r.g.sendDuplex(r.circuit, body)
	if err != nil && host {
		r.g.sites.mu.Lock()
		var h *HostedService
		for _, candidate := range r.g.sites.hosts {
			if candidate.route == r {
				h = candidate
				break
			}
		}
		r.g.sites.mu.Unlock()
		if h != nil {
			select {
			case h.wake <- struct{}{}:
			default:
			}
		}
		// QUIC retransmits after the hosting loop registers a replacement.
		return nil
	}
	return err
}

func (r *siteRoute) accepts(id CircuitID) bool {
	current := r.current.Load()
	return current != nil && *current == id
}
func (r *siteRoute) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.circuit != (CircuitID{}) {
		r.g.CloseCircuit(r.circuit)
		r.circuit = CircuitID{}
		r.current.Store(nil)
	}
}

type sitePacketConn struct {
	g                           *Garlic
	gid                         GID
	id                          CircuitID
	secret                      [32]byte
	host                        bool
	route                       *siteRoute
	in                          chan sitePacket
	ctx                         context.Context
	cancel                      context.CancelFunc
	once                        sync.Once
	mu                          sync.Mutex
	readDeadline, writeDeadline time.Time
	wake                        chan struct{}
}

func newSitePacketConn(g *Garlic, gid GID, host bool, route *siteRoute) (*sitePacketConn, error) {
	id, err := randomCircuitID()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(g.sites.ctx)
	route.ctx = ctx
	p := &sitePacketConn{g: g, gid: gid, id: id, host: host, route: route, in: make(chan sitePacket, 128), ctx: ctx, cancel: cancel, wake: make(chan struct{})}
	if _, err := rand.Read(p.secret[:]); err != nil {
		cancel()
		return nil, err
	}
	return p, nil
}

func (p *sitePacketConn) deliver(id CircuitID, body []byte) {
	if len(body) > 2048 {
		return
	}
	copyBody := append([]byte(nil), body...)
	select {
	case <-p.ctx.Done():
		return
	default:
	}
	select {
	case p.in <- sitePacket{id, copyBody}:
	default:
	}
}

func (p *sitePacketConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	for {
		p.mu.Lock()
		deadline, wake := p.readDeadline, p.wake
		p.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			if time.Now().After(deadline) {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		select {
		case packet := <-p.in:
			if timer != nil {
				timer.Stop()
			}
			return copy(buf, packet.body), flowAddr(packet.peer), nil
		case <-p.ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, net.ErrClosed
		case <-wake:
			if timer != nil {
				timer.Stop()
			}
		case <-timeout:
			return 0, nil, os.ErrDeadlineExceeded
		}
	}
}

func (p *sitePacketConn) WriteTo(body []byte, addr net.Addr) (int, error) {
	select {
	case <-p.ctx.Done():
		return 0, net.ErrClosed
	default:
	}
	p.mu.Lock()
	deadline := p.writeDeadline
	p.mu.Unlock()
	if !deadline.IsZero() && time.Now().After(deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	a, ok := addr.(*net.UDPAddr)
	if !ok || a.Port != 1 || len(a.IP.To16()) != 16 || len(body) > 2048 {
		return 0, net.InvalidAddrError("invalid garlic flow")
	}
	var peer CircuitID
	copy(peer[:], a.IP.To16())
	var packet []byte
	if p.host {
		packet = append([]byte{siteServerPacket}, p.gid[:]...)
		packet = append(packet, peer[:]...)
	} else {
		if peer != p.id {
			return 0, net.InvalidAddrError("wrong garlic flow")
		}
		packet = append([]byte{siteClientPacket}, p.gid[:]...)
		packet = append(packet, p.id[:]...)
		packet = append(packet, p.secret[:]...)
	}
	packet = append(packet, body...)
	if err := p.route.send(packet, p.host); err != nil {
		return 0, err
	}
	return len(body), nil
}

func (p *sitePacketConn) Close() error {
	p.once.Do(func() {
		p.cancel()
		if !p.host {
			p.g.sites.mu.Lock()
			delete(p.g.sites.clients, p.id)
			p.g.sites.mu.Unlock()
			p.route.close()
		}
	})
	return nil
}
func (p *sitePacketConn) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv6loopback, Port: 1} }
func (p *sitePacketConn) SetDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.readDeadline = t
	p.writeDeadline = t
	close(p.wake)
	p.wake = make(chan struct{})
	return nil
}
func (p *sitePacketConn) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.readDeadline = t
	close(p.wake)
	p.wake = make(chan struct{})
	return nil
}
func (p *sitePacketConn) SetWriteDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.writeDeadline = t
	return nil
}

// There is no kernel UDP socket here. Buffering is the bounded packet
// queue above; QUIC's optional socket buffer tuning does not apply.
func (p *sitePacketConn) SetReadBuffer(int) error  { return nil }
func (p *sitePacketConn) SetWriteBuffer(int) error { return nil }
