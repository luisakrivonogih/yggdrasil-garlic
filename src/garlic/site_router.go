package garlic

// A rendezvous relay joins two independently constructed duplex circuits.
// It forwards opaque QUIC packets. Service registration proves ownership
// of both the descriptor and the exact circuit, preventing a copied public
// descriptor from registering an attacker's circuit for someone else's GID.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"time"
)

const (
	siteRegister byte = iota + 1
	siteRegistered
	siteClientPacket
	siteToServer
	siteServerPacket
	siteToClient
	siteDirectoryRequest
	siteDirectoryResponse
)

const maxSiteFlows = 2048

type siteEvent struct {
	circuit CircuitID
	body    []byte
	reply   bool
}
type siteRegistration struct {
	Descriptor *ServiceDescriptor
	Signature  []byte
}
type siteBinding struct {
	circuit CircuitID
	expires time.Time
}
type siteFlow struct {
	gid                GID
	clientID, serverID CircuitID
	secret             [32]byte
	clientCircuit      CircuitID
	touched            time.Time
}

type siteRouter struct {
	g           *Garlic
	mu          sync.Mutex
	bindings    map[GID]siteBinding
	flows       map[CircuitID]*siteFlow
	clientFlows map[CircuitID]CircuitID
	hosts       map[GID]*HostedService
	clients     map[CircuitID]*sitePacketConn
	acks        map[CircuitID]chan bool
	queue       chan siteEvent
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

func newSiteRouter(g *Garlic) *siteRouter {
	ctx, cancel := context.WithCancel(context.Background())
	r := &siteRouter{g: g, ctx: ctx, cancel: cancel, bindings: make(map[GID]siteBinding), flows: make(map[CircuitID]*siteFlow), clientFlows: make(map[CircuitID]CircuitID), hosts: make(map[GID]*HostedService), clients: make(map[CircuitID]*sitePacketConn), acks: make(map[CircuitID]chan bool), queue: make(chan siteEvent, 256)}
	for range 4 {
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			for {
				select {
				case e := <-r.queue:
					r.handle(e)
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	return r
}

func (r *siteRouter) enqueue(id CircuitID, body []byte, reply bool) {
	if len(body) == 0 || len(body) > maxSiteDatagram {
		return
	}
	select {
	case <-r.ctx.Done():
		return
	default:
	}
	select {
	case r.queue <- siteEvent{id, bytes.Clone(body), reply}:
	default:
	}
}

func registrationBytes(gid GID, gateway []byte, circuit CircuitID) []byte {
	b := append([]byte("yggdrasil-garlic-site-registration-v1"), gid[:]...)
	b = append(b, gateway...)
	return append(b, circuit[:]...)
}

func (r *siteRouter) pruneLocked() {
	now := time.Now()
	for gid, b := range r.bindings {
		if now.After(b.expires) {
			delete(r.bindings, gid)
		}
	}
	for id, f := range r.flows {
		if now.Sub(f.touched) > 2*time.Minute {
			delete(r.clientFlows, f.clientID)
			delete(r.flows, id)
		}
	}
}

func (r *siteRouter) handle(e siteEvent) {
	op, body := e.body[0], e.body[1:]
	if e.reply {
		switch op {
		case siteDirectoryResponse:
			r.g.directory.handleResponse(e.circuit, body)
		case siteRegistered:
			r.mu.Lock()
			ack := r.acks[e.circuit]
			r.mu.Unlock()
			if ack != nil {
				select {
				case ack <- true:
				default:
				}
			}
		case siteToClient:
			if len(body) < 16 || len(body) > 16+2048 {
				return
			}
			var id CircuitID
			copy(id[:], body[:16])
			r.mu.Lock()
			pc := r.clients[id]
			r.mu.Unlock()
			if pc != nil && pc.route.accepts(e.circuit) {
				pc.deliver(id, body[16:])
			}
		case siteToServer:
			if len(body) < 33+16 || len(body) > 33+16+2048 {
				return
			}
			var gid GID
			var id CircuitID
			copy(gid[:], body[:33])
			copy(id[:], body[33:49])
			r.mu.Lock()
			host := r.hosts[gid]
			r.mu.Unlock()
			if host != nil && host.route.accepts(e.circuit) {
				host.pc.deliver(id, body[49:])
			}
		}
		return
	}
	switch op {
	case siteDirectoryRequest:
		r.g.directory.handleRequest(e.circuit, body)
	case siteRegister:
		var reg siteRegistration
		if json.Unmarshal(body, &reg) != nil || reg.Descriptor == nil {
			return
		}
		d := reg.Descriptor
		gid := ComputeGID(d.ServicePublicKey, d.ServiceID)
		if VerifyServiceDescriptor(d, gid, uint64(time.Now().Unix())) != nil {
			return
		}
		gateway := r.g.core.PublicKey()
		listed := false
		for _, p := range d.IntroPoints {
			if bytes.Equal(p.NodeKey, gateway) {
				listed = true
			}
		}
		if !listed || !ed25519.Verify(d.ServicePublicKey, registrationBytes(gid, gateway, e.circuit), reg.Signature) {
			return
		}
		r.mu.Lock()
		r.pruneLocked()
		_, exists := r.bindings[gid]
		if !exists && len(r.bindings) >= 1024 {
			r.mu.Unlock()
			return
		}
		r.bindings[gid] = siteBinding{e.circuit, minTime(time.Unix(int64(d.ExpiresAt), 0), time.Now().Add(duplexLifetime))}
		r.mu.Unlock()
		_ = r.g.duplex.send(e.circuit, []byte{siteRegistered}, true)
	case siteClientPacket:
		if len(body) < 33+16+32 || len(body) > 33+16+32+2048 {
			return
		}
		var gid GID
		var client CircuitID
		var secret [32]byte
		copy(gid[:], body[:33])
		copy(client[:], body[33:49])
		copy(secret[:], body[49:81])
		r.mu.Lock()
		r.pruneLocked()
		binding, ok := r.bindings[gid]
		if !ok {
			r.mu.Unlock()
			return
		}
		server, exists := r.clientFlows[client]
		flow := r.flows[server]
		if !exists {
			if len(r.flows) >= maxSiteFlows {
				r.mu.Unlock()
				return
			}
			var err error
			server, err = randomCircuitID()
			if err != nil {
				r.mu.Unlock()
				return
			}
			flow = &siteFlow{gid: gid, clientID: client, serverID: server, secret: secret}
			r.flows[server] = flow
			r.clientFlows[client] = server
		}
		if flow == nil || flow.gid != gid || flow.secret != secret {
			r.mu.Unlock()
			return
		}
		flow.clientCircuit = e.circuit
		flow.touched = time.Now()
		r.mu.Unlock()
		packet := append([]byte{siteToServer}, gid[:]...)
		packet = append(packet, server[:]...)
		packet = append(packet, body[81:]...)
		_ = r.g.duplex.send(binding.circuit, packet, true)
	case siteServerPacket:
		if len(body) < 33+16 || len(body) > 33+16+2048 {
			return
		}
		var gid GID
		var id CircuitID
		copy(gid[:], body[:33])
		copy(id[:], body[33:49])
		r.mu.Lock()
		binding, exists := r.bindings[gid]
		flow := r.flows[id]
		if !exists || binding.circuit != e.circuit || time.Now().After(binding.expires) || flow == nil || flow.gid != gid {
			r.mu.Unlock()
			return
		}
		client, circuit := flow.clientID, flow.clientCircuit
		flow.touched = time.Now()
		r.mu.Unlock()
		packet := append([]byte{siteToClient}, client[:]...)
		packet = append(packet, body[49:]...)
		_ = r.g.duplex.send(circuit, packet, true)
	}
}

func (r *siteRouter) register(ctx context.Context, id CircuitID, gateway []byte, d *ServiceDescriptor) error {
	c, ok := r.g.circuits.Get(id)
	if !ok {
		return ErrCircuitNotFound
	}
	c.mu.Lock()
	terminal := c.hops[len(c.hops)-1].LocalCircuitID
	c.mu.Unlock()
	gid := ComputeGID(d.ServicePublicKey, d.ServiceID)
	reg := siteRegistration{d, ed25519.Sign(r.g.identity.SigningPrivateKey, registrationBytes(gid, gateway, terminal))}
	body, err := json.Marshal(reg)
	if err != nil {
		return err
	}
	ack := make(chan bool, 1)
	r.mu.Lock()
	r.acks[id] = ack
	r.mu.Unlock()
	defer func() { r.mu.Lock(); delete(r.acks, id); r.mu.Unlock() }()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(4 * time.Second)
	defer timeout.Stop()
	for {
		if err := r.g.sendDuplex(id, append([]byte{siteRegister}, body...)); err != nil {
			return err
		}
		select {
		case <-ack:
			return nil
		case <-ticker.C:
		case <-timeout.C:
			return errors.New("garlic: site relay registration timed out")
		case <-ctx.Done():
			return ctx.Err()
		case <-r.ctx.Done():
			return net.ErrClosed
		}
	}
}

func (r *siteRouter) close() {
	r.cancel()
	r.mu.Lock()
	hosts := make([]*HostedService, 0, len(r.hosts))
	clients := make([]*sitePacketConn, 0, len(r.clients))
	for _, h := range r.hosts {
		hosts = append(hosts, h)
	}
	for _, pc := range r.clients {
		clients = append(clients, pc)
	}
	r.mu.Unlock()
	for _, h := range hosts {
		h.Close()
	}
	for _, pc := range clients {
		pc.Close()
	}
	r.wg.Wait()
}
