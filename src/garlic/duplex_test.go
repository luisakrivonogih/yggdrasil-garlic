package garlic

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/gologme/log"
	"github.com/yggdrasil-network/yggdrasil-go/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
)

func TestDuplexReplyAuthenticatesEveryHopAndRejectsReplay(t *testing.T) {
	secret := bytes.Repeat([]byte{7}, KeySize)
	forward, _ := deriveLayerKeyHopLocal(secret)
	reply, _ := deriveReplyKey(secret)
	if bytes.Equal(forward, reply) {
		t.Fatal("forward and reply keys coincide")
	}
	g := &Garlic{cfg: DefaultConfig(), stop: make(chan struct{})}
	g.sites = newSiteRouter(g)
	defer g.sites.close()
	g.duplex = newDuplexState(g)
	originID := testCircuitID(99)
	flow := testCircuitID(44)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	route := &siteRoute{}
	route.current.Store(&originID)
	pc := &sitePacketConn{host: true, ctx: ctx, cancel: cancel, route: route, in: make(chan sitePacket, 8), wake: make(chan struct{})}
	g.sites.clients[flow] = pc
	var hops []Hop
	var windows []*ReplayWindow
	for i := range 3 {
		key, _ := deriveReplyKey(bytes.Repeat([]byte{byte(i + 1)}, KeySize))
		hops = append(hops, Hop{LocalCircuitID: testCircuitID(uint64(i + 1)), ReplyKey: key})
		windows = append(windows, NewReplayWindow())
	}
	peer := bytes.Repeat([]byte{8}, 32)
	g.duplex.origins[hops[0].LocalCircuitID] = &returnOrigin{id: originID, first: peer, hops: hops, windows: windows, expires: time.Now().Add(time.Minute)}
	body := append([]byte{siteToClient}, flow[:]...)
	body = append(body, []byte("authenticated reply")...)
	for i := len(hops) - 1; i >= 0; i-- {
		n := uint64(500 + i*100)
		sealed, err := Seal(hops[i].ReplyKey, n, body, hops[i].LocalCircuitID[:])
		if err != nil {
			t.Fatal(err)
		}
		body = binary.BigEndian.AppendUint64(nil, n)
		body = append(body, sealed...)
	}
	packet := append(append([]byte(nil), hops[0].LocalCircuitID[:]...), body...)
	corrupt := bytes.Clone(packet)
	corrupt[len(corrupt)-1] ^= 1
	g.duplex.receive(peer, corrupt)
	g.duplex.receive(bytes.Repeat([]byte{9}, 32), packet)
	g.duplex.receive(peer, packet)
	pc.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 100)
	n, _, err := pc.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "authenticated reply" {
		t.Fatalf("reply: %q %v", buf[:n], err)
	}
	g.duplex.receive(peer, packet)
	pc.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, _, err := pc.ReadFrom(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("replay delivered: %v", err)
	}
}

func TestDuplexRouteCannotBeHijackedOrGrowPastCapacity(t *testing.T) {
	g := &Garlic{cfg: DefaultConfig()}
	g.cfg.MaxRelayCircuits = 1
	s := newDuplexState(g)
	a := circuitAction{kind: actionForward, circuitID: testCircuitID(1), nextCircuitID: testCircuitID(2), forwardTo: []byte("next"), replyKey: bytes.Repeat([]byte{1}, KeySize)}
	if !s.record(a, []byte("previous")) {
		t.Fatal("initial route refused")
	}
	if s.record(a, []byte("attacker")) {
		t.Fatal("route previous hop was replaced")
	}
	changed := a
	changed.replyKey = bytes.Repeat([]byte{2}, KeySize)
	if s.record(changed, []byte("previous")) {
		t.Fatal("route key was replaced")
	}
	changed = a
	changed.circuitID = testCircuitID(3)
	changed.nextCircuitID = testCircuitID(4)
	if s.record(changed, []byte("previous")) {
		t.Fatal("route capacity was exceeded")
	}
	if len(s.routes) != 1 || len(s.children) != 1 {
		t.Fatal("refused routes left state behind")
	}
}

func TestSiteRegistrationRequiresProofForTheExactCircuit(t *testing.T) {
	cfg := config.GenerateConfig()
	if err := cfg.GenerateSelfSignedCertificate(); err != nil {
		t.Fatal(err)
	}
	c, err := core.New(cfg.Certificate, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Stop()
	identity := testDescriptorIdentity(t)
	g := New(c, identity, DefaultConfig(), NewStaticRendezvous())
	defer g.Close()
	now := uint64(time.Now().Unix())
	d, err := SignServiceDescriptor(identity.SigningPublicKey, identity.SigningPrivateKey, nil, []IntroPoint{{NodeKey: c.PublicKey()}}, now, now+180)
	if err != nil {
		t.Fatal(err)
	}
	gid := ComputeGID(identity.SigningPublicKey, nil)
	circuit := testCircuitID(7)
	signature := ed25519.Sign(identity.SigningPrivateKey, registrationBytes(gid, c.PublicKey(), circuit))
	encode := func(sig []byte) []byte {
		b, err := json.Marshal(siteRegistration{d, sig})
		if err != nil {
			t.Fatal(err)
		}
		return append([]byte{siteRegister}, b...)
	}
	g.sites.handle(siteEvent{circuit: testCircuitID(8), body: encode(signature)})
	attacker := testDescriptorIdentity(t)
	forged := ed25519.Sign(attacker.SigningPrivateKey, registrationBytes(gid, c.PublicKey(), circuit))
	g.sites.handle(siteEvent{circuit: circuit, body: encode(forged)})
	if len(g.sites.bindings) != 0 {
		t.Fatal("a copied descriptor registered an unauthenticated circuit")
	}
	g.sites.handle(siteEvent{circuit: circuit, body: encode(signature)})
	if binding, ok := g.sites.bindings[gid]; !ok || binding.circuit != circuit {
		t.Fatal("valid registration failed")
	}
}

func TestNetworkDirectoryValidatesRecordsAndCopiesOwnership(t *testing.T) {
	d := &NetworkRendezvous{records: make(map[GID]*ServiceDescriptor)}
	id := testDescriptorIdentity(t)
	now := uint64(time.Now().Unix())
	key := bytes.Repeat([]byte{1}, 32)
	record, gid := testDescriptor(t, id, "site", []IntroPoint{{NodeKey: key}}, now, now+60)
	if !d.store(gid, record) {
		t.Fatal("valid record refused")
	}
	record.IntroPoints[0].NodeKey[0] = 'X'
	got := d.local(gid)
	if got.IntroPoints[0].NodeKey[0] != 1 {
		t.Fatal("stored record aliases publisher memory")
	}
	got.IntroPoints[0].NodeKey[0] = 'Y'
	if d.local(gid).IntroPoints[0].NodeKey[0] != 1 {
		t.Fatal("lookup exposes stored memory")
	}
	if d.store(gid, record) {
		t.Fatal("tampered record accepted")
	}
	expired, _ := testDescriptor(t, id, "site", nil, now-100, now-1)
	if d.store(gid, expired) {
		t.Fatal("expired record accepted")
	}
	older, _ := testDescriptor(t, id, "site", nil, now-1, now+59)
	if d.store(gid, older) {
		t.Fatal("older descriptor overwrote a newer one")
	}
	if d.store(gid, nil) {
		t.Fatal("nil descriptor accepted")
	}
}
