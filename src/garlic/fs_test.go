package garlic

import (
	"bytes"
	"testing"
)

// The relay and the originator end up with the same per-circuit keys, and
// those differ from anything derivable from the onion-key secret alone.
func TestFSKeysAgreeAndNeedTheRelaysOneTimeKey(t *testing.T) {
	onionPub, onionPriv, _ := GenerateKeypair()
	xPub, xPriv, _ := GenerateKeypair()
	originSecret, _ := ECDH(xPriv, onionPub)
	relaySecret, _ := ECDH(onionPriv, xPub)
	if !bytes.Equal(originSecret, relaySecret) {
		t.Fatal("onion secrets differ")
	}
	fwd, reply, relayPub, err := relayFSKeys(relaySecret, xPub)
	if err != nil {
		t.Fatal(err)
	}
	c := &Circuit{hops: []Hop{{Key: []byte("old")}}, fs: []hopFS{{capable: true, secret: bytes.Clone(originSecret), priv: bytes.Clone(xPriv)}}}
	replies, err := c.fsLearn([][]byte{relayPub})
	if err != nil || replies == nil {
		t.Fatalf("originator did not switch: %v", err)
	}
	if !bytes.Equal(c.hops[0].Key, fwd) || !bytes.Equal(replies[0], reply) {
		t.Fatal("originator and relay derived different per-circuit keys")
	}
	if !c.FSUpgraded() || c.fs[0].priv != nil || c.fs[0].secret != nil {
		t.Fatal("originator kept its ephemeral secrets after switching")
	}
	baseFwd, _ := deriveLayerKeyHopLocal(originSecret)
	baseReply, _ := deriveReplyKey(originSecret)
	if bytes.Equal(fwd, baseFwd) || bytes.Equal(reply, baseReply) {
		t.Fatal("per-circuit keys equal the onion-key keys")
	}
	// A second relay key must not change anything once switched.
	if again, _ := c.fsLearn([][]byte{relayPub}); again != nil {
		t.Fatal("circuit switched twice")
	}
}

// Waiting for every FS-capable hop: the switch happens only when all of
// their relay keys are known; hops without FS keep their keys.
func TestFSWaitsForAllCapableHops(t *testing.T) {
	var fs []hopFS
	var pubs [][]byte
	for i := range 3 {
		xPub, xPriv, _ := GenerateKeypair()
		_, onionPriv, _ := GenerateKeypair()
		secret, _ := ECDH(onionPriv, xPub)
		fs = append(fs, hopFS{capable: i != 1, secret: secret, priv: xPriv})
		_, _, relayPub, _ := relayFSKeys(secret, xPub)
		pubs = append(pubs, relayPub)
	}
	c := &Circuit{hops: []Hop{{Key: []byte("a")}, {Key: []byte("b")}, {Key: []byte("c")}}, fs: fs}
	if r, _ := c.fsLearn([][]byte{pubs[0], nil, nil}); r != nil {
		t.Fatal("switched before every capable hop answered")
	}
	r, err := c.fsLearn([][]byte{nil, nil, pubs[2]})
	if err != nil || r == nil {
		t.Fatalf("did not switch once all capable hops answered: %v", err)
	}
	if !bytes.Equal(c.hops[1].Key, []byte("b")) || r[1] != nil {
		t.Fatal("a hop without FS support got new keys")
	}
}

// Once a relayed leg runs on per-circuit keys, packets under the
// onion-key keys are refused.
func TestFSRefusesDowngrade(t *testing.T) {
	g := newTestGarlic(t)
	g.duplex = newDuplexState(g)
	g.cfg.MaxRelayCircuits = 16
	var id CircuitID
	id[0] = 1
	from := []byte("previous")
	base := circuitAction{kind: actionDeliver, circuitID: id, replyKey: []byte("base-reply"), fsForward: []byte("fs-fwd"), fsReply: []byte("fs-reply"), fsPub: []byte("pub")}
	if !g.duplex.record(base, from) {
		t.Fatal("first packet refused")
	}
	if !g.duplex.record(circuitAction{kind: actionDeliver, circuitID: id, replyKey: []byte("base-reply")}, from) {
		t.Fatal("onion-key packet refused before the switch")
	}
	if !g.duplex.record(circuitAction{kind: actionDeliver, circuitID: id, replyKey: []byte("fs-reply"), fsUsed: true}, from) {
		t.Fatal("per-circuit packet refused")
	}
	if g.duplex.record(circuitAction{kind: actionDeliver, circuitID: id, replyKey: []byte("base-reply")}, from) {
		t.Fatal("onion-key packet accepted after the switch (downgrade)")
	}
	if fwd, _ := g.duplex.fsKeys(id); !bytes.Equal(fwd, []byte("fs-fwd")) {
		t.Fatal("per-circuit forward key not kept for the leg")
	}
}
