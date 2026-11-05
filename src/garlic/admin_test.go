package garlic_test

// Wire-level tests for the Garlic admin handlers the dashboard (Task 9
// of the yggdashboard v2 plan) consumes: verifies the exact JSON a
// client sees on the admin socket, not just Go-level return values -
// this is what actually reaches the browser-facing /api/* layer, so
// it's the right place to assert no private-key-shaped field ever
// appears.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gologme/log"

	"github.com/yggdrasil-network/yggdrasil-go/src/admin"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
	"github.com/yggdrasil-network/yggdrasil-go/src/garlic"
)

func newTestGarlicWithCore(t *testing.T) (*garlic.Garlic, *core.Core) {
	t.Helper()
	c := newLinkedTestNode(t)
	id, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity returned error: %v", err)
	}
	g := garlic.New(c, id, garlic.DefaultConfig(), garlic.NewStaticRendezvous())
	t.Cleanup(g.Close)
	return g, c
}

// newTestAdminSocket wires a real admin.AdminSocket, listening on a
// temporary unix socket, with garlicInst's handlers registered - the
// same SetupAdminHandlers call cmd/yggdrasil/main.go makes.
func newTestAdminSocket(t *testing.T, c *core.Core, garlicInst *garlic.Garlic) string {
	t.Helper()
	sockPath := filepath.Join(t.TempDir(), "admin.sock")
	logger := log.New(io.Discard, "", 0)
	a, err := admin.New(c, logger, admin.ListenAddress("unix://"+sockPath))
	if err != nil {
		t.Fatalf("admin.New returned error: %v", err)
	}
	if a == nil {
		t.Fatal("admin.New returned a nil AdminSocket for a real unix listen address")
	}
	garlicInst.SetupAdminHandlers(a)
	return sockPath
}

// callAdmin sends one request to the admin socket at sockPath and
// returns the decoded "response" object.
func callAdmin(t *testing.T, sockPath, request string) map[string]interface{} {
	t.Helper()
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("net.Dial returned error: %v", err)
	}
	defer conn.Close()

	enc := json.NewEncoder(conn)
	if err := enc.Encode(map[string]interface{}{"request": request, "arguments": map[string]interface{}{}}); err != nil {
		t.Fatalf("Encode returned error: %v", err)
	}
	var resp map[string]interface{}
	dec := json.NewDecoder(conn)
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("Decode returned error: %v", err)
	}
	if resp["status"] != "success" {
		t.Fatalf("admin request %q failed: %v", request, resp["error"])
	}
	respBody, _ := resp["response"].(map[string]interface{})
	return respBody
}

// callAdminWithArgs behaves like callAdmin but sends a non-empty
// arguments object - needed for handlers that take a required argument
// (e.g. garlicGossipPull's "key").
func callAdminWithArgs(t *testing.T, sockPath, request string, args map[string]interface{}) map[string]interface{} {
	t.Helper()
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("net.Dial returned error: %v", err)
	}
	defer conn.Close()

	enc := json.NewEncoder(conn)
	if err := enc.Encode(map[string]interface{}{"request": request, "arguments": args}); err != nil {
		t.Fatalf("Encode returned error: %v", err)
	}
	var resp map[string]interface{}
	dec := json.NewDecoder(conn)
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("Decode returned error: %v", err)
	}
	if resp["status"] != "success" {
		t.Fatalf("admin request %q failed: %v", request, resp["error"])
	}
	respBody, _ := resp["response"].(map[string]interface{})
	return respBody
}

func TestGetGarlicStatsResponseShapeAndNoSecrets(t *testing.T) {
	g, c := newTestGarlicWithCore(t)
	sockPath := newTestAdminSocket(t, c, g)

	resp := callAdmin(t, sockPath, "getGarlicStats")
	for _, want := range []string{"originatedCircuits", "relayedCircuits", "originatedBytes", "relayedBytes", "security"} {
		if _, ok := resp[want]; !ok {
			t.Errorf("getGarlicStats response missing expected field %q, got %+v", want, resp)
		}
	}
	body, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	for _, forbidden := range []string{"privateKey", "PrivateKey", "secret", "Secret", "sessionKey", "aeadKey"} {
		if strings.Contains(string(body), forbidden) {
			t.Errorf("getGarlicStats response contains forbidden substring %q: %s", forbidden, body)
		}
	}
}

// TestGetGarlicCircuitsResponseShapeAndNoSecrets builds one real
// originated circuit through the same public API path
// createGarlicCircuit's admin handler uses (CreateCircuit + SendGarlic),
// rather than asserting against an empty {"originated":[],"relayed":[]}
// response. CreateCircuit derives a genuine per-hop AEAD key via
// ECDH+HKDF for that hop (Circuit.hops[i].Key) - HopKeys() is supposed
// to expose only the hop's NodeKey and never that derived key
// (circuit.go's doc comment on HopKeys). A no-secret-leak scan over a
// response with no circuits in it can't actually exercise that
// distinction; it would pass just as trivially if HopKeys() leaked
// Key too. This only strengthens the *originated* side: relayed-side
// circuit state (relaystate.go's relayCircuitInfo) never stores
// anything but hop NodeKeys and traffic counters in the first place -
// populating it would require a full multi-node mesh with capability
// negotiation (as in integration_test.go) for no corresponding increase
// in what's actually at risk of leaking.
func TestGetGarlicCircuitsResponseShapeAndNoSecrets(t *testing.T) {
	g, c := newTestGarlicWithCore(t)
	sockPath := newTestAdminSocket(t, c, g)

	// hopIdentity's public key stands in for a real hop's long-term
	// Garlic key - CreateCircuit ECDHs the circuit's ephemeral private
	// key against it to derive that hop's layer key, exactly as it
	// would for a real capability-verified peer.
	hopIdentity, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity returned error: %v", err)
	}
	// nodeIdentity's public key is only ever used as the hop's NodeKey
	// (the mesh address CreateCircuit's caller already knows in
	// plaintext) - never as key material - but reuses NewIdentity for a
	// convenient 32-byte value.
	nodeIdentity, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity returned error: %v", err)
	}
	nodeKey := nodeIdentity.PublicKey

	circuitID, err := g.CreateCircuit(
		[]garlic.CapabilityMessage{{Versions: []string{"garlic-v1", garlic.CapabilityGarlicV3}, PublicKey: hopIdentity.PublicKey}},
		[][]byte{nodeKey},
	)
	if err != nil {
		t.Fatalf("CreateCircuit returned error: %v", err)
	}
	if err := g.SendGarlic(circuitID, []byte("hello")); err != nil {
		t.Fatalf("SendGarlic returned error: %v", err)
	}

	resp := callAdmin(t, sockPath, "getGarlicCircuits")
	for _, want := range []string{"originated", "relayed"} {
		if _, ok := resp[want]; !ok {
			t.Errorf("getGarlicCircuits response missing expected field %q, got %+v", want, resp)
		}
	}

	originated, ok := resp["originated"].([]interface{})
	if !ok || len(originated) != 1 {
		t.Fatalf("resp[\"originated\"] = %+v, want exactly 1 entry", resp["originated"])
	}
	entry, ok := originated[0].(map[string]interface{})
	if !ok {
		t.Fatalf("originated[0] = %+v, want a JSON object", originated[0])
	}
	wantHopHex := hex.EncodeToString(nodeKey)
	hops, ok := entry["hops"].([]interface{})
	if !ok || len(hops) != 1 || hops[0] != wantHopHex {
		t.Fatalf("originated[0][\"hops\"] = %+v, want [%q]", entry["hops"], wantHopHex)
	}
	if packets, _ := entry["packets"].(float64); packets != 1 {
		t.Errorf("originated[0][\"packets\"] = %v, want 1", entry["packets"])
	}
	if bytesSent, _ := entry["bytes"].(float64); bytesSent != 5 {
		t.Errorf("originated[0][\"bytes\"] = %v, want 5 (len(\"hello\"))", entry["bytes"])
	}

	body, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	// Positive control: confirms the scan below runs over a genuinely
	// populated response (containing the real hop key, hex-encoded) and
	// not a vacuously-passing empty one.
	if !strings.Contains(string(body), wantHopHex) {
		t.Fatalf("response does not contain the expected hop key %q - test failed to populate a real circuit: %s", wantHopHex, body)
	}
	for _, forbidden := range []string{"privateKey", "PrivateKey", "secret", "Secret", "sessionKey", "aeadKey"} {
		if strings.Contains(string(body), forbidden) {
			t.Errorf("getGarlicCircuits response contains forbidden substring %q: %s", forbidden, body)
		}
	}
}

func TestGetGarlicIdentityOnlyExposesPublicKey(t *testing.T) {
	g, c := newTestGarlicWithCore(t)
	sockPath := newTestAdminSocket(t, c, g)

	resp := callAdmin(t, sockPath, "getGarlicIdentity")
	if _, ok := resp["publicKey"]; !ok {
		t.Error("getGarlicIdentity response missing publicKey field")
	}
	if _, ok := resp["privateKey"]; ok {
		t.Error("getGarlicIdentity response must never contain a privateKey field")
	}
}

func TestGetSelfResponseHasNoPrivateKeyField(t *testing.T) {
	c := newLinkedTestNode(t)
	sockPath := filepath.Join(t.TempDir(), "admin2.sock")
	logger := log.New(io.Discard, "", 0)
	a, err := admin.New(c, logger, admin.ListenAddress("unix://"+sockPath))
	if err != nil {
		t.Fatalf("admin.New returned error: %v", err)
	}
	a.SetupAdminHandlers()

	resp := callAdmin(t, sockPath, "getSelf")
	if _, ok := resp["uptime"]; !ok {
		t.Error("getSelf response missing uptime field")
	}
	body, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	if strings.Contains(string(body), "privateKey") || strings.Contains(string(body), "PrivateKey") {
		t.Errorf("getSelf response contains a private key field: %s", body)
	}
}

func TestCreateGarlicCircuitAutoHandlerDefaultsHopCountToPathLength(t *testing.T) {
	cA := newLinkedTestNode(t)
	defer cA.Stop()
	cB := newLinkedTestNode(t)
	defer cB.Stop()
	connectChain(t, []*core.Core{cA, cB})
	pumpAll([]*core.Core{cA, cB})

	idA, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (A) returned error: %v", err)
	}
	idB, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (B) returned error: %v", err)
	}
	cfg := garlic.DefaultConfig()
	cfg.CapabilityTimeout = 2 * time.Second
	cfg.MinHopCount = 0
	cfg.PathLength = 1

	gB := garlic.New(cB, idB, cfg, garlic.NewStaticRendezvous())
	defer gB.Close()
	cfgA := cfg
	cfgA.TrustedPeers = []string{hex.EncodeToString(cB.PublicKey())}
	gA := garlic.New(cA, idA, cfgA, garlic.NewStaticRendezvous())
	defer gA.Close()

	waitForCapability(t, gA, cB.PublicKey(), 60*time.Second)

	sockPath := newTestAdminSocket(t, cA, gA)
	resp := callAdmin(t, sockPath, "createGarlicCircuitAuto")
	if id, _ := resp["circuitId"].(string); id == "" {
		t.Fatalf("createGarlicCircuitAuto response = %+v, want a non-empty circuitId", resp)
	}
}

func TestGetGarlicAutoPoolHandlerListsPool(t *testing.T) {
	cA := newLinkedTestNode(t)
	defer cA.Stop()
	cB := newLinkedTestNode(t)
	defer cB.Stop()
	connectChain(t, []*core.Core{cA, cB})
	pumpAll([]*core.Core{cA, cB})

	idA, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (A) returned error: %v", err)
	}
	idB, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (B) returned error: %v", err)
	}

	cfgB := garlic.DefaultConfig()
	cfgB.CapabilityTimeout = 2 * time.Second
	gB := garlic.New(cB, idB, cfgB, garlic.NewStaticRendezvous())
	defer gB.Close()

	cfgA := garlic.DefaultConfig()
	cfgA.CapabilityTimeout = 2 * time.Second
	cfgA.MinHopCount = 0
	cfgA.PathLength = 1
	cfgA.TrustedPeers = []string{hex.EncodeToString(cB.PublicKey())}
	cfgA.AutoPoolEnabled = true
	cfgA.AutoPoolSize = 1
	cfgA.CoverTrafficEnabled = false
	gA := garlic.New(cA, idA, cfgA, garlic.NewStaticRendezvous())
	defer gA.Close()

	deadline := time.Now().Add(15 * time.Second)
	for len(gA.AutoPoolStatus()) != 1 {
		if time.Now().After(deadline) {
			t.Fatal("auto-pool never reached target size 1")
		}
		time.Sleep(100 * time.Millisecond)
	}

	sockPath := newTestAdminSocket(t, cA, gA)
	resp := callAdmin(t, sockPath, "getGarlicAutoPool")
	pool, ok := resp["pool"].([]interface{})
	if !ok || len(pool) != 1 {
		t.Fatalf("getGarlicAutoPool response pool = %+v, want 1 entry", resp["pool"])
	}
}

func TestGetGarlicKnownPeersHandlerIncludesSelfVerified(t *testing.T) {
	cA := newLinkedTestNode(t)
	defer cA.Stop()
	cB := newLinkedTestNode(t)
	defer cB.Stop()
	connectChain(t, []*core.Core{cA, cB})
	pumpAll([]*core.Core{cA, cB})

	idA, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (A) returned error: %v", err)
	}
	idB, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (B) returned error: %v", err)
	}
	cfg := garlic.DefaultConfig()
	cfg.CapabilityTimeout = 2 * time.Second
	gB := garlic.New(cB, idB, cfg, garlic.NewStaticRendezvous())
	defer gB.Close()
	gA := garlic.New(cA, idA, cfg, garlic.NewStaticRendezvous())
	defer gA.Close()

	waitForCapability(t, gA, cB.PublicKey(), 60*time.Second)

	sockPath := newTestAdminSocket(t, cA, gA)
	resp := callAdmin(t, sockPath, "getGarlicKnownPeers")
	peers, ok := resp["peers"].([]interface{})
	if !ok || len(peers) != 1 {
		t.Fatalf("getGarlicKnownPeers response peers = %+v, want 1 entry", resp["peers"])
	}
	entry, ok := peers[0].(map[string]interface{})
	if !ok {
		t.Fatalf("peers[0] = %#v, want a JSON object", peers[0])
	}
	if sv, ok := entry["selfVerified"].(bool); !ok || !sv {
		t.Fatalf("peers[0][\"selfVerified\"] = %v, want true", entry["selfVerified"])
	}
}

func TestGarlicGossipPullHandlerTriggersRequestGossip(t *testing.T) {
	cA := newLinkedTestNode(t)
	defer cA.Stop()
	cB := newLinkedTestNode(t)
	defer cB.Stop()
	cC := newLinkedTestNode(t)
	defer cC.Stop()
	connectChain(t, []*core.Core{cA, cB, cC}) // A -- B -- C
	pumpAll([]*core.Core{cA, cB, cC})

	idA, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (A) returned error: %v", err)
	}
	idB, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (B) returned error: %v", err)
	}
	idC, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (C) returned error: %v", err)
	}
	cfg := garlic.DefaultConfig()
	cfg.CapabilityTimeout = 2 * time.Second
	gA := garlic.New(cA, idA, cfg, garlic.NewStaticRendezvous())
	defer gA.Close()
	gB := garlic.New(cB, idB, cfg, garlic.NewStaticRendezvous())
	defer gB.Close()
	gC := garlic.New(cC, idC, cfg, garlic.NewStaticRendezvous())
	defer gC.Close()

	waitForCapability(t, gA, cB.PublicKey(), 60*time.Second)
	waitForCapability(t, gB, cC.PublicKey(), 60*time.Second)

	sockPath := newTestAdminSocket(t, cA, gA)
	callAdminWithArgs(t, sockPath, "garlicGossipPull", map[string]interface{}{"key": hex.EncodeToString(cB.PublicKey())})

	deadline := time.Now().Add(10 * time.Second)
	for {
		found := false
		for _, p := range gA.KnownPeers() {
			if bytes.Equal(p.NodeKey, cC.PublicKey()) {
				found = true
			}
		}
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("A never learned about C via the garlicGossipPull admin RPC")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestGarlicPingCapabilityHandlerResponseShape is the wire-level test for
// garlicPingCapability (see garlicQueryCapability's own tests elsewhere
// in this file for the sibling handler's shape) - added alongside the
// admin RPC itself, which exists so an operator can check whether a
// peer's advertised versions changed (e.g. after an upgrade) without
// waiting on this node's own capability cache, which QueryCapability
// consults and which never expires on its own. PingCapability's actual
// cache-bypass behavior is a pre-existing, already-unconditional code
// path (manager.go's PingCapability calls requestCapability directly,
// never consulting capabilityCache) - this test is scoped to what's new
// here: the admin wiring and its JSON response shape.
func TestGarlicPingCapabilityHandlerResponseShape(t *testing.T) {
	cA := newLinkedTestNode(t)
	defer cA.Stop()
	cB := newLinkedTestNode(t)
	defer cB.Stop()
	connectChain(t, []*core.Core{cA, cB})
	pumpAll([]*core.Core{cA, cB})

	idA, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (A) returned error: %v", err)
	}
	idB, err := garlic.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity (B) returned error: %v", err)
	}
	cfg := garlic.DefaultConfig()
	cfg.CapabilityTimeout = 2 * time.Second
	gB := garlic.New(cB, idB, cfg, garlic.NewStaticRendezvous())
	defer gB.Close()
	gA := garlic.New(cA, idA, cfg, garlic.NewStaticRendezvous())
	defer gA.Close()

	waitForCapability(t, gA, cB.PublicKey(), 60*time.Second)

	sockPath := newTestAdminSocket(t, cA, gA)
	resp := callAdminWithArgs(t, sockPath, "garlicPingCapability", map[string]interface{}{"key": hex.EncodeToString(cB.PublicKey())})

	versions, ok := resp["versions"].([]interface{})
	if !ok || len(versions) == 0 {
		t.Fatalf("garlicPingCapability response versions = %+v, want a non-empty list", resp["versions"])
	}
	if pk, ok := resp["publicKey"].(string); !ok || pk != hex.EncodeToString(idB.PublicKey) {
		t.Fatalf("garlicPingCapability response publicKey = %v, want %q", resp["publicKey"], hex.EncodeToString(idB.PublicKey))
	}
	if _, ok := resp["rttMillis"].(float64); !ok {
		t.Fatalf("garlicPingCapability response rttMillis = %v (%T), want a number", resp["rttMillis"], resp["rttMillis"])
	}
}
