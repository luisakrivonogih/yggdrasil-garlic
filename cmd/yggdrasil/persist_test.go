package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/yggdrasil-network/yggdrasil-go/src/config"
)

func writeTestConfig(t *testing.T, edit func(*config.NodeConfig), asJSON bool) (string, *config.NodeConfig) {
	t.Helper()
	cfg := config.GenerateConfig()
	edit(cfg)
	out, err := marshalConfig(cfg, asJSON)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "yggdrasil.conf")
	if err := os.WriteFile(path, out, 0o640); err != nil {
		t.Fatal(err)
	}
	return path, cfg
}

func readTestConfig(t *testing.T, path string) (*config.NodeConfig, []byte) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.GenerateConfig()
	if _, err := cfg.ReadFrom(bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	return cfg, raw
}

func applyEdit(t *testing.T, p *configPersister, name, args string) {
	t.Helper()
	if err := p.update(func(cfg *config.NodeConfig) bool { return configEdits[name](json.RawMessage(args), cfg) }); err != nil {
		t.Fatalf("%s %s: %v", name, args, err)
	}
}

func TestPersistPeersSurviveAndKeepTheRestOfTheConfig(t *testing.T) {
	path, orig := writeTestConfig(t, func(cfg *config.NodeConfig) {
		cfg.Peers = []string{"tls://a.example:1"}
		cfg.AdminListen = "tcp://127.0.0.1:47099"
	}, false)
	p := &configPersister{path: path, privateKey: ed25519.PrivateKey(orig.PrivateKey)}

	applyEdit(t, p, "addPeer", `{"uri":"tls://b.example:2"}`)
	applyEdit(t, p, "addPeer", `{"uri":"tls://b.example:2"}`) // duplicate: no change
	applyEdit(t, p, "addPeer", `{"uri":"tls://c.example:3","interface":"eth0"}`)
	upper := strings.ToUpper(hex.EncodeToString(bytes.Repeat([]byte{0xab}, 32)))
	applyEdit(t, p, "addGarlicPeer", `{"key":"`+upper+`"}`)
	applyEdit(t, p, "addGarlicPeer", `{"key":"`+strings.ToLower(upper)+`"}`) // same key
	applyEdit(t, p, "addGarlicPeer", `{"key":"not-a-key"}`)

	cfg, raw := readTestConfig(t, path)
	if !slices.Equal(cfg.Peers, []string{"tls://a.example:1", "tls://b.example:2"}) {
		t.Fatalf("Peers = %v", cfg.Peers)
	}
	if !slices.Equal(cfg.InterfacePeers["eth0"], []string{"tls://c.example:3"}) {
		t.Fatalf("InterfacePeers = %v", cfg.InterfacePeers)
	}
	if !slices.Equal(cfg.Garlic.TrustedPeers, []string{strings.ToLower(upper)}) {
		t.Fatalf("TrustedPeers = %v", cfg.Garlic.TrustedPeers)
	}
	if !bytes.Equal(cfg.PrivateKey, orig.PrivateKey) || !bytes.Equal(cfg.Garlic.SigningPrivateKey, orig.Garlic.SigningPrivateKey) {
		t.Fatal("saving a peer changed the node's keys")
	}
	if cfg.AdminListen != "tcp://127.0.0.1:47099" {
		t.Fatalf("custom AdminListen lost: %q", cfg.AdminListen)
	}
	if json.Valid(raw) {
		t.Fatal("an HJSON config was rewritten as JSON")
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o640 {
		t.Fatalf("file mode changed to %v", info.Mode().Perm())
	}

	applyEdit(t, p, "removePeer", `{"uri":"tls://a.example:1"}`)
	applyEdit(t, p, "removePeer", `{"uri":"tls://c.example:3","interface":"eth0"}`)
	applyEdit(t, p, "removeGarlicPeer", `{"key":"`+upper+`"}`)
	cfg, _ = readTestConfig(t, path)
	if !slices.Equal(cfg.Peers, []string{"tls://b.example:2"}) || len(cfg.InterfacePeers) != 0 || len(cfg.Garlic.TrustedPeers) != 0 {
		t.Fatalf("after removal: Peers=%v InterfacePeers=%v TrustedPeers=%v", cfg.Peers, cfg.InterfacePeers, cfg.Garlic.TrustedPeers)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".*tmp*")); len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v", leftovers)
	}
}

func TestPersistKeepsJSONAndTheRunningKey(t *testing.T) {
	path, _ := writeTestConfig(t, func(cfg *config.NodeConfig) { cfg.PrivateKey = nil }, true)
	_, running, _ := ed25519.GenerateKey(nil)
	p := &configPersister{path: path, privateKey: running}
	applyEdit(t, p, "addPeer", `{"uri":"tcp://d.example:4"}`)
	cfg, raw := readTestConfig(t, path)
	if !json.Valid(raw) {
		t.Fatal("a JSON config was rewritten as HJSON")
	}
	if !bytes.Equal(cfg.PrivateKey, running) {
		t.Fatal("a config without a key got a random one instead of the running node's key")
	}
}

func TestMarshalConfigOmitsOnlyTheDefaultAdminListen(t *testing.T) {
	cfg := config.GenerateConfig()
	out, err := marshalConfig(cfg, true)
	if err != nil || bytes.Contains(out, []byte(`"AdminListen"`)) {
		t.Fatalf("default AdminListen written out: %v", err)
	}
	if cfg.AdminListen == "" {
		t.Fatal("marshalConfig modified its argument")
	}
	cfg.AdminListen = "tcp://127.0.0.1:47099"
	if out, _ := marshalConfig(cfg, true); !bytes.Contains(out, []byte("47099")) {
		t.Fatal("custom AdminListen dropped")
	}
}
