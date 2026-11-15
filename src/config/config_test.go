package config

import (
	"bytes"
	"encoding/hex"
	"github.com/hjson/hjson-go/v4"
	"strings"
	"testing"
)

// ReadFrom previously sliced conf[0:2] for the BOM check without
// guarding the length, so empty or single-byte configs piped via
// -useconf panicked with index out of range.
func TestConfigReadFromEmpty(t *testing.T) {
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{name: "empty", body: nil},
		{name: "single byte", body: []byte{'{'}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ReadFrom must not panic on short input, got: %v", r)
				}
			}()
			var cfg NodeConfig
			_, _ = cfg.ReadFrom(bytes.NewReader(tc.body))
		})
	}
}

func TestGarlicConfigDefaultsEnabled(t *testing.T) {
	cfg := GenerateConfig()
	if !cfg.Garlic.Enabled {
		t.Error("Garlic.Enabled = false by default, want true")
	}
}

// Site domains derive from Garlic.SigningPrivateKey. A config without one
// gets one while being read and says so, so the writer (normaliseconf, the
// daemon) can save it once; a configured key is kept as it is.
func TestGarlicSigningKeyGeneratedOnceAndKept(t *testing.T) {
	cfg := GenerateConfig()
	cfg.Garlic.SigningPrivateKey = nil
	if err := cfg.UnmarshalHJSON([]byte("{}")); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Garlic.SigningPrivateKey) != 32 || !cfg.GeneratedSigningKey {
		t.Fatalf("missing signing key not generated and flagged (len %d, flagged %v)", len(cfg.Garlic.SigningPrivateKey), cfg.GeneratedSigningKey)
	}
	key := hex.EncodeToString(cfg.Garlic.SigningPrivateKey)
	again := GenerateConfig()
	if _, err := again.ReadFrom(strings.NewReader(`{ Garlic: { SigningPrivateKey: "` + key + `" } }`)); err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(again.Garlic.SigningPrivateKey) != key || again.GeneratedSigningKey {
		t.Fatal("a configured signing key was replaced")
	}
}

func TestGarlicConfigPaddingAndJitterDefaults(t *testing.T) {
	cfg := GenerateConfig()
	if !cfg.Garlic.Padding.Enabled {
		t.Error("Garlic.Padding.Enabled = false by default, want true")
	}
	if cfg.Garlic.Padding.MinSize <= 0 || cfg.Garlic.Padding.MaxSize <= cfg.Garlic.Padding.MinSize {
		t.Errorf("Garlic.Padding min/max = %d/%d, want 0 < min < max", cfg.Garlic.Padding.MinSize, cfg.Garlic.Padding.MaxSize)
	}
	if !cfg.Garlic.Jitter.Enabled {
		t.Error("Garlic.Jitter.Enabled = false by default, want true")
	}
	if cfg.Garlic.Jitter.MaxDelay == "" {
		t.Error("Garlic.Jitter.MaxDelay is empty by default")
	}
	if cfg.Garlic.MaxDiscoveredPeers <= 0 {
		t.Error("Garlic.MaxDiscoveredPeers <= 0 by default, want a positive bound")
	}
}

// A config file written before the Garlic block existed inherits the
// defaults (Garlic enabled, client mode) via the GenerateConfig base that
// ReadFrom parses on top of. An explicit Enabled: false must still win.
func TestGarlicConfigAbsentFromInputInheritsDefault(t *testing.T) {
	var cfg NodeConfig
	if _, err := cfg.ReadFrom(bytes.NewReader([]byte("{}"))); err != nil {
		t.Fatalf("ReadFrom returned error: %v", err)
	}
	if !cfg.Garlic.Enabled {
		t.Error("Garlic.Enabled = false for a config that never mentions garlic, want the enabled default")
	}
	if cfg.Garlic.Mode != "client" {
		t.Errorf("Garlic.Mode = %q for a config that never mentions garlic, want the client default", cfg.Garlic.Mode)
	}

	var off NodeConfig
	if _, err := off.ReadFrom(bytes.NewReader([]byte("{ Garlic: { Enabled: false } }"))); err != nil {
		t.Fatalf("ReadFrom returned error: %v", err)
	}
	if off.Garlic.Enabled {
		t.Error("explicit Garlic.Enabled: false was overridden by the default")
	}
}

func TestConfig_Keys(t *testing.T) {
	/*
		var nodeConfig NodeConfig
		nodeConfig.NewKeys()

		publicKey1, err := hex.DecodeString(nodeConfig.PublicKey)

		if err != nil {
			t.Fatal("can not decode generated public key")
		}

		if len(publicKey1) == 0 {
			t.Fatal("empty public key generated")
		}

		privateKey1, err := hex.DecodeString(nodeConfig.PrivateKey)

		if err != nil {
			t.Fatal("can not decode generated private key")
		}

		if len(privateKey1) == 0 {
			t.Fatal("empty private key generated")
		}

		nodeConfig.NewKeys()

		publicKey2, err := hex.DecodeString(nodeConfig.PublicKey)

		if err != nil {
			t.Fatal("can not decode generated public key")
		}

		if bytes.Equal(publicKey2, publicKey1) {
			t.Fatal("same public key generated")
		}

		privateKey2, err := hex.DecodeString(nodeConfig.PrivateKey)

		if err != nil {
			t.Fatal("can not decode generated private key")
		}

		if bytes.Equal(privateKey2, privateKey1) {
			t.Fatal("same private key generated")
		}
	*/
}

func TestGenerateConfigSetsGarlicAutoPoolDefaults(t *testing.T) {
	cfg := GenerateConfig()
	if cfg.Garlic.AutoPoolSize != 3 {
		t.Errorf("Garlic.AutoPoolSize = %d, want 3", cfg.Garlic.AutoPoolSize)
	}
	if !cfg.Garlic.CoverTrafficEnabled {
		t.Error("Garlic.CoverTrafficEnabled = false, want true (default-on per design decision)")
	}
}

func TestDashboardConfigDefaults(t *testing.T) {
	cfg := GenerateConfig()
	if cfg.Dashboard.Enabled {
		t.Error("Dashboard.Enabled = true by default, want false")
	}
	if cfg.Dashboard.Listen != "127.0.0.1:8080" {
		t.Errorf("Dashboard.Listen = %q, want \"127.0.0.1:8080\"", cfg.Dashboard.Listen)
	}
	if cfg.Dashboard.Path != "" {
		t.Errorf("Dashboard.Path = %q, want empty (tries conventional install paths)", cfg.Dashboard.Path)
	}
}

func TestGarlicServicePorts(t *testing.T) {
	ok := GarlicServiceConfig{Ports: map[string]string{"80": "127.0.0.1:8080", "22": "127.0.0.1:22", "9000": "[::1]:9000"}}
	ports, err := ok.VirtualPorts()
	if err != nil || len(ports) != 3 || ports[22] != "127.0.0.1:22" || ports[9000] != "[::1]:9000" {
		t.Fatalf("VirtualPorts = %v, %v", ports, err)
	}
	for name, p := range map[string]map[string]string{
		"zero":      {"0": "127.0.0.1:1"},
		"too large": {"65536": "127.0.0.1:1"},
		"not a num": {"http": "127.0.0.1:1"},
		"duplicate": {"80": "127.0.0.1:1", "080": "127.0.0.1:2"},
	} {
		if _, err := (GarlicServiceConfig{Ports: p}).VirtualPorts(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestGarlicServicePortsRoundTrip(t *testing.T) {
	cfg := GenerateConfig()
	cfg.Garlic.Services = []GarlicServiceConfig{{Name: "x", Ports: map[string]string{"22": "127.0.0.1:22", "7000": "127.0.0.1:7000"}, LocalAddr: "127.0.0.1:8080"}}
	bs, err := hjson.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var back NodeConfig
	if _, err := back.ReadFrom(bytes.NewReader(bs)); err != nil {
		t.Fatal(err)
	}
	s := back.Garlic.Services[0]
	if s.Ports["22"] != "127.0.0.1:22" || s.Ports["7000"] != "127.0.0.1:7000" || s.LocalAddr != "127.0.0.1:8080" {
		t.Fatalf("round trip lost ports: %+v", s)
	}
}
