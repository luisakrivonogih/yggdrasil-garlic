/*
The config package contains structures related to the configuration of an
Yggdrasil node.

The configuration contains, amongst other things, encryption keys which are used
to derive a node's identity, information about peerings and node information
that is shared with the network. There are also some module-specific options
related to TUN, multicast and the admin socket.

In order for a node to maintain the same identity across restarts, you should
persist the configuration onto the filesystem or into some configuration storage
so that the encryption keys (and therefore the node ID) do not change.

Note that Yggdrasil will automatically populate sane defaults for any
configuration option that is not provided.
*/
package config

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"

	"github.com/hjson/hjson-go/v4"
	"golang.org/x/text/encoding/unicode"
)

// NodeConfig is the main configuration structure, containing configuration
// options that are necessary for an Yggdrasil node to run. You will need to
// supply one of these structs to the Yggdrasil core when starting a node.
type NodeConfig struct {
	PrivateKey          KeyBytes                   `json:",omitempty" comment:"Your private key. DO NOT share this with anyone!"`
	PrivateKeyPath      string                     `json:",omitempty" comment:"The path to your private key file in PEM format."`
	Certificate         *tls.Certificate           `json:"-"`
	Peers               []string                   `comment:"List of outbound peer connection strings (e.g. tls://a.b.c.d:e or\nsocks://a.b.c.d:e/f.g.h.i:j). Connection strings can contain options,\nsee https://yggdrasil-network.github.io/configurationref.html#peers.\nYggdrasil has no concept of bootstrap nodes - all network traffic\nwill transit peer connections. Therefore make sure to only peer with\nnearby nodes that have good connectivity and low latency. Avoid adding\npeers to this list from distant countries as this will worsen your\nnode's connectivity and performance considerably."`
	InterfacePeers      map[string][]string        `comment:"List of connection strings for outbound peer connections in URI format,\narranged by source interface, e.g. { \"eth0\": [ \"tls://a.b.c.d:e\" ] }.\nYou should only use this option if your machine is multi-homed and you\nwant to establish outbound peer connections on different interfaces.\nOtherwise you should use \"Peers\"."`
	Listen              []string                   `comment:"Listen addresses for incoming connections. You will need to add\nlisteners in order to accept incoming peerings from non-local nodes.\nThis is not required if you wish to establish outbound peerings only.\nMulticast peer discovery will work regardless of any listeners set\nhere. Each listener should be specified in URI format as above, e.g.\ntls://0.0.0.0:0 or tls://[::]:0 to listen on all interfaces."`
	AdminListen         string                     `json:",omitempty" comment:"Listen address for admin connections. Default is to listen for local\nconnections either on TCP/9001 or a UNIX socket depending on your\nplatform. Use this value for yggdrasilctl -endpoint=X. To disable\nthe admin socket, use the value \"none\" instead."`
	MulticastInterfaces []MulticastInterfaceConfig `comment:"Configuration for which interfaces multicast peer discovery should be\nenabled on. Regex is a regular expression which is matched against an\ninterface name, and interfaces use the first configuration that they\nmatch against. Beacon controls whether or not your node advertises its\npresence to others, whereas Listen controls whether or not your node\nlistens out for and tries to connect to other advertising nodes. See\nhttps://yggdrasil-network.github.io/configurationref.html#multicastinterfaces\nfor more supported options."`
	AllowedPublicKeys   []string                   `comment:"List of peer public keys to allow incoming peering connections\nfrom. If left empty/undefined then all connections will be allowed\nby default. This does not affect outgoing peerings, nor does it\naffect link-local peers discovered via multicast.\nWARNING: THIS IS NOT A FIREWALL and DOES NOT limit who can reach\nopen ports or services running on your machine, for that see the\nGroupPassword option below."`
	GroupPassword       string                     `comment:"Traffic is only allowed to/from nodes with the same group password.\nIf you want to form a private sub-network or ensure that other public\nusers cannot connect to your machines, choose a strong group password\nand then configure the same password only with other group members.\nIf left empty or not specified, public connectivity will be permitted.\nIf specified, you WILL NOT be able to reach public services or hosts.\nThis option DOES NOT affect peering connections or traffic routing."`
	IfName              string                     `comment:"Local network interface name for TUN adapter, or \"auto\" to select\nan interface automatically, or \"none\" to run without TUN."`
	IfMTU               uint64                     `comment:"Maximum Transmission Unit (MTU) size for your local TUN interface.\nDefault is the largest supported size for your platform. The lowest\npossible value is 1280."`
	LogLookups          bool                       `json:",omitempty"`
	NodeInfoPrivacy     bool                       `comment:"By default, nodeinfo contains some defaults including the platform,\narchitecture and Yggdrasil version. These can help when surveying\nthe network and diagnosing network routing problems. Enabling\nnodeinfo privacy prevents this, so that only items specified in\n\"NodeInfo\" are sent back if specified."`
	NodeInfo            map[string]interface{}     `comment:"Optional nodeinfo. This must be a { \"key\": \"value\", ... } map\nor set as null. This is entirely optional but, if set, is visible\nto the whole network on request."`
	Garlic              GarlicConfig               `comment:"Configuration for the experimental Garlic Routing Overlay, an optional\nprivacy-enhanced routing layer built on top of Yggdrasil - see\ndocs/garlic-architecture.md. When Enabled is false (the default),\nbehavior is identical to a node with no Garlic support at all."`
	Dashboard           DashboardConfig            `comment:"Configuration for the local operator dashboard - a web UI and\nread-only API showing this node's live status, traffic, peers, and\n(if enabled) Garlic circuits. Disabled by default. When enabled, the\nlistener should stay loopback-only - the dashboard and its API have\nno authentication of their own."`
}

// GarlicConfig holds configuration for the experimental Garlic Routing
// Overlay (see docs/garlic-architecture.md). The zero value (Enabled:
// false) means vanilla Yggdrasil behavior.
type GarlicConfig struct {
	Proxy                GarlicProxyConfig     `comment:"Local browser proxy for .domains.yggg sites. Uses Garlic circuits;\nnever performs public DNS resolution for these names."`
	Services             []GarlicServiceConfig `comment:"Hidden websites hosted by this node. Empty means client/relay only.\nEach service forwards virtual port 80 to LocalAddr, and optionally\n443 to TLSLocalAddr, through an authenticated encrypted stream."`
	Enabled              bool                  `comment:"Enables the experimental Garlic Routing Overlay. Default is false."`
	PrivateKey           KeyBytes              `json:",omitempty" comment:"This node's long-term Garlic identity private key. Independent of\nyour main Yggdrasil PrivateKey above - compromise of one does not\nimplicate the other. If left unset while Enabled is true, a fresh\nkey is generated at startup and your Garlic identity will not be\nstable across restarts."`
	SigningPrivateKey    KeyBytes              `json:",omitempty" comment:"This node's Garlic service-descriptor signing key (Ed25519 seed,\n32 bytes). Independent of both PrivateKey above and your main\nYggdrasil key. Used only when publishing a Garlic service - see\ndocs/garlic-protocol.md section 6. If left unset while Enabled is\ntrue, a fresh key is generated at startup."`
	PathLength           int                   `comment:"Number of hops for circuits this node originates."`
	CircuitLifetime      string                `comment:"Maximum lifetime of a circuit before it must be rebuilt (Go duration\nformat, e.g. \"10m\")."`
	MaxCircuits          int                   `comment:"Maximum number of circuits this node will originate at once."`
	MaxCircuitsPerPeer   int                   `comment:"Maximum number of originated circuits through any single first-hop\npeer at once."`
	MaxRelayCircuits     int                   `comment:"Maximum number of other nodes' circuits this node will relay at once."`
	Padding              GarlicPaddingConfig   `comment:"Per-hop packet size randomization: the originator and every relay\nindependently pick a new random wire size within [MinSize, MaxSize]\nfor each packet, so a hop-to-hop link's packet sizes don't match\nthose on the next link - see docs/garlic-threat-model.md's\ndiscussion of traffic correlation."`
	Jitter               GarlicJitterConfig    `comment:"Random delay before actually transmitting a circuit packet (origin\nsend or relay forward), independently re-rolled per packet - the\ntiming half of the same traffic-correlation defense as Padding."`
	MaxDiscoveredPeers   int                   `comment:"Maximum number of other Garlic nodes this node will remember, learned\neither directly (a successful capability query) or via gossip from\nanother already-verified Garlic peer. Never exposed to, or\ndiscoverable by, a non-Garlic node."`
	MinHopCount          int                   `comment:"Minimum mesh hop distance for a candidate to be selected as a circuit\nhop by SelectPath - a node too close is more likely to be run by the\nsame operator or network as this one. Does not affect hops supplied\ndirectly to CreateCircuit."`
	BootstrapPeers       []string              `comment:"Hex-encoded node keys of a few known Garlic-capable peers, queried at\nstartup so this node's candidate pool starts non-empty - analogous to\nthe top-level Peers setting, but for Garlic circuit-hop discovery\nrather than mesh transport. Empty by default."`
	AutoPoolEnabled      bool                  `comment:"Maintains a small background pool of automatically-built circuits\n(no manual hop keys needed) for sendGarlic/recvGarlic-style use and\nthe dashboard. Default is false; a node can still relay/terminate for\nother nodes' auto-pool circuits with this off."`
	AutoPoolSize         int                   `comment:"Number of circuits the auto-pool maintains."`
	AutoRotationInterval string                `comment:"How often one auto-pool circuit (the oldest) is retired and rebuilt\n(Go duration format, e.g. \"15m\"). Never the whole pool at once."`
	CoverTrafficEnabled  bool                  `comment:"Sends periodic dummy traffic over every auto-pool circuit, even when\nthere's nothing real to send - raises the cost of traffic-volume\ncorrelation. Real, ongoing bandwidth cost - see docs/garlic-threat-model.md.\nDefault is true, with a low-bandwidth default interval."`
	CoverTrafficInterval string                `comment:"Average spacing between cover packets per auto-pool circuit (Go\nduration format), jittered +/-50% so it isn't perfectly periodic."`
}

type GarlicProxyConfig struct {
	Enabled bool
	Listen  string
}

type GarlicServiceConfig struct {
	ServiceID    string `comment:"Optional hex service ID; empty selects the default hash domain."`
	LocalAddr    string `comment:"Existing local HTTP server, e.g. 127.0.0.1:8080 (virtual port 80)."`
	TLSLocalAddr string `json:",omitempty" comment:"Optional existing HTTPS server for virtual port 443. Browser certificate\nvalidation is independent of the Garlic transport's authenticated TLS."`
}

type GarlicPaddingConfig struct {
	Enabled bool `comment:"Enables per-hop packet size randomization. Default is true."`
	MinSize int  `comment:"Minimum padded packet size in bytes."`
	MaxSize int  `comment:"Maximum padded packet size in bytes."`
}

type GarlicJitterConfig struct {
	Enabled  bool   `comment:"Enables random pre-send delay. Default is true."`
	MinDelay string `comment:"Minimum delay before sending (Go duration format, e.g. \"0s\")."`
	MaxDelay string `comment:"Maximum delay before sending (Go duration format, e.g. \"75ms\")."`
}

// DashboardConfig holds configuration for the local operator dashboard.
// The zero value (Enabled: false) means yggdrasil starts no dashboard
// process and behaves exactly as it does today.
type DashboardConfig struct {
	Enabled bool   `comment:"Enables the local operator dashboard HTTP server (UI and its\nread-only API together) as a subprocess yggdrasil manages. Default is\nfalse."`
	Listen  string `comment:"Listen address (host:port) for the dashboard's HTTP server. Must\ndefault to a loopback address (127.0.0.1 or ::1). Changing this to a\nnon-loopback address is your own choice and your own risk - the\ndashboard and its API have no authentication."`
	Path    string `comment:"Directory containing the dashboard's built assets (the 'npm run\nbuild' output's build/ directory). Empty tries conventional install\npaths, then a path relative to the yggdrasil binary for development."`
}

type MulticastInterfaceConfig struct {
	Regex    string
	Beacon   bool
	Listen   bool
	Port     uint16 `json:",omitempty"`
	Priority uint64 `json:",omitempty"` // really uint8, but gobind won't export it
	Password string
}

// Generates default configuration and returns a pointer to the resulting
// NodeConfig. This is used when outputting the -genconf parameter and also when
// using -autoconf.
func GenerateConfig() *NodeConfig {
	// Get the defaults for the platform.
	defaults := GetDefaults()
	// Create a node configuration and populate it.
	cfg := new(NodeConfig)
	cfg.NewPrivateKey()
	cfg.Listen = []string{}
	cfg.AdminListen = defaults.DefaultAdminListen
	cfg.Peers = []string{}
	cfg.InterfacePeers = map[string][]string{}
	cfg.AllowedPublicKeys = []string{}
	cfg.MulticastInterfaces = defaults.DefaultMulticastInterfaces
	cfg.IfName = defaults.DefaultIfName
	cfg.IfMTU = defaults.DefaultIfMTU
	cfg.NodeInfoPrivacy = false
	cfg.Garlic = GarlicConfig{
		Proxy:              GarlicProxyConfig{Enabled: true, Listen: "127.0.0.1:4444"},
		Services:           []GarlicServiceConfig{},
		Enabled:            false,
		PathLength:         3,
		CircuitLifetime:    "10m",
		MaxCircuits:        1024,
		MaxCircuitsPerPeer: 64,
		MaxRelayCircuits:   4096,
		Padding: GarlicPaddingConfig{
			Enabled: true,
			MinSize: 512,
			MaxSize: 1400,
		},
		Jitter: GarlicJitterConfig{
			Enabled:  true,
			MinDelay: "0s",
			MaxDelay: "75ms",
		},
		MaxDiscoveredPeers:   1024,
		MinHopCount:          2,
		BootstrapPeers:       []string{},
		AutoPoolEnabled:      false,
		AutoPoolSize:         3,
		AutoRotationInterval: "15m",
		CoverTrafficEnabled:  true,
		CoverTrafficInterval: "75s",
	}
	cfg.Dashboard = DashboardConfig{
		Enabled: false,
		Listen:  "127.0.0.1:8080",
		Path:    "",
	}
	if err := cfg.postprocessConfig(); err != nil {
		panic(err)
	}
	return cfg
}

func (cfg *NodeConfig) ReadFrom(r io.Reader) (int64, error) {
	conf, err := io.ReadAll(r)
	if err != nil {
		return 0, err
	}
	n := int64(len(conf))
	// If there's a byte order mark - which Windows 10 is now incredibly fond of
	// throwing everywhere when it's converting things into UTF-16 for the hell
	// of it - remove it and decode back down into UTF-8. This is necessary
	// because hjson doesn't know what to do with UTF-16 and will panic
	if len(conf) >= 2 && (bytes.Equal(conf[0:2], []byte{0xFF, 0xFE}) ||
		bytes.Equal(conf[0:2], []byte{0xFE, 0xFF})) {
		utf := unicode.UTF16(unicode.BigEndian, unicode.UseBOM)
		decoder := utf.NewDecoder()
		conf, err = decoder.Bytes(conf)
		if err != nil {
			return n, err
		}
	}
	// Generate a new configuration - this gives us a set of sane defaults -
	// then parse the configuration we loaded above on top of it. The effect
	// of this is that any configuration item that is missing from the provided
	// configuration will use a sane default.
	*cfg = *GenerateConfig()
	if err := cfg.UnmarshalHJSON(conf); err != nil {
		return n, err
	}
	return n, nil
}

func (cfg *NodeConfig) UnmarshalHJSON(b []byte) error {
	if err := hjson.Unmarshal(b, cfg); err != nil {
		return err
	}
	return cfg.postprocessConfig()
}

func (cfg *NodeConfig) postprocessConfig() error {
	if cfg.PrivateKeyPath != "" {
		cfg.PrivateKey = nil
		f, err := os.ReadFile(cfg.PrivateKeyPath)
		if err != nil {
			return err
		}
		if err := cfg.UnmarshalPEMPrivateKey(f); err != nil {
			return err
		}
	}
	switch {
	case cfg.Certificate == nil:
		// No self-signed certificate has been generated yet.
		fallthrough
	case !bytes.Equal(cfg.Certificate.PrivateKey.(ed25519.PrivateKey), cfg.PrivateKey):
		// A self-signed certificate was generated but the private
		// key has changed since then, possibly because a new config
		// was parsed.
		if err := cfg.GenerateSelfSignedCertificate(); err != nil {
			return err
		}
	}
	return nil
}

// RFC5280 section 4.1.2.5
var notAfterNeverExpires = time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC)

func (cfg *NodeConfig) GenerateSelfSignedCertificate() error {
	key, err := cfg.MarshalPEMPrivateKey()
	if err != nil {
		return err
	}
	cert, err := cfg.MarshalPEMCertificate()
	if err != nil {
		return err
	}
	tlsCert, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return err
	}
	cfg.Certificate = &tlsCert
	return nil
}

func (cfg *NodeConfig) MarshalPEMCertificate() ([]byte, error) {
	privateKey := ed25519.PrivateKey(cfg.PrivateKey)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: hex.EncodeToString(publicKey),
		},
		NotBefore:             time.Now(),
		NotAfter:              notAfterNeverExpires,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certbytes, err := x509.CreateCertificate(rand.Reader, cert, cert, publicKey, privateKey)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certbytes,
	}
	return pem.EncodeToMemory(block), nil
}

func (cfg *NodeConfig) NewPrivateKey() {
	_, spriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	cfg.PrivateKey = KeyBytes(spriv)
}

func (cfg *NodeConfig) MarshalPEMPrivateKey() ([]byte, error) {
	b, err := x509.MarshalPKCS8PrivateKey(ed25519.PrivateKey(cfg.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal PKCS8 key: %w", err)
	}
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	}
	return pem.EncodeToMemory(block), nil
}

func (cfg *NodeConfig) UnmarshalPEMPrivateKey(b []byte) error {
	p, _ := pem.Decode(b)
	if p == nil {
		return fmt.Errorf("failed to parse PEM file")
	}
	if p.Type != "PRIVATE KEY" {
		return fmt.Errorf("unexpected PEM type %q", p.Type)
	}
	k, err := x509.ParsePKCS8PrivateKey(p.Bytes)
	if err != nil {
		return fmt.Errorf("failed to unmarshal PKCS8 key: %w", err)
	}
	key, ok := k.(ed25519.PrivateKey)
	if !ok {
		return fmt.Errorf("private key must be ed25519 key")
	}
	if len(key) != ed25519.PrivateKeySize {
		return fmt.Errorf("unexpected ed25519 private key length")
	}
	cfg.PrivateKey = KeyBytes(key)
	return nil
}

type KeyBytes []byte

func (k KeyBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(k))
}

func (k *KeyBytes) UnmarshalJSON(b []byte) error {
	var s string
	var err error
	if err = json.Unmarshal(b, &s); err != nil {
		return err
	}
	*k, err = hex.DecodeString(s)
	return err
}
