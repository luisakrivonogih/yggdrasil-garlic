package garlic

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/yggdrasil-network/yggdrasil-go/src/core"
)

// testRelay is a relay identity for unit tests that have no running mesh:
// it signs RelayInfo exactly the way core.Core.SignGarlic would.
type testRelay struct {
	nodePub             ed25519.PublicKey
	nodePriv            ed25519.PrivateKey
	onionPub, onionPriv []byte
}

func newTestRelay(t *testing.T) *testRelay {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	onionPub, onionPriv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	return &testRelay{nodePub: pub, nodePriv: priv, onionPub: onionPub, onionPriv: onionPriv}
}

func (r *testRelay) sign(statement []byte) []byte {
	return ed25519.Sign(r.nodePriv, append([]byte(core.GarlicSignaturePrefix), statement...))
}

// info returns a signed RelayInfo advertising versions (all supported
// versions if nil) valid for lifetime from now.
func (r *testRelay) info(t *testing.T, versions []string, lifetime time.Duration) []byte {
	t.Helper()
	now := time.Now()
	if lifetime < 0 {
		// Already expired: published two hours ago, expired lifetime ago.
		return r.infoAt(t, versions, now.Add(-2*time.Hour), now.Add(lifetime))
	}
	return r.infoAt(t, versions, now, now.Add(lifetime))
}

func (r *testRelay) infoAt(t *testing.T, versions []string, published, expires time.Time) []byte {
	t.Helper()
	if versions == nil {
		versions = supportedVersions()
	}
	ri := &RelayInfo{
		NodeKey:     r.nodePub,
		Capability:  CapabilityMessage{Versions: versions, PublicKey: r.onionPub},
		PublishedAt: uint64(published.Unix()),
		ExpiresAt:   uint64(expires.Unix()),
	}
	if err := signRelayInfoWith(r.sign, ri); err != nil {
		t.Fatal(err)
	}
	raw, err := ri.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// testOnion gives a struct-literal test relay an onion keyring holding the
// identity's X25519 key as its current key.
func testOnion(id *Identity) *onionKeyring {
	return newOnionKeyring(time.Hour, time.Hour, id.PublicKey, id.PrivateKey)
}
