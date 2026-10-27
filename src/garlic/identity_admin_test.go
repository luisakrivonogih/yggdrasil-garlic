package garlic

import (
	"encoding/hex"
	"testing"
)

// TestIdentityResponseIncludesSigningPublicKey covers the response
// shape getGarlicIdentity returns over the admin socket: before signed
// service descriptors existed, only the X25519 PublicKey was exposed.
// An operator now also needs a way to read out the Ed25519 signing
// public key - e.g. to confirm a configured Garlic.SigningPrivateKey
// took effect, or to learn a service's signing public key.
func TestIdentityResponseIncludesSigningPublicKey(t *testing.T) {
	id, err := NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity returned error: %v", err)
	}
	g := &Garlic{identity: id}

	resp := g.identityResponse()

	wantPublicKey := hex.EncodeToString(id.PublicKey)
	if resp["publicKey"] != wantPublicKey {
		t.Errorf("publicKey = %q, want %q", resp["publicKey"], wantPublicKey)
	}
	wantSigningPublicKey := hex.EncodeToString(id.SigningPublicKey)
	if resp["signingPublicKey"] != wantSigningPublicKey {
		t.Errorf("signingPublicKey = %q, want %q", resp["signingPublicKey"], wantSigningPublicKey)
	}
	if want := ComputeGID(id.SigningPublicKey, nil).Domain(); resp["domain"] != want {
		t.Errorf("domain = %q, want %q", resp["domain"], want)
	}
	if len(resp) != 3 {
		t.Errorf("identityResponse() has %d fields, want 3: %+v", len(resp), resp)
	}
}
