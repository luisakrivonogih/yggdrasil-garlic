package garlic

import "testing"

func TestComputeGIDIsDeterministic(t *testing.T) {
	pub := []byte("a garlic public key (32b, padded for test)")
	svc := []byte("service-1")

	g1 := ComputeGID(pub, svc)
	g2 := ComputeGID(pub, svc)
	if g1 != g2 {
		t.Errorf("ComputeGID produced different values for identical inputs: %x != %x", g1, g2)
	}
}

func TestComputeGIDDiffersByPublicKey(t *testing.T) {
	svc := []byte("service-1")
	g1 := ComputeGID([]byte("public key A"), svc)
	g2 := ComputeGID([]byte("public key B"), svc)
	if g1 == g2 {
		t.Error("ComputeGID produced the same value for two different public keys")
	}
}

func TestComputeGIDDiffersByServiceID(t *testing.T) {
	pub := []byte("a garlic public key")
	g1 := ComputeGID(pub, []byte("service-1"))
	g2 := ComputeGID(pub, []byte("service-2"))
	if g1 == g2 {
		t.Error("ComputeGID produced the same value for two different service IDs")
	}
}

func TestComputeGIDCarriesVersion(t *testing.T) {
	g := ComputeGID([]byte("pub"), []byte("svc"))
	if g[0] != GIDVersion1 {
		t.Errorf("GID version byte = %d, want %d", g[0], GIDVersion1)
	}
}

func TestGIDStringParseRoundTrip(t *testing.T) {
	g := ComputeGID([]byte("a garlic public key"), []byte("service-1"))
	s := g.String()

	got, err := ParseGID(s)
	if err != nil {
		t.Fatalf("ParseGID returned error: %v", err)
	}
	if got != g {
		t.Errorf("ParseGID(%q) = %x, want %x", s, got, g)
	}
}

func TestParseGIDRejectsInvalidEncoding(t *testing.T) {
	if _, err := ParseGID("not valid base32!!!"); err == nil {
		t.Fatal("expected error for invalid encoding, got nil")
	}
}

func TestParseGIDRejectsWrongLength(t *testing.T) {
	// Valid base32 but too short to be a real GID.
	if _, err := ParseGID("AAAA"); err == nil {
		t.Fatal("expected error for wrong-length GID, got nil")
	}
}

func TestParseGIDRejectsUnsupportedVersion(t *testing.T) {
	g := ComputeGID([]byte("pub"), []byte("svc"))
	g[0] = GIDVersion2 + 1 // craft an otherwise-well-formed GID with an unknown version
	if _, err := ParseGID(g.String()); err == nil {
		t.Fatal("expected error for unsupported GID version, got nil")
	}
}
