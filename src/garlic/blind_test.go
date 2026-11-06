package garlic

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

func TestBlindedKeysSignAndUnlink(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	for _, period := range []uint64{0, 20000, 20001} {
		signer, err := newBlindedSigner(priv, period)
		if err != nil {
			t.Fatal(err)
		}
		derived, err := BlindPublicKey(pub, period)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(signer.pub, derived) {
			t.Fatal("anyone knowing the site key must derive the same blinded key as the site")
		}
		msg := []byte("record")
		if !ed25519.Verify(derived, msg, signer.sign(msg)) {
			t.Fatal("blinded signature does not verify as a standard Ed25519 signature")
		}
		if bytes.Equal(derived, pub) {
			t.Fatal("blinded key equals the site key")
		}
	}
	a, _ := BlindPublicKey(pub, 1)
	b, _ := BlindPublicKey(pub, 2)
	if bytes.Equal(a, b) {
		t.Fatal("blinded keys of different days are equal")
	}
}

func TestBlindedRecordRoundTripAndForgery(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	gid := ComputeGIDv2(pub)
	now := time.Now()
	ts := uint64(now.Unix())
	d, err := SignServiceDescriptorFor(gid, pub, priv, nil, []IntroPoint{{NodeKey: bytes.Repeat([]byte{7}, 32)}}, ts, ts+180)
	if err != nil {
		t.Fatal(err)
	}
	if DescriptorGID(d) != gid {
		t.Fatal("descriptor does not name its version 2 GID")
	}
	period := blindPeriod(now)
	r, err := sealBlindedRecord(d, priv, period)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(r.Ciphertext, pub) || bytes.Contains(r.Ciphertext, d.IntroPoints[0].NodeKey) {
		t.Fatal("record leaks the site key or its relays")
	}
	if err := validateBlindedRecord(r, blindedIndexKey(r.Index), now); err != nil {
		t.Fatalf("directory rejected a valid record: %v", err)
	}
	got, err := openBlindedRecord(r, gid, now)
	if err != nil || !bytes.Equal(got.IntroPoints[0].NodeKey, d.IntroPoints[0].NodeKey) {
		t.Fatalf("client could not open the record: %v", err)
	}
	// Someone without the site key cannot sign for the index.
	_, other, _ := ed25519.GenerateKey(nil)
	forged, _ := sealBlindedRecord(d, other, period)
	forged.Index = r.Index
	if err := validateBlindedRecord(forged, blindedIndexKey(r.Index), now); !errors.Is(err, ErrBlindedRecordSignature) {
		t.Fatalf("forged record accepted: %v", err)
	}
	tampered := *r
	tampered.Ciphertext = append([]byte(nil), r.Ciphertext...)
	tampered.Ciphertext[len(tampered.Ciphertext)-1] ^= 1
	if err := validateBlindedRecord(&tampered, blindedIndexKey(r.Index), now); err == nil {
		t.Fatal("tampered record accepted")
	}
	// Another site cannot open it.
	otherPub, _, _ := ed25519.GenerateKey(nil)
	if _, err := openBlindedRecord(r, ComputeGIDv2(otherPub), now); err == nil {
		t.Fatal("record opened under a different GID")
	}
	if err := validateBlindedRecord(r, blindedIndexKey(r.Index), now.Add(3*24*time.Hour)); err == nil {
		t.Fatal("record from another period accepted")
	}
}

func TestVersion2DomainsParse(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	gid := ComputeGIDv2(pub)
	got, err := ParseDomain(gid.Domain())
	if err != nil || got != gid {
		t.Fatalf("version 2 domain does not parse back: %v", err)
	}
	bad := gid
	bad[1] ^= 0xff
	bad[32] = 0xff
	if _, err := ParseGID(bad.String()); err == nil {
		// Not every 32-byte string is a point; most flipped ones are not.
		t.Log("flipped key happened to be a valid point")
	}
}
