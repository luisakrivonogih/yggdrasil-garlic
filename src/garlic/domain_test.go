package garlic

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDomainEncoding(t *testing.T) {
	gid := GID{GIDVersion1}
	want := "ae" + strings.Repeat("a", 51) + ".domains.yggg"
	if got := gid.Domain(); got != want {
		t.Fatalf("Domain() = %q, want %q", got, want)
	}
	for _, name := range []string{want, strings.ToUpper(want), want + ".", strings.ToUpper(want) + "."} {
		got, err := ParseDomain(name)
		if err != nil || got != gid {
			t.Errorf("ParseDomain(%q) = %v, %v; want %v", name, got, err, gid)
		}
	}
}

func TestParseDomainRejectsMalformedNames(t *testing.T) {
	label := "ae" + strings.Repeat("a", 51)
	unknown := GID{GIDVersion1 + 1}
	for _, name := range []string{
		"", ".domains.yggg", "domains.yggg", "example.yggg", label,
		label + ".yggg", label + ".garlic.ygg", label + ".domains.yggg.evil",
		"sub." + label + DomainSuffix, label + DomainSuffix + "..",
		"https://" + label + DomainSuffix, label + DomainSuffix + ":80",
		" " + label + DomainSuffix, label + DomainSuffix + "\n",
		label[:52] + DomainSuffix, label + "a" + DomainSuffix,
		label[:52] + "0" + DomainSuffix, label[:52] + "=" + DomainSuffix,
		label[:52] + "-" + DomainSuffix, label[:52] + "." + DomainSuffix,
		label[:52] + "b" + DomainSuffix, // same decoded bytes, nonzero unused bits
		unknown.Domain(), strings.Repeat("a", 4096) + DomainSuffix,
		label[:52] + "ſ" + DomainSuffix, // Unicode must never fold to an ASCII label
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseDomain(name); !errors.Is(err, ErrInvalidDomain) {
				t.Fatalf("ParseDomain(%q) = %v, want ErrInvalidDomain", name, err)
			}
		})
	}
}

func TestDomainIdentityPersistenceAndIsolation(t *testing.T) {
	id := testDescriptorIdentity(t)
	loaded, err := LoadIdentityFromPrivateKeys(id.PrivateKey, id.SigningPrivateKey.Seed())
	if err != nil {
		t.Fatal(err)
	}
	serviceID := []byte("web")
	want := ComputeGID(id.SigningPublicKey, serviceID).Domain()
	if got := ComputeGID(loaded.SigningPublicKey, serviceID).Domain(); got != want {
		t.Fatalf("domain changed after reloading keys: %s != %s", got, want)
	}
	other := testDescriptorIdentity(t)
	// Rotating the X25519 key must not change a signing identity's domain.
	rotated, err := LoadIdentityFromPrivateKeys(other.PrivateKey, id.SigningPrivateKey.Seed())
	if err != nil {
		t.Fatal(err)
	}
	if got := ComputeGID(rotated.SigningPublicKey, serviceID).Domain(); got != want {
		t.Fatalf("domain depends on X25519 key: %s != %s", got, want)
	}
	if ComputeGID(other.SigningPublicKey, serviceID).Domain() == want {
		t.Fatal("different signing identities have the same domain")
	}
	if ComputeGID(id.SigningPublicKey, []byte("other")).Domain() == want {
		t.Fatal("different services have the same domain")
	}
}

func TestLookupDomainVerifiesDirectoryRecords(t *testing.T) {
	id := testDescriptorIdentity(t)
	attacker := testDescriptorIdentity(t)
	rv := NewStaticRendezvous()
	publisher := &Garlic{identity: id, rendezvous: rv}
	client := &Garlic{rendezvous: rv}
	serviceID := []byte("web")
	gid := ComputeGID(id.SigningPublicKey, serviceID)
	if _, err := client.LookupDomain(gid.Domain()); !errors.Is(err, ErrGIDNotFound) {
		t.Fatalf("unpublished domain: got %v", err)
	}
	points := []IntroPoint{{NodeKey: bytes.Repeat([]byte{1}, 32)}}
	published, err := publisher.PublishService(serviceID, points, time.Hour)
	if err != nil || published != gid {
		t.Fatalf("publish: %v, %v", published, err)
	}
	got, err := client.LookupDomain(strings.ToUpper(gid.Domain()) + ".")
	if err != nil || len(got) != 1 || !bytes.Equal(got[0].NodeKey, points[0].NodeKey) {
		t.Fatalf("resolve: %v, %v", got, err)
	}
	now := uint64(time.Now().Unix())
	for _, tc := range []struct {
		name      string
		identity  *Identity
		published uint64
		expires   uint64
		tamper    bool
		want      error
	}{
		{"forged", attacker, now, now + 3600, false, ErrDescriptorGIDMismatch},
		{"tampered", id, now, now + 3600, true, ErrInvalidDescriptorSignature},
		{"expired", id, now - 100, now - 1, false, ErrDescriptorExpired},
		{"future", id, now + 3600, now + 7200, false, ErrDescriptorNotYetValid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := SignServiceDescriptor(tc.identity.SigningPublicKey, tc.identity.SigningPrivateKey, serviceID, points, tc.published, tc.expires)
			if err != nil {
				t.Fatal(err)
			}
			if tc.tamper {
				d.IntroPoints = []IntroPoint{{NodeKey: []byte("attacker")}}
			}
			if err := rv.Publish(gid, d); err != nil {
				t.Fatal(err)
			}
			if _, err := client.LookupDomain(gid.Domain()); !errors.Is(err, tc.want) {
				t.Fatalf("lookup error = %v, want %v", err, tc.want)
			}
		})
	}
	// Reject invalid names before consulting any backend (which is nil here).
	if _, err := (&Garlic{}).LookupDomain("example.yggg"); !errors.Is(err, ErrInvalidDomain) {
		t.Fatalf("invalid domain: %v", err)
	}
}

func FuzzParseDomain(f *testing.F) {
	f.Add((GID{GIDVersion1}).Domain())
	f.Add("example.yggg")
	f.Add("")
	f.Fuzz(func(t *testing.T, name string) {
		gid, err := ParseDomain(name)
		if err != nil {
			return
		}
		if gid.Domain() != strings.ToLower(strings.TrimSuffix(name, ".")) {
			t.Fatalf("accepted noncanonical domain %q", name)
		}
	})
}
