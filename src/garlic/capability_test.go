package garlic

import (
	"bytes"
	"testing"
)

func TestCapabilityMessageMarshalUnmarshalRoundTrip(t *testing.T) {
	m := &CapabilityMessage{
		Versions:  []string{CapabilityGarlicV2, "garlic-v2-experimental"},
		PublicKey: []byte("a 32-byte garlic public key!!!!"),
	}
	data, err := m.Marshal()
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	got, err := UnmarshalCapabilityMessage(data)
	if err != nil {
		t.Fatalf("UnmarshalCapabilityMessage returned error: %v", err)
	}
	if len(got.Versions) != len(m.Versions) {
		t.Fatalf("got %d versions, want %d", len(got.Versions), len(m.Versions))
	}
	for i := range m.Versions {
		if got.Versions[i] != m.Versions[i] {
			t.Errorf("version %d = %q, want %q", i, got.Versions[i], m.Versions[i])
		}
	}
	if !bytes.Equal(got.PublicKey, m.PublicKey) {
		t.Errorf("PublicKey = %q, want %q", got.PublicKey, m.PublicKey)
	}
}

func TestCapabilityMessageMarshalEmpty(t *testing.T) {
	m := &CapabilityMessage{}
	data, err := m.Marshal()
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	got, err := UnmarshalCapabilityMessage(data)
	if err != nil {
		t.Fatalf("UnmarshalCapabilityMessage returned error: %v", err)
	}
	if len(got.Versions) != 0 || len(got.PublicKey) != 0 {
		t.Fatalf("got %+v, want empty", got)
	}
}

func TestCapabilityMessageMarshalRejectsTooManyVersions(t *testing.T) {
	m := &CapabilityMessage{Versions: make([]string, maxCapabilityVersions+1)}
	if _, err := m.Marshal(); err == nil {
		t.Fatal("expected error for too many versions, got nil")
	}
}

func TestCapabilityMessageMarshalRejectsVersionTooLong(t *testing.T) {
	m := &CapabilityMessage{Versions: []string{string(make([]byte, maxCapabilityVersionLen+1))}}
	if _, err := m.Marshal(); err == nil {
		t.Fatal("expected error for an oversized version string, got nil")
	}
}

func TestCapabilityMessageMarshalRejectsKeyTooLong(t *testing.T) {
	m := &CapabilityMessage{PublicKey: make([]byte, maxCapabilityKeyLen+1)}
	if _, err := m.Marshal(); err == nil {
		t.Fatal("expected error for an oversized public key, got nil")
	}
}

func TestUnmarshalCapabilityMessageRejectsEmptyInput(t *testing.T) {
	if _, err := UnmarshalCapabilityMessage(nil); err == nil {
		t.Fatal("expected error for empty input, got nil")
	}
}

func TestUnmarshalCapabilityMessageRejectsTruncatedVersionList(t *testing.T) {
	// Claims 2 versions but provides none.
	if _, err := UnmarshalCapabilityMessage([]byte{2}); err == nil {
		t.Fatal("expected error for truncated version list, got nil")
	}
}

func TestUnmarshalCapabilityMessageRejectsVersionLengthExceedingBuffer(t *testing.T) {
	// Claims 1 version of length 100, but provides no such bytes.
	if _, err := UnmarshalCapabilityMessage([]byte{1, 100}); err == nil {
		t.Fatal("expected error for version length exceeding buffer, got nil")
	}
}

func TestSupportsGarlicV2(t *testing.T) {
	yes := &CapabilityMessage{Versions: []string{CapabilityGarlicV2}}
	if !yes.SupportsGarlicV2() {
		t.Error("SupportsGarlicV2() = false, want true")
	}
	no := &CapabilityMessage{Versions: []string{"something-else"}}
	if no.SupportsGarlicV2() {
		t.Error("SupportsGarlicV2() = true, want false")
	}
	empty := &CapabilityMessage{}
	if empty.SupportsGarlicV2() {
		t.Error("SupportsGarlicV2() on empty message = true, want false")
	}
}

func TestSupportsAutoCircuit(t *testing.T) {
	yes := &CapabilityMessage{Versions: []string{CapabilityGarlicV2, CapabilityAutoCircuit}}
	if !yes.SupportsAutoCircuit() {
		t.Fatal("SupportsAutoCircuit() = false, want true")
	}
	no := &CapabilityMessage{Versions: []string{CapabilityGarlicV2}}
	if no.SupportsAutoCircuit() {
		t.Fatal("SupportsAutoCircuit() = true, want false")
	}
}

func TestSupportsGarlicV3(t *testing.T) {
	withV3 := &CapabilityMessage{Versions: []string{CapabilityGarlicV2, CapabilityGarlicV3}}
	if !withV3.SupportsGarlicV3() {
		t.Fatal("SupportsGarlicV3() = false, want true when garlic-v3 is present")
	}
	withoutV3 := &CapabilityMessage{Versions: []string{CapabilityGarlicV2}}
	if withoutV3.SupportsGarlicV3() {
		t.Fatal("SupportsGarlicV3() = true, want false when garlic-v3 is absent")
	}
}

func TestRelaysAdvertiseGarlicV3(t *testing.T) {
	msg := &CapabilityMessage{Versions: supportedVersions()}
	if !msg.SupportsGarlicV3() || !msg.SupportsGarlicV2() {
		t.Fatalf("advertised versions = %v, want garlic-v2 and garlic-v3", msg.Versions)
	}
}
