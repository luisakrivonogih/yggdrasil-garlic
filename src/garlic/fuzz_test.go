package garlic

// Adversarial fuzzing (Phase 13 of the roadmap) for every parser that
// handles bytes an untrusted remote peer controls. The property under
// test is simply "never panics" - malformed input must always come back
// as an error, never a crash, never an unbounded allocation. Run with:
//
//	go test ./src/garlic/... -fuzz=FuzzEnvelopeUnmarshal -fuzztime=60s
//
// (and similarly for the other Fuzz* targets below).

import (
	"testing"
	"time"
)

func FuzzEnvelopeUnmarshal(f *testing.F) {
	valid := &Envelope{
		Version:       EnvelopeVersion1,
		CircuitID:     testCircuitID(1),
		PacketCounter: 1,
		Expiration:    9999999999,
		Body:          []byte("hello"),
		Padding:       []byte{0, 0, 0},
	}
	validBytes, _ := valid.Marshal()
	f.Add(validBytes)
	validV2 := &Envelope{
		Version:       EnvelopeVersion2,
		CircuitID:     testCircuitID(2),
		PacketCounter: 1,
		Expiration:    9999999999,
		Body:          []byte("hello"),
		Padding:       []byte{0, 0, 0},
	}
	validV2Bytes, _ := validV2.Marshal()
	f.Add(validV2Bytes)
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add(make([]byte, envelopeFixedHeaderSize-1))
	f.Add(make([]byte, envelopeFixedHeaderSize))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Unmarshal(data)
	})
}

func FuzzBundleUnmarshal(f *testing.F) {
	valid := &Bundle{Messages: [][]byte{[]byte("a"), []byte("bb"), {}}}
	validBytes, _ := valid.Marshal()
	f.Add(validBytes)
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = UnmarshalBundle(data)
	})
}

func FuzzCapabilityMessageUnmarshal(f *testing.F) {
	valid := &CapabilityMessage{Versions: []string{CapabilityGarlicV2}, PublicKey: make([]byte, KeySize)}
	validBytes, _ := valid.Marshal()
	f.Add(validBytes)
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add([]byte{255})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = UnmarshalCapabilityMessage(data)
	})
}

func FuzzProcessCircuitData(f *testing.F) {
	id, err := NewIdentity()
	if err != nil {
		f.Fatalf("NewIdentity returned error: %v", err)
	}
	g := &Garlic{
		identity:   id,
		onion:      testOnion(id),
		cfg:        DefaultConfig(),
		relayState: newRelayCircuitState(1024),
		delivered:  make(chan DeliveredMessage, 256),
	}

	valid, _ := buildTestCircuitDataForFuzz(id, []byte("payload"), time.Minute)
	f.Add(valid)
	validHopLocal, _ := buildTestCircuitDataHopLocalForFuzz(id, []byte("payload"), time.Minute)
	f.Add(validHopLocal)
	f.Add([]byte{})
	f.Add(make([]byte, KeySize))
	f.Add(make([]byte, circuitDataMinSize))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = g.processCircuitData(data, msgTypeCircuitData)
	})
}

func FuzzLayerPlaintextUnmarshal(f *testing.F) {
	valid := &LayerPlaintext{
		NextHop:          []byte("next-hop-key"),
		NextHopEphemeral: make([]byte, KeySize),
		Inner:            []byte("inner ciphertext"),
	}
	validBytes, _ := valid.marshal()
	f.Add(validBytes)
	validHopLocal := &LayerPlaintext{
		NextHop:             []byte("next-hop-key"),
		NextHopEphemeral:    make([]byte, KeySize),
		Inner:               []byte("inner ciphertext"),
		NextLocalCircuitID:  make([]byte, 16),
		NextLocalCounter:    1,
		NextLocalExpiration: 9999999999,
	}
	validHopLocalBytes, _ := validHopLocal.marshalHopLocal()
	f.Add(validHopLocalBytes)
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0})    // empty next_hop, truncated before the flag byte
	f.Add([]byte{0, 0, 0, 0, 1}) // flag says "ephemeral present" but provides none
	f.Add([]byte{0, 0, 0, 0, 2}) // invalid flag byte
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = unmarshalLayerPlaintext(data)
		_, _ = unmarshalLayerPlaintextHopLocal(data)
	})
}

func FuzzServiceDescriptorFieldsUnmarshal(f *testing.F) {
	id, err := NewIdentity()
	if err != nil {
		f.Fatalf("NewIdentity returned error: %v", err)
	}
	d, err := SignServiceDescriptor(id.SigningPublicKey, id.SigningPrivateKey, []byte("svc"), []IntroPoint{{NodeKey: []byte("intro")}}, 1000, 2000)
	if err != nil {
		f.Fatalf("SignServiceDescriptor returned error: %v", err)
	}
	validBytes, _ := d.signedBytes()
	f.Add(validBytes)
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add([]byte{255})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = unmarshalServiceDescriptorFields(data)
	})
}

// buildTestCircuitDataForFuzz is a minimal standalone variant of
// buildTestCircuitData (relay_logic_test.go) that doesn't depend on
// *testing.T, since Fuzz seed setup runs outside a single subtest.
func buildTestCircuitDataForFuzz(id *Identity, payload []byte, ttl time.Duration) ([]byte, error) {
	ephemeralPub, ephemeralPriv, err := GenerateKeypair()
	if err != nil {
		return nil, err
	}
	secret, err := ECDH(ephemeralPriv, id.PublicKey)
	if err != nil {
		return nil, err
	}
	key, err := deriveLayerKey(secret)
	if err != nil {
		return nil, err
	}
	c, err := NewCircuit([]Hop{{NodeKey: id.PublicKey, Key: key}}, time.Minute, 100, 100000)
	if err != nil {
		return nil, err
	}
	onion, _, counter, err := c.Seal(payload)
	if err != nil {
		return nil, err
	}
	env := &Envelope{
		Version:       EnvelopeVersion1,
		CircuitID:     c.ID,
		PacketCounter: counter,
		Expiration:    uint64(time.Now().Add(ttl).Unix()),
		Body:          onion,
	}
	envBytes, err := env.Marshal()
	if err != nil {
		return nil, err
	}
	return append(append([]byte(nil), ephemeralPub...), envBytes...), nil
}

// buildTestCircuitDataHopLocalForFuzz is buildTestCircuitDataForFuzz's
// counterpart for the hop-local envelope format.
func buildTestCircuitDataHopLocalForFuzz(id *Identity, payload []byte, ttl time.Duration) ([]byte, error) {
	ephemeralPub, ephemeralPriv, err := GenerateKeypair()
	if err != nil {
		return nil, err
	}
	secret, err := ECDH(ephemeralPriv, id.PublicKey)
	if err != nil {
		return nil, err
	}
	key, err := deriveLayerKeyHopLocal(secret)
	if err != nil {
		return nil, err
	}
	localID, err := randomCircuitID()
	if err != nil {
		return nil, err
	}
	c, err := NewCircuit([]Hop{{NodeKey: id.PublicKey, Key: key, LocalCircuitID: localID}}, time.Minute, 100, 100000)
	if err != nil {
		return nil, err
	}
	onion, _, legID, counter, expiration, err := c.SealHopLocal(payload, ttl)
	if err != nil {
		return nil, err
	}
	env := &Envelope{
		Version:       EnvelopeVersion2,
		CircuitID:     legID,
		PacketCounter: counter,
		Expiration:    expiration,
		Body:          onion,
	}
	envBytes, err := env.Marshal()
	if err != nil {
		return nil, err
	}
	return append(append([]byte(nil), ephemeralPub...), envBytes...), nil
}
