package garlic

// Benchmarks (Phase 14 of the roadmap) for the CPU-bound per-packet
// operations: envelope (de)serialization, the AEAD/KDF primitives, onion
// construction, and the full receive-side decrypt/replay/forward
// pipeline. Run with:
//
//	go test ./src/garlic/... -run '^$' -bench . -benchmem

import (
	"testing"
	"time"
)

func BenchmarkEnvelopeMarshal(b *testing.B) {
	env := &Envelope{Version: EnvelopeVersion1, CircuitID: testCircuitID(1), PacketCounter: 1, Expiration: 1, Body: make([]byte, 1200)}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := env.Marshal(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEnvelopeUnmarshal(b *testing.B) {
	env := &Envelope{Version: EnvelopeVersion1, CircuitID: testCircuitID(1), PacketCounter: 1, Expiration: 1, Body: make([]byte, 1200)}
	data, err := env.Marshal()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Unmarshal(data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDeriveKey(b *testing.B) {
	secret := make([]byte, 32)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := DeriveKey(secret, nil, LabelCircuitDataSend); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkECDH(b *testing.B) {
	_, priv, err := GenerateKeypair()
	if err != nil {
		b.Fatal(err)
	}
	pub, _, err := GenerateKeypair()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := ECDH(priv, pub); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSeal(b *testing.B) {
	key, _ := DeriveKey([]byte("secret"), nil, LabelCircuitDataSend)
	plaintext := make([]byte, 1200)
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		if _, err := Seal(key, uint64(i), plaintext, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOpen(b *testing.B) {
	key, _ := DeriveKey([]byte("secret"), nil, LabelCircuitDataSend)
	plaintext := make([]byte, 1200)
	ciphertext, err := Seal(key, 1, plaintext, nil)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Open(key, 1, ciphertext, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBuildOnionThreeHops(b *testing.B) {
	hops := make([]Hop, 3)
	for i := range hops {
		key, _ := DeriveKey([]byte{byte(i)}, nil, LabelCircuitDataSend)
		hops[i] = Hop{NodeKey: []byte{byte(i)}, Key: key}
	}
	payload := make([]byte, 1200)
	b.ReportAllocs()
	for b.Loop() {
		for i := range hops {
			hops[i].Counter = 0
		}
		if _, err := BuildOnion(hops, payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCircuitSeal(b *testing.B) {
	hops := make([]Hop, 3)
	for i := range hops {
		key, _ := DeriveKey([]byte{byte(i)}, nil, LabelCircuitDataSend)
		hops[i] = Hop{NodeKey: []byte{byte(i)}, Key: key}
	}
	c, err := NewCircuit(hops, time.Hour, 1<<40, 1<<50)
	if err != nil {
		b.Fatal(err)
	}
	payload := make([]byte, 1200)
	b.ReportAllocs()
	for b.Loop() {
		if _, _, _, err := c.Seal(payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkProcessCircuitDataTerminalHop(b *testing.B) {
	id, err := NewIdentity()
	if err != nil {
		b.Fatal(err)
	}
	g := &Garlic{
		identity: id,
		onion:    testOnion(id),
		cfg:      DefaultConfig(),
	}
	payload := make([]byte, 1200)
	b.ReportAllocs()
	for b.Loop() {
		b.StopTimer()
		g.relayState = newRelayCircuitState(1024) // fresh replay state each iteration
		body, err := buildTestCircuitDataForFuzz(id, payload, time.Minute)
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		if action := g.processCircuitData(body, msgTypeCircuitData); action.kind != actionDeliver {
			b.Fatalf("action.kind = %v, want actionDeliver", action.kind)
		}
	}
}
