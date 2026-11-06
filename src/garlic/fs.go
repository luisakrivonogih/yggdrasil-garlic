package garlic

// Per-circuit forward secrecy for duplex (site and directory) circuits.
//
// Without it a hop's layer key is derived from ECDH(originator ephemeral,
// relay onion key) only: whoever later obtains the relay's onion key
// (valid for an hour or two) can decrypt that hop's layers of everything
// recorded meanwhile. With it, on the first packet of a circuit every
// FS-capable relay (CapabilityDuplexFS) also makes a one-time key pair y/Y,
// immediately derives
//
//	fs  = ECDH(y, X)                 (X: the originator's ephemeral for this hop)
//	key = HKDF(ECDH(x, onion) || fs) (separately for each direction)
//
// and wipes y. Y travels back to the originator in the header of the
// relay's reply layer; the originator computes ECDH(x, Y) = fs, derives
// the same keys, wipes x and uses only the new keys from then on (the
// relay then refuses packets under the old ones). When the circuit ends
// both sides drop the keys, and the circuit's traffic after the first
// round trip cannot be decrypted any more, even with the relay's onion key.
//
// The first exchange of a circuit (before Y arrives) is still protected
// only by the onion key rotation; site content is additionally protected
// end to end by the QUIC/TLS 1.3 session.

const (
	labelFSForward = "yggdrasil-garlic-fs-forward-v1"
	labelFSReply   = "yggdrasil-garlic-fs-reply-v1"

	// Reply layer headers (FS-capable hops only).
	fsHeaderNone     byte = 0
	fsHeaderRelayKey byte = 1
)

// deriveFSKeys derives a hop's forward and reply keys from the onion-key
// secret and the per-circuit ephemeral secret.
func deriveFSKeys(secret, fs []byte) (forward, reply []byte, err error) {
	ikm := make([]byte, 0, len(secret)+len(fs))
	ikm = append(append(ikm, secret...), fs...)
	defer clear(ikm)
	if forward, err = DeriveKey(ikm, nil, labelFSForward); err != nil {
		return nil, nil, err
	}
	if reply, err = DeriveKey(ikm, nil, labelFSReply); err != nil {
		return nil, nil, err
	}
	return forward, reply, nil
}

// relayFSKeys makes the relay's one-time key pair for a new circuit hop
// and returns the derived keys and the public half to send back. The
// private half never leaves this function.
func relayFSKeys(secret, originatorEphemeral []byte) (forward, reply, relayPub []byte, err error) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		return nil, nil, nil, err
	}
	defer clear(priv)
	fs, err := ECDH(priv, originatorEphemeral)
	if err != nil {
		return nil, nil, nil, err
	}
	defer clear(fs)
	forward, reply, err = deriveFSKeys(secret, fs)
	return forward, reply, pub, err
}

// hopFS is the originator's forward-secrecy state for one hop.
type hopFS struct {
	capable bool   // the relay advertised CapabilityDuplexFS
	secret  []byte // ECDH(x, onion), until the upgrade
	priv    []byte // x, until the upgrade
	relay   []byte // Y, once received
}

// fsLearn records the relay keys found in a reply. When every FS-capable
// hop's key is known it switches the circuit's forward keys and returns
// the new reply keys (nil entries for hops without FS); otherwise nil.
func (c *Circuit) fsLearn(relayKeys [][]byte) ([][]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fsDone || len(c.fs) != len(c.hops) {
		return nil, nil
	}
	for i, k := range relayKeys {
		if i < len(c.fs) && c.fs[i].capable && len(k) == KeySize && c.fs[i].relay == nil {
			c.fs[i].relay = append([]byte(nil), k...)
		}
	}
	for _, h := range c.fs {
		if h.capable && h.relay == nil {
			return nil, nil
		}
	}
	replies := make([][]byte, len(c.hops))
	forwards := make([][]byte, len(c.hops))
	for i := range c.fs {
		h := &c.fs[i]
		if !h.capable {
			continue
		}
		fs, err := ECDH(h.priv, h.relay)
		if err != nil {
			return nil, err
		}
		forwards[i], replies[i], err = deriveFSKeys(h.secret, fs)
		clear(fs)
		if err != nil {
			return nil, err
		}
	}
	for i := range c.fs {
		if forwards[i] != nil {
			c.hops[i].Key = forwards[i]
		}
		clear(c.fs[i].priv)
		clear(c.fs[i].secret)
		c.fs[i].priv, c.fs[i].secret = nil, nil
	}
	c.fsDone = true
	return replies, nil
}

// fsWipe drops the originator's ephemeral secrets (circuit closed).
func (c *Circuit) fsWipe() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.fs {
		clear(c.fs[i].priv)
		clear(c.fs[i].secret)
		c.fs[i].priv, c.fs[i].secret = nil, nil
	}
}

// FSUpgraded reports whether the circuit runs on per-circuit keys.
func (c *Circuit) FSUpgraded() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fsDone
}
