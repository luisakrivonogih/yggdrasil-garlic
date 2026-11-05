package core

import "crypto/ed25519"

// GarlicHandler receives packets sent with WriteGarlic once decrypted from
// the mesh's own transport-level encryption (see src/garlic). from is the
// sending node's Yggdrasil public key.
//
// A GarlicHandler MUST NOT block: it is invoked synchronously from within
// Core.ReadFrom's read loop, exactly like the existing NodeInfo/debug
// protocol handlers, so a slow handler would stall ordinary IPv6 traffic
// for this node. Implementations should hand off to their own
// worker/queue and return immediately.
type GarlicHandler func(from ed25519.PublicKey, data []byte)

// SetGarlicHandler registers the callback that receives incoming Garlic
// Routing Overlay traffic (see WriteGarlic). Passing nil unregisters it,
// reverting to the default legacy behavior of silently dropping
// typeSessionGarlic packets. Safe to call concurrently with ReadFrom.
func (c *Core) SetGarlicHandler(h GarlicHandler) {
	if h == nil {
		c.garlicHandler.Store(nil)
		return
	}
	c.garlicHandler.Store(&h)
}

func (c *Core) getGarlicHandler() GarlicHandler {
	if p := c.garlicHandler.Load(); p != nil {
		return *p
	}
	return nil
}

// GarlicSignaturePrefix domain-separates every statement this node signs
// for the Garlic overlay (see SignGarlic) from anything else ever signed
// with the same Yggdrasil key, so a Garlic signature can never be replayed
// as a mesh-protocol signature or vice versa.
const GarlicSignaturePrefix = "yggdrasil-garlic-node-statement-v1\x00"

// SignGarlic signs statement with this node's Yggdrasil private key under
// GarlicSignaturePrefix. src/garlic uses it to bind a relay's rotating
// onion key to its node key, so other nodes can verify that binding from
// gossip without contacting the relay directly. Verify with
// ed25519.Verify(nodeKey, append([]byte(GarlicSignaturePrefix), statement...), sig).
func (c *Core) SignGarlic(statement []byte) []byte {
	msg := make([]byte, 0, len(GarlicSignaturePrefix)+len(statement))
	msg = append(msg, GarlicSignaturePrefix...)
	msg = append(msg, statement...)
	return ed25519.Sign(c.secret, msg)
}
