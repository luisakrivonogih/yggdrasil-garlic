package garlic

// Rotating onion keys (forward secrecy for relay layers).
//
// A relay decrypts its onion layer with ECDH(onion private key, the
// originator's per-circuit ephemeral key). If that private key lived
// forever, anyone who later stole it could strip this relay's layer from
// every recorded packet ever relayed. Onion keys are therefore:
//
//   - generated in memory at startup and never written to disk;
//   - replaced every Config.OnionKeyRotation;
//   - kept for a grace period afterwards (circuits built just before a
//     rotation keep working), then overwritten with zeros and dropped.
//
// After a key is dropped, traffic encrypted to it cannot be decrypted even
// by someone who later obtains everything on this machine. The forward
// secrecy window is therefore one rotation interval plus the grace period.

import (
	"sync"
	"time"
)

type onionKey struct {
	public, private []byte
	created         time.Time
	expires         time.Time // private key is deleted at this moment
}

type onionKeyring struct {
	mu       sync.Mutex
	rotation time.Duration
	grace    time.Duration
	keys     []*onionKey // newest first
}

func newOnionKeyring(rotation, grace time.Duration, initialPub, initialPriv []byte) *onionKeyring {
	k := &onionKeyring{rotation: rotation, grace: grace}
	now := time.Now()
	if len(initialPub) == KeySize && len(initialPriv) == KeySize {
		k.keys = []*onionKey{{public: append([]byte(nil), initialPub...), private: append([]byte(nil), initialPriv...), created: now, expires: now.Add(rotation + grace)}}
	}
	return k
}

// current returns the newest key, generating one if none exists yet.
func (k *onionKeyring) current() (*onionKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.keys) == 0 {
		if err := k.addLocked(time.Now()); err != nil {
			return nil, err
		}
	}
	return k.keys[0], nil
}

func (k *onionKeyring) addLocked(now time.Time) error {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		return err
	}
	k.keys = append([]*onionKey{{public: pub, private: priv, created: now, expires: now.Add(k.rotation + k.grace)}}, k.keys...)
	return nil
}

// rotate creates a new current key if the newest one is older than the
// rotation interval and wipes every expired key. It reports whether the
// advertised key changed.
func (k *onionKeyring) rotate(now time.Time) (bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	changed := false
	if len(k.keys) == 0 || now.Sub(k.keys[0].created) >= k.rotation {
		if err := k.addLocked(now); err != nil {
			return false, err
		}
		changed = true
	}
	kept := k.keys[:0]
	for _, key := range k.keys {
		if now.Before(key.expires) {
			kept = append(kept, key)
			continue
		}
		clear(key.private)
	}
	k.keys = kept
	return changed, nil
}

// privateKeys returns every still-valid private key, newest first.
func (k *onionKeyring) privateKeys() [][]byte {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := time.Now()
	out := make([][]byte, 0, len(k.keys))
	for _, key := range k.keys {
		if now.Before(key.expires) {
			out = append(out, key.private)
		}
	}
	return out
}

// wipe deletes every key (used when the overlay shuts down).
func (k *onionKeyring) wipe() {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, key := range k.keys {
		clear(key.private)
	}
	k.keys = nil
}
