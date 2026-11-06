package garlic

// Blinded directory records for version 2 GIDs (as in Tor v3 onion
// services).
//
// A version 2 GID is the site's Ed25519 public key A. For every day
// (period p) both the site and anyone who knows its domain derive a
// blinding factor h_p = H(A, p) and the blinded key A_p = h_p·A. The site
// can sign for A_p, because it knows a_p = h_p·a for its secret scalar a;
// nobody else can. A record is stored in the directory under A_p, signed
// with a_p, and its content - the ordinary signed descriptor - is
// encrypted with a key derived from A and p.
//
// Directory nodes therefore see only A_p and ciphertext: they cannot tell
// which site a record belongs to, cannot read its relays, cannot link the
// same site from one day to the next, and cannot forge or alter a record
// (the signature is checked against A_p, the index itself).

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/json"
	"errors"
	"time"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	blindPeriodSeconds  = 24 * 60 * 60
	blindFactorDomain   = "yggdrasil-garlic-blind-factor-v1\x00"
	blindPrefixDomain   = "yggdrasil-garlic-blind-prefix-v1\x00"
	blindKeyDomain      = "yggdrasil-garlic-blind-desc-key-v1\x00"
	blindRecordDomain   = "yggdrasil-garlic-blind-record-v1\x00"
	maxBlindedCipherLen = 4096
	// gidBlindedIndex marks a directory key that is a blinded key, not a
	// GID. It never appears in a domain.
	gidBlindedIndex uint8 = 0x80
)

var (
	ErrBlindedRecordInvalid   = errors.New("garlic: invalid blinded directory record")
	ErrBlindedRecordSignature = errors.New("garlic: blinded directory record signature invalid")
)

// blindPeriod returns the blinding period (UTC day) of t.
func blindPeriod(t time.Time) uint64 { return uint64(t.Unix()) / blindPeriodSeconds }

func blindFactor(pub []byte, period uint64) *edwards25519.Scalar {
	h := sha512.New()
	h.Write([]byte(blindFactorDomain))
	h.Write(pub)
	_ = binary.Write(h, binary.BigEndian, period)
	s, _ := new(edwards25519.Scalar).SetUniformBytes(h.Sum(nil))
	return s
}

// BlindPublicKey returns the blinded key A_p of site key pub for period.
func BlindPublicKey(pub ed25519.PublicKey, period uint64) (ed25519.PublicKey, error) {
	a, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil {
		return nil, ErrBlindedRecordInvalid
	}
	return new(edwards25519.Point).ScalarMult(blindFactor(pub, period), a).Bytes(), nil
}

// blindedSigner signs with the blinded key of one period.
type blindedSigner struct {
	pub    ed25519.PublicKey
	scalar *edwards25519.Scalar
	prefix []byte
}

func newBlindedSigner(priv ed25519.PrivateKey, period uint64) (*blindedSigner, error) {
	digest := sha512.Sum512(priv.Seed())
	a, err := new(edwards25519.Scalar).SetBytesWithClamping(digest[:32])
	if err != nil {
		return nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	blinded := new(edwards25519.Scalar).Multiply(blindFactor(pub, period), a)
	h := sha512.New()
	h.Write([]byte(blindPrefixDomain))
	h.Write(digest[32:])
	_ = binary.Write(h, binary.BigEndian, period)
	return &blindedSigner{
		pub:    new(edwards25519.Point).ScalarBaseMult(blinded).Bytes(),
		scalar: blinded,
		prefix: h.Sum(nil)[:32],
	}, nil
}

// sign makes a standard Ed25519 signature (verifiable with ed25519.Verify
// against s.pub) from the blinded secret scalar.
func (s *blindedSigner) sign(msg []byte) []byte {
	rh := sha512.New()
	rh.Write(s.prefix)
	rh.Write(msg)
	r, _ := new(edwards25519.Scalar).SetUniformBytes(rh.Sum(nil))
	R := new(edwards25519.Point).ScalarBaseMult(r).Bytes()
	kh := sha512.New()
	kh.Write(R)
	kh.Write(s.pub)
	kh.Write(msg)
	k, _ := new(edwards25519.Scalar).SetUniformBytes(kh.Sum(nil))
	S := new(edwards25519.Scalar).MultiplyAdd(k, s.scalar, r)
	return append(R, S.Bytes()...)
}

// blindedIndexKey is the directory key of blinded key index.
func blindedIndexKey(index []byte) GID {
	var g GID
	g[0] = gidBlindedIndex
	copy(g[1:], index)
	return g
}

func blindedContentKey(pub []byte, period uint64) []byte {
	h := sha256.New()
	h.Write([]byte(blindKeyDomain))
	h.Write(pub)
	_ = binary.Write(h, binary.BigEndian, period)
	return h.Sum(nil)
}

// BlindedRecord is what the directory stores for a version 2 GID.
type BlindedRecord struct {
	Index       []byte // blinded key for Period: the directory key
	Period      uint64
	PublishedAt uint64
	ExpiresAt   uint64
	Ciphertext  []byte // nonce || XChaCha20-Poly1305(descriptor)
	Signature   []byte // by Index over signedBytes
}

func (r *BlindedRecord) signedBytes() []byte {
	b := []byte(blindRecordDomain)
	b = append(b, r.Index...)
	b = binary.BigEndian.AppendUint64(b, r.Period)
	b = binary.BigEndian.AppendUint64(b, r.PublishedAt)
	b = binary.BigEndian.AppendUint64(b, r.ExpiresAt)
	return append(b, r.Ciphertext...)
}

// sealBlindedRecord encrypts and signs d for period with the site key.
func sealBlindedRecord(d *ServiceDescriptor, priv ed25519.PrivateKey, period uint64) (*BlindedRecord, error) {
	signer, err := newBlindedSigner(priv, period)
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(blindedContentKey(priv.Public().(ed25519.PublicKey), period))
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	r := &BlindedRecord{Index: signer.pub, Period: period, PublishedAt: d.PublishedAt, ExpiresAt: d.ExpiresAt}
	r.Ciphertext = aead.Seal(nonce, nonce, plain, append([]byte(nil), signer.pub...))
	if len(r.Ciphertext) > maxBlindedCipherLen {
		return nil, ErrBlindedRecordInvalid
	}
	r.Signature = signer.sign(r.signedBytes())
	return r, nil
}

// validateBlindedRecord is what a directory node can check: the record is
// for key, signed by the holder of its blinded key, and current.
func validateBlindedRecord(r *BlindedRecord, key GID, now time.Time) error {
	if r == nil || len(r.Index) != ed25519.PublicKeySize || blindedIndexKey(r.Index) != key ||
		len(r.Ciphertext) > maxBlindedCipherLen || len(r.Signature) != ed25519.SignatureSize {
		return ErrBlindedRecordInvalid
	}
	cur := blindPeriod(now)
	if r.Period+1 < cur || r.Period > cur+1 {
		return ErrBlindedRecordInvalid
	}
	unix := uint64(now.Unix())
	if r.ExpiresAt < r.PublishedAt || r.ExpiresAt-r.PublishedAt > MaxDescriptorLifetime {
		return ErrDescriptorLifetimeTooLong
	}
	if r.PublishedAt > unix+descriptorClockSkew {
		return ErrDescriptorNotYetValid
	}
	if unix > r.ExpiresAt+descriptorClockSkew {
		return ErrDescriptorExpired
	}
	if !ed25519.Verify(r.Index, r.signedBytes(), r.Signature) {
		return ErrBlindedRecordSignature
	}
	return nil
}

// openBlindedRecord decrypts a record found for gid (version 2) and
// returns the descriptor inside, fully verified.
func openBlindedRecord(r *BlindedRecord, gid GID, now time.Time) (*ServiceDescriptor, error) {
	pub := ed25519.PublicKey(gid[1:])
	index, err := BlindPublicKey(pub, r.Period)
	if err != nil {
		return nil, err
	}
	if err := validateBlindedRecord(r, blindedIndexKey(index), now); err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(blindedContentKey(pub, r.Period))
	if err != nil {
		return nil, err
	}
	if len(r.Ciphertext) < aead.NonceSize() {
		return nil, ErrBlindedRecordInvalid
	}
	plain, err := aead.Open(nil, r.Ciphertext[:aead.NonceSize()], r.Ciphertext[aead.NonceSize():], index)
	if err != nil {
		return nil, ErrBlindedRecordInvalid
	}
	var d ServiceDescriptor
	if err := json.Unmarshal(plain, &d); err != nil {
		return nil, ErrBlindedRecordInvalid
	}
	if err := VerifyServiceDescriptor(&d, gid, uint64(now.Unix())); err != nil {
		return nil, err
	}
	return &d, nil
}

// blindPeriodsFor are the periods to publish at now: the current day and,
// in its last two hours, the next one too (clients with a clock slightly
// ahead already ask for it).
func blindPeriodsFor(now time.Time) []uint64 {
	p := blindPeriod(now)
	if int64(blindPeriodSeconds)-now.Unix()%blindPeriodSeconds < 2*60*60 {
		return []uint64{p, p + 1}
	}
	return []uint64{p}
}

// blindLookupPeriods are the periods a client asks for, most likely first.
func blindLookupPeriods(now time.Time) []uint64 {
	p := blindPeriod(now)
	return []uint64{p, p - 1, p + 1}
}
