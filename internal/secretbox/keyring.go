package secretbox

import (
	"crypto/sha256"
	"sync"
)

// Tiers Open/OpenTier report: which configured key opened a value.
const (
	tierPrimary  = "primary"
	tierPrevious = "previous"
)

// Keyring seals with the primary key and opens with the primary, then each
// previous key in turn (verify-only), until one authenticates. AES-GCM's own
// authentication tag tells a wrong key apart from a right one, so the stored
// ciphertext format needs no key id or prefix — every value sealed before a
// rotation keeps opening, untouched, until the background Rekey pass re-seals
// it under the new primary.
//
// Safe for concurrent use. Update swaps the primary and previous keys
// atomically, so a rotation (or a live secret-manager refresh) never fails a
// Seal or Open already in flight.
type Keyring struct {
	mu       sync.RWMutex
	primary  *Cipher
	previous []*Cipher
	// primaryID is a hash of the current primary key, compared on Update to
	// detect a primary rotation (as opposed to only the previous list
	// changing) and nudge changed.
	primaryID string
	changed   chan struct{} // buffered 1; nudged when Update changes the primary
}

// NewKeyring builds a ring from the primary key and zero or more previous
// ones. primary may be nil (INTEGRATION_SECRET_KEY unset): Seal/Open then
// return ErrNoKey, exactly like a *Cipher built from a nil key.
func NewKeyring(primary []byte, previous [][]byte) (*Keyring, error) {
	k := &Keyring{changed: make(chan struct{}, 1)}
	if err := k.Update(primary, previous); err != nil {
		return nil, err
	}
	return k, nil
}

// Changed returns a channel that receives a value whenever Update changes the
// primary key (not merely the previous list) — the signal the Rekey pass
// wakes up on after a rotation.
func (k *Keyring) Changed() <-chan struct{} {
	if k == nil {
		return nil
	}
	return k.changed
}

// Update swaps the ring's primary and previous keys atomically. The
// integrator's live secret-manager refresh calls this when
// INTEGRATION_SECRET_KEY or INTEGRATION_SECRET_KEY_PREVIOUS changes without a
// restart.
func (k *Keyring) Update(primary []byte, previous [][]byte) error {
	p, err := New(primary)
	if err != nil {
		return err
	}
	prev := make([]*Cipher, 0, len(previous))
	for _, key := range previous {
		c, err := New(key)
		if err != nil {
			return err
		}
		prev = append(prev, c)
	}
	id := keyID(primary)

	k.mu.Lock()
	primaryChanged := k.primaryID != id
	k.primary, k.previous, k.primaryID = p, prev, id
	k.mu.Unlock()

	if primaryChanged {
		select {
		case k.changed <- struct{}{}:
		default:
		}
	}
	return nil
}

// Configured reports whether a primary key is set: Seal and Open work
// without ErrNoKey.
func (k *Keyring) Configured() bool {
	if k == nil {
		return false
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.primary != nil
}

// HasPrevious reports whether any previous (verify-only) key is configured —
// a rotation in progress that the Rekey pass should run for.
func (k *Keyring) HasPrevious() bool {
	if k == nil {
		return false
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	return len(k.previous) > 0
}

// Seal encrypts plaintext bound to aad with the primary key.
func (k *Keyring) Seal(plaintext, aad string) ([]byte, error) {
	if k == nil {
		return nil, ErrNoKey
	}
	k.mu.RLock()
	primary := k.primary
	k.mu.RUnlock()
	return primary.Seal(plaintext, aad)
}

// Open decrypts a value produced by Seal (by this ring's primary key, or in
// the past by one of its previous keys) with the same aad.
func (k *Keyring) Open(sealed []byte, aad string) (string, error) {
	plain, _, err := k.OpenTier(sealed, aad)
	return plain, err
}

// OpenTier decrypts like Open and also reports which key opened it:
// tierPrimary, tierPrevious, or "" when none did. The Rekey pass uses this to
// find and re-seal rows still sealed with a previous key.
func (k *Keyring) OpenTier(sealed []byte, aad string) (plaintext, tier string, err error) {
	if k == nil {
		return "", "", ErrNoKey
	}
	k.mu.RLock()
	primary, previous := k.primary, k.previous
	k.mu.RUnlock()

	plain, lastErr := primary.Open(sealed, aad)
	if lastErr == nil {
		return plain, tierPrimary, nil
	}
	for _, c := range previous {
		p, err := c.Open(sealed, aad)
		if err == nil {
			return p, tierPrevious, nil
		}
		lastErr = err
	}
	return "", "", lastErr
}

// keyID is a non-reversible fingerprint of a key, used only to detect
// whether Update changed the primary — never persisted or logged.
func keyID(key []byte) string {
	sum := sha256.Sum256(key)
	return string(sum[:])
}
