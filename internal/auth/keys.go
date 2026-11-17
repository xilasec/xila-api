package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// kidFor derives a short, non-reversible id for a signing secret: the first
// 8 bytes of its SHA-256 hash, hex-encoded. A verifier uses it to pick the
// right key out of the ring without the token (or a log line) ever carrying
// the secret itself.
func kidFor(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:8])
}

// Keys is a JWT signing/verification key ring for JWT_SECRET: it signs with
// the current secret and stamps a `kid` header naming it, and verifies a
// token against the current secret or any previous one (JWT_PREVIOUS_SECRETS,
// verify-only), matched by kid. A token issued before key rings existed
// carries no kid; it is tried against the current secret, then every
// previous one, oldest first.
//
// Safe for concurrent use. Update swaps the ring atomically, so a rotation
// (or a live secret-manager refresh) never fails a request already in
// flight, and signs and verifications always see one consistent ring.
type Keys struct {
	mu        sync.RWMutex
	current   string
	currentID string
	previous  map[string]string // kid -> secret, verify-only
	legacy    []string          // previous secrets, oldest first: tried for a kid-less token
}

// NewKeys builds a ring from the current secret and zero or more previous
// ones.
func NewKeys(current string, previous []string) *Keys {
	k := &Keys{}
	k.Update(current, previous)
	return k
}

// Update swaps the ring's current and previous secrets atomically. The
// integrator's live secret refresh calls this when JWT_SECRET or
// JWT_PREVIOUS_SECRETS changes without a restart.
func (k *Keys) Update(current string, previous []string) {
	prev := make(map[string]string, len(previous))
	for _, s := range previous {
		prev[kidFor(s)] = s
	}
	k.mu.Lock()
	k.current, k.currentID = current, kidFor(current)
	k.previous, k.legacy = prev, append([]string(nil), previous...)
	k.mu.Unlock()
}

// snapshot returns a consistent view of the ring for one sign or verify.
func (k *Keys) snapshot() (current, currentID string, previous map[string]string, legacy []string) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.current, k.currentID, k.previous, k.legacy
}
