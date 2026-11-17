package secretbox

import (
	"bytes"
	"errors"
	"testing"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestKeyringSealOpenPrimary(t *testing.T) {
	ring, err := NewKeyring(key(1), nil)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := ring.Seal("secret", "aad")
	if err != nil {
		t.Fatal(err)
	}
	got, tier, err := ring.OpenTier(sealed, "aad")
	if err != nil || got != "secret" || tier != tierPrimary {
		t.Fatalf("OpenTier = %q, %q, %v; want secret, primary, nil", got, tier, err)
	}
}

// A value sealed under the old key still opens (verify-only) once that key
// moves from primary to previous, and OpenTier reports it as such.
func TestKeyringOpenWithPrevious(t *testing.T) {
	old, err := NewKeyring(key(1), nil)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := old.Seal("secret", "aad")
	if err != nil {
		t.Fatal(err)
	}

	rotated, err := NewKeyring(key(2), [][]byte{key(1)})
	if err != nil {
		t.Fatal(err)
	}
	got, tier, err := rotated.OpenTier(sealed, "aad")
	if err != nil || got != "secret" || tier != tierPrevious {
		t.Fatalf("OpenTier after rotation = %q, %q, %v; want secret, previous, nil", got, tier, err)
	}
	if plain, err := rotated.Open(sealed, "aad"); err != nil || plain != "secret" {
		t.Fatalf("Open after rotation = %q, %v", plain, err)
	}
}

// Sealing always uses the primary key, even when previous keys are set.
func TestKeyringSealsWithPrimaryOnly(t *testing.T) {
	ring, err := NewKeyring(key(2), [][]byte{key(1)})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := ring.Seal("secret", "aad")
	if err != nil {
		t.Fatal(err)
	}
	if _, tier, err := ring.OpenTier(sealed, "aad"); err != nil || tier != tierPrimary {
		t.Fatalf("a fresh Seal opened as %q, %v; want primary", tier, err)
	}
}

// A key that was never primary or previous cannot open anything.
func TestKeyringOpenFailsWithoutMatchingKey(t *testing.T) {
	a, err := NewKeyring(key(1), nil)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := a.Seal("secret", "aad")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewKeyring(key(2), [][]byte{key(3)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Open(sealed, "aad"); err == nil {
		t.Error("opened with neither the primary nor any previous key")
	}
}

// Update swaps the ring atomically: a value sealed before Update keeps
// opening via Previous, and a fresh Seal after Update uses the new primary.
func TestKeyringUpdateSwapsAtomically(t *testing.T) {
	ring, err := NewKeyring(key(1), nil)
	if err != nil {
		t.Fatal(err)
	}
	before, err := ring.Seal("old-secret", "aad")
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.Update(key(2), [][]byte{key(1)}); err != nil {
		t.Fatal(err)
	}
	if plain, tier, err := ring.OpenTier(before, "aad"); err != nil || plain != "old-secret" || tier != tierPrevious {
		t.Fatalf("pre-rotation value after Update = %q, %q, %v", plain, tier, err)
	}
	after, err := ring.Seal("new-secret", "aad")
	if err != nil {
		t.Fatal(err)
	}
	if _, tier, err := ring.OpenTier(after, "aad"); err != nil || tier != tierPrimary {
		t.Fatalf("post-rotation value tier = %q, %v, want primary", tier, err)
	}

	// Dropping the old key from Previous stops it from opening anything.
	if err := ring.Update(key(2), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := ring.Open(before, "aad"); err == nil {
		t.Error("value opened after its key was fully removed from the ring")
	}
}

// Update notifies Changed only when the primary itself moves, not when just
// the previous list is edited.
func TestKeyringChangedSignalsOnlyOnPrimaryRotation(t *testing.T) {
	ring, err := NewKeyring(key(1), nil)
	if err != nil {
		t.Fatal(err)
	}
	drain := func() bool {
		select {
		case <-ring.Changed():
			return true
		default:
			return false
		}
	}
	drain() // NewKeyring's initial Update may have signaled; discard it.

	if err := ring.Update(key(1), [][]byte{key(2)}); err != nil {
		t.Fatal(err)
	}
	if drain() {
		t.Error("Changed signaled for a previous-list-only edit")
	}

	if err := ring.Update(key(3), [][]byte{key(2)}); err != nil {
		t.Fatal(err)
	}
	if !drain() {
		t.Error("Changed did not signal a primary rotation")
	}
}

// A nil Keyring behaves like a Cipher built without a key: ErrNoKey, not a
// panic, so a caller that holds one before INTEGRATION_SECRET_KEY is set
// (mirroring the existing Sealer nil-safety) keeps working.
func TestNilKeyringIsSafe(t *testing.T) {
	var ring *Keyring
	if ring.Configured() || ring.HasPrevious() {
		t.Error("nil Keyring reports configured")
	}
	if _, err := ring.Seal("x", "aad"); !errors.Is(err, ErrNoKey) {
		t.Errorf("nil Keyring Seal = %v, want ErrNoKey", err)
	}
	if _, err := ring.Open(nil, "aad"); !errors.Is(err, ErrNoKey) {
		t.Errorf("nil Keyring Open = %v, want ErrNoKey", err)
	}
	if ring.Changed() != nil {
		t.Error("nil Keyring Changed() is non-nil")
	}
}

// NewKeyring(nil, nil) (INTEGRATION_SECRET_KEY unset) is configured=false and
// every Seal/Open fails with ErrNoKey, exactly like New(nil).
func TestKeyringWithoutPrimaryKey(t *testing.T) {
	ring, err := NewKeyring(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ring.Configured() {
		t.Error("Configured() true without a primary key")
	}
	if _, err := ring.Seal("x", "aad"); !errors.Is(err, ErrNoKey) {
		t.Errorf("Seal without a key = %v, want ErrNoKey", err)
	}
}

func TestNewKeyringRejectsBadKeyLength(t *testing.T) {
	if _, err := NewKeyring([]byte("short"), nil); err == nil {
		t.Error("short primary key accepted")
	}
	if _, err := NewKeyring(key(1), [][]byte{[]byte("short")}); err == nil {
		t.Error("short previous key accepted")
	}
}
