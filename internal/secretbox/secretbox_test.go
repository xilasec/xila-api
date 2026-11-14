package secretbox

import (
	"bytes"
	"errors"
	"testing"
)

func TestCipher(t *testing.T) {
	c, err := New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := c.Seal("ghp_secret", "project-a")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("ghp_secret")) {
		t.Error("ciphertext contains the plaintext")
	}
	again, _ := c.Seal("ghp_secret", "project-a")
	if bytes.Equal(sealed, again) {
		t.Error("two seals are identical: nonce not random")
	}
	if got, err := c.Open(sealed, "project-a"); err != nil || got != "ghp_secret" {
		t.Errorf("Open = %q, %v", got, err)
	}
	if _, err := c.Open(sealed, "project-b"); err == nil {
		t.Error("ciphertext opened under another project's additional data")
	}
	other, _ := New(bytes.Repeat([]byte{8}, 32))
	if _, err := other.Open(sealed, "project-a"); err == nil {
		t.Error("ciphertext opened with the wrong key")
	}

	var none *Cipher
	if _, err := none.Seal("x", "p"); !errors.Is(err, ErrNoKey) {
		t.Errorf("nil cipher Seal err = %v, want ErrNoKey", err)
	}
	if c, err := New(nil); c != nil || err != nil {
		t.Errorf("New(nil) = %v, %v; want nil, nil", c, err)
	}
	if _, err := New([]byte("short")); err == nil {
		t.Error("short key accepted")
	}
}
