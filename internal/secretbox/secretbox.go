// Package secretbox encrypts integration credentials (issue-tracker and
// connector tokens) at rest with AES-256-GCM, keyed by INTEGRATION_SECRET_KEY.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// ErrNoKey is returned when a token must be encrypted or decrypted but no
// INTEGRATION_SECRET_KEY is configured.
var ErrNoKey = errors.New("INTEGRATION_SECRET_KEY not configured")

// Cipher seals tokens at rest with AES-256-GCM. The stored form is
// nonce || ciphertext+tag. The additional data binds a ciphertext to its row
// (the project id), so copying one project's token into another's row fails to
// decrypt rather than handing over the credential.
type Cipher struct {
	aead cipher.AEAD
}

// New builds a Cipher from a 32-byte key. An empty key yields a nil Cipher,
// whose methods return ErrNoKey.
func New(key []byte) (*Cipher, error) {
	if len(key) == 0 {
		return nil, nil
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("integration key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: aead}, nil
}

// Seal encrypts plaintext bound to aad.
func (c *Cipher) Seal(plaintext, aad string) ([]byte, error) {
	if c == nil {
		return nil, ErrNoKey
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	return c.aead.Seal(nonce, nonce, []byte(plaintext), []byte(aad)), nil
}

// Open decrypts a value produced by Seal with the same aad.
func (c *Cipher) Open(sealed []byte, aad string) (string, error) {
	if c == nil {
		return "", ErrNoKey
	}
	n := c.aead.NonceSize()
	if len(sealed) < n+c.aead.Overhead() {
		return "", errors.New("decrypt token: ciphertext too short")
	}
	plain, err := c.aead.Open(nil, sealed[:n], sealed[n:], []byte(aad))
	if err != nil {
		return "", fmt.Errorf("decrypt token (wrong INTEGRATION_SECRET_KEY?): %w", err)
	}
	return string(plain), nil
}
