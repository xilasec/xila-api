package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/xilasec/xila-api/internal/secretbox"
)

// Without INTEGRATION_SECRET_KEY, secretbox.New returns a nil *Cipher; passed
// as a Sealer it is a non-nil interface. Two-factor must then be unavailable
// (a clear 400 to the user), not a sealer that fails every setup with a 500.
func TestEnableMFAWithoutKeyIsUnavailable(t *testing.T) {
	noKey, err := secretbox.New(nil)
	if err != nil || noKey != nil {
		t.Fatalf("secretbox.New(nil) = %v, %v", noKey, err)
	}
	s := &Service{}
	s.EnableMFA(noKey, nil)
	if s.MFAAvailable() {
		t.Error("MFA available without a key")
	}
	if _, err := s.SetupMFA(context.Background(), "u"); !errors.Is(err, ErrMFAUnavailable) {
		t.Errorf("SetupMFA = %v, want ErrMFAUnavailable", err)
	}

	withKey, err := secretbox.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	s.EnableMFA(withKey, nil)
	if !s.MFAAvailable() {
		t.Error("MFA unavailable with a key")
	}
}
