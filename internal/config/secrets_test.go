package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Rewriting a NAME_FILE's content changes the live value after a refresh
// tick, and fires the registered OnChange hook with the new value.
func TestSecretsRefreshPicksUpRewrittenFile(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	unset(t, "JWT_SECRET")
	path := filepath.Join(t.TempDir(), "jwt")
	if err := os.WriteFile(path, []byte("first-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JWT_SECRET_FILE", path)
	t.Setenv("SECRETS_REFRESH_INTERVAL", "20ms")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.JWT.Secret != "first-value" {
		t.Fatalf("JWT.Secret = %q", cfg.JWT.Secret)
	}

	changed := make(chan string, 1)
	cfg.Secrets.OnChange("JWT_SECRET", func(v string) { changed <- v })

	ctx := t.Context()
	go cfg.Secrets.Run(ctx)

	if err := os.WriteFile(path, []byte("rotated-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	select {
	case v := <-changed:
		if v != "rotated-value" {
			t.Errorf("OnChange value = %q, want rotated-value", v)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the refresh tick to notice the rewritten file")
	}

	if got := cfg.Secrets.Get("JWT_SECRET"); got != "rotated-value" {
		t.Errorf("Get(JWT_SECRET) = %q, want rotated-value", got)
	}
}

// A refresh that fails (the file disappears) keeps the last good value and
// never calls OnChange.
func TestSecretsRefreshFailureKeepsLastGoodValue(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	unset(t, "JWT_SECRET")
	path := filepath.Join(t.TempDir(), "jwt")
	if err := os.WriteFile(path, []byte("good-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JWT_SECRET_FILE", path)
	t.Setenv("SECRETS_REFRESH_INTERVAL", "20ms")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	var changedCalls int
	cfg.Secrets.OnChange("JWT_SECRET", func(string) { changedCalls++ })

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	// Give the refresh loop several ticks to try (and fail) rereading the
	// now-missing file.
	time.AfterFunc(300*time.Millisecond, cancel)
	cfg.Secrets.Run(ctx)

	if got := cfg.Secrets.Get("JWT_SECRET"); got != "good-value" {
		t.Errorf("Get(JWT_SECRET) = %q, want the last good value kept", got)
	}
	if changedCalls != 0 {
		t.Errorf("OnChange fired %d times, want 0 (a failed refresh never changes the value)", changedCalls)
	}
}

// SECRETS_REFRESH_INTERVAL=0 disables refreshing; Run just blocks until ctx
// ends (so callers can always `go cfg.Secrets.Run(ctx)` unconditionally).
func TestSecretsRefreshDisabledByZeroInterval(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	unset(t, "JWT_SECRET")
	path := filepath.Join(t.TempDir(), "jwt")
	if err := os.WriteFile(path, []byte("value"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JWT_SECRET_FILE", path)
	t.Setenv("SECRETS_REFRESH_INTERVAL", "0")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { cfg.Secrets.Run(ctx); close(done) }()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after ctx was done")
	}
}

// Getter returns a func() string that always reflects the current value.
func TestSecretsGetter(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	unset(t, "JWT_SECRET_FILE")
	t.Setenv("JWT_SECRET", "literal-value")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	get := cfg.Secrets.Getter("JWT_SECRET")
	if got := get(); got != "literal-value" {
		t.Errorf("Getter()() = %q", got)
	}
}

// A nil Secrets (a Config not built by Load) never panics.
func TestSecretsNilSafe(t *testing.T) {
	var s *Secrets
	if got := s.Get("X"); got != "" {
		t.Errorf("nil Get = %q", got)
	}
	s.OnChange("X", func(string) {})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	s.Run(ctx) // must return when ctx is done, not panic
}
