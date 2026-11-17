package saml_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/saml"
	"github.com/xilasec/xila-api/internal/secretbox"
	"github.com/xilasec/xila-api/internal/sso"
	"github.com/xilasec/xila-api/internal/user"
)

// Replicas booting at once generate one shared SP key pair, sealed at rest.
func TestKeyStoreSharedAcrossReplicas(t *testing.T) {
	pool := pgtest.Pool(t)
	cipher, err := secretbox.NewKeyring([]byte("saml-test-integration-key-32byte"), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	const replicas = 4
	serials := make([]string, replicas)
	var wg sync.WaitGroup
	for i := range replicas {
		wg.Go(func() {
			kp, err := saml.NewKeyStore(pool, cipher).LoadOrCreate(ctx, "xila.test")
			if err != nil {
				t.Errorf("replica %d: %v", i, err)
				return
			}
			serials[i] = kp.Cert.SerialNumber.String()
		})
	}
	wg.Wait()
	for i := 1; i < replicas; i++ {
		if serials[i] != serials[0] {
			t.Fatalf("replicas disagree on the SP certificate: %v", serials)
		}
	}
	var keyEnc []byte
	if err := pool.QueryRow(ctx, `SELECT key_enc FROM saml_sp_keys`).Scan(&keyEnc); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(keyEnc, []byte("PRIVATE KEY")) {
		t.Error("the SP private key is stored in clear")
	}

	// Without INTEGRATION_SECRET_KEY there is nothing to seal with.
	if _, err := saml.NewKeyStore(pool, nil).LoadOrCreate(ctx, "xila.test"); !errors.Is(err, secretbox.ErrNoKey) {
		t.Errorf("no cipher = %v, want ErrNoKey", err)
	}
}

// An assertion id is accepted once, across replicas, and forgotten once expired.
func TestReplayStore(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	a, b := saml.NewReplayStore(pool), saml.NewReplayStore(pool) // two replicas

	if err := a.Consume(ctx, "id-1", time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if err := b.Consume(ctx, "id-1", time.Now().Add(time.Minute)); !errors.Is(err, saml.ErrReplay) {
		t.Errorf("replay on another replica = %v, want ErrReplay", err)
	}
	if err := a.Consume(ctx, "id-old", time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := b.Consume(ctx, "id-2", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM saml_seen_assertions WHERE assertion_id = 'id-old'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("expired ids are not pruned (%d, %v)", n, err)
	}
}

// An IdP-initiated logout signs out exactly the users its LogoutRequest names:
// their token_version moves (so every JWT they hold stops working), the
// matched session rows go, and nobody else is touched.
func TestSessionStoreEndByIdentity(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	users := user.NewRepository(pool)
	alice, err := users.Create(ctx, "alice@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := users.Create(ctx, "bob@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	store := saml.NewSessionStore(pool, users)
	env := sso.Provider{ID: sso.ProviderSAML, Slug: sso.ProviderSAML, Kind: sso.ProviderSAML, Source: sso.SourceEnvironment}
	exp := time.Now().Add(time.Hour)
	for _, r := range []struct{ id, nameID, idx string }{{alice.ID, "alice", "s1"}, {alice.ID, "alice", "s2"}, {bob.ID, "bob", "s9"}} {
		if err := store.Record(ctx, r.id, env, r.nameID, "", r.idx, exp); err != nil {
			t.Fatal(err)
		}
	}
	version := func(id string) int {
		u, err := users.GetByID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return u.TokenVersion
	}
	a0, b0 := version(alice.ID), version(bob.ID)

	// With a SessionIndex: that session only.
	if n, err := store.EndByIdentity(ctx, env, "alice", "s1"); err != nil || n != 1 {
		t.Fatalf("EndByIdentity(alice, s1) = %d, %v", n, err)
	}
	if version(alice.ID) != a0+1 || version(bob.ID) != b0 {
		t.Errorf("token versions alice %d→%d bob %d→%d, want only alice bumped", a0, version(alice.ID), b0, version(bob.ID))
	}
	if ok, _ := users.SessionValid(ctx, alice.ID, a0); ok {
		t.Error("alice's pre-logout token is still valid")
	}
	if s, ok, err := store.Latest(ctx, alice.ID); err != nil || !ok || s.SessionIndex != "s2" {
		t.Errorf("remaining session = %+v %v %v, want s2 kept", s, ok, err)
	}

	// Without one: every session of that principal at this IdP.
	if n, err := store.EndByIdentity(ctx, env, "alice", ""); err != nil || n != 1 {
		t.Fatalf("EndByIdentity(alice) = %d, %v", n, err)
	}
	if _, ok, _ := store.Latest(ctx, alice.ID); ok {
		t.Error("alice still has a recorded session")
	}
	// Unknown principal: nothing to do, not an error.
	if n, err := store.EndByIdentity(ctx, env, "carol", ""); err != nil || n != 0 {
		t.Errorf("unknown principal = %d, %v", n, err)
	}
	if version(bob.ID) != b0 {
		t.Error("bob was signed out by someone else's logout")
	}
}
