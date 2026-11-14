package user_test

import (
	"context"
	"errors"
	"testing"

	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/user"
)

const issuer = "https://idp.example.com"

func oidcID(subject, email string) user.Identity {
	return user.Identity{Provider: "oidc", Issuer: issuer, Subject: subject, Email: email}
}

var (
	verified   = user.LinkPolicy{EmailVerified: true, AllowCreate: true}
	unverified = user.LinkPolicy{EmailVerified: false, AllowCreate: true}
)

func TestLinkIdentity(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := user.NewRepository(pool)
	ctx := context.Background()

	// First SSO user of an empty instance bootstraps as owner + admin.
	first, outcome, err := repo.LinkIdentity(ctx, oidcID("sub-a", "first@x.io"), verified)
	if err != nil || outcome != user.LinkedCreated {
		t.Fatalf("first login = %v / %v", outcome, err)
	}
	if !first.IsAdmin || !first.IsOwner {
		t.Error("first SSO user should be the owner + admin")
	}
	second, _, _ := repo.LinkIdentity(ctx, oidcID("sub-b", "second@x.io"), verified)
	if second.IsAdmin || second.IsOwner {
		t.Error("second SSO user should be a regular user")
	}

	// The same identity returns the same user — even when the IdP now asserts
	// another email (which the account adopts, as it's free and verified)…
	again, outcome, err := repo.LinkIdentity(ctx, oidcID("sub-a", "renamed@x.io"), verified)
	if err != nil || outcome != user.LinkedExisting || again.ID != first.ID || again.Email != "renamed@x.io" {
		t.Errorf("returning login = %v %v %+v, want the same user with the new email", outcome, err, again)
	}
	// …but not one another account holds (the account keeps its email).
	kept, _, err := repo.LinkIdentity(ctx, oidcID("sub-a", "second@x.io"), verified)
	if err != nil || kept.ID != first.ID || kept.Email != "renamed@x.io" {
		t.Errorf("email collision: %v %+v, want same user, email unchanged", err, kept)
	}
	// An unverified email is never adopted.
	kept, _, _ = repo.LinkIdentity(ctx, oidcID("sub-a", "elsewhere@x.io"), unverified)
	if kept.Email != "renamed@x.io" {
		t.Errorf("unverified email adopted: %q", kept.Email)
	}

	// An existing password account is linked by a *verified* email…
	pw, err := repo.Create(ctx, "human@x.io", "hash")
	if err != nil {
		t.Fatalf("create pw user: %v", err)
	}
	if _, _, err := repo.LinkIdentity(ctx, oidcID("sub-human", "human@x.io"), unverified); !errors.Is(err, user.ErrEmailUnverified) {
		t.Errorf("unverified email link = %v, want ErrEmailUnverified", err)
	}
	linked, outcome, err := repo.LinkIdentity(ctx, oidcID("sub-human", "human@x.io"), verified)
	if err != nil || outcome != user.LinkedByEmail || linked.ID != pw.ID {
		t.Errorf("verified email link = %v %v (%s), want %s", outcome, err, linked.ID, pw.ID)
	}
	// …and a second subject from the same IdP claiming that email (a recycled
	// address) is refused rather than handed the account.
	if _, _, err := repo.LinkIdentity(ctx, oidcID("sub-impostor", "human@x.io"), verified); !errors.Is(err, user.ErrIdentityConflict) {
		t.Errorf("second subject for a linked email = %v, want ErrIdentityConflict", err)
	}
	// A different protocol may link the same account (OIDC + SAML side by side).
	samlID := user.Identity{Provider: "saml", Issuer: "urn:idp", Subject: "human", SubjectFormat: "persistent", Email: "human@x.io"}
	if u, _, err := repo.LinkIdentity(ctx, samlID, verified); err != nil || u.ID != pw.ID {
		t.Errorf("saml link to the same account = %v (%s)", err, u.ID)
	}

	// Provisioning off: unknown people are refused, known identities still work.
	noCreate := user.LinkPolicy{EmailVerified: true}
	if _, _, err := repo.LinkIdentity(ctx, oidcID("sub-new", "new@x.io"), noCreate); !errors.Is(err, user.ErrNoAccount) {
		t.Errorf("auto-create off = %v, want ErrNoAccount", err)
	}
	if u, _, err := repo.LinkIdentity(ctx, oidcID("sub-b", "second@x.io"), noCreate); err != nil || u.ID != second.ID {
		t.Errorf("known identity with auto-create off = %v", err)
	}
}

// OIDC links migrated from users.oidc_subject have no issuer; the environment-
// configured OIDC provider (the one they were made against) claims them on the
// subject's next login — never another OIDC provider with a colliding subject.
func TestLinkIdentityClaimsLegacyOIDCLink(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := user.NewRepository(pool)
	ctx := context.Background()

	legacy, err := repo.Create(ctx, "legacy@x.io", "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO user_identities (user_id, provider, issuer, subject, email_at_link)
		VALUES ($1, 'oidc', '', 'legacy-sub', 'legacy@x.io')`, legacy.ID); err != nil {
		t.Fatalf("seed legacy link: %v", err)
	}
	// Another OIDC provider's identity with the same subject is someone else.
	other := user.Identity{Provider: "oidc", Issuer: "https://other-idp.example.com", Subject: "legacy-sub", Email: "stranger@x.io"}
	if u, outcome, err := repo.LinkIdentity(ctx, other, unverified); err != nil || outcome != user.LinkedCreated || u.ID == legacy.ID {
		t.Fatalf("other provider's colliding subject = %v %v (%s), want a new account", outcome, err, u.ID)
	}
	// Even with an unverified, different email: the subject is the link.
	envLogin := func(email string) user.Identity {
		id := oidcID("legacy-sub", email)
		id.ClaimLegacy = true
		return id
	}
	u, outcome, err := repo.LinkIdentity(ctx, envLogin("other@x.io"), unverified)
	if err != nil || outcome != user.LinkedExisting || u.ID != legacy.ID {
		t.Fatalf("legacy login = %v %v (%s)", outcome, err, u.ID)
	}
	var got string
	if err := pool.QueryRow(ctx, `SELECT issuer FROM user_identities WHERE subject = 'legacy-sub' AND user_id = $1`, legacy.ID).Scan(&got); err != nil || got != issuer {
		t.Errorf("legacy link issuer = %q (%v), want it rewritten to %q", got, err, issuer)
	}
	// Idempotent: the next login finds the rewritten link.
	if u2, outcome, err := repo.LinkIdentity(ctx, envLogin("legacy@x.io"), verified); err != nil || outcome != user.LinkedExisting || u2.ID != legacy.ID {
		t.Errorf("second legacy login = %v %v", outcome, err)
	}
}
