package sso_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/xilasec/xila-api/internal/secretbox"
	"github.com/xilasec/xila-api/internal/sso"
)

var rules = sso.Rules{PublicURL: "https://xila.test", CanSeal: true}

func providerRepo(t *testing.T, f fixture) *sso.ProviderRepository {
	t.Helper()
	cipher, err := secretbox.NewKeyring([]byte("sso-provider-test-key-32-bytes!!"), nil)
	if err != nil {
		t.Fatal(err)
	}
	return sso.NewProviderRepository(f.pool, cipher, "https://xila.test")
}

func createOIDC(t *testing.T, repo *sso.ProviderRepository, slug, issuer string) sso.Provider {
	t.Helper()
	p, err := sso.ProviderInput{Slug: slug, Kind: sso.ProviderOIDC, Name: slug, Issuer: issuer, ClientID: slug, ClientSecret: slug + "-secret"}.Apply(nil, rules)
	if err != nil {
		t.Fatal(err)
	}
	created, err := repo.Create(context.Background(), p, "")
	if err != nil {
		t.Fatalf("create %s: %v", slug, err)
	}
	return created
}

// Secrets are sealed per provider: they open for their own row only.
func TestProviderSecretsSealedPerRow(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	repo := providerRepo(t, f)
	a := createOIDC(t, repo, "alpha", "https://a.example.com")
	b := createOIDC(t, repo, "beta", "https://b.example.com")

	got, err := repo.GetBySlug(ctx, "alpha")
	if err != nil || got.ClientSecret != "" || !got.HasClientSecret {
		t.Fatalf("loaded = %+v / %v; the secret must stay sealed until needed", got, err)
	}
	if err := repo.Unseal(&got); err != nil || got.ClientSecret != "alpha-secret" {
		t.Errorf("unseal = %q / %v", got.ClientSecret, err)
	}
	// alpha's ciphertext copied into beta's row does not open.
	if _, err := f.pool.Exec(ctx, `UPDATE sso_providers SET client_secret_enc = (SELECT client_secret_enc FROM sso_providers WHERE id = $1) WHERE id = $2`, a.ID, b.ID); err != nil {
		t.Fatal(err)
	}
	moved, _ := repo.Get(ctx, b.ID)
	if err := repo.Unseal(&moved); err == nil {
		t.Error("a secret moved to another provider's row must not decrypt")
	}
	if _, err := repo.Create(ctx, a, ""); !errors.Is(err, sso.ErrSlugTaken) {
		t.Errorf("duplicate slug = %v, want ErrSlugTaken", err)
	}
}

type countingProtocol struct{ builds atomic.Int32 }

type issuerClient string

func (c issuerClient) Report() sso.Report { return sso.Report{} }

func (c *countingProtocol) Build(_ context.Context, p sso.Provider) (sso.Client, error) {
	c.builds.Add(1)
	return issuerClient(p.Issuer + "|" + p.ClientSecret), nil
}

// Two registries over one database (two replicas): an edit, a disable and a
// delete made through one are seen by the other at its next resolve.
func TestRegistryReplicasFollowTheDatabase(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	repo := providerRepo(t, f)
	p := createOIDC(t, repo, "corp", "https://a.example.com")

	proto := &countingProtocol{}
	replicaA := sso.NewRegistry(repo, nil, map[string]sso.Protocol{sso.ProviderOIDC: proto})
	replicaB := sso.NewRegistry(providerRepo(t, f), nil, map[string]sso.Protocol{sso.ProviderOIDC: proto})
	resolve := func(r *sso.Registry) (string, error) {
		res, err := r.Resolve(ctx, sso.ProviderOIDC, "corp")
		if err != nil {
			return "", err
		}
		return string(res.Client.(issuerClient)), nil
	}
	if got, err := resolve(replicaB); err != nil || got != "https://a.example.com|corp-secret" {
		t.Fatalf("replica B = %q / %v (the sealed secret must reach the client)", got, err)
	}

	// Edit through replica A (no secret in the input: the stored one is kept).
	in := sso.ProviderInput{Name: "Corp", Issuer: "https://b.example.com", ClientID: "corp"}
	updated, err := in.Apply(&p, rules)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Update(ctx, updated); err != nil {
		t.Fatal(err)
	}
	if got, err := resolve(replicaB); err != nil || got != "https://b.example.com|corp-secret" {
		t.Errorf("replica B after the edit = %q / %v, want the new issuer", got, err)
	}
	if got, _ := resolve(replicaB); got == "" || proto.builds.Load() != 2 {
		t.Errorf("builds = %d, want one per version (cached in between)", proto.builds.Load())
	}

	off := false
	in.Enabled = &off
	disabled, _ := in.Apply(&updated, rules)
	if _, err := repo.Update(ctx, disabled); err != nil {
		t.Fatal(err)
	}
	if _, err := resolve(replicaB); !errors.Is(err, sso.ErrProviderNotFound) {
		t.Errorf("replica B after disable = %v, want not found", err)
	}
	if err := repo.Delete(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := resolve(replicaA); !errors.Is(err, sso.ErrProviderNotFound) {
		t.Errorf("replica A after delete = %v, want not found", err)
	}
}

// Mapping scopes: any provider; every provider of a kind (pre-existing
// oidc/saml mappings keep this meaning); exactly one database provider; exactly
// the environment provider.
func TestGroupMappingScopes(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	repo := providerRepo(t, f)
	corp := createOIDC(t, repo, "corp", "https://corp.example.com")
	lab := createOIDC(t, repo, "lab", "https://lab.example.com")

	f.mapGroup(t, sso.GroupMapping{Provider: sso.ProviderOIDC, Group: "kind-wide", TargetKind: sso.TargetTeam, TargetID: f.teamA, Role: "viewer"})
	f.mapGroup(t, sso.GroupMapping{Provider: sso.ProviderOIDC, ProviderID: corp.ID, Group: "corp-only", TargetKind: sso.TargetTeam, TargetID: f.teamB, Role: "editor"})
	f.mapGroup(t, sso.GroupMapping{Provider: sso.ProviderOIDC, ProviderID: sso.ProviderOIDC, Group: "env-only", TargetKind: sso.TargetProject, TargetID: f.pA, Role: "owner"})
	if _, err := f.repo.Create(ctx, sso.GroupMapping{Provider: sso.ProviderSAML, ProviderID: corp.ID, Group: "x", TargetKind: sso.TargetInstanceAdmin}); !errors.Is(err, sso.ErrProviderNotFound) {
		t.Errorf("mapping with the wrong kind for its provider = %v, want rejected", err)
	}

	groups := []string{"kind-wide", "corp-only", "env-only"}
	for _, tc := range []struct {
		via                       sso.Provider
		email                     string
		teamA, teamB, projectRole string
	}{
		{corp, "c@x.io", "viewer", "editor", ""},
		{lab, "l@x.io", "viewer", "", ""},
		{envOIDC, "e@x.io", "viewer", "", "owner"},
		{envSAML, "s@x.io", "", "", ""},
	} {
		u := f.login(t, tc.via, "sub-"+tc.email, tc.email, groups...)
		a, _ := f.source(t, "team_members", "team_id", f.teamA, u.ID)
		b, _ := f.source(t, "team_members", "team_id", f.teamB, u.ID)
		p, _ := f.source(t, "project_members", "project_id", f.pA, u.ID)
		if a != tc.teamA || b != tc.teamB || p != tc.projectRole {
			t.Errorf("via %s: team A %q, team B %q, project %q; want %q %q %q", tc.via.Slug, a, b, p, tc.teamA, tc.teamB, tc.projectRole)
		}
	}

	list, err := f.repo.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	scopes := map[string]string{}
	for _, m := range list {
		scopes[m.Group] = m.Provider + "/" + m.ProviderID + "/" + m.ProviderName
	}
	if scopes["kind-wide"] != "oidc//" || scopes["corp-only"] != "oidc/"+corp.ID+"/corp" || scopes["env-only"] != "oidc/oidc/" {
		t.Errorf("listed scopes = %v", scopes)
	}

	// A login through a provider records it on the identity (display only).
	var recorded *string
	if err := f.pool.QueryRow(ctx, `SELECT provider_id::text FROM user_identities WHERE subject = 'sub-c@x.io'`).Scan(&recorded); err != nil || recorded == nil || *recorded != corp.ID {
		t.Errorf("identity provider_id = %v (%v), want corp", recorded, err)
	}
}

// Per-provider login policy: auto_create_users overrides the instance default;
// link_by_email=false never attaches a login to an existing account by email.
func TestProviderLoginPolicy(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	repo := providerRepo(t, f)
	if _, err := f.users.Create(ctx, "taken@x.io", "hash"); err != nil {
		t.Fatal(err)
	}
	no, yes := false, true
	closed := createOIDC(t, repo, "closed", "https://closed.example.com")
	closed.AutoCreateUsers = &no
	login := func(svc *sso.Service, p sso.Provider, email string) error {
		_, err := svc.Login(ctx, p, sso.Assertion{Issuer: p.Issuer, Subject: "s-" + email, Email: email, EmailTrust: sso.EmailVerified})
		return err
	}
	if err := login(f.svc, closed, "new@x.io"); sso.FailureCode(err) != sso.FailureNoAccount {
		t.Errorf("auto-create off on the provider = %v, want no account", err)
	}
	open := createOIDC(t, repo, "open", "https://open.example.com")
	open.AutoCreateUsers = &yes
	strict := sso.NewService(f.users, f.repo, nil, false) // instance default off
	if err := login(strict, open, "fresh@x.io"); err != nil {
		t.Errorf("auto-create on the provider over an instance default of off = %v", err)
	}
	noLink := createOIDC(t, repo, "nolink", "https://nolink.example.com")
	noLink.LinkByEmail = false
	if err := login(f.svc, noLink, "taken@x.io"); sso.FailureCode(err) != sso.FailureEmailUnverified {
		t.Errorf("link_by_email off onto an existing account = %v, want refused", err)
	}
}
