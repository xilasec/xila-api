package sso_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/config"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/membership"
	"github.com/xilasec/xila-api/internal/org"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/sso"
	"github.com/xilasec/xila-api/internal/user"
)

type fixture struct {
	pool                    *pgxpool.Pool
	users                   *user.Repository
	members                 *membership.Repository
	orgs                    *org.Repository
	repo                    *sso.Repository
	svc                     *sso.Service
	orgID, teamA, teamB, pA string
}

func setup(t *testing.T) fixture {
	t.Helper()
	pool := pgtest.Pool(t)
	f := fixture{
		pool: pool, users: user.NewRepository(pool), members: membership.NewRepository(pool),
		orgs: org.NewRepository(pool), repo: sso.NewRepository(pool),
	}
	f.svc = sso.NewService(f.users, f.repo, auth.NewService(f.users, config.JWT{Secret: "s"}, true), true)
	ctx := context.Background()
	if err := pool.QueryRow(ctx, `INSERT INTO organizations (slug, name) VALUES ('acme', 'Acme') RETURNING id`).Scan(&f.orgID); err != nil {
		t.Fatal(err)
	}
	for _, p := range []struct {
		dst  *string
		slug string
	}{{&f.teamA, "a"}, {&f.teamB, "b"}} {
		if err := pool.QueryRow(ctx, `INSERT INTO teams (org_id, slug, name) VALUES ($1, $2, $2) RETURNING id`, f.orgID, p.slug).Scan(p.dst); err != nil {
			t.Fatal(err)
		}
	}
	if err := pool.QueryRow(ctx, `INSERT INTO projects (team_id, slug, name) VALUES ($1, 'p', 'P') RETURNING id`, f.teamB).Scan(&f.pA); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f fixture) mapGroup(t *testing.T, m sso.GroupMapping) {
	t.Helper()
	if err := m.Validate(); err != nil {
		t.Fatalf("validate %+v: %v", m, err)
	}
	if _, err := f.repo.Create(context.Background(), m); err != nil {
		t.Fatalf("create mapping %+v: %v", m, err)
	}
}

// Environment providers (OIDC_*, SAML_*), as sso.EnvProviders builds them.
var (
	envOIDC = sso.Provider{ID: sso.ProviderOIDC, Slug: sso.ProviderOIDC, Kind: sso.ProviderOIDC, Source: sso.SourceEnvironment, Enabled: true, LinkByEmail: true}
	envSAML = sso.Provider{ID: sso.ProviderSAML, Slug: sso.ProviderSAML, Kind: sso.ProviderSAML, Source: sso.SourceEnvironment, Enabled: true, LinkByEmail: true}
)

func (f fixture) login(t *testing.T, p sso.Provider, subject, email string, groups ...string) user.User {
	t.Helper()
	u, err := f.svc.Login(context.Background(), p, sso.Assertion{
		Issuer: "https://idp", Subject: subject, Email: email,
		EmailTrust: sso.EmailVerified, Groups: groups,
	})
	if err != nil {
		t.Fatalf("sso login %s: %v", email, err)
	}
	return u
}

func (f fixture) source(t *testing.T, table, target, targetID, userID string) (role, source string) {
	t.Helper()
	_ = f.pool.QueryRow(context.Background(),
		`SELECT role, source FROM `+table+` WHERE `+target+` = $1 AND user_id = $2`, targetID, userID).Scan(&role, &source)
	return role, source
}

// The feature end to end: IdP groups grant team/project/org roles and instance
// admin on login; leaving a group revokes exactly the SSO-made grant on the
// next login; manual grants and the owner are never touched.
func TestGroupSyncGrantsAndRevokes(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	owner := f.login(t, envOIDC, "owner-sub", "owner@x.io", "xila-admins") // first user: the owner
	f.mapGroup(t, sso.GroupMapping{Provider: sso.ProviderAny, Group: "xila-admins", TargetKind: sso.TargetInstanceAdmin})
	f.mapGroup(t, sso.GroupMapping{Provider: sso.ProviderOIDC, Group: "devs", TargetKind: sso.TargetTeam, TargetID: f.teamA, Role: "editor"})
	f.mapGroup(t, sso.GroupMapping{Provider: sso.ProviderAny, Group: "leads", TargetKind: sso.TargetTeam, TargetID: f.teamA, Role: "owner"})
	f.mapGroup(t, sso.GroupMapping{Provider: sso.ProviderSAML, Group: "devs", TargetKind: sso.TargetTeam, TargetID: f.teamB, Role: "viewer"})
	f.mapGroup(t, sso.GroupMapping{Provider: sso.ProviderAny, Group: "auditors", TargetKind: sso.TargetProject, TargetID: f.pA, Role: "viewer"})
	f.mapGroup(t, sso.GroupMapping{Provider: sso.ProviderAny, Group: "auditors", TargetKind: sso.TargetOrg, TargetID: f.orgID, Role: "member"})

	alice := f.login(t, envOIDC, "alice-sub", "alice@x.io", "devs", "xila-admins", "auditors", "unmapped")
	if !alice.IsAdmin || alice.AdminSource != "sso" {
		t.Errorf("alice admin = %v (%s), want granted by sso", alice.IsAdmin, alice.AdminSource)
	}
	if role, src := f.source(t, "team_members", "team_id", f.teamA, alice.ID); role != "editor" || src != "sso" {
		t.Errorf("team A = %s/%s, want editor/sso", role, src)
	}
	// The saml-only mapping does not apply to an OIDC login.
	if role, _ := f.source(t, "team_members", "team_id", f.teamB, alice.ID); role != "" {
		t.Errorf("team B = %q, want nothing (mapping is saml-only)", role)
	}
	if role, src := f.source(t, "project_members", "project_id", f.pA, alice.ID); role != "viewer" || src != "sso" {
		t.Errorf("project = %s/%s, want viewer/sso", role, src)
	}
	if role, src := f.source(t, "org_members", "org_id", f.orgID, alice.ID); role != "member" || src != "sso" {
		t.Errorf("org = %s/%s, want member/sso", role, src)
	}
	// Two groups on one target: the highest role wins.
	f.login(t, envOIDC, "alice-sub", "alice@x.io", "devs", "leads", "xila-admins", "auditors")
	if role, _ := f.source(t, "team_members", "team_id", f.teamA, alice.ID); role != "owner" {
		t.Errorf("devs+leads on team A = %s, want owner", role)
	}

	// Someone grants alice project editor by hand; that row is now manual.
	if err := f.members.AddToProject(ctx, f.pA, alice.ID, domain.TeamEditor); err != nil {
		t.Fatal(err)
	}

	// Alice leaves every group at the IdP. Next login: the SSO grants go, the
	// manual project grant stays.
	alice = f.login(t, envOIDC, "alice-sub", "alice@x.io")
	if alice.IsAdmin {
		t.Error("admin granted by sso must be revoked when the group goes")
	}
	if role, _ := f.source(t, "team_members", "team_id", f.teamA, alice.ID); role != "" {
		t.Errorf("team A after leaving = %q, want revoked", role)
	}
	if role, _ := f.source(t, "org_members", "org_id", f.orgID, alice.ID); role != "" {
		t.Errorf("org after leaving = %q, want revoked", role)
	}
	if role, src := f.source(t, "project_members", "project_id", f.pA, alice.ID); role != "editor" || src != "manual" {
		t.Errorf("manual project grant = %s/%s, want editor/manual untouched", role, src)
	}

	// The owner logs in without the admin group: still owner, still admin.
	owner = f.login(t, envOIDC, "owner-sub", "owner@x.io")
	if !owner.IsOwner || !owner.IsAdmin {
		t.Error("the owner must never be demoted by group sync")
	}

	// A manually made admin is not demoted by a login without the group.
	bob := f.login(t, envSAML, "bob", "bob@x.io")
	if _, err := f.users.SetAdmin(ctx, bob.ID, true); err != nil {
		t.Fatal(err)
	}
	if bob = f.login(t, envSAML, "bob", "bob@x.io"); !bob.IsAdmin || bob.AdminSource != "manual" {
		t.Errorf("manual admin after sso login = %v/%s, want kept", bob.IsAdmin, bob.AdminSource)
	}
	// A manual team grant is not re-roled by a mapping for the same team.
	if err := f.members.Add(ctx, f.teamB, bob.ID, domain.TeamOwner); err != nil {
		t.Fatal(err)
	}
	f.login(t, envSAML, "bob", "bob@x.io", "devs") // saml devs → team B viewer
	if role, src := f.source(t, "team_members", "team_id", f.teamB, bob.ID); role != "owner" || src != "manual" {
		t.Errorf("manual team owner after mapping = %s/%s, want owner/manual", role, src)
	}
}

// Linking rules surface as login refusals.
func TestLoginRefusals(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if _, err := f.users.Create(ctx, "taken@x.io", "hash"); err != nil {
		t.Fatal(err)
	}
	refuse := func(svc *sso.Service, trust sso.EmailTrust, email, want string) {
		t.Helper()
		_, err := svc.Login(ctx, envOIDC, sso.Assertion{Issuer: "https://idp", Subject: "s-" + email, Email: email, EmailTrust: trust})
		if got := sso.FailureCode(err); err == nil || got != want {
			t.Errorf("login %s (trust %v) = %v (%s), want %s", email, trust, err, got, want)
		}
	}
	refuse(f.svc, sso.EmailUnknown, "taken@x.io", sso.FailureEmailUnverified)
	refuse(f.svc, sso.EmailUnverified, "new@x.io", sso.FailureEmailUnverified)
	refuse(f.svc, sso.EmailVerified, "", sso.FailureNoEmail)
	closed := sso.NewService(f.users, f.repo, auth.NewService(f.users, config.JWT{Secret: "s"}, true), false)
	refuse(closed, sso.EmailVerified, "stranger@x.io", sso.FailureNoAccount)

	// An absent email_verified may still provision a brand-new account.
	if _, err := f.svc.Login(ctx, envOIDC, sso.Assertion{Issuer: "https://idp", Subject: "fresh", Email: "fresh@x.io", EmailTrust: sso.EmailUnknown}); err != nil {
		t.Errorf("new account with unknown email trust: %v", err)
	}

	// A deactivated account stays out, whatever the IdP vouches for.
	gone, err := f.users.Create(ctx, "gone@x.io", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.users.SetDisabled(ctx, gone.ID, true); err != nil {
		t.Fatal(err)
	}
	refuse(f.svc, sso.EmailVerified, "gone@x.io", sso.FailureDisabled)
}
