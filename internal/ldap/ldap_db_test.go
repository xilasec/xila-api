package ldap_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jimlambrt/gldap"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/config"
	"github.com/xilasec/xila-api/internal/ldap"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/sso"
	"github.com/xilasec/xila-api/internal/user"
)

// dirUser is one account in the fake directory.
type dirUser struct {
	dn, uid, mail, password, entryUUID string
	groups                             []string
}

// fakeDirectory is an in-process LDAP server: binds check passwords, searches
// match on the (escaped) login in the filter — and record the filters seen.
type fakeDirectory struct {
	addr    string
	mu      sync.Mutex
	filters []string
}

func startDirectory(t *testing.T, service dirUser, users ...dirUser) *fakeDirectory {
	t.Helper()
	fd := &fakeDirectory{}
	srv, err := gldap.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	mux, _ := gldap.NewMux()
	all := append([]dirUser{service}, users...)
	mux.Bind(func(w *gldap.ResponseWriter, r *gldap.Request) {
		resp := r.NewBindResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials))
		defer w.Write(resp)
		m, err := r.GetSimpleBindMessage()
		if err != nil {
			return
		}
		for _, u := range all {
			if strings.EqualFold(m.UserName, u.dn) && string(m.Password) == u.password && u.password != "" {
				resp.SetResultCode(gldap.ResultSuccess)
			}
		}
	})
	mux.Search(func(w *gldap.ResponseWriter, r *gldap.Request) {
		done := r.NewSearchDoneResponse()
		defer w.Write(done)
		m, err := r.GetSearchMessage()
		if err != nil {
			return
		}
		fd.mu.Lock()
		fd.filters = append(fd.filters, m.Filter)
		fd.mu.Unlock()
		for _, u := range users {
			f := strings.ToLower(m.Filter) // directories match uid and mail case-insensitively
			if strings.Contains(f, "(uid="+strings.ToLower(u.uid)+")") || (u.mail != "" && strings.Contains(f, "(mail="+strings.ToLower(u.mail)+")")) {
				attrs := map[string][]string{"uid": {u.uid}, "memberOf": u.groups, "entryUUID": {u.entryUUID}}
				if u.mail != "" {
					attrs["mail"] = []string{u.mail}
				}
				w.Write(r.NewSearchResponseEntry(u.dn, gldap.WithAttributes(attrs)))
			}
		}
		done.SetResultCode(gldap.ResultSuccess)
	})
	if err := srv.Router(mux); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fd.addr = l.Addr().String()
	l.Close()
	go srv.Run(fd.addr)
	t.Cleanup(func() { srv.Stop() })
	for range 100 {
		if srv.Ready() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fd
}

// Directory sign-in through the password form: the directory checks the
// password, Xila links the account and maps its groups like any SSO login —
// and nothing the directory would accept by mistake (empty password, an
// injected filter) gets anyone in.
func TestDirectorySignIn(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	users := user.NewRepository(pool)
	ssoRepo := sso.NewRepository(pool)

	service := dirUser{dn: "cn=xila,ou=services,dc=corp,dc=example", password: "svc-secret"}
	alice := dirUser{dn: "uid=alice,ou=people,dc=corp,dc=example", uid: "alice", mail: "Alice@Corp.Example", password: "alice-pw",
		entryUUID: "5f0f8a1e-0001-4000-8000-000000000001", groups: []string{"cn=xila-admins,ou=groups,dc=corp,dc=example"}}
	bob := dirUser{dn: "uid=bob,ou=people,dc=corp,dc=example", uid: "bob", password: "bob-pw", entryUUID: "5f0f8a1e-0002-4000-8000-000000000002"} // no mail
	fd := startDirectory(t, service, alice, bob)

	// An owner exists first (bootstrap), so directory users are regular users.
	if _, err := users.Create(ctx, "owner@corp.example", "$2a$10$abcdefghijklmnopqrstuuJ8vHnS0kOUaXnhBZfpp1E7kKq1YQwBK"); err != nil {
		t.Fatal(err)
	}
	// Members of xila-admins (matched by CN) become instance admins.
	if _, err := ssoRepo.Create(ctx, sso.GroupMapping{Provider: sso.ProviderLDAP, Group: "xila-admins", TargetKind: sso.TargetInstanceAdmin}); err != nil {
		t.Fatal(err)
	}

	cfg := config.LDAP{Enabled: true, URL: "ldap://" + fd.addr, StartTLS: false, BindDN: service.dn, BindPassword: service.password,
		BaseDN: "dc=corp,dc=example", UserFilter: "(&(objectClass=person)(|(uid={login})(mail={login})))",
		EmailAttribute: "mail", GroupAttribute: "memberOf", LinkByEmail: true}
	ssoSvc := sso.NewService(users, ssoRepo, nil, true)
	dir, err := ldap.New(cfg, ssoSvc)
	if err != nil {
		t.Fatal(err)
	}
	authSvc := auth.NewService(users, config.JWT{Secret: "s", TTL: time.Hour}, true)
	authSvc.EnableDirectory(dir)

	token, u, err := authSvc.Login(ctx, "alice", "alice-pw")
	if err != nil || token == "" {
		t.Fatalf("alice by uid: %v", err)
	}
	if u.Email != "alice@corp.example" || !u.IsAdmin || u.HasPassword {
		t.Errorf("alice = %+v; want the directory email, admin via the group mapping, no local password", u)
	}
	// Same account by email, and the identity is stable (no second user).
	if _, again, err := authSvc.Login(ctx, "alice@corp.example", "alice-pw"); err != nil || again.ID != u.ID {
		t.Errorf("alice by email = %v, %v; want the same user", again.ID, err)
	}

	for name, c := range map[string]struct{ login, pw string }{
		"wrong password":   {"alice", "nope"},
		"empty password":   {"alice", ""}, // an unauthenticated bind must never count
		"unknown account":  {"mallory", "x"},
		"filter injection": {"*)(uid=*", "alice-pw"},
		"wildcard login":   {"*", "alice-pw"},
	} {
		if _, _, err := authSvc.Login(ctx, c.login, c.pw); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("%s: %v, want invalid credentials", name, err)
		}
	}
	fd.mu.Lock()
	for _, f := range fd.filters {
		if strings.Contains(f, "(uid=*") {
			t.Errorf("login was not escaped into the filter: %s", f)
		}
	}
	fd.mu.Unlock()

	// A directory account without an email can't become a Xila user.
	if _, _, err := authSvc.Login(ctx, "bob", "bob-pw"); !errors.Is(err, auth.ErrDirectoryRefused) {
		t.Errorf("bob (no mail) = %v, want ErrDirectoryRefused", err)
	}

	// Deactivation applies to directory sign-in too.
	if _, err := users.SetDisabled(ctx, u.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := authSvc.Login(ctx, "alice", "alice-pw"); !errors.Is(err, auth.ErrAccountDisabled) {
		t.Errorf("deactivated alice = %v, want ErrAccountDisabled", err)
	}

	// A local password account authenticates locally, never against the
	// directory (the directory can't take over a local admin's login).
	if _, _, err := authSvc.Login(ctx, "owner@corp.example", "alice-pw"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("local owner with a directory password = %v, want invalid credentials", err)
	}
}
