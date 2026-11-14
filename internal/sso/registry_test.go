package sso

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// memStore is an in-memory ProviderStore.
type memStore struct {
	mu        sync.Mutex
	providers map[string]Provider // by slug
}

func (s *memStore) put(p Provider) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.providers[p.Slug] = p
}

func (s *memStore) List(context.Context) ([]Provider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Provider
	for _, p := range s.providers {
		out = append(out, p)
	}
	return out, nil
}

func (s *memStore) Get(_ context.Context, id string) (Provider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.providers {
		if p.ID == id {
			return p, nil
		}
	}
	return Provider{}, ErrProviderNotFound
}

func (s *memStore) GetBySlug(_ context.Context, slug string) (Provider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.providers[slug]; ok {
		return p, nil
	}
	return Provider{}, ErrProviderNotFound
}

func (s *memStore) Unseal(*Provider) error { return nil }

// fakeProtocol builds a client per call, failing for issuers in fail.
type fakeProtocol struct {
	mu     sync.Mutex
	builds int
	fail   map[string]bool
}

type fakeClient struct{ issuer string }

func (c fakeClient) Report() Report {
	return Report{Details: []Setting{{Label: "Issuer", Value: c.issuer}}}
}

func (f *fakeProtocol) Build(_ context.Context, p Provider) (Client, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.builds++
	if f.fail[p.Issuer] {
		return nil, errors.New("discovery failed")
	}
	return fakeClient{issuer: p.Issuer}, nil
}

func (f *fakeProtocol) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.builds
}

func dbProvider(slug, issuer string, updated time.Time) Provider {
	return Provider{
		ID: "id-" + slug, Slug: slug, Kind: ProviderOIDC, Name: slug, Source: SourceDatabase, Enabled: true,
		Issuer: issuer, UpdatedAt: updated, Endpoints: Endpoints{LoginURL: "/api/v1/auth/oidc/" + slug + "/login"},
	}
}

// A client is built once per provider version and reused; an update (new
// updated_at) is picked up at the next resolve; disabling or deleting makes
// the provider unknown at once.
func TestRegistryFollowsProviderVersions(t *testing.T) {
	ctx := context.Background()
	store := &memStore{providers: map[string]Provider{}}
	proto := &fakeProtocol{fail: map[string]bool{}}
	reg := NewRegistry(store, nil, map[string]Protocol{ProviderOIDC: proto})
	t0 := time.Now()
	store.put(dbProvider("corp", "https://a", t0))

	for range 3 {
		res, err := reg.Resolve(ctx, ProviderOIDC, "corp")
		if err != nil || res.Client.(fakeClient).issuer != "https://a" {
			t.Fatalf("resolve = %+v, %v", res, err)
		}
	}
	if n := proto.count(); n != 1 {
		t.Errorf("builds = %d, want 1 (cached)", n)
	}

	store.put(dbProvider("corp", "https://b", t0.Add(time.Second)))
	if res, err := reg.Resolve(ctx, ProviderOIDC, "corp"); err != nil || res.Client.(fakeClient).issuer != "https://b" {
		t.Errorf("after update = %+v, %v; want the new issuer", res, err)
	}

	if _, err := reg.Resolve(ctx, ProviderSAML, "corp"); !errors.Is(err, ErrProviderNotFound) {
		t.Errorf("wrong kind = %v, want not found", err)
	}
	off := dbProvider("corp", "https://b", t0.Add(2*time.Second))
	off.Enabled = false
	store.put(off)
	if _, err := reg.Resolve(ctx, ProviderOIDC, "corp"); !errors.Is(err, ErrProviderNotFound) {
		t.Errorf("disabled = %v, want not found", err)
	}
	if _, err := reg.Resolve(ctx, ProviderOIDC, "login"); !errors.Is(err, ErrProviderNotFound) {
		t.Errorf("reserved slug = %v, want not found", err)
	}
}

// A provider whose IdP is down is reported with its error and left off the
// login page; the others are unaffected; it is not rebuilt on every request.
func TestRegistryIsolatesBrokenProviders(t *testing.T) {
	ctx := context.Background()
	store := &memStore{providers: map[string]Provider{}}
	proto := &fakeProtocol{fail: map[string]bool{"https://down": true}}
	env := Provider{
		ID: ProviderOIDC, Slug: ProviderOIDC, Kind: ProviderOIDC, Name: "Env", Source: SourceEnvironment, Enabled: true,
		Issuer: "https://env", SortOrder: 5, Endpoints: Endpoints{LoginURL: "/api/v1/auth/oidc/login"},
	}
	reg := NewRegistry(store, []Provider{env}, map[string]Protocol{ProviderOIDC: proto})
	now := time.Now()
	good, broken, off := dbProvider("good", "https://good", now), dbProvider("broken", "https://down", now), dbProvider("off", "https://off", now)
	off.Enabled = false
	for _, p := range []Provider{good, broken, off} {
		store.put(p)
	}

	opts, err := reg.LoginOptions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var urls []string
	for _, o := range opts {
		urls = append(urls, o.LoginURL)
	}
	if len(urls) != 2 || urls[0] != good.Endpoints.LoginURL || urls[1] != env.Endpoints.LoginURL {
		t.Errorf("login options = %v, want good then the environment provider (sort order)", urls)
	}

	all, _ := reg.All(ctx)
	byID := map[string]Status{}
	for i, st := range reg.Statuses(ctx, all, time.Second) {
		byID[all[i].ID] = st
	}
	if st := byID[broken.ID]; st.Status != StatusError || st.LastError == "" {
		t.Errorf("broken status = %+v, want error with its cause", st)
	}
	if byID[off.ID].Status != StatusDisabled || byID[good.ID].Status != StatusOK {
		t.Errorf("statuses = %+v", byID)
	}
	if _, err := reg.Resolve(ctx, ProviderOIDC, "broken"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("resolve broken = %v, want unavailable", err)
	}
	before := proto.count()
	_, _ = reg.Resolve(ctx, ProviderOIDC, "broken")
	if proto.count() != before {
		t.Error("a failed build must be retried after a pause, not on every request")
	}

	// The dry run builds from scratch and reports either way.
	if r := reg.Test(ctx, broken); r.OK || r.Error == "" {
		t.Errorf("test broken = %+v", r)
	}
	if r := reg.Test(ctx, good); !r.OK || r.Details[0].Value != "https://good" {
		t.Errorf("test good = %+v", r)
	}
}

func TestProviderInputValidation(t *testing.T) {
	rules := Rules{PublicURL: "https://xila.test", CanSeal: true}
	oidc := func(mut func(*ProviderInput)) ProviderInput {
		in := ProviderInput{Slug: "corp", Kind: ProviderOIDC, Name: "Corp", Issuer: " https://idp.example.com ", ClientID: "c", ClientSecret: "s"}
		if mut != nil {
			mut(&in)
		}
		return in
	}
	p, err := oidc(nil).Apply(nil, rules)
	if err != nil {
		t.Fatalf("valid oidc: %v", err)
	}
	if p.Issuer != "https://idp.example.com" || p.Endpoints.RedirectURI != "https://xila.test/api/v1/auth/oidc/corp/callback" ||
		p.Endpoints.LoginURL != "/api/v1/auth/oidc/corp/login" || len(p.Scopes) != 3 || !p.Enabled || !p.LinkByEmail {
		t.Errorf("oidc provider = %+v", p)
	}
	saml, err := ProviderInput{Slug: "ent", Kind: ProviderSAML, Name: "Entra", IDPMetadataURL: "https://login.example.com/md"}.Apply(nil, rules)
	if err != nil {
		t.Fatalf("valid saml: %v", err)
	}
	if saml.Endpoints.ACSURL != "https://xila.test/api/v1/auth/saml/ent/acs" || saml.Endpoints.SPEntityID != "https://xila.test/api/v1/auth/saml/ent/metadata" ||
		!saml.SignRequests {
		t.Errorf("saml provider = %+v", saml.Endpoints)
	}

	for name, in := range map[string]ProviderInput{
		"bad slug":          oidc(func(i *ProviderInput) { i.Slug = "Corp_1" }),
		"reserved slug":     oidc(func(i *ProviderInput) { i.Slug = "callback" }),
		"kind":              oidc(func(i *ProviderInput) { i.Kind = "ldap" }),
		"no name":           oidc(func(i *ProviderInput) { i.Name = " " }),
		"http issuer":       oidc(func(i *ProviderInput) { i.Issuer = "http://idp.example.com" }),
		"relative issuer":   oidc(func(i *ProviderInput) { i.Issuer = "idp.example.com" }),
		"no client id":      oidc(func(i *ProviderInput) { i.ClientID = "" }),
		"no client secret":  oidc(func(i *ProviderInput) { i.ClientSecret = "" }),
		"saml no metadata":  {Slug: "s", Kind: ProviderSAML, Name: "S"},
		"saml half keypair": {Slug: "s", Kind: ProviderSAML, Name: "S", IDPMetadataURL: "https://x/md", SPKey: "k"},
	} {
		if _, err := in.Apply(nil, rules); !errors.Is(err, ErrInvalidProvider) {
			t.Errorf("%s: %v, want invalid", name, err)
		}
	}
	// http is fine outside production.
	if _, err := oidc(func(i *ProviderInput) { i.Issuer = "http://localhost:8081/realms/x" }).Apply(nil, Rules{PublicURL: "http://localhost", AllowHTTP: true, CanSeal: true}); err != nil {
		t.Errorf("http issuer in development: %v", err)
	}
	if _, err := oidc(nil).Apply(nil, Rules{PublicURL: "https://x", CanSeal: false}); !errors.Is(err, ErrInvalidProvider) {
		t.Errorf("no INTEGRATION_SECRET_KEY = %v, want invalid", err)
	}

	// Update: slug and kind are fixed; an omitted secret keeps the stored one.
	stored := p
	stored.clientSecretEnc = []byte("sealed")
	if _, err := oidc(func(i *ProviderInput) { i.Slug = "other" }).Apply(&stored, rules); !errors.Is(err, ErrInvalidProvider) {
		t.Errorf("slug change = %v, want invalid", err)
	}
	kept, err := oidc(func(i *ProviderInput) { i.Slug, i.Kind, i.ClientSecret = "", "", "" }).Apply(&stored, rules)
	if err != nil || string(kept.clientSecretEnc) != "sealed" || kept.ClientSecret != "" {
		t.Errorf("update without secret = %v / %q, want the stored secret kept", err, kept.clientSecretEnc)
	}
}
