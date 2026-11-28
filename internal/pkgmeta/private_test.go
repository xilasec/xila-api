package pkgmeta

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/xilasec/xila-api/internal/secretbox"
)

// staticPrivate is a privateLoader answering with fixed registries.
type staticPrivate []configured

func (s staticPrivate) load(context.Context) ([]configured, error) { return s, nil }

// An internal package (M13 13.11) is only looked up in internal private
// registries, never the public one; an external one goes to the other
// private registries first and falls through to the public registry when
// they don't have it.
func TestSweepKeepsInternalPackagesPrivate(t *testing.T) {
	internalPkg, externalPkg := "pkg:npm/%40acme/billing@1.0.0", "pkg:npm/lodash@4.17.20"
	public := &stubRegistry{eco: NPM, pkgs: map[string]Package{"pkg:npm/lodash": {}}}
	mirror := &stubRegistry{eco: NPM, pkgs: map[string]Package{}} // has nothing: falls through
	acme := &stubRegistry{eco: NPM, pkgs: map[string]Package{"pkg:npm/%40acme/billing": {}}}
	svc := NewService(newMemStore(internalPkg, externalPkg), map[string]Registry{NPM: public}, Options{})
	svc.private = staticPrivate{{ecosystem: NPM, reg: mirror}, {ecosystem: NPM, internal: true, reg: acme}}
	svc.WithInternal(func(context.Context) func(string, string, string) bool {
		return func(_, ns, _ string) bool { return ns == "@acme" }
	})

	if _, err := svc.Sweep(context.Background()); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if acme.calls != 1 || mirror.calls != 1 || public.calls != 1 {
		t.Errorf("calls: internal registry %d, mirror %d, public %d; want 1 each", acme.calls, mirror.calls, public.calls)
	}
	st := svc.store.(*memStore)
	if _, ok := st.metas["pkg:npm/%40acme/billing"]; !ok {
		t.Error("the internal package's metadata wasn't stored")
	}

	// With no internal registry, an internal package is skipped, not sent public.
	public.calls = 0
	svc2 := NewService(newMemStore(internalPkg), map[string]Registry{NPM: public}, Options{})
	svc2.WithInternal(func(context.Context) func(string, string, string) bool {
		return func(_, ns, _ string) bool { return ns == "@acme" }
	})
	res, err := svc2.Sweep(context.Background())
	if err != nil || public.calls != 0 || res.Skipped != 1 {
		t.Errorf("no internal registry: public calls %d, skipped %d, err %v; want 0, 1", public.calls, res.Skipped, err)
	}
}

// A private registry's credentials go to its own host only, never to another
// host a registry document points at.
func TestRegistryCredentialsStayOnTheirHost(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]string{}
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen["other"] = r.Header.Get("Authorization")
		mu.Unlock()
		http.NotFound(w, r)
	}))
	defer other.Close()
	reg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen["registry"] = r.Header.Get("Authorization")
		mu.Unlock()
		http.NotFound(w, r)
	}))
	defer reg.Close()

	keys, err := secretbox.NewKeyring([]byte("pkgmeta-test-key-32-bytes-long!!"), nil)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := keys.Seal("s3cret", sealAAD("id", "token"))
	if err != nil {
		t.Fatal(err)
	}
	p := &PrivateRegistries{keys: keys}
	if _, err := p.authFor("other-id", reg.URL, AuthBearer, "", nil, sealed); err == nil {
		t.Error("a token sealed for another registry must not open")
	}
	sign, err := p.authFor("id", reg.URL, AuthBearer, "", nil, sealed)
	if err != nil || sign == nil {
		t.Fatalf("authFor = %v", err)
	}
	g := &getter{hc: http.DefaultClient, auth: sign}
	_ = g.get(context.Background(), reg.URL+"/x", "", nil)
	_ = g.get(context.Background(), other.URL+"/x", "", nil)
	if seen["registry"] != "Bearer s3cret" || seen["other"] != "" {
		t.Errorf("Authorization: registry %q, other host %q; want the token on the registry only", seen["registry"], seen["other"])
	}
}
