package pkgmeta_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/pkgmeta"
	"github.com/xilasec/xila-api/internal/sbom"
)

// fakeRegistry answers from a map keyed by base purl; anything else is 404.
type fakeRegistry struct {
	eco   string
	mu    sync.Mutex
	pkgs  map[string]pkgmeta.Package
	fail  error
	calls int
}

func (f *fakeRegistry) Ecosystem() string { return f.eco }

func (f *fakeRegistry) Fetch(_ context.Context, p pkgmeta.PURL) (pkgmeta.Package, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.fail != nil {
		return pkgmeta.Package{}, f.fail
	}
	pkg, ok := f.pkgs[p.Base()]
	if !ok {
		return pkgmeta.Package{}, pkgmeta.ErrNotFound
	}
	return pkg, nil
}

func date(s string) *time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return &t
}

func lib(name, version, purl string) sbom.Component {
	return sbom.Component{Type: "library", Name: name, Version: version, Purl: purl, Hashes: map[string]string{}}
}

// TestOutdatedComponents runs the whole path: current inventory → sweep with
// fake registries → package_status → the ?outdated filter and Repository.Info
// agree, and anything unknown is never reported as up to date.
func TestOutdatedComponents(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	sbomRepo := sbom.NewRepository(pool)
	repo := pkgmeta.NewRepository(pool)

	var projectID string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-pm','o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'p','p' FROM tm RETURNING id`).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}

	const (
		lodashOld   = "pkg:npm/lodash@4.17.20"
		lodashNew   = "pkg:npm/lodash@4.17.21"
		requests    = "pkg:pypi/requests@2.31.0?extra=socks" // qualifiers are ignored
		guava       = "pkg:maven/com.google.guava/guava@33.7.2-jre"
		internalPkg = "pkg:npm/%40acme/internal@1.0.0" // not in the public registry
		debPkg      = "pkg:deb/debian/curl@7.88.1"     // unsupported ecosystem
	)
	// History: the first snapshot shipped lodash 4.17.20; the current one
	// upgraded. Only current inventory is swept, but both get a status.
	if _, err := sbomRepo.Ingest(ctx, sbom.Sbom{ProjectID: projectID, Artifact: "web", Format: "CycloneDX"},
		[]sbom.Component{lib("lodash", "4.17.20", lodashOld)}, nil, nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond) // distinct created_at for "newest snapshot"
	current, err := sbomRepo.Ingest(ctx, sbom.Sbom{ProjectID: projectID, Artifact: "web", Format: "CycloneDX"},
		[]sbom.Component{
			lib("lodash", "4.17.21", lodashNew),
			lib("requests", "2.31.0", requests),
			lib("guava", "33.7.2-jre", guava),
			lib("internal", "1.0.0", internalPkg),
			lib("curl", "7.88.1", debPkg),
			lib("no-purl", "1.0", ""),
		}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	npm := &fakeRegistry{eco: pkgmeta.NPM, pkgs: map[string]pkgmeta.Package{
		"pkg:npm/lodash": {Latest: "4.17.21", Versions: []pkgmeta.Version{
			{Version: "4.17.19"}, {Version: "4.17.20", Published: date("2020-08-13T16:53:54Z")},
			{Version: "4.17.21", Published: date("2021-02-20T15:42:16Z")}, {Version: "5.0.0-alpha.1"},
		}},
	}}
	pypi := &fakeRegistry{eco: pkgmeta.PyPI, pkgs: map[string]pkgmeta.Package{
		"pkg:pypi/requests": {Latest: "2.34.2", Versions: []pkgmeta.Version{
			{Version: "2.31.0"}, {Version: "2.32.0", Yanked: true}, {Version: "2.32.2"}, {Version: "2.34.2"},
		}},
	}}
	maven := &fakeRegistry{eco: pkgmeta.Maven, fail: errors.New("GET …: status 503")}
	svc := pkgmeta.NewService(repo, map[string]pkgmeta.Registry{
		pkgmeta.NPM: npm, pkgmeta.PyPI: pypi, pkgmeta.Maven: maven,
	}, pkgmeta.Options{TTL: 24 * time.Hour})

	// Before any lookup, nothing is known: not outdated, not up to date.
	assertFilter(t, sbomRepo, projectID, true, nil)
	assertFilter(t, sbomRepo, projectID, false, nil)

	res, err := svc.Sweep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// lodash, @acme/internal, requests, guava (curl and the purl-less one aren't supported).
	if res.Packages != 4 || res.Fetched != 2 || res.Failed != 2 {
		t.Errorf("sweep = %+v", res)
	}

	assertFilter(t, sbomRepo, projectID, true, []string{lodashOld, requests})
	assertFilter(t, sbomRepo, projectID, false, []string{lodashNew})

	// Component rows carry the freshness; unknown ones carry nulls.
	hits, err := sbomRepo.ListComponents(ctx, sbom.ComponentFilter{SbomID: current.ID})
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hits {
		switch h.Purl {
		case requests:
			if h.Outdated == nil || !*h.Outdated || *h.LatestVersion != "2.34.2" || *h.VersionsBehind != 2 {
				t.Errorf("requests = %+v", h.PackageFreshness)
			}
		case lodashNew:
			if h.Outdated == nil || *h.Outdated || h.VersionPublishedAt == nil || h.VersionPublishedAt.Year() != 2021 {
				t.Errorf("lodash 4.17.21 = %+v", h.PackageFreshness)
			}
		default:
			if h.Outdated != nil || h.LatestVersion != nil || h.VersionsBehind != nil {
				t.Errorf("%q (unknown) = %+v, want all null", h.Purl, h.PackageFreshness)
			}
		}
	}

	// Repository.Info (the policy engine's view) agrees with the SQL status,
	// keyed by the caller's string; unknown purls are absent.
	info, err := repo.Info(ctx, []string{lodashOld, lodashNew, requests, guava, internalPkg, debPkg, "garbage", "pkg:npm/lodash"})
	if err != nil {
		t.Fatal(err)
	}
	if len(info) != 3 {
		t.Errorf("Info returned %d entries, want lodash x2 + requests: %v", len(info), info)
	}
	if i := info[lodashOld]; !i.Outdated || i.Latest != "4.17.21" || *i.VersionsBehind != 1 ||
		i.Published == nil || i.Published.Year() != 2020 || i.LatestPublished == nil || i.LatestPublished.Year() != 2021 || i.FetchedAt == nil {
		t.Errorf("Info(lodash 4.17.20) = %+v", i)
	}
	if i := info[requests]; !i.Outdated || *i.VersionsBehind != 2 {
		t.Errorf("Info(requests) = %+v", i)
	}
	if i, ok := info[lodashNew]; !ok || i.Outdated {
		t.Errorf("Info(lodash 4.17.21) = %+v, %v", i, ok)
	}

	// Failures are recorded with backoff; the 404 waits longer than the 503.
	priv, err := repo.Get(ctx, "pkg:npm/%40acme/internal")
	if err != nil {
		t.Fatal(err)
	}
	g, err := repo.Get(ctx, "pkg:maven/com.google.guava/guava")
	if err != nil {
		t.Fatal(err)
	}
	if priv.ErrorCount != 1 || priv.FetchedAt != nil || priv.LastError == "" || g.ErrorCount != 1 ||
		!priv.NextFetchAt.After(g.NextFetchAt) {
		t.Errorf("backoff: private %+v, guava %+v", priv, g)
	}

	// A second sweep within the TTL fetches nothing and rewrites no status.
	npm.calls, pypi.calls = 0, 0
	res, err = svc.Sweep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if npm.calls != 0 || pypi.calls != 0 || res.Statuses != 0 {
		t.Errorf("sweep within TTL: %+v, npm %d pypi %d calls", res, npm.calls, pypi.calls)
	}

	// The SBOM page's summary counts the same thing.
	f, err := repo.SbomFreshness(ctx, current.ID)
	if err != nil {
		t.Fatal(err)
	}
	if f != (pkgmeta.Freshness{Total: 6, Outdated: 1, UpToDate: 1, Unknown: 4}) {
		t.Errorf("freshness = %+v", f)
	}

	// A new release makes the current lodash outdated once its metadata is
	// refetched (forced here by expiring it).
	npm.pkgs["pkg:npm/lodash"] = pkgmeta.Package{Latest: "4.18.0", Versions: append(npm.pkgs["pkg:npm/lodash"].Versions,
		pkgmeta.Version{Version: "4.18.0"})}
	if _, err := pool.Exec(ctx, `UPDATE package_meta SET next_fetch_at = now() - interval '1 minute' WHERE base_purl = 'pkg:npm/lodash'`); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	assertFilter(t, sbomRepo, projectID, true, []string{lodashOld, lodashNew, requests})

	// GET /pkgmeta's source: the cached versions, newest first.
	m, err := repo.Get(ctx, "pkg:npm/lodash")
	if err != nil {
		t.Fatal(err)
	}
	if m.LatestVersion != "4.18.0" || len(m.Versions) != 5 || m.Versions[0].Version != "5.0.0-alpha.1" || m.Versions[1].Version != "4.18.0" {
		t.Errorf("cached meta = %+v", m)
	}
}

// TestRefreshProjectAfterUpload: an upload's new packages are looked up right
// away and get a status; packages already cached aren't refetched.
func TestRefreshProjectAfterUpload(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	sbomRepo := sbom.NewRepository(pool)
	repo := pkgmeta.NewRepository(pool)
	var projectID string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-pm2','o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'p','p' FROM tm RETURNING id`).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	cargo := &fakeRegistry{eco: pkgmeta.Cargo, pkgs: map[string]pkgmeta.Package{
		"pkg:cargo/serde": {Latest: "1.0.200", Versions: []pkgmeta.Version{{Version: "1.0.100"}, {Version: "1.0.200"}}},
	}}
	svc := pkgmeta.NewService(repo, map[string]pkgmeta.Registry{pkgmeta.Cargo: cargo}, pkgmeta.Options{})
	if _, err := sbomRepo.Ingest(ctx, sbom.Sbom{ProjectID: projectID, Artifact: "a", Format: "CycloneDX"},
		[]sbom.Component{lib("serde", "1.0.100", "pkg:cargo/serde@1.0.100")}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := svc.RefreshProject(ctx, projectID); err != nil {
		t.Fatal(err)
	}
	assertFilter(t, sbomRepo, projectID, true, []string{"pkg:cargo/serde@1.0.100"})

	// Another artifact with the same package: no new fetch, status still set.
	if _, err := sbomRepo.Ingest(ctx, sbom.Sbom{ProjectID: projectID, Artifact: "b", Format: "CycloneDX"},
		[]sbom.Component{lib("serde", "1.0.200", "pkg:cargo/serde@1.0.200")}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := svc.RefreshProject(ctx, projectID); err != nil {
		t.Fatal(err)
	}
	if cargo.calls != 1 {
		t.Errorf("registry calls = %d, want 1", cargo.calls)
	}
	assertFilter(t, sbomRepo, projectID, false, []string{"pkg:cargo/serde@1.0.200"})
}

// assertFilter checks which purls ?outdated=<outdated> returns for a project.
func assertFilter(t *testing.T, repo *sbom.Repository, projectID string, outdated bool, want []string) {
	t.Helper()
	hits, err := repo.ListComponents(context.Background(), sbom.ComponentFilter{ProjectID: projectID, Outdated: &outdated})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, h := range hits {
		got[h.Purl] = true
	}
	if len(got) != len(want) {
		t.Errorf("outdated=%v: got %v, want %v", outdated, got, want)
		return
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("outdated=%v: got %v, want %v", outdated, got, want)
			return
		}
	}
}
