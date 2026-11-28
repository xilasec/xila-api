package pkgmeta

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// The testdata files are REAL registry responses, fetched 2026-10-27 and
// trimmed to the fields (and a handful of versions) the clients read:
//
//	npm_left-pad.json            https://registry.npmjs.org/left-pad
//	pypi_requests.json           https://pypi.org/pypi/requests/json
//	maven_guava.xml              https://repo1.maven.org/maven2/com/google/guava/guava/maven-metadata.xml
//	go_toml_list.txt             https://proxy.golang.org/github.com/!burnt!sushi/toml/@v/list
//	go_toml_latest.json          https://proxy.golang.org/github.com/!burnt!sushi/toml/@latest
//	cargo_libc.json              https://crates.io/api/v1/crates/libc
//	nuget_index.json             https://api.nuget.org/v3/index.json
//	nuget_newtonsoft_index.json  https://api.nuget.org/v3/registration5-gz-semver2/newtonsoft.json/index.json (pages inlined)
//	nuget_awssdk_index.json      https://api.nuget.org/v3/registration5-gz-semver2/awssdk.core/index.json (pages not inlined)
//	nuget_awssdk_page_*.json     the two pages it links to
//	gem_nokogiri.json            https://rubygems.org/api/v1/versions/nokogiri.json
//	composer_monolog.json        https://repo.packagist.org/p2/monolog/monolog.json (minified)

// fakeRegistry serves testdata files by request path and records requests.
type fakeRegistry struct {
	t       *testing.T
	routes  map[string]string // path → testdata file
	mu      sync.Mutex
	paths   []string
	agents  []string
	rewrite func(body string, base string) string
	srv     *httptest.Server
}

func newFake(t *testing.T, routes map[string]string) *fakeRegistry {
	t.Helper()
	f := &fakeRegistry{t: t, routes: routes}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.paths = append(f.paths, r.URL.EscapedPath())
		f.agents = append(f.agents, r.UserAgent())
		f.mu.Unlock()
		file, ok := f.routes[r.URL.EscapedPath()]
		if !ok {
			http.NotFound(w, r)
			return
		}
		data, err := os.ReadFile(filepath.Join("testdata", file))
		if err != nil {
			t.Errorf("read %s: %v", file, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		body := string(data)
		if f.rewrite != nil {
			body = f.rewrite(body, f.srv.URL)
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func registry(t *testing.T, eco, base string) Registry {
	t.Helper()
	regs := NewRegistries(RegistryConfig{UserAgent: "xila/test (+https://xila.example)", RequestsPerSecond: 1000,
		URLs: map[string]string{eco: base}})
	return regs[eco]
}

func fetch(t *testing.T, r Registry, purl string) Package {
	t.Helper()
	p, err := ParsePURL(purl)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := r.Fetch(context.Background(), p)
	if err != nil {
		t.Fatalf("fetch %s: %v", purl, err)
	}
	return pkg
}

func versionNames(pkg Package) []string {
	var out []string
	for _, v := range pkg.Versions {
		out = append(out, v.Version)
	}
	slices.Sort(out)
	return out
}

func find(pkg Package, version string) Version {
	for _, v := range pkg.Versions {
		if v.Version == version {
			return v
		}
	}
	return Version{}
}

func TestNPMClient(t *testing.T) {
	f := newFake(t, map[string]string{"/left-pad": "npm_left-pad.json", "/@angular%2fcore": "npm_left-pad.json"})
	r := registry(t, NPM, f.srv.URL)
	pkg := fetch(t, r, "pkg:npm/left-pad@1.1.0")
	if pkg.Latest != "1.3.0" || len(pkg.Versions) != 15 {
		t.Fatalf("latest %q, %d versions", pkg.Latest, len(pkg.Versions))
	}
	if p := find(pkg, "1.3.0").Published; p == nil || !p.Equal(*ts("2018-04-09T01:10:45.796Z")) {
		t.Errorf("1.3.0 published = %v", p)
	}
	if f.agents[0] != "xila/test (+https://xila.example)" {
		t.Errorf("user agent = %q", f.agents[0])
	}
	// Scoped packages are requested with the slash encoded.
	fetch(t, r, "pkg:npm/%40angular/core@17.0.0")
	if got := f.paths[len(f.paths)-1]; got != "/@angular%2fcore" {
		t.Errorf("scoped request path = %q", got)
	}
	info, ok := evaluate(NPM, newMeta("pkg:npm/left-pad", NPM, pkg, time.Now(), time.Hour), "1.1.0")
	if !ok || !info.Outdated || info.Latest != "1.3.0" || *info.VersionsBehind != 5 {
		t.Errorf("left-pad 1.1.0: %+v", info) // 1.1.1, 1.1.2, 1.1.3, 1.2.0, 1.3.0
	}
}

func TestPyPIClient(t *testing.T) {
	f := newFake(t, map[string]string{"/requests/json": "pypi_requests.json"})
	pkg := fetch(t, registry(t, PyPI, f.srv.URL), "pkg:pypi/Requests@2.31.0")
	if pkg.Latest != "2.34.2" {
		t.Errorf("latest = %q", pkg.Latest)
	}
	if got := versionNames(pkg); !slices.Equal(got, []string{"2.31.0", "2.32.0", "2.32.1", "2.32.2", "2.34.0.dev1", "2.34.2"}) {
		t.Errorf("versions = %v", got)
	}
	if !find(pkg, "2.32.0").Yanked || !find(pkg, "2.32.1").Yanked || find(pkg, "2.32.2").Yanked {
		t.Error("yanked releases not detected")
	}
	if p := find(pkg, "2.31.0").Published; p == nil || p.Year() != 2023 {
		t.Errorf("2.31.0 published = %v", p)
	}
	info, _ := evaluate(PyPI, newMeta("pkg:pypi/requests", PyPI, pkg, time.Now(), time.Hour), "2.31.0")
	if !info.Outdated || *info.VersionsBehind != 2 { // 2.32.2, 2.34.2
		t.Errorf("requests 2.31.0: %+v", info)
	}
}

func TestMavenClient(t *testing.T) {
	f := newFake(t, map[string]string{"/com/google/guava/guava/maven-metadata.xml": "maven_guava.xml"})
	pkg := fetch(t, registry(t, Maven, f.srv.URL+"/"), "pkg:maven/com.google.guava/guava@32.1.3-jre")
	if pkg.Latest != "33.7.2-jre" || len(pkg.Versions) != 20 {
		t.Fatalf("latest %q, %d versions", pkg.Latest, len(pkg.Versions))
	}
	m := newMeta("pkg:maven/com.google.guava/guava", Maven, pkg, time.Now(), time.Hour)
	info, _ := evaluate(Maven, m, "32.1.3-jre")
	if info.Latest != "33.7.2-jre" || *info.VersionsBehind != 4 || info.Published != nil {
		t.Errorf("guava 32.1.3-jre: %+v", info)
	}
	info, _ = evaluate(Maven, m, "33.7.1-android")
	if info.Latest != "33.7.2-android" || *info.VersionsBehind != 1 {
		t.Errorf("guava 33.7.1-android: %+v", info)
	}
}

func TestGoClient(t *testing.T) {
	f := newFake(t, map[string]string{
		"/github.com/!burnt!sushi/toml/@v/list": "go_toml_list.txt",
		"/github.com/!burnt!sushi/toml/@latest": "go_toml_latest.json",
	})
	pkg := fetch(t, registry(t, Golang, f.srv.URL), "pkg:golang/github.com/BurntSushi/toml@v1.3.0")
	if pkg.Latest != "v1.6.0" || len(pkg.Versions) != 16 {
		t.Fatalf("latest %q, %d versions", pkg.Latest, len(pkg.Versions))
	}
	if p := find(pkg, "v1.6.0").Published; p == nil || !p.Equal(*ts("2025-12-18T12:15:22Z")) {
		t.Errorf("v1.6.0 published = %v", p)
	}
	info, _ := evaluate(Golang, newMeta("pkg:golang/github.com/BurntSushi/toml", Golang, pkg, time.Now(), time.Hour), "v1.3.0")
	if !info.Outdated || *info.VersionsBehind != 5 { // v1.3.1, v1.3.2, v1.4.0, v1.5.0, v1.6.0
		t.Errorf("toml v1.3.0: %+v", info)
	}
}

func TestCargoClient(t *testing.T) {
	f := newFake(t, map[string]string{"/api/v1/crates/libc": "cargo_libc.json"})
	pkg := fetch(t, registry(t, Cargo, f.srv.URL+"/api/v1"), "pkg:cargo/libc@0.2.164")
	// max_stable_version, not max_version (1.0.0-alpha.5).
	if pkg.Latest != "0.2.191" {
		t.Errorf("latest = %q", pkg.Latest)
	}
	if !find(pkg, "0.2.165").Yanked || find(pkg, "0.2.166").Yanked {
		t.Error("yanked flag not read")
	}
	if f.agents[0] == "" || f.agents[0] == "Go-http-client/1.1" {
		t.Errorf("crates.io needs a descriptive user agent, got %q", f.agents[0])
	}
	info, _ := evaluate(Cargo, newMeta("pkg:cargo/libc", Cargo, pkg, time.Now(), time.Hour), "0.2.164")
	if info.Latest != "0.2.191" || *info.VersionsBehind != 3 { // 0.2.166, 0.2.190, 0.2.191 (0.2.165 yanked)
		t.Errorf("libc 0.2.164: %+v", info)
	}
}

func TestNuGetClient(t *testing.T) {
	f := newFake(t, map[string]string{
		"/v3/index.json": "nuget_index.json",
		"/v3/registration5-gz-semver2/newtonsoft.json/index.json":               "nuget_newtonsoft_index.json",
		"/v3/registration5-gz-semver2/awssdk.core/index.json":                   "nuget_awssdk_index.json",
		"/v3/registration5-gz-semver2/awssdk.core/page/4.0.0.15/4.0.7.1.json":   "nuget_awssdk_page_4.0.7.1.json",
		"/v3/registration5-gz-semver2/awssdk.core/page/4.0.7.2/4.0.102.14.json": "nuget_awssdk_page_4.0.102.14.json",
	})
	// Point the real service index and page links at the fake.
	f.rewrite = func(body, base string) string { return strings.ReplaceAll(body, "https://api.nuget.org", base) }
	r := registry(t, NuGet, f.srv.URL+"/v3/index.json")

	pkg := fetch(t, r, "pkg:nuget/Newtonsoft.Json@13.0.1")
	if got := versionNames(pkg); !slices.Equal(got, []string{"12.0.1", "12.0.1-beta1", "13.0.1", "13.0.3", "13.0.4", "13.0.5-beta1"}) {
		t.Errorf("versions = %v", got)
	}
	if !find(pkg, "13.0.5-beta1").Yanked || find(pkg, "13.0.4").Yanked {
		t.Error("unlisted versions not treated as yanked")
	}
	if find(pkg, "12.0.1-beta1").Published != nil {
		t.Error("an unlisted version's 1900 placeholder date was kept")
	}
	info, _ := evaluate(NuGet, newMeta("pkg:nuget/newtonsoft.json", NuGet, pkg, time.Now(), time.Hour), "13.0.1")
	if info.Latest != "13.0.4" || *info.VersionsBehind != 2 || info.LatestPublished == nil || info.LatestPublished.Year() != 2025 {
		t.Errorf("newtonsoft 13.0.1: %+v", info)
	}

	// Large packages: pages are fetched one request each.
	pkg = fetch(t, r, "pkg:nuget/AWSSDK.Core@4.0.7")
	if got := versionNames(pkg); !slices.Equal(got, []string{"4.0.102.13", "4.0.102.14", "4.0.7", "4.0.7.1"}) {
		t.Errorf("paged versions = %v", got)
	}
	// The service index is resolved once.
	n := 0
	for _, p := range f.paths {
		if p == "/v3/index.json" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("service index fetched %d times", n)
	}
}

func TestGemClient(t *testing.T) {
	f := newFake(t, map[string]string{"/api/v1/versions/nokogiri.json": "gem_nokogiri.json"})
	pkg := fetch(t, registry(t, Gem, f.srv.URL), "pkg:gem/nokogiri@1.18.10?platform=java")
	// One entry per platform build collapses to one version each.
	if got := versionNames(pkg); !slices.Equal(got, []string{"1.18.10", "1.19.2", "1.19.3", "1.19.4", "1.9.0.rc1"}) {
		t.Errorf("versions = %v", got)
	}
	info, _ := evaluate(Gem, newMeta("pkg:gem/nokogiri", Gem, pkg, time.Now(), time.Hour), "1.18.10")
	if info.Latest != "1.19.4" || *info.VersionsBehind != 3 {
		t.Errorf("nokogiri 1.18.10: %+v", info)
	}
	// A version's date is its first platform build's.
	if p := info.LatestPublished; p == nil || !p.Equal(*ts("2026-06-18T15:18:13.773Z")) {
		t.Errorf("latest published = %v", p)
	}
	// A pre-release user hears about every newer release.
	info, _ = evaluate(Gem, newMeta("pkg:gem/nokogiri", Gem, pkg, time.Now(), time.Hour), "1.9.0.rc1")
	if info.Latest != "1.19.4" || *info.VersionsBehind != 4 {
		t.Errorf("nokogiri 1.9.0.rc1: %+v", info)
	}
}

func TestComposerClient(t *testing.T) {
	f := newFake(t, map[string]string{"/p2/monolog/monolog.json": "composer_monolog.json"})
	pkg := fetch(t, registry(t, Composer, f.srv.URL), "pkg:composer/monolog/monolog@3.9.0")
	if len(pkg.Versions) != 18 {
		t.Fatalf("%d versions", len(pkg.Versions))
	}
	// Minified entries inherit unchanged keys; each carries its own time.
	if p := find(pkg, "3.10.0").Published; p == nil || !p.Equal(*ts("2026-01-02T08:56:05Z")) {
		t.Errorf("3.10.0 published = %v", p)
	}
	info, _ := evaluate(Composer, newMeta("pkg:composer/monolog/monolog", Composer, pkg, time.Now(), time.Hour), "3.9.0")
	if info.Latest != "3.12.1" || *info.VersionsBehind != 4 { // 3.10.0, 3.11.0, 3.12.0, 3.12.1
		t.Errorf("monolog 3.9.0: %+v", info)
	}
}

func TestMinifiedUnset(t *testing.T) {
	f := newFake(t, nil)
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"packages":{"a/b":[{"version":"2.0.0","time":"2024-01-01T00:00:00+00:00"},` +
			`{"version":"1.0.0","time":"__unset"}]}}`))
	})
	pkg := fetch(t, registry(t, Composer, f.srv.URL), "pkg:composer/a/b@1.0.0")
	if find(pkg, "1.0.0").Published != nil || find(pkg, "2.0.0").Published == nil {
		t.Errorf("__unset not applied: %+v", pkg.Versions)
	}
}

func TestClientErrors(t *testing.T) {
	status := http.StatusNotFound
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	r := registry(t, NPM, srv.URL)
	p, _ := ParsePURL("pkg:npm/internal-only@1.0.0")
	if _, err := r.Fetch(context.Background(), p); !errors.Is(err, ErrNotFound) {
		t.Errorf("404: err = %v, want ErrNotFound", err)
	}
	status = http.StatusServiceUnavailable
	if _, err := r.Fetch(context.Background(), p); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("503: err = %v, want a transient error", err)
	}
}

func TestGetterRateLimit(t *testing.T) {
	g := &getter{every: 20 * time.Millisecond}
	start := time.Now()
	for range 4 {
		if err := g.wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if elapsed := time.Since(start); elapsed < 55*time.Millisecond {
		t.Errorf("4 requests at 50/s took %v, want >= 60ms", elapsed)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	g.next = time.Now().Add(time.Hour)
	if err := g.wait(ctx); err == nil {
		t.Error("wait ignored a cancelled context")
	}
}

func TestGoEscape(t *testing.T) {
	if got := goEscape("github.com/BurntSushi/toml"); got != "github.com/!burnt!sushi/toml" {
		t.Errorf("goEscape = %q", got)
	}
}
