package pkgmeta

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/xilasec/xila-api/internal/netguard"
)

// ErrNotFound means the registry doesn't know the package (404/410) — typical
// for private packages resolved from an internal registry.
var ErrNotFound = errors.New("package not found in registry")

// Registry fetches every published version of a package from one ecosystem's
// registry.
type Registry interface {
	Ecosystem() string
	Fetch(ctx context.Context, p PURL) (Package, error)
}

// maxBody caps a registry response. npm's full package documents are the
// largest (every manifest of every version); a few popular ones run to tens of
// MiB.
const maxBody = 128 << 20

// Public registry endpoints, overridable per ecosystem for internal mirrors.
var defaultURLs = map[string]string{
	NPM:      "https://registry.npmjs.org",
	PyPI:     "https://pypi.org/pypi",
	Maven:    "https://repo1.maven.org/maven2",
	Golang:   "https://proxy.golang.org",
	Cargo:    "https://crates.io/api/v1",
	NuGet:    "https://api.nuget.org/v3/index.json",
	Gem:      "https://rubygems.org",
	Composer: "https://repo.packagist.org",
}

// RegistryConfig configures the registry clients.
type RegistryConfig struct {
	UserAgent string
	// RequestsPerSecond caps requests to each registry (politeness); <= 0
	// means 5. crates.io's crawler policy asks for at most 1/s, so its public
	// endpoint is held to that regardless.
	RequestsPerSecond int
	Timeout           time.Duration     // per request; 0 = 30s
	URLs              map[string]string // ecosystem → base URL override; "" = public registry
}

// NewRegistries builds one client per supported ecosystem.
func NewRegistries(c RegistryConfig) map[string]Registry {
	rps := c.RequestsPerSecond
	if rps <= 0 {
		rps = 5
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	hc := netguard.NewClient(timeout)
	out := map[string]Registry{}
	for _, eco := range Ecosystems {
		base := strings.TrimRight(c.URLs[eco], "/")
		r := rps
		if base == "" {
			base = defaultURLs[eco]
			if eco == Cargo {
				r = 1 // https://crates.io/data-access#api
			}
		}
		g := &getter{hc: hc, ua: c.UserAgent, every: time.Second / time.Duration(r)}
		if reg := newRegistry(eco, base, g); reg != nil {
			out[eco] = reg
		}
	}
	return out
}

// newRegistry is the client for one ecosystem's registry at base; nil for an
// unsupported ecosystem.
func newRegistry(eco, base string, g *getter) Registry {
	switch eco {
	case NPM:
		return &npmRegistry{base: base, g: g}
	case PyPI:
		return &pypiRegistry{base: base, g: g}
	case Maven:
		return &mavenRegistry{base: base, g: g}
	case Golang:
		return &goRegistry{base: base, g: g}
	case Cargo:
		return &cargoRegistry{base: base, g: g}
	case NuGet:
		return &nugetRegistry{index: base, g: g}
	case Gem:
		return &gemRegistry{base: base, g: g}
	case Composer:
		return &composerRegistry{base: base, g: g}
	}
	return nil
}

// UserAgent is the User-Agent registries see: "xila/<version> (+<url>)", with
// the instance's public URL so an operator can be contacted (crates.io
// requires a descriptive one).
func UserAgent(publicURL string) string {
	version := "dev"
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		version = bi.Main.Version
	}
	contact := publicURL
	if contact == "" {
		contact = "https://github.com/xilasec/xila-api"
	}
	return fmt.Sprintf("xila/%s (+%s)", version, contact)
}

// getter is a polite HTTP client for one registry: every request carries the
// User-Agent and waits its turn so requests start at most once per `every`.
type getter struct {
	hc    *http.Client
	ua    string
	every time.Duration
	// auth, when set, signs a request to the registry's own host (a private
	// registry's credentials; never sent to another host a registry names).
	auth func(*http.Request)

	mu   sync.Mutex
	next time.Time
}

// wait blocks until this registry's next request slot.
func (g *getter) wait(ctx context.Context) error {
	g.mu.Lock()
	now := time.Now()
	at := g.next
	if at.Before(now) {
		at = now
	}
	g.next = at.Add(g.every)
	g.mu.Unlock()
	if d := time.Until(at); d > 0 {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
	return nil
}

// get fetches url and hands the (size-capped) body to read. 404/410 map to
// ErrNotFound.
func (g *getter) get(ctx context.Context, url, accept string, read func(io.Reader) error) error {
	if err := g.wait(ctx); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if g.ua != "" {
		req.Header.Set("User-Agent", g.ua)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if g.auth != nil {
		g.auth(req)
	}
	resp, err := g.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return fmt.Errorf("%w: %s", ErrNotFound, url)
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("GET %s: status %d: %s", url, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return read(io.LimitReader(resp.Body, maxBody))
}

// getJSON decodes a JSON response into v.
func (g *getter) getJSON(ctx context.Context, url string, v any) error {
	return g.get(ctx, url, "application/json", func(r io.Reader) error {
		if err := json.NewDecoder(r).Decode(v); err != nil {
			return fmt.Errorf("decode %s: %w", url, err)
		}
		return nil
	})
}

// parseTime reads an RFC 3339 timestamp; nil when absent or malformed.
func parseTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return nil
	}
	t = t.UTC()
	return &t
}
