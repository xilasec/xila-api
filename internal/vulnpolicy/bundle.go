package vulnpolicy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"gopkg.in/yaml.v3"
)

// Bundle is the GitOps-portable policy set: every policy, without its
// database id (bundles are meant to live in git and be reapplied verbatim —
// an id would just be noise, since ImportBundle always assigns fresh ones).
type Bundle struct {
	Policies []Policy `json:"policies" yaml:"policies"`
}

// bundleOf strips database-only fields so an export round-trips cleanly
// through import (id/created_by/created_at/updated_at are regenerated).
func bundleOf(ps []Policy) Bundle {
	out := make([]Policy, len(ps))
	for i, p := range ps {
		p.ID, p.CreatedBy, p.CreatedAt, p.UpdatedAt = "", "", time.Time{}, time.Time{}
		out[i] = p
	}
	return Bundle{Policies: out}
}

// EncodeBundle renders ps as a YAML or JSON bundle ("yaml"/"json"; anything
// else defaults to YAML — the git-friendly format).
func EncodeBundle(ps []Policy, format string) ([]byte, error) {
	b := bundleOf(ps)
	if format == "json" {
		return json.MarshalIndent(b, "", "  ")
	}
	return yaml.Marshal(b)
}

// DecodeBundle parses a YAML or JSON bundle (sniffed: a JSON body starts
// with '{' after whitespace; everything else is parsed as YAML, which is a
// superset of JSON anyway).
func DecodeBundle(raw []byte) (Bundle, error) {
	var b Bundle
	if err := yaml.Unmarshal(raw, &b); err != nil {
		return Bundle{}, fmt.Errorf("invalid bundle: %w", err)
	}
	return b, nil
}

// maxBundleBytes caps a fetched/uploaded bundle.
const maxBundleBytes = 4 << 20

// Syncer periodically fetches a bundle URL (VULN_POLICY_BUNDLE_URL) through
// an injected client (netguard — outbound HTTP to a configured URL must
// always go through it) and imports it. A failed fetch, parse or validation
// leaves the current policy set untouched — the same "a failed source never
// deletes what it can't replace" rule every feed in this codebase follows.
type Syncer struct {
	svc    *Service
	url    string
	client *http.Client
}

// NewSyncer constructs a Syncer for url using client (netguard.NewClient).
func NewSyncer(svc *Service, url string, client *http.Client) *Syncer {
	return &Syncer{svc: svc, url: url, client: client}
}

// Sync fetches and imports the bundle once.
func (s *Syncer) Sync(ctx context.Context) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return 0, err
	}
	res, err := s.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("%s: HTTP %d", s.url, res.StatusCode)
	}
	lr := &io.LimitedReader{R: res.Body, N: maxBundleBytes + 1}
	raw, err := io.ReadAll(lr)
	if err != nil {
		return 0, err
	}
	if lr.N <= 0 {
		return 0, fmt.Errorf("%s: larger than %d bytes", s.url, maxBundleBytes)
	}
	b, err := DecodeBundle(raw)
	if err != nil {
		return 0, err
	}
	out, err := s.svc.ImportBundle(ctx, b.Policies, Schema, "vuln-policy-bundle-sync", false)
	if err != nil {
		return 0, err
	}
	return len(out), nil
}

// RunEvery syncs at start, then on interval, until ctx ends. interval <= 0
// disables it.
func (s *Syncer) RunEvery(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if _, err := s.Sync(ctx); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "vuln policy bundle sync failed", "url", s.url, "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
