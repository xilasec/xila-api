package connector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
)

// Client talks to one remote project.
type Client interface {
	// Check makes one cheap authenticated call and returns the remote
	// project's display name.
	Check(ctx context.Context) (string, error)
	// Fetch returns every finding the remote currently reports, mapped to
	// findings (fingerprinted, metadata set; project/scanner/scan are stamped by
	// ApplyFindings). It fails rather than return a partial list.
	Fetch(ctx context.Context) ([]finding.Finding, error)
	// Category is the scan-level category for a pull's findings.
	Category(fs []finding.Finding) domain.Category
}

// NewClient builds the client for a connector's kind.
func NewClient(c Connector, token string, hc *http.Client) (Client, error) {
	switch c.Kind {
	case KindDependencyTrack:
		return &dependencyTrack{base: c.BaseURL, project: c.RemoteProject, token: token, hc: hc, pageSize: dtPageSize}, nil
	case KindDefectDojo:
		return &defectDojo{base: c.BaseURL, scope: c.RemoteProject, token: token, hc: hc, pageSize: ddPageSize}, nil
	}
	return nil, fmt.Errorf("unsupported connector kind %q", c.Kind)
}

// RemoteError is a failed call to the remote (HTTP 502 to our caller). Detail
// holds what the remote said (a response snippet, a dial error); it is shown to
// instance admins only — anyone else who can point a connector at a URL would
// otherwise get a probe that reads internal services' responses.
type RemoteError struct{ msg, detail string }

func (e RemoteError) Error() string {
	if e.detail == "" {
		return e.msg
	}
	return e.msg + ": " + e.detail
}

// Public is the message without the remote's own words.
func (e RemoteError) Public() string { return e.msg }

func remoteErr(format string, args ...any) error {
	return RemoteError{msg: fmt.Sprintf(format, args...)}
}

// PublicMessage is err as safe to show a non-admin.
func PublicMessage(err error) string {
	var r RemoteError
	if errors.As(err, &r) {
		return r.Public()
	}
	return err.Error()
}

// maxPages bounds one pull, so a remote that ignores paging (returns the same
// page forever) fails the pull instead of looping.
const maxPages = 2000

// maxBody bounds one response page.
const maxBody = 64 << 20

// getJSON GETs url with the auth header and decodes a 2xx JSON body into dst.
func getJSON(ctx context.Context, hc *http.Client, url, authHeader, authValue string, dst any) (http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, remoteErr("build request: %v", err)
	}
	req.Header.Set(authHeader, authValue)
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, RemoteError{msg: req.Method + " " + req.URL.Path + ": request failed", detail: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return nil, RemoteError{
			msg:    fmt.Sprintf("%s %s: HTTP %d", req.Method, req.URL.Path, resp.StatusCode),
			detail: strings.TrimSpace(string(snippet)),
		}
	}
	body := io.LimitReader(resp.Body, maxBody+1)
	dec := json.NewDecoder(body)
	if err := dec.Decode(dst); err != nil {
		return nil, RemoteError{msg: req.Method + " " + req.URL.Path + ": invalid JSON response", detail: err.Error()}
	}
	return resp.Header, nil
}

// fingerprint is a finding's stable identity within a connector's version.
func fingerprint(kind Kind, key string) string {
	sum := sha256.Sum256([]byte(string(kind) + "|" + key))
	return hex.EncodeToString(sum[:])
}

// mapSeverity normalizes a remote severity word; ok=false for unassigned /
// unknown values.
func mapSeverity(s string) (domain.Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return domain.SeverityCritical, true
	case "high":
		return domain.SeverityHigh, true
	case "medium", "moderate":
		return domain.SeverityMedium, true
	case "low":
		return domain.SeverityLow, true
	case "info", "informational", "none":
		return domain.SeverityInfo, true
	}
	return "", false
}

// severityFromScore maps a CVSS base score onto the CVSS v3 qualitative scale.
func severityFromScore(score *float64) domain.Severity {
	switch {
	case score == nil:
		return domain.SeverityInfo
	case *score >= 9:
		return domain.SeverityCritical
	case *score >= 7:
		return domain.SeverityHigh
	case *score >= 4:
		return domain.SeverityMedium
	case *score > 0:
		return domain.SeverityLow
	}
	return domain.SeverityInfo
}

// withSection appends a titled paragraph to a description.
func withSection(desc, title, text string) string {
	desc, text = strings.TrimSpace(desc), strings.TrimSpace(text)
	switch {
	case text == "":
		return desc
	case desc == "":
		return title + ": " + text
	}
	return desc + "\n\n" + title + ": " + text
}

// addCVE appends id when it is a CVE not yet in list.
func addCVE(list []string, id string) []string {
	id = strings.ToUpper(strings.TrimSpace(id))
	if !strings.HasPrefix(id, "CVE-") {
		return list
	}
	for _, c := range list {
		if c == id {
			return list
		}
	}
	return append(list, id)
}

// uniqueByFingerprint drops later findings that share a fingerprint with an
// earlier one: one upsert batch can't touch a row twice.
func uniqueByFingerprint(fs []finding.Finding) []finding.Finding {
	seen := make(map[string]bool, len(fs))
	out := fs[:0]
	for _, f := range fs {
		if seen[f.Fingerprint] {
			continue
		}
		seen[f.Fingerprint] = true
		out = append(out, f)
	}
	return out
}
