package connector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

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
	case KindSnyk:
		return &snyk{base: c.BaseURL, scope: c.RemoteProject, token: token, hc: hc, pageSize: snykPageSize}, nil
	case KindGitHub:
		return &gitHub{base: c.BaseURL, scope: c.RemoteProject, token: token, hc: hc, pageSize: githubPageSize}, nil
	case KindGitLab:
		return &gitLab{base: c.BaseURL, project: c.RemoteProject, token: token, hc: hc, pageSize: gitlabPageSize}, nil
	case KindWiz:
		creds, err := parseWizCredentials(token)
		if err != nil {
			return nil, err
		}
		return &wiz{base: c.BaseURL, authURL: c.AuthURL, scope: c.RemoteProject,
			clientID: creds.ClientID, clientSecret: creds.ClientSecret, hc: hc, pageSize: wizPageSize}, nil
	case KindTenable:
		creds, err := parseTenableCredentials(token)
		if err != nil {
			return nil, err
		}
		return &tenable{base: c.BaseURL, scope: c.RemoteProject,
			accessKey: creds.AccessKey, secretKey: creds.SecretKey, hc: hc, pollInterval: tenablePollInterval}, nil
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

// maxRateLimitRetries bounds how many 429s one call absorbs, so a remote that
// never recovers fails the pull instead of hanging it.
const maxRateLimitRetries = 5

// maxRateLimitWait caps how long a single Retry-After is honored.
const maxRateLimitWait = 90 * time.Second

// retryAfter parses a Retry-After header (seconds, or an HTTP-date) into a
// wait duration. ok=false means none was given or it couldn't be parsed, so
// the caller falls back to its own backoff.
func retryAfter(h http.Header) (time.Duration, bool) {
	v := strings.TrimSpace(h.Get("Retry-After"))
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			secs = 0
		}
		return time.Duration(secs) * time.Second, true
	}
	if when, err := http.ParseTime(v); err == nil {
		if d := time.Until(when); d > 0 {
			return d, true
		}
		return 0, true
	}
	return 0, false
}

// httpJSON issues method to url with headers, retrying on 429 per
// Retry-After (an exponential fallback when the remote doesn't send one),
// capped at maxRateLimitRetries attempts and maxRateLimitWait per wait. body
// is the raw request payload ("" for none). A 2xx response decodes into dst
// (nil drains and discards it — some callers only need the status/headers,
// e.g. Tenable's export status poll). A non-2xx response that persists past
// the retries is a RemoteError carrying a response snippet.
func httpJSON(ctx context.Context, hc *http.Client, method, url string, headers map[string]string, body []byte, dst any) (http.Header, error) {
	for attempt := 0; ; attempt++ {
		var rdr io.Reader
		if body != nil {
			rdr = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, rdr)
		if err != nil {
			return nil, remoteErr("build request: %v", err)
		}
		if _, ok := headers["Accept"]; !ok {
			req.Header.Set("Accept", "application/json")
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := hc.Do(req)
		if err != nil {
			return nil, RemoteError{msg: method + " " + req.URL.Path + ": request failed", detail: err.Error()}
		}
		if resp.StatusCode == http.StatusTooManyRequests && attempt < maxRateLimitRetries {
			wait, ok := retryAfter(resp.Header)
			resp.Body.Close()
			if !ok {
				wait = time.Duration(1<<uint(attempt)) * time.Second
			}
			if wait > maxRateLimitWait {
				wait = maxRateLimitWait
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
			resp.Body.Close()
			return nil, RemoteError{
				msg:    fmt.Sprintf("%s %s: HTTP %d", method, req.URL.Path, resp.StatusCode),
				detail: strings.TrimSpace(string(snippet)),
			}
		}
		if dst == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
			resp.Body.Close()
			return resp.Header, nil
		}
		dec := json.NewDecoder(io.LimitReader(resp.Body, maxBody+1))
		err = dec.Decode(dst)
		resp.Body.Close()
		if err != nil {
			return nil, RemoteError{msg: method + " " + req.URL.Path + ": invalid JSON response", detail: err.Error()}
		}
		return resp.Header, nil
	}
}

// getJSON GETs url with the auth header and decodes a 2xx JSON body into dst.
func getJSON(ctx context.Context, hc *http.Client, url, authHeader, authValue string, dst any) (http.Header, error) {
	return httpJSON(ctx, hc, http.MethodGet, url, map[string]string{authHeader: authValue}, nil, dst)
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

// cweFromID parses a "CWE-79" style identifier (case-insensitive, the
// external identifier format several of these APIs use) into its number.
func cweFromID(s string) *int {
	s = strings.TrimSpace(s)
	n, ok := strings.CutPrefix(strings.ToUpper(s), "CWE-")
	if !ok {
		return nil
	}
	id, err := strconv.Atoi(n)
	if err != nil || id <= 0 {
		return nil
	}
	return &id
}

// mostCommonCategory is a pull's scan-level category when its findings mix
// tools or issue types: the most common one, def when there are none.
func mostCommonCategory(fs []finding.Finding, def domain.Category) domain.Category {
	counts := map[domain.Category]int{}
	best, bestN := def, 0
	for _, f := range fs {
		counts[f.Category]++
		if n := counts[f.Category]; n > bestN {
			best, bestN = f.Category, n
		}
	}
	return best
}
