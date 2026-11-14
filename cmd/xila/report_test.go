package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func f64(v float64) *float64 { return &v }
func boolp(v bool) *bool     { return &v }

func TestRenderCommentLeadsWithTheVerdict(t *testing.T) {
	gate := &gateResult{Passed: false, NewOnly: true}
	gate.Violations = []struct {
		Rule    string `json:"rule"`
		Message string `json:"message"`
	}{{Rule: "max_critical", Message: "1 critical finding exceeds the limit of 0"}}
	gate.Stats.OpenCritical = 1
	gate.Stats.OpenHigh = 3
	gate.Stats.OpenKEV = 1
	gate.Stats.MaxEPSS = 0.97

	findings := []prFinding{
		{ID: "f1", Title: "Remote code execution in log4j-core", Severity: "critical",
			CVE: []string{"CVE-2021-44228"}, KEV: true,
			Package: "log4j-core", PackageVersion: "2.14.1", FixedVersion: "2.15.0"},
		{ID: "f2", Title: "Prototype pollution", Severity: "high", EPSS: f64(0.2),
			Package: "lodash", PackageVersion: "4.17.20", DepDirect: boolp(false)},
		{ID: "f3", Title: "Hardcoded AWS key", Severity: "high",
			FilePath: "config/prod.env", Line: intp(12)},
	}

	got := renderComment("https://xila.acme.io", "p1", gate, findings, 3)

	// The verdict is the first line: it's the only line most people read.
	first := strings.SplitN(got, "\n", 2)[0]
	if !strings.Contains(first, "❌") || !strings.Contains(first, "failed") {
		t.Errorf("first line must be the verdict, got %q", first)
	}
	for _, want := range []string{
		"1 critical finding exceeds the limit of 0", // why it failed
		"3 new findings", // what this PR did
		"CVE-2021-44228",
		"**KEV**",    // being exploited right now — the thing that changes your afternoon
		"transitive", // …and the thing that means it can wait
		"`2.15.0`",   // the fix: the most actionable cell in the table
		"config/prod.env:12",
		"https://xila.acme.io/findings/f1", // deep link back
		"gate scoped to new findings",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("comment missing %q\n---\n%s", want, got)
		}
	}
}

func TestRenderCommentCleanPR(t *testing.T) {
	gate := &gateResult{Passed: true}
	got := renderComment("https://xila.acme.io", "p1", gate, nil, 0)
	if !strings.Contains(got, "✅") || !strings.Contains(got, "no new findings") {
		t.Errorf("a clean PR should say so plainly:\n%s", got)
	}
}

// A title containing a pipe must not break the markdown table.
func TestRenderCommentEscapesTableBreakers(t *testing.T) {
	got := renderComment("", "p1", nil, []prFinding{
		{ID: "f1", Title: "Command injection via a | b", Severity: "high"},
	}, 1)
	for _, line := range strings.Split(got, "\n") {
		if !strings.Contains(line, "Command injection") {
			continue
		}
		if !strings.Contains(line, `\|`) {
			t.Errorf("the pipe in the title must be escaped: %q", line)
		}
		// Once the escaped pipe is removed, only the four cell delimiters remain.
		if n := strings.Count(strings.ReplaceAll(line, `\|`, ""), "|"); n != 5 {
			t.Errorf("row has %d delimiters, want 5 — the title broke the table: %q", n, line)
		}
	}
}

func intp(v int) *int { return &v }

// --- the sticky comment ---

// TestUpsertCommentEditsInPlace is the property that decides whether developers
// keep this bot enabled: a PR must carry exactly ONE Xila comment, updated on
// every push. A bot that appends a fresh verdict per push gets muted within a week.
func TestUpsertCommentEditsInPlace(t *testing.T) {
	var patched, created int
	var patchedBody string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/issues/7/comments"):
			// Someone else's comment, then ours.
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"id": 1, "body": "LGTM"},
				{"id": 42, "body": "## old verdict\n" + commentMarker},
			})
		case r.Method == http.MethodPatch && strings.HasSuffix(r.URL.Path, "/issues/comments/42"):
			patched++
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			patchedBody = body["body"]
			_ = json.NewEncoder(w).Encode(map[string]string{"html_url": "https://github.com/acme/app/pull/7#c42"})
		case r.Method == http.MethodPost:
			created++
			_ = json.NewEncoder(w).Encode(map[string]string{"html_url": "new"})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	gh := &ghClient{token: "t", repo: "acme/app", api: srv.URL, hc: srv.Client()}
	url, err := gh.UpsertComment(7, "## new verdict")
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if created != 0 || patched != 1 {
		t.Errorf("created=%d patched=%d — an existing comment must be edited, never duplicated", created, patched)
	}
	if !strings.Contains(patchedBody, "new verdict") || !strings.Contains(patchedBody, commentMarker) {
		t.Errorf("patched body = %q; it must carry the marker so the next run finds it again", patchedBody)
	}
	if url == "" {
		t.Error("expected the comment URL back")
	}
}

func TestUpsertCommentCreatesWhenAbsent(t *testing.T) {
	var created int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 1, "body": "LGTM"}})
			return
		}
		created++
		_ = json.NewEncoder(w).Encode(map[string]string{"html_url": "https://github.com/acme/app/pull/7#c99"})
	}))
	defer srv.Close()

	gh := &ghClient{token: "t", repo: "acme/app", api: srv.URL, hc: srv.Client()}
	if _, err := gh.UpsertComment(7, "## verdict"); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if created != 1 {
		t.Errorf("created = %d, want 1", created)
	}
}

// --- PR detection ---

func TestPRNumberFromEventPayload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "event.json")
	if err := os.WriteFile(path, []byte(`{"pull_request":{"number":123}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_EVENT_PATH", path)
	t.Setenv("GITHUB_REF", "")

	if n, ok := prNumber(); !ok || n != 123 {
		t.Errorf("prNumber() = %d, %v; want 123, true", n, ok)
	}
}

func TestPRNumberFallsBackToRef(t *testing.T) {
	t.Setenv("GITHUB_EVENT_PATH", "")
	t.Setenv("GITHUB_REF", "refs/pull/456/merge")
	if n, ok := prNumber(); !ok || n != 456 {
		t.Errorf("prNumber() = %d, %v; want 456, true", n, ok)
	}
}

// Outside a pull request there is nothing to comment on. That is normal — a push
// to main must not fail the build over it.
func TestNoPRContextIsNotAnError(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "t")
	t.Setenv("GITHUB_REPOSITORY", "acme/app")
	t.Setenv("GITHUB_EVENT_PATH", "")
	t.Setenv("GITHUB_REF", "refs/heads/main")

	if _, _, ok := ghFromEnv(); ok {
		t.Error("a push to a branch is not a PR context")
	}
	if err := postPRComment(nil, "", "", "", nil, os.Stdout); err != nil {
		t.Errorf("outside a PR, commenting must be a silent no-op, got %v", err)
	}
}
