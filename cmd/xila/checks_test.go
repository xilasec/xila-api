package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// --- pure: annotation building ---

func TestBuildAnnotationsPathLineLevel(t *testing.T) {
	findings := []prFinding{
		{ID: "f1", Title: "RCE", Severity: "critical", CVE: []string{"CVE-2021-44228"},
			FilePath: "config/prod.env", Line: new(12)},
		{ID: "f2", Title: "Hardcoded key", Severity: "medium", KEV: true,
			FilePath: "src/app.js", Line: new(5)},
		{ID: "f3", Title: "Minor issue", Severity: "low",
			FilePath: "src/app.js", Line: new(9)},
		{ID: "f4", Title: "No location", Severity: "critical"}, // no file/line: skipped
	}

	got := buildAnnotations(findings)
	if len(got) != 3 {
		t.Fatalf("len(annotations) = %d, want 3 (the locationless finding must be skipped)", len(got))
	}

	if got[0].Path != "config/prod.env" || got[0].StartLine != 12 || got[0].EndLine != 12 {
		t.Errorf("annotation[0] path/line = %q:%d-%d, want config/prod.env:12", got[0].Path, got[0].StartLine, got[0].EndLine)
	}
	if got[0].AnnotationLevel != "failure" {
		t.Errorf("critical finding level = %q, want failure", got[0].AnnotationLevel)
	}
	if !strings.Contains(got[0].Title, "CVE-2021-44228") {
		t.Errorf("annotation[0] title = %q, want the CVE prefixed", got[0].Title)
	}

	// medium severity but KEV: still a failure — exploited in the wild outranks
	// the raw severity.
	if got[1].AnnotationLevel != "failure" {
		t.Errorf("KEV finding level = %q, want failure", got[1].AnnotationLevel)
	}

	// low severity, not KEV: a quieter warning.
	if got[2].AnnotationLevel != "warning" {
		t.Errorf("low severity finding level = %q, want warning", got[2].AnnotationLevel)
	}
}

func TestBuildAnnotationsCapsAtMax(t *testing.T) {
	var findings []prFinding
	for i := range maxAnnotations + 37 {
		findings = append(findings, prFinding{
			ID: fmt.Sprintf("f%d", i), Title: "finding", Severity: "high",
			FilePath: "a.go", Line: new(i + 1),
		})
	}
	got := buildAnnotations(findings)
	if len(got) != maxAnnotations {
		t.Fatalf("len(annotations) = %d, want the cap %d", len(got), maxAnnotations)
	}
	if n := countLocatable(findings); n != len(findings) {
		t.Fatalf("countLocatable = %d, want %d", n, len(findings))
	}
}

// --- pure: batching ---

func TestBatchAnnotationsSplitsAtFifty(t *testing.T) {
	var all []checkAnnotation
	for i := range 120 {
		all = append(all, checkAnnotation{Path: "a.go", StartLine: i + 1, EndLine: i + 1})
	}
	first, rest := batchAnnotations(all)
	if len(first) != 50 {
		t.Fatalf("first batch = %d, want the Checks API max of 50", len(first))
	}
	if len(rest) != 2 {
		t.Fatalf("rest = %d batches, want 2 (50 + 20)", len(rest))
	}
	if len(rest[0]) != 50 || len(rest[1]) != 20 {
		t.Errorf("rest batch sizes = %d, %d, want 50, 20", len(rest[0]), len(rest[1]))
	}
	// Every annotation must land in exactly one batch, none dropped or duplicated.
	total := len(first)
	for _, b := range rest {
		total += len(b)
	}
	if total != len(all) {
		t.Errorf("total batched = %d, want %d (no annotation lost)", total, len(all))
	}
}

func TestBatchAnnotationsUnderLimitIsOneBatch(t *testing.T) {
	first, rest := batchAnnotations([]checkAnnotation{{Path: "a.go", StartLine: 1, EndLine: 1}})
	if len(first) != 1 || len(rest) != 0 {
		t.Errorf("first=%d rest=%d, want 1, 0 for a single annotation", len(first), len(rest))
	}
	if first, rest := batchAnnotations(nil); first != nil || rest != nil {
		t.Errorf("empty input must produce no batches, got first=%v rest=%v", first, rest)
	}
}

// --- pure: conclusion mapping ---

func TestCheckConclusionMapping(t *testing.T) {
	cases := []struct {
		name string
		gate *gateResult
		want string
	}{
		{"no gate", nil, "neutral"},
		{"passed", &gateResult{Passed: true}, "success"},
		{"failed", &gateResult{Passed: false}, "failure"},
	}
	for _, c := range cases {
		if got := checkConclusion(c.gate); got != c.want {
			t.Errorf("%s: checkConclusion = %q, want %q", c.name, got, c.want)
		}
	}
}

// --- HTTP flow: create / update / batch ---

func TestUpsertCheckRunCreatesWhenAbsent(t *testing.T) {
	var created bool
	var sentBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/check-runs"):
			_ = json.NewEncoder(w).Encode(map[string]any{"check_runs": []any{}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/check-runs"):
			created = true
			_ = json.NewDecoder(r.Body).Decode(&sentBody)
			_ = json.NewEncoder(w).Encode(map[string]string{"html_url": "https://github.com/acme/app/runs/1"})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	gh := &ghClient{token: "t", repo: "acme/app", api: srv.URL, hc: srv.Client()}
	annotations := []checkAnnotation{{Path: "a.go", StartLine: 1, EndLine: 1, AnnotationLevel: "failure", Message: "m"}}
	url, err := gh.UpsertCheckRun("deadbeef", checkRunName, "failure", "summary text", annotations)
	if err != nil {
		t.Fatalf("UpsertCheckRun: %v", err)
	}
	if !created {
		t.Fatal("expected a POST to create the check run")
	}
	if url == "" {
		t.Error("expected the check run URL back")
	}
	if sentBody["conclusion"] != "failure" || sentBody["head_sha"] != "deadbeef" {
		t.Errorf("sent body = %+v, want conclusion=failure head_sha=deadbeef", sentBody)
	}
	output, _ := sentBody["output"].(map[string]any)
	if output["summary"] != "summary text" {
		t.Errorf("output.summary = %v, want the rendered summary", output["summary"])
	}
	anns, _ := output["annotations"].([]any)
	if len(anns) != 1 {
		t.Errorf("output.annotations = %v, want 1 annotation on create", anns)
	}
}

func TestUpsertCheckRunUpdatesExisting(t *testing.T) {
	var patchedID string
	var created bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/check-runs"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"check_runs": []map[string]any{{"id": 99, "html_url": "https://github.com/acme/app/runs/99"}},
			})
		case r.Method == http.MethodPatch && strings.HasSuffix(r.URL.Path, "/check-runs/99"):
			patchedID = "99"
			_ = json.NewEncoder(w).Encode(map[string]string{"html_url": "https://github.com/acme/app/runs/99"})
		case r.Method == http.MethodPost:
			created = true
			_ = json.NewEncoder(w).Encode(map[string]string{"html_url": "new"})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	gh := &ghClient{token: "t", repo: "acme/app", api: srv.URL, hc: srv.Client()}
	_, err := gh.UpsertCheckRun("deadbeef", checkRunName, "success", "all good", nil)
	if err != nil {
		t.Fatalf("UpsertCheckRun: %v", err)
	}
	if created {
		t.Error("an existing check run on this commit must be updated, never duplicated")
	}
	if patchedID != "99" {
		t.Errorf("patched id = %q, want 99", patchedID)
	}
}

func TestUpsertCheckRunBatchesOverFifty(t *testing.T) {
	var createAnnotations int
	var patchCalls [][]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/check-runs"):
			_ = json.NewEncoder(w).Encode(map[string]any{"check_runs": []any{}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/check-runs"):
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			output := body["output"].(map[string]any)
			anns, _ := output["annotations"].([]any)
			createAnnotations = len(anns)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 7, "html_url": "https://github.com/acme/app/runs/7"})
		case r.Method == http.MethodPatch && strings.HasSuffix(r.URL.Path, "/check-runs/7"):
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			output := body["output"].(map[string]any)
			anns, _ := output["annotations"].([]any)
			patchCalls = append(patchCalls, anns)
			_ = json.NewEncoder(w).Encode(map[string]string{"html_url": "https://github.com/acme/app/runs/7"})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	gh := &ghClient{token: "t", repo: "acme/app", api: srv.URL, hc: srv.Client()}
	var annotations []checkAnnotation
	for i := range 120 {
		annotations = append(annotations, checkAnnotation{Path: "a.go", StartLine: i + 1, EndLine: i + 1, AnnotationLevel: "warning", Message: "m"})
	}
	if _, err := gh.UpsertCheckRun("deadbeef", checkRunName, "failure", "summary", annotations); err != nil {
		t.Fatalf("UpsertCheckRun: %v", err)
	}
	if createAnnotations != 50 {
		t.Errorf("create carried %d annotations, want 50 (the per-request max)", createAnnotations)
	}
	if len(patchCalls) != 2 {
		t.Fatalf("expected 2 further PATCH calls for the remaining 70 annotations, got %d", len(patchCalls))
	}
	if len(patchCalls[0]) != 50 || len(patchCalls[1]) != 20 {
		t.Errorf("patch batch sizes = %d, %d, want 50, 20", len(patchCalls[0]), len(patchCalls[1]))
	}
}

// A Checks API failure (most commonly a missing checks: write permission, 403)
// must warn and never change the exit code — the same best-effort rule as the
// PR comment.
func TestUpsertCheckRun403IsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/check-runs"):
			_ = json.NewEncoder(w).Encode(map[string]any{"check_runs": []any{}})
		default:
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"Resource not accessible by integration"}`))
		}
	}))
	defer srv.Close()

	gh := &ghClient{token: "t", repo: "acme/app", api: srv.URL, hc: srv.Client()}
	_, err := gh.UpsertCheckRun("deadbeef", checkRunName, "failure", "summary", nil)
	if err == nil {
		t.Fatal("expected an error on 403")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error = %v, want it to mention the 403", err)
	}
}

func TestCmdGateCheck403WarnsButExitCodeUnchanged(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"passed": false, "scope": "project",
			"violations": []map[string]string{{"rule": "max_critical", "message": "1 open critical findings exceed the limit of 0"}},
			"stats":      map[string]any{"open_critical": 1},
		})
	})
	apiSrv := httptest.NewServer(mux)
	defer apiSrv.Close()

	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/check-runs"):
			_ = json.NewEncoder(w).Encode(map[string]any{"check_runs": []any{}})
		default:
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"Resource not accessible by integration"}`))
		}
	}))
	defer ghSrv.Close()

	t.Setenv("GITHUB_TOKEN", "t")
	t.Setenv("GITHUB_REPOSITORY", "acme/app")
	t.Setenv("GITHUB_API_URL", ghSrv.URL)
	t.Setenv("GITHUB_SHA", "deadbeef")
	t.Setenv("GITHUB_EVENT_PATH", "")

	var out, errw bytes.Buffer
	code := run([]string{"gate", "--url", apiSrv.URL, "--token", "xila_test", "--project", "p1", "--max-critical", "0", "--check"}, &out, &errw)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (the gate's own verdict, unaffected by the check-run failure)", code)
	}
	if !strings.Contains(errw.String(), "warning: could not post check run") {
		t.Errorf("stderr = %q, want a warning about the check run", errw.String())
	}
}

// --- env resolution ---

func TestGhCheckEnvNoContext(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GITHUB_REPOSITORY", "")
	if _, _, ok := ghCheckEnv(); ok {
		t.Error("no GitHub Actions env at all must be a silent no-op")
	}
}

func TestGhCheckEnvFallsBackToGitHubSHAOnPush(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "t")
	t.Setenv("GITHUB_REPOSITORY", "acme/app")
	t.Setenv("GITHUB_EVENT_PATH", "")
	t.Setenv("GITHUB_SHA", "cafebabe")
	_, sha, ok := ghCheckEnv()
	if !ok || sha != "cafebabe" {
		t.Errorf("ghCheckEnv = sha=%q ok=%v, want cafebabe/true (a push has no PR head to prefer)", sha, ok)
	}
}

func TestPrHeadSHAPrefersEventHeadOverGitHubSHA(t *testing.T) {
	path := t.TempDir() + "/event.json"
	if err := os.WriteFile(path, []byte(`{"pull_request":{"head":{"sha":"realhead123"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_EVENT_PATH", path)
	t.Setenv("GITHUB_SHA", "mergecommit456") // what GITHUB_SHA would be on pull_request

	if got := prHeadSHA(); got != "realhead123" {
		t.Errorf("prHeadSHA = %q, want the PR's actual head commit, not the merge ref", got)
	}
}
