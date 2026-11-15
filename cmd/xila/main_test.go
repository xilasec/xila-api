package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeAPI mimics the Xila endpoints the CLI uses.
func fakeAPI(t *testing.T, gatePasses bool) (*httptest.Server, *[]string) {
	t.Helper()
	var seen []string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/", func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery+" auth="+r.Header.Get("Authorization"))
		switch {
		case strings.HasSuffix(r.URL.Path, "/scans"):
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"scan-1","status":"completed"}`))
		case strings.HasSuffix(r.URL.Path, "/gate"):
			body := map[string]any{
				"passed": gatePasses, "scope": "project",
				"violations": []map[string]string{},
				"stats":      map[string]any{"open_critical": 1},
			}
			if !gatePasses {
				body["violations"] = []map[string]string{{"rule": "max_critical", "message": "1 open critical findings exceed the limit of 0"}}
				w.WriteHeader(http.StatusUnprocessableEntity)
			}
			_ = json.NewEncoder(w).Encode(body)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &seen
}

func TestUploadThenGatePass(t *testing.T) {
	srv, seen := fakeAPI(t, true)
	tmp := filepath.Join(t.TempDir(), "trivy.json")
	if err := os.WriteFile(tmp, []byte(`{"Results":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errw bytes.Buffer
	code := run([]string{"upload", "--url", srv.URL, "--token", "xila_test", "--project", "p1", "--scanner", "trivy", "--gate", tmp}, &out, &errw)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errw.String())
	}
	// It hit both the scans and gate endpoints with the token.
	joined := strings.Join(*seen, "\n")
	if !strings.Contains(joined, "/scans?scanner=trivy") || !strings.Contains(joined, "/gate") {
		t.Errorf("requests = %v, want scans+gate", *seen)
	}
	if !strings.Contains(joined, "auth=Bearer xila_test") {
		t.Errorf("token not sent: %v", *seen)
	}
	if !strings.Contains(out.String(), "gate PASSED") {
		t.Errorf("output = %q, want PASS", out.String())
	}
}

func TestGateFailExitsOne(t *testing.T) {
	srv, _ := fakeAPI(t, false)
	var out, errw bytes.Buffer
	code := run([]string{"gate", "--url", srv.URL, "--token", "xila_test", "--project", "p1", "--max-critical", "0"}, &out, &errw)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 for a failed gate", code)
	}
	if !strings.Contains(out.String(), "gate FAILED") || !strings.Contains(out.String(), "exceed the limit") {
		t.Errorf("output = %q, want failure detail", out.String())
	}
}

func TestMissingArgsUsageError(t *testing.T) {
	var out, errw bytes.Buffer
	if code := run([]string{"gate", "--token", "x"}, &out, &errw); code != 2 { // no --project
		t.Errorf("exit = %d, want 2 for missing project", code)
	}
	if code := run(nil, &out, &errw); code != 2 {
		t.Errorf("no args exit = %d, want 2", code)
	}
	if code := run([]string{"bogus"}, io.Discard, io.Discard); code != 2 {
		t.Errorf("unknown command exit = %d, want 2", code)
	}
}

func TestGateNewFlagSendsNewOnly(t *testing.T) {
	var gotBody string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"passed": true, "scope": "project", "new_only": true,
			"violations": []any{}, "stats": map[string]any{"open_critical": 0},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var out, errw bytes.Buffer
	code := run([]string{"gate", "--url", srv.URL, "--token", "t", "--project", "p1", "--new", "--max-critical", "0"}, &out, &errw)
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.Contains(gotBody, `"new_only":true`) {
		t.Errorf("request body %q missing new_only", gotBody)
	}
	if !strings.Contains(gotBody, `"max_critical":0`) {
		t.Errorf("request body %q missing inline policy", gotBody)
	}
	if !strings.Contains(out.String(), "new-only") {
		t.Errorf("output %q should note new-only mode", out.String())
	}
}

// TestGateBaselineAndMaxRiskScoreFlags pins --baseline to the ?baseline= query
// param (not the body — the server resolves it against the project's versions)
// and --max-risk-score to the inline policy, same as the other threshold flags.
func TestGateBaselineAndMaxRiskScoreFlags(t *testing.T) {
	var gotBody, gotQuery string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		gotQuery = r.URL.RawQuery
		_ = json.NewEncoder(w).Encode(map[string]any{
			"passed": true, "scope": "project", "new_only": true, "baseline": "main",
			"violations": []any{}, "stats": map[string]any{"open_critical": 0, "risk_score": 12.5},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var out, errw bytes.Buffer
	code := run([]string{"gate", "--url", srv.URL, "--token", "t", "--project", "p1",
		"--new", "--baseline", "main", "--max-risk-score", "50"}, &out, &errw)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errw.String())
	}
	if !strings.Contains(gotQuery, "baseline=main") {
		t.Errorf("request query %q missing baseline=main", gotQuery)
	}
	if !strings.Contains(gotBody, `"max_risk_score":50`) {
		t.Errorf("request body %q missing inline max_risk_score", gotBody)
	}
	if !strings.Contains(out.String(), "vs main") {
		t.Errorf("output %q should note the baseline used", out.String())
	}
	if !strings.Contains(out.String(), "risk 12.5") {
		t.Errorf("output %q should show the risk score", out.String())
	}
}

// TestUploadBaselineFlagPassesThrough confirms upload --gate --baseline forwards
// the baseline name on the gate request it issues after the upload.
func TestUploadBaselineFlagPassesThrough(t *testing.T) {
	var gotQuery string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/scans"):
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"scan-1","status":"completed","version_id":"v1"}`))
		case strings.HasSuffix(r.URL.Path, "/gate"):
			gotQuery = r.URL.RawQuery
			_ = json.NewEncoder(w).Encode(map[string]any{
				"passed": true, "scope": "project",
				"violations": []any{}, "stats": map[string]any{"open_critical": 0},
			})
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tmp := filepath.Join(t.TempDir(), "trivy.json")
	if err := os.WriteFile(tmp, []byte(`{"Results":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errw bytes.Buffer
	code := run([]string{"upload", "--url", srv.URL, "--token", "t", "--project", "p1",
		"--scanner", "trivy", "--gate", "--baseline", "main", tmp}, &out, &errw)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errw.String())
	}
	if !strings.Contains(gotQuery, "baseline=main") {
		t.Errorf("gate request query %q missing baseline=main", gotQuery)
	}
}

// --force bypasses skip-unchanged (M11 11.4): the CLI must send force=true on
// the upload request.
func TestUploadForceFlagSendsForceTrue(t *testing.T) {
	var gotQuery string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/scans") {
			gotQuery = r.URL.RawQuery
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"scan-1","status":"completed","version_id":"v1"}`))
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tmp := filepath.Join(t.TempDir(), "trivy.json")
	if err := os.WriteFile(tmp, []byte(`{"Results":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errw bytes.Buffer
	code := run([]string{"upload", "--url", srv.URL, "--token", "t", "--project", "p1",
		"--scanner", "trivy", "--force", tmp}, &out, &errw)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errw.String())
	}
	if !strings.Contains(gotQuery, "force=true") {
		t.Errorf("upload request query %q missing force=true", gotQuery)
	}
}
