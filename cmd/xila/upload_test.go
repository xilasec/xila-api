package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sbomAPI serves an SBOM upload by name whose processing reports running, then
// final, and a gate; it records the requests in order.
func sbomAPI(t *testing.T, final string) (*httptest.Server, *[]string) {
	t.Helper()
	var seen []string
	polls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/sboms", func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, "upload "+r.URL.RawQuery)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"s1","project_id":"p9","version_id":"v3"}`))
	})
	mux.HandleFunc("GET /api/v1/sboms/s1/status", func(w http.ResponseWriter, _ *http.Request) {
		polls++
		status := "running"
		if polls > 1 {
			status = final
		}
		seen = append(seen, "status "+status)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": status, "error": "advisory source unavailable"})
	})
	mux.HandleFunc("POST /api/v1/projects/{id}/gate", func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, "gate "+r.PathValue("id")+"?"+r.URL.RawQuery)
		_ = json.NewEncoder(w).Encode(map[string]any{"passed": true, "scope": "project", "violations": []any{}, "stats": map[string]any{}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &seen
}

func writeSBOM(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "bom.cdx.xml")
	if err := os.WriteFile(p, []byte(`<bom xmlns="http://cyclonedx.org/schema/bom/1.6"/>`), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestUploadSBOMByNameWaitsThenGates(t *testing.T) {
	srv, seen := sbomAPI(t, "completed")
	var out, errw bytes.Buffer
	code := run([]string{"upload", "--url", srv.URL, "--token", "t", "--sbom",
		"--project-name", "web", "--team", "core", "--create", "--artifact", "web", "--artifact-version", "1.2.0",
		"--branch", "main", "--gate", writeSBOM(t)}, &out, &errw)
	if code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, errw.String())
	}
	want := []string{
		"upload artifact=web&auto_create=true&branch=main&project_name=web&team=core&version=1.2.0",
		"status running",
		"status completed",
		"gate p9?version_id=v3",
	}
	if strings.Join(*seen, "\n") != strings.Join(want, "\n") {
		t.Errorf("requests =\n%s\nwant\n%s", strings.Join(*seen, "\n"), strings.Join(want, "\n"))
	}
	if !strings.Contains(out.String(), "uploaded SBOM to project p9 (sbom s1)") {
		t.Errorf("output = %q", out.String())
	}
}

// A failed processing means the backlog is stale: no gate on it.
func TestUploadSBOMProcessingFailureSkipsGate(t *testing.T) {
	srv, seen := sbomAPI(t, "failed")
	var out, errw bytes.Buffer
	code := run([]string{"upload", "--url", srv.URL, "--token", "t", "--sbom", "--project-name", "web", "--gate", writeSBOM(t)}, &out, &errw)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if strings.Contains(strings.Join(*seen, "\n"), "gate") {
		t.Errorf("gated a failed upload: %v", *seen)
	}
	if !strings.Contains(errw.String(), "SBOM processing failed: advisory source unavailable") {
		t.Errorf("stderr = %q", errw.String())
	}
}

func TestUploadFlagCombinations(t *testing.T) {
	file := writeSBOM(t)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--scanner", "trivy"}, "give --project or --project-name"},
		{[]string{"--project", "p1", "--project-name", "web", "--scanner", "trivy"}, "give --project or --project-name"},
		{[]string{"--project", "p1", "--team", "core", "--scanner", "trivy"}, "--team and --create go with --project-name"},
		{[]string{"--project-name", "web", "--create", "--scanner", "trivy"}, "--create needs --team"},
		{[]string{"--project", "p1"}, "--scanner is required"},
		{[]string{"--project", "p1", "--sbom", "--scanner", "trivy"}, "--scanner is for scanner reports"},
		{[]string{"--project", "p1", "--sbom", "--force"}, "--force is for scanner reports"},
		{[]string{"--project", "p1", "--scanner", "trivy", "--strict"}, "--strict goes with --sbom"},
		{[]string{"--project", "p1", "--sbom", "--branch", "b", "--release", "r"}, "not both"},
	} {
		var errw bytes.Buffer
		args := append(append([]string{"upload", "--url", "http://127.0.0.1:1", "--token", "t"}, tc.args...), file)
		if code := run(args, &bytes.Buffer{}, &errw); code != 2 || !strings.Contains(errw.String(), tc.want) {
			t.Errorf("%v: exit %d, stderr %q, want 2 and %q", tc.args, code, errw.String(), tc.want)
		}
	}
}
