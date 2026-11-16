package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

const gitlabProject = "acme/widgets"

// gitlabNodes is shaped like the worked GraphQL example in GitLab's own docs
// (vulnerability_findings.md's "Replace REST API with GraphQL" section) and
// the `Vulnerability` object's field set
// (ee/app/graphql/types/vulnerability_type.rb).
var gitlabNodes = []string{
	`{"id": "gid://gitlab/Vulnerability/1", "title": "Deserialization of Untrusted Data",
	  "description": "A possible escalation to RCE.", "state": "DETECTED", "severity": "CRITICAL",
	  "reportType": "DEPENDENCY_SCANNING", "webUrl": "https://gitlab.example.com/acme/widgets/-/security/vulnerabilities/1",
	  "dismissalReason": null,
	  "identifiers": [{"externalType": "cve", "externalId": "CVE-2022-32224", "name": "CVE-2022-32224"}],
	  "location": {"file": "Gemfile.lock", "dependency": {"package": {"name": "activerecord"}, "version": "5.0.0"}}}`,
	`{"id": "gid://gitlab/Vulnerability/2", "title": "SQL Injection", "description": "User input reaches a query.",
	  "state": "CONFIRMED", "severity": "HIGH", "reportType": "SAST",
	  "webUrl": "https://gitlab.example.com/acme/widgets/-/security/vulnerabilities/2",
	  "identifiers": [{"externalType": "cwe", "externalId": "89", "name": "CWE-89"}],
	  "location": {"file": "app/db.rb", "startLine": 42}}`,
	`{"id": "gid://gitlab/Vulnerability/3", "title": "Outdated base image", "description": "CVE in base image.",
	  "state": "DISMISSED", "severity": "MEDIUM", "reportType": "CONTAINER_SCANNING",
	  "webUrl": "https://gitlab.example.com/acme/widgets/-/security/vulnerabilities/3",
	  "dismissalReason": "MITIGATING_CONTROL",
	  "identifiers": [{"externalType": "cve", "externalId": "CVE-2021-1111", "name": "CVE-2021-1111"}],
	  "location": {"image": "registry.example.com/acme/widgets:latest", "operatingSystem": "alpine:3.15"}}`,
}

func fakeGitLab(t *testing.T, project string, nodes []string, pageSize int) (*httptest.Server, *int) {
	t.Helper()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v4/projects/"+project {
			if r.Header.Get("PRIVATE-TOKEN") != "glpat-key" {
				http.Error(w, `{"message":"401 Unauthorized"}`, http.StatusUnauthorized)
				return
			}
			fmt.Fprint(w, `{"name":"widgets","name_with_namespace":"Acme / Widgets"}`)
			return
		}
		if r.URL.Path != "/api/graphql" {
			http.NotFound(w, r)
			return
		}
		calls++
		if r.Header.Get("Authorization") != "Bearer glpat-key" {
			fmt.Fprint(w, `{"errors":[{"message":"401 Unauthorized"}]}`)
			return
		}
		var req struct {
			Variables struct {
				FullPath string  `json:"fullPath"`
				After    *string `json:"after"`
			} `json:"variables"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Variables.FullPath != project {
			http.Error(w, "wrong project", http.StatusBadRequest)
			return
		}
		start := 0
		if req.Variables.After != nil {
			fmt.Sscanf(*req.Variables.After, "%d", &start)
		}
		end := min(start+pageSize, len(nodes))
		hasNext := end < len(nodes)
		fmt.Fprintf(w, `{"data":{"project":{"vulnerabilities":{"pageInfo":{"hasNextPage":%v,"endCursor":"%d"},"nodes":[%s]}}}}`,
			hasNext, end, strings.Join(nodes[start:end], ","))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func newGitLab(base, project string) *gitLab {
	return &gitLab{base: base, project: project, token: "glpat-key", hc: http.DefaultClient, pageSize: 2}
}

func TestGitLabFetch(t *testing.T) {
	srv, calls := fakeGitLab(t, gitlabProject, gitlabNodes, 2)
	fs, err := newGitLab(srv.URL, gitlabProject).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if *calls != 2 {
		t.Fatalf("graphql requests = %d, want 2 pages", *calls)
	}
	if len(fs) != 3 {
		t.Fatalf("findings = %d, want 3", len(fs))
	}

	dep := fs[0]
	if dep.Category != domain.CategorySCA || dep.Severity != domain.SeverityCritical || len(dep.CVE) != 1 ||
		dep.CVE[0] != "CVE-2022-32224" || dep.PackageName != "activerecord" || dep.PackageVersion != "5.0.0" ||
		dep.FilePath != "Gemfile.lock" {
		t.Errorf("dependency scanning = %+v", dep)
	}
	if _, ok := dep.Metadata["remote_triage"]; ok {
		t.Error("DETECTED vulnerability produced a remote verdict")
	}

	sast := fs[1]
	if sast.Category != domain.CategorySAST || sast.Severity != domain.SeverityHigh || sast.CWE == nil || *sast.CWE != 89 ||
		sast.FilePath != "app/db.rb" || sast.Line == nil || *sast.Line != 42 {
		t.Errorf("sast = %+v", sast)
	}
	if sast.Metadata["remote_triage"] != string(domain.FindingConfirmed) {
		t.Errorf("confirmed vulnerability metadata = %v", sast.Metadata)
	}

	container := fs[2]
	if container.Category != domain.CategoryContainer || container.PackageName != "registry.example.com/acme/widgets:latest" {
		t.Errorf("container scanning = %+v", container)
	}
	if container.Metadata["remote_triage"] != string(domain.FindingWontFix) ||
		container.Metadata["remote_triage_reason"] != "GitLab dismissal: mitigating_control" {
		t.Errorf("dismissed vulnerability metadata = %v", container.Metadata)
	}

	if name, err := newGitLab(srv.URL, gitlabProject).Check(context.Background()); err != nil || name != "Acme / Widgets" {
		t.Errorf("check = %q, %v", name, err)
	}
}

func TestGitLabAuthFailure(t *testing.T) {
	srv, _ := fakeGitLab(t, gitlabProject, gitlabNodes, 10)
	bad := newGitLab(srv.URL, gitlabProject)
	bad.token = "wrong"
	if _, err := bad.Fetch(context.Background()); !errors.As(err, new(RemoteError)) || !strings.Contains(err.Error(), "401") {
		t.Fatalf("bad token err = %v, want a RemoteError mentioning 401", err)
	}
	if _, err := bad.Check(context.Background()); err == nil {
		t.Error("check passed with a bad token")
	}
}

func TestGitLabRateLimit(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	_, err := newGitLab(srv.URL, gitlabProject).Fetch(context.Background())
	var rerr RemoteError
	if !errors.As(err, &rerr) || !strings.Contains(err.Error(), "429") {
		t.Fatalf("err = %v, want a RemoteError mentioning 429", err)
	}
	if attempts != maxRateLimitRetries+1 {
		t.Fatalf("attempts = %d, want %d", attempts, maxRateLimitRetries+1)
	}
}
