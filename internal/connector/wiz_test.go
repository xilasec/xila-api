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

// wizNodes mirror the vulnerabilityFindings fields reproduced in Wiz's
// third-party integration guides (see wiz.go's doc comment for the exact
// sources); Wiz's own interactive GraphQL reference requires an authenticated
// tenant to browse.
var wizNodes = []string{
	`{"id": "f-1", "name": "CVE-2024-12345", "severity": "CRITICAL", "status": "OPEN",
	  "vulnerableAsset": {"id": "a-1", "name": "web-prod-01", "type": "VIRTUAL_MACHINE", "providerUniqueId": "i-0abc"}}`,
	`{"id": "f-2", "name": "Publicly exposed storage bucket", "severity": "HIGH", "status": "REJECTED",
	  "vulnerableAsset": {"id": "a-2", "name": "logs-bucket", "type": "BUCKET", "providerUniqueId": "logs-bucket"}}`,
	`{"id": "f-3", "name": "CVE-2023-9999", "severity": "MEDIUM", "status": "IN_PROGRESS",
	  "vulnerableAsset": {"id": "a-3", "name": "api-container", "type": "CONTAINER_IMAGE", "providerUniqueId": "sha256:abc"}}`,
}

func fakeWiz(t *testing.T, nodes []string, pageSize int) (*httptest.Server, *int) {
	t.Helper()
	tokenCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			tokenCalls++
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			if r.Form.Get("client_id") != "wiz-client" || r.Form.Get("client_secret") != "wiz-secret" ||
				r.Form.Get("grant_type") != "client_credentials" {
				http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
				return
			}
			fmt.Fprint(w, `{"access_token":"wiz-access-token","token_type":"Bearer","expires_in":3600}`)
		case "/graphql":
			if r.Header.Get("Authorization") != "Bearer wiz-access-token" {
				fmt.Fprint(w, `{"errors":[{"message":"401 Unauthorized"}]}`)
				return
			}
			var req struct {
				Variables struct {
					After *string `json:"after"`
				} `json:"variables"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			start := 0
			if req.Variables.After != nil {
				fmt.Sscanf(*req.Variables.After, "%d", &start)
			}
			end := min(start+pageSize, len(nodes))
			hasNext := end < len(nodes)
			fmt.Fprintf(w, `{"data":{"vulnerabilityFindings":{"pageInfo":{"hasNextPage":%v,"endCursor":"%d"},"nodes":[%s]}}}`,
				hasNext, end, strings.Join(nodes[start:end], ","))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &tokenCalls
}

func newWiz(base string) *wiz {
	return &wiz{base: base + "/graphql", authURL: base + "/oauth/token", clientID: "wiz-client",
		clientSecret: "wiz-secret", hc: http.DefaultClient, pageSize: 2}
}

func TestWizFetch(t *testing.T) {
	srv, tokenCalls := fakeWiz(t, wizNodes, 2)
	fs, err := newWiz(srv.URL).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if *tokenCalls != 1 {
		t.Fatalf("oauth token calls = %d, want 1 (reused across pages)", *tokenCalls)
	}
	if len(fs) != 3 {
		t.Fatalf("findings = %d, want 3", len(fs))
	}

	vm := fs[0]
	if vm.Category != domain.CategoryCloud || vm.Severity != domain.SeverityCritical || len(vm.CVE) != 1 ||
		vm.CVE[0] != "CVE-2024-12345" || vm.PackageName != "web-prod-01" {
		t.Errorf("vm finding = %+v", vm)
	}
	if _, ok := vm.Metadata["remote_triage"]; ok {
		t.Error("open finding produced a remote verdict")
	}

	bucket := fs[1]
	if bucket.Metadata["remote_triage"] != string(domain.FindingFalsePositive) || bucket.Metadata["remote_triage_reason"] != "Wiz: rejected" {
		t.Errorf("rejected finding metadata = %v", bucket.Metadata)
	}

	container := fs[2]
	if container.Category != domain.CategoryContainer {
		t.Errorf("container asset category = %s, want container", container.Category)
	}

	if name, err := newWiz(srv.URL).Check(context.Background()); err != nil || !strings.Contains(name, "wiz-client") {
		t.Errorf("check = %q, %v", name, err)
	}
}

func TestWizBadCredentials(t *testing.T) {
	srv, _ := fakeWiz(t, wizNodes, 10)
	bad := newWiz(srv.URL)
	bad.clientSecret = "wrong"
	if _, err := bad.Fetch(context.Background()); !errors.As(err, new(RemoteError)) || !strings.Contains(err.Error(), "401") {
		t.Fatalf("bad client secret err = %v, want a 401 RemoteError", err)
	}
}

func TestWizRateLimitOnTokenEndpoint(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	_, err := newWiz(srv.URL).Fetch(context.Background())
	var rerr RemoteError
	if !errors.As(err, &rerr) || !strings.Contains(err.Error(), "429") {
		t.Fatalf("err = %v, want a RemoteError mentioning 429", err)
	}
	if attempts != maxRateLimitRetries+1 {
		t.Fatalf("attempts = %d, want %d", attempts, maxRateLimitRetries+1)
	}
}

func TestParseWizCredentials(t *testing.T) {
	if _, err := parseWizCredentials(`{"client_id":"a","client_secret":"b"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := parseWizCredentials(`not json`); !errors.As(err, new(ValidationError)) {
		t.Errorf("invalid json err = %v, want ValidationError", err)
	}
	if _, err := parseWizCredentials(`{"client_id":"a"}`); !errors.As(err, new(ValidationError)) {
		t.Errorf("missing secret err = %v, want ValidationError", err)
	}
}
