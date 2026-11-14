package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// federatedAPI accepts exactly one identity token at /auth/token and the
// resulting session on uploads.
func federatedAPI(t *testing.T, acceptSubject string) (*httptest.Server, *[]string) {
	t.Helper()
	var seen []string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != grantTokenExchange || r.Form.Get("subject_token_type") != tokenTypeJWT ||
			r.Form.Get("subject_token") != acceptSubject {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"no binding matches the token's claims"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"session-jwt","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":900}`))
	})
	mux.HandleFunc("/api/v1/projects/", func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.Path+" auth="+r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"scan-1","status":"completed"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &seen
}

func clearCIEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"XILA_TOKEN", "XILA_OIDC_TOKEN", "XILA_ID_TOKEN", "XILA_OIDC_AUDIENCE",
		"ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"} {
		t.Setenv(k, "")
	}
}

func report(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "trivy.json")
	if err := os.WriteFile(p, []byte(`{"Results":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestUploadExchangesGitHubActionsToken(t *testing.T) {
	clearCIEnv(t)
	var gotAudience, gotAuth string
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAudience, gotAuth = r.URL.Query().Get("audience"), r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"value":"gh-id-token"}`))
	}))
	t.Cleanup(gh.Close)
	srv, seen := federatedAPI(t, "gh-id-token")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", gh.URL+"/token?api-version=2.0")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "runtime-secret")
	t.Setenv("XILA_OIDC_AUDIENCE", "https://xila.example")

	var out, errw bytes.Buffer
	if code := run([]string{"upload", "--url", srv.URL, "--project", "p1", "--scanner", "trivy", report(t)}, &out, &errw); code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, errw.String())
	}
	if gotAudience != "https://xila.example" || gotAuth != "Bearer runtime-secret" {
		t.Errorf("GitHub token request: audience %q auth %q", gotAudience, gotAuth)
	}
	if len(*seen) != 1 || !strings.HasSuffix((*seen)[0], "auth=Bearer session-jwt") {
		t.Errorf("upload used %v, want the exchanged session", *seen)
	}
}

func TestGateExchangesGitLabIDToken(t *testing.T) {
	clearCIEnv(t)
	srv, seen := federatedAPI(t, "gl-id-token")
	t.Setenv("XILA_ID_TOKEN", "gl-id-token")
	var out, errw bytes.Buffer
	run([]string{"gate", "--url", srv.URL, "--project", "p1"}, &out, &errw)
	if len(*seen) != 1 || !strings.HasSuffix((*seen)[0], "auth=Bearer session-jwt") {
		t.Errorf("gate used %v (stderr %s), want the exchanged session", *seen, errw.String())
	}
}

func TestExplicitTokenWinsOverFederation(t *testing.T) {
	clearCIEnv(t)
	srv, seen := federatedAPI(t, "never")
	t.Setenv("XILA_ID_TOKEN", "gl-id-token")
	var out, errw bytes.Buffer
	if code := run([]string{"upload", "--url", srv.URL, "--token", "xila_k", "--project", "p1", "--scanner", "trivy", report(t)}, &out, &errw); code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, errw.String())
	}
	if !strings.HasSuffix((*seen)[0], "auth=Bearer xila_k") {
		t.Errorf("upload used %v, want the API token", *seen)
	}
}

func TestFederationFailuresExitTwo(t *testing.T) {
	clearCIEnv(t)
	srv, seen := federatedAPI(t, "good")

	var out, errw bytes.Buffer
	if code := run([]string{"upload", "--url", srv.URL, "--project", "p1", "--scanner", "trivy", report(t)}, &out, &errw); code != 2 ||
		!strings.Contains(errw.String(), "id-token: write") {
		t.Errorf("no identity: exit %d, stderr %q", code, errw.String())
	}

	errw.Reset()
	if code := run([]string{"upload", "--url", srv.URL, "--oidc-token", "bad", "--project", "p1", "--scanner", "trivy", report(t)}, &out, &errw); code != 2 ||
		!strings.Contains(errw.String(), "no binding matches") {
		t.Errorf("refused exchange: exit %d, stderr %q", code, errw.String())
	}
	if len(*seen) != 0 {
		t.Errorf("uploaded without a session: %v", *seen)
	}
}
