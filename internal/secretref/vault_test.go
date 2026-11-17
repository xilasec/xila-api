package secretref

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestVaultStaticTokenKV2(t *testing.T) {
	var gotToken, gotPath, gotNamespace string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Vault-Token")
		gotPath = r.URL.Path
		gotNamespace = r.Header.Get("X-Vault-Namespace")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"data":     map[string]any{"jwt": "s3cr3t", "other": "x"},
				"metadata": map[string]any{"version": 1},
			},
		})
	}))
	defer srv.Close()

	t.Setenv("VAULT_ADDR", srv.URL)
	t.Setenv("VAULT_TOKEN", "root-token")
	t.Setenv("VAULT_NAMESPACE", "my-ns")

	r := NewResolver()
	v, err := r.Resolve(context.Background(), "vault://kv/data/xila#jwt")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v != "s3cr3t" {
		t.Errorf("value = %q, want s3cr3t", v)
	}
	if gotToken != "root-token" {
		t.Errorf("X-Vault-Token = %q", gotToken)
	}
	if gotPath != "/v1/kv/data/xila" {
		t.Errorf("path = %q", gotPath)
	}
	if gotNamespace != "my-ns" {
		t.Errorf("X-Vault-Namespace = %q", gotNamespace)
	}
}

func TestVaultKV1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"jwt": "kv1-value"},
		})
	}))
	defer srv.Close()

	t.Setenv("VAULT_ADDR", srv.URL)
	t.Setenv("VAULT_TOKEN", "root-token")

	r := NewResolver()
	v, err := r.Resolve(context.Background(), "vault://secret/xila#jwt")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v != "kv1-value" {
		t.Errorf("value = %q, want kv1-value", v)
	}
}

// A secret with exactly one field doesn't need #key.
func TestVaultSingleFieldNoKeyRequired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"data": map[string]any{"only-field": "the-value"}},
		})
	}))
	defer srv.Close()

	t.Setenv("VAULT_ADDR", srv.URL)
	t.Setenv("VAULT_TOKEN", "root-token")

	r := NewResolver()
	v, err := r.Resolve(context.Background(), "vault://kv/data/single")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v != "the-value" {
		t.Errorf("value = %q, want the-value", v)
	}
}

// Without #key, a secret with more than one field is ambiguous.
func TestVaultMultiFieldRequiresKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"data": map[string]any{"a": "1", "b": "2"}},
		})
	}))
	defer srv.Close()

	t.Setenv("VAULT_ADDR", srv.URL)
	t.Setenv("VAULT_TOKEN", "root-token")

	r := NewResolver()
	if _, err := r.Resolve(context.Background(), "vault://kv/data/multi"); err == nil {
		t.Fatal("expected an error: #key is required for a multi-field secret")
	}
}

func TestVaultTokenFromFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "file-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": map[string]any{"k": "v"}}})
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VAULT_ADDR", srv.URL)
	t.Setenv("VAULT_TOKEN_FILE", path)

	r := NewResolver()
	v, err := r.Resolve(context.Background(), "vault://kv/data/x#k")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v != "v" {
		t.Errorf("value = %q", v)
	}
}

func TestVaultKubernetesLogin(t *testing.T) {
	var gotLoginBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/kubernetes/login":
			_ = json.NewDecoder(r.Body).Decode(&gotLoginBody)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"auth": map[string]any{"client_token": "k8s-issued-token"},
			})
		case "/v1/kv/data/x":
			if r.Header.Get("X-Vault-Token") != "k8s-issued-token" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": map[string]any{"k": "v"}}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	jwtPath := filepath.Join(t.TempDir(), "sa-token")
	if err := os.WriteFile(jwtPath, []byte("the-pod-jwt"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("VAULT_ADDR", srv.URL)
	t.Setenv("VAULT_AUTH", "kubernetes")
	t.Setenv("VAULT_K8S_ROLE", "xila")

	r := NewResolver()
	r.VaultK8STokenPath = jwtPath
	v, err := r.Resolve(context.Background(), "vault://kv/data/x#k")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v != "v" {
		t.Errorf("value = %q", v)
	}
	if gotLoginBody["role"] != "xila" || gotLoginBody["jwt"] != "the-pod-jwt" {
		t.Errorf("login body = %+v", gotLoginBody)
	}
}

func TestVaultAppRoleLogin(t *testing.T) {
	var gotLoginBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/approle/login":
			_ = json.NewDecoder(r.Body).Decode(&gotLoginBody)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"auth": map[string]any{"client_token": "approle-issued-token"},
			})
		case "/v1/kv/data/x":
			if r.Header.Get("X-Vault-Token") != "approle-issued-token" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": map[string]any{"k": "v"}}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	t.Setenv("VAULT_ADDR", srv.URL)
	t.Setenv("VAULT_AUTH", "approle")
	t.Setenv("VAULT_ROLE_ID", "role-id-123")
	t.Setenv("VAULT_SECRET_ID", "secret-id-456")

	r := NewResolver()
	v, err := r.Resolve(context.Background(), "vault://kv/data/x#k")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v != "v" {
		t.Errorf("value = %q", v)
	}
	if gotLoginBody["role_id"] != "role-id-123" || gotLoginBody["secret_id"] != "secret-id-456" {
		t.Errorf("login body = %+v", gotLoginBody)
	}
}

// A cached token that stops working (403) triggers exactly one re-login, and
// the retry succeeds with the new token.
func TestVaultReLoginOn403(t *testing.T) {
	logins := 0
	currentToken := "stale-token"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/approle/login":
			logins++
			currentToken = "fresh-token"
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"auth": map[string]any{"client_token": currentToken},
			})
		case "/v1/kv/data/x":
			if r.Header.Get("X-Vault-Token") != currentToken {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": map[string]any{"k": "v"}}})
		}
	}))
	defer srv.Close()

	t.Setenv("VAULT_ADDR", srv.URL)
	t.Setenv("VAULT_AUTH", "approle")
	t.Setenv("VAULT_ROLE_ID", "r")
	t.Setenv("VAULT_SECRET_ID", "s")

	r := NewResolver()
	// Seed the resolver's cached (now-stale) token by logging in once, then
	// force it stale to simulate a token that expired since the last tick.
	if _, err := r.Resolve(context.Background(), "vault://kv/data/x#k"); err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	// vault.go's backend caches the token internally; invalidate it the same
	// way a revoked token would show up: the server now requires a different
	// token than what's cached, forcing the 403 retry path.
	currentToken = "rotated-server-side"

	v, err := r.Resolve(context.Background(), "vault://kv/data/x#k")
	if err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	if v != "v" {
		t.Errorf("value = %q", v)
	}
	if logins < 2 {
		t.Errorf("logins = %d, want at least 2 (initial + re-login after 403)", logins)
	}
}

func TestVaultNoAuthConfigured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	t.Setenv("VAULT_ADDR", srv.URL)

	r := NewResolver()
	if _, err := r.Resolve(context.Background(), "vault://kv/data/x#k"); err == nil {
		t.Fatal("expected an error: no VAULT_TOKEN and no VAULT_AUTH")
	}
}

func TestVaultMissingAddr(t *testing.T) {
	t.Setenv("VAULT_ADDR", "")
	r := NewResolver()
	if _, err := r.Resolve(context.Background(), "vault://kv/data/x#k"); err == nil {
		t.Fatal("expected an error: VAULT_ADDR is not set")
	}
}

func TestVaultBackendDown(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	t.Setenv("VAULT_ADDR", "http://"+addr)
	t.Setenv("VAULT_TOKEN", "root")

	r := NewResolver()
	if _, err := r.Resolve(context.Background(), "vault://kv/data/x#k"); err == nil {
		t.Fatal("expected an error reaching an unreachable Vault")
	}
}
