package secretref

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// fakeAzureCredential always returns tok, bypassing DefaultAzureCredential.
type fakeAzureCredential struct{ tok string }

func (f fakeAzureCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: f.tok, ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func TestAzureKeyVaultLiteral(t *testing.T) {
	cred := fakeAzureCredential{tok: "azure-bearer-token"}
	var gotAuth, gotPath, gotAPIVersion string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotAPIVersion = r.URL.Query().Get("api-version")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"value": "a-plain-secret", "id": r.URL.Path})
	}))
	defer srv.Close()

	r := NewResolver()
	r.AzureCredential = cred
	r.AzureBaseURL = srv.URL
	v, err := r.Resolve(context.Background(), "azure-kv://myvault/my-secret")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v != "a-plain-secret" {
		t.Errorf("value = %q", v)
	}
	if gotAuth != "Bearer azure-bearer-token" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotPath != "/secrets/my-secret" {
		t.Errorf("path = %q", gotPath)
	}
	if gotAPIVersion != "7.5" {
		t.Errorf("api-version = %q", gotAPIVersion)
	}
}

func TestAzureKeyVaultVersion(t *testing.T) {
	cred := fakeAzureCredential{tok: "tok"}
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"value": "v"})
	}))
	defer srv.Close()

	r := NewResolver()
	r.AzureCredential = cred
	r.AzureBaseURL = srv.URL
	if _, err := r.Resolve(context.Background(), "azure-kv://myvault/my-secret/abcdef0123"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if gotPath != "/secrets/my-secret/abcdef0123" {
		t.Errorf("path = %q", gotPath)
	}
}

func TestAzureKeyVaultMalformedPath(t *testing.T) {
	r := NewResolver()
	r.AzureCredential = fakeAzureCredential{tok: "tok"}
	if _, err := r.Resolve(context.Background(), "azure-kv://justonevaultname"); err == nil {
		t.Fatal("expected an error for a path without a secret name")
	}
}

func TestAzureKeyVaultNotFound(t *testing.T) {
	cred := fakeAzureCredential{tok: "tok"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	r := NewResolver()
	r.AzureCredential = cred
	r.AzureBaseURL = srv.URL
	if _, err := r.Resolve(context.Background(), "azure-kv://myvault/missing"); err == nil {
		t.Fatal("expected an error for a secret the vault doesn't have")
	}
}

func TestAzureKeyVaultBackendDown(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	r := NewResolver()
	r.AzureCredential = fakeAzureCredential{tok: "tok"}
	r.AzureBaseURL = "http://" + addr
	if _, err := r.Resolve(context.Background(), "azure-kv://myvault/my-secret"); err == nil {
		t.Fatal("expected an error reaching an unreachable vault")
	}
}
