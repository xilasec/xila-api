package secretref

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"hash/crc32"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// fakeTokenSource always returns tok, bypassing Application Default
// Credentials.
type fakeTokenSource struct{ tok string }

func (f fakeTokenSource) Token() (*oauth2.Token, error) {
	return &oauth2.Token{AccessToken: f.tok, Expiry: time.Now().Add(time.Hour)}, nil
}

func gcpFakeServer(t *testing.T, wantAuth string, payload []byte) *httptest.Server {
	t.Helper()
	crc := crc32.Checksum(payload, crc32.MakeTable(crc32.Castagnoli))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+wantAuth {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Google's Secret Manager REST API encodes dataCrc32c as a decimal
		// string (it is a protobuf int64 field).
		resp := map[string]any{
			"name": r.URL.Path,
			"payload": map[string]any{
				"data":       base64.StdEncoding.EncodeToString(payload),
				"dataCrc32c": strconv.FormatUint(uint64(crc), 10),
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestGCPSecretManagerLiteral(t *testing.T) {
	ts := fakeTokenSource{tok: "gcp-bearer-token"}
	srv := gcpFakeServer(t, ts.tok, []byte("a-plain-secret"))

	r := NewResolver()
	r.GCPBaseURL = srv.URL
	r.GCPTokenSource = ts

	v, err := r.Resolve(context.Background(), "gcp-sm://projects/myproj/secrets/jwt")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v != "a-plain-secret" {
		t.Errorf("value = %q", v)
	}
}

func TestGCPSecretManagerExplicitVersion(t *testing.T) {
	ts := fakeTokenSource{tok: "tok"}
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		payload := []byte("v")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"payload": map[string]any{"data": base64.StdEncoding.EncodeToString(payload)},
		})
	}))
	defer srv.Close()

	r := NewResolver()
	r.GCPBaseURL = srv.URL
	r.GCPTokenSource = ts
	if _, err := r.Resolve(context.Background(), "gcp-sm://projects/p/secrets/s/versions/3"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if gotPath != "/v1/projects/p/secrets/s/versions/3:access" {
		t.Errorf("path = %q", gotPath)
	}
}

func TestGCPSecretManagerDefaultVersionLatest(t *testing.T) {
	ts := fakeTokenSource{tok: "tok"}
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"payload": map[string]any{"data": base64.StdEncoding.EncodeToString([]byte("v"))},
		})
	}))
	defer srv.Close()

	r := NewResolver()
	r.GCPBaseURL = srv.URL
	r.GCPTokenSource = ts
	if _, err := r.Resolve(context.Background(), "gcp-sm://projects/p/secrets/s"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if gotPath != "/v1/projects/p/secrets/s/versions/latest:access" {
		t.Errorf("path = %q, want .../versions/latest:access", gotPath)
	}
}

func TestGCPSecretManagerJSONKey(t *testing.T) {
	ts := fakeTokenSource{tok: "tok"}
	srv := gcpFakeServer(t, ts.tok, []byte(`{"jwt":"s3cr3t","other":"x"}`))

	r := NewResolver()
	r.GCPBaseURL = srv.URL
	r.GCPTokenSource = ts
	v, err := r.Resolve(context.Background(), "gcp-sm://projects/p/secrets/s#jwt")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v != "s3cr3t" {
		t.Errorf("value = %q, want s3cr3t", v)
	}
}

func TestGCPSecretManagerChecksumMismatch(t *testing.T) {
	ts := fakeTokenSource{tok: "tok"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"payload": map[string]any{
				"data":       base64.StdEncoding.EncodeToString([]byte("v")),
				"dataCrc32c": "1", // wrong on purpose
			},
		})
	}))
	defer srv.Close()

	r := NewResolver()
	r.GCPBaseURL = srv.URL
	r.GCPTokenSource = ts
	if _, err := r.Resolve(context.Background(), "gcp-sm://projects/p/secrets/s"); err == nil {
		t.Fatal("expected a checksum mismatch error")
	}
}

func TestGCPSecretManagerBadPath(t *testing.T) {
	r := NewResolver()
	r.GCPTokenSource = fakeTokenSource{tok: "tok"}
	if _, err := r.Resolve(context.Background(), "gcp-sm://not-a-valid-path"); err == nil {
		t.Fatal("expected an error for a malformed resource path")
	}
}

func TestGCPSecretManagerBackendDown(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close() // closed: connections are refused immediately

	r := NewResolver()
	r.GCPBaseURL = "http://" + addr
	r.GCPTokenSource = fakeTokenSource{tok: "tok"}
	if _, err := r.Resolve(context.Background(), "gcp-sm://projects/p/secrets/s"); err == nil {
		t.Fatal("expected an error reaching an unreachable backend")
	}
}
