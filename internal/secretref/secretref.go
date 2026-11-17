// Package secretref resolves a secret setting's value when it is a reference
// to a native secrets manager, instead of a literal value: `aws-sm://...`
// (AWS Secrets Manager), `gcp-sm://...` (GCP Secret Manager), `vault://...`
// (HashiCorp/OpenBao Vault) or `azure-kv://...` (Azure Key Vault).
//
// This is operator infrastructure, resolved by internal/config before
// internal/netguard's outbound policy exists (the policy itself can be
// supplied by a secret setting), so backend calls here deliberately do not go
// through netguard.
package secretref

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"golang.org/x/oauth2"
)

// Recognized reference schemes.
const (
	schemeAWSSM   = "aws-sm"
	schemeGCPSM   = "gcp-sm"
	schemeVault   = "vault"
	schemeAzureKV = "azure-kv"
)

// ref is one parsed reference. Parsing is manual (not url.Parse) because an
// AWS Secrets Manager ARN contains colons that url.Parse treats as a port
// separator in the authority.
type ref struct {
	scheme string
	path   string     // everything after "scheme://", before "?" or "#"
	key    string     // the "#key" fragment, if any
	query  url.Values // the "?..." query, if any (aws-sm only)
}

// IsRef reports whether v is one of the recognized reference schemes. A
// value with no known scheme is used literally, exactly as today.
func IsRef(v string) bool {
	_, ok := parse(v)
	return ok
}

func parse(v string) (ref, bool) {
	scheme, rest, ok := splitScheme(v)
	if !ok {
		return ref{}, false
	}
	main, key, _ := strings.Cut(rest, "#")
	path, rawQuery, _ := strings.Cut(main, "?")
	r := ref{scheme: scheme, path: path, key: key}
	if rawQuery != "" {
		if q, err := url.ParseQuery(rawQuery); err == nil {
			r.query = q
		}
	}
	return r, true
}

func splitScheme(v string) (scheme, rest string, ok bool) {
	for _, s := range [...]string{schemeAWSSM, schemeGCPSM, schemeVault, schemeAzureKV} {
		if p := s + "://"; strings.HasPrefix(v, p) {
			return s, strings.TrimPrefix(v, p), true
		}
	}
	return "", "", false
}

// Resolver resolves references, lazily building and caching a client per
// backend (AWS/GCP/Azure credentials, a Vault login) on first use, reused on
// every later call — important for periodic refresh (config.Secrets),
// which would otherwise rebuild a client, or log back in to Vault, on every
// tick.
//
// A Resolver is safe for concurrent use. The zero value is not ready to use;
// construct one with NewResolver.
type Resolver struct {
	aws   *awsBackend
	gcp   *gcpBackend
	vault *vaultBackend
	azure *azureBackend

	// Overrides for tests. Set them right after NewResolver, before the
	// first Resolve call — backends are built lazily, so a later change has
	// no effect once a backend has already been used.
	GCPBaseURL        string                 // default: https://secretmanager.googleapis.com
	GCPTokenSource    oauth2.TokenSource     // default: Application Default Credentials
	AzureCredential   azcore.TokenCredential // default: azidentity.NewDefaultAzureCredential
	AzureBaseURL      string                 // non-empty overrides the vault host entirely
	VaultK8STokenPath string                 // default: /var/run/secrets/kubernetes.io/serviceaccount/token
}

// NewResolver constructs a ready-to-use Resolver.
func NewResolver() *Resolver {
	return &Resolver{
		aws:   &awsBackend{},
		gcp:   &gcpBackend{},
		vault: &vaultBackend{},
		azure: &azureBackend{},
	}
}

// Default is the process-wide Resolver used by internal/config: one for the
// initial load and every later refresh tick, so a backend's client (and a
// Vault login token) is built once per process, not once per tick.
var Default = NewResolver()

// Resolve returns v's resolved value. v must be a reference (IsRef(v));
// callers are expected to check that first and use literal values as-is.
// The returned error never contains the secret value, only the reference's
// scheme and path, so it is safe to log or wrap into a config error.
func (r *Resolver) Resolve(ctx context.Context, v string) (string, error) {
	rf, ok := parse(v)
	if !ok {
		return "", fmt.Errorf("not a secret reference")
	}
	var (
		val string
		err error
	)
	switch rf.scheme {
	case schemeAWSSM:
		val, err = r.aws.resolve(ctx, rf)
	case schemeGCPSM:
		val, err = r.gcp.resolve(ctx, rf, r.GCPTokenSource, r.GCPBaseURL)
	case schemeVault:
		val, err = r.vault.resolve(ctx, rf, r.VaultK8STokenPath)
	case schemeAzureKV:
		val, err = r.azure.resolve(ctx, rf, r.AzureCredential, r.AzureBaseURL)
	default:
		return "", fmt.Errorf("unknown secret reference scheme %q", rf.scheme)
	}
	if err != nil {
		return "", fmt.Errorf("%s://%s: %w", rf.scheme, rf.path, err)
	}
	return val, nil
}

// jsonField selects one field from a secret value that is itself a JSON
// object (the AWS Secrets Manager / GCP Secret Manager convention of storing
// several named values in one secret). An empty key returns raw unchanged —
// the whole secret is used literally, as it is for a single-value secret.
func jsonField(raw, key string) (string, error) {
	if key == "" {
		return raw, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return "", fmt.Errorf("value is not a JSON object, cannot select key %q", key)
	}
	v, ok := m[key]
	if !ok {
		return "", fmt.Errorf("key %q not found", key)
	}
	return decodeJSONString(v), nil
}

// decodeJSONString renders a JSON value as a plain string: unquoted if it was
// a JSON string, its raw text otherwise.
func decodeJSONString(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return strings.TrimSpace(string(raw))
}

// onceValue builds a value of type T exactly once, synchronized, and caches
// it (or the error) for every later call. Used by each backend to build its
// client/credential lazily and share it across resolves and refresh ticks.
type onceValue[T any] struct {
	mu    sync.Mutex
	built bool
	val   T
	err   error
}

func (o *onceValue[T]) get(build func() (T, error)) (T, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.built {
		o.val, o.err = build()
		o.built = true
	}
	return o.val, o.err
}
