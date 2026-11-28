package secretref

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// defaultVaultK8STokenPath is where Kubernetes projects the pod's service
// account token.
const defaultVaultK8STokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token" //nolint:gosec // G101: the service-account token path, not a token

// vaultBackend resolves vault:// references over plain HTTPS. The token
// comes from VAULT_TOKEN(_FILE), or a login (VAULT_AUTH=kubernetes or
// approle) whose result is cached and reused — refreshed only on a 403,
// which is the signal the cached token stopped working.
type vaultBackend struct {
	client onceValue[*http.Client]

	mu    sync.Mutex
	token string // cached static token or last successful login
}

func (b *vaultBackend) httpClient() (*http.Client, error) {
	return b.client.get(func() (*http.Client, error) {
		tr := http.DefaultTransport.(*http.Transport).Clone() //nolint:errcheck,forcetypeassert // net/http's DefaultTransport is always *http.Transport; nothing in this binary replaces it
		if ca := os.Getenv("VAULT_CACERT"); ca != "" {
			pem, err := os.ReadFile(filepath.Clean(ca)) //nolint:gosec // G703: VAULT_CACERT is operator configuration
			if err != nil {
				return nil, fmt.Errorf("VAULT_CACERT: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, errors.New("VAULT_CACERT: no PEM certificate found")
			}
			tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		}
		return &http.Client{Transport: tr}, nil
	})
}

func (b *vaultBackend) resolve(ctx context.Context, r ref, k8sTokenPathOverride string) (string, error) {
	addr := strings.TrimRight(os.Getenv("VAULT_ADDR"), "/")
	if addr == "" {
		return "", errors.New("VAULT_ADDR is not set")
	}
	client, err := b.httpClient()
	if err != nil {
		return "", err
	}

	token, err := b.currentToken(ctx, client, addr, k8sTokenPathOverride)
	if err != nil {
		return "", err
	}
	body, status, err := b.readSecret(ctx, client, addr, token, r.path)
	if err != nil {
		return "", err
	}
	if status == http.StatusForbidden {
		// The cached token stopped working (expired, revoked): log in again
		// once and retry.
		token, err = b.login(ctx, client, addr, k8sTokenPathOverride)
		if err != nil {
			return "", fmt.Errorf("re-login after 403: %w", err)
		}
		b.mu.Lock()
		b.token = token
		b.mu.Unlock()
		body, status, err = b.readSecret(ctx, client, addr, token, r.path)
		if err != nil {
			return "", err
		}
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("%s: HTTP %d", r.path, status)
	}
	fields, err := vaultFields(body)
	if err != nil {
		return "", err
	}
	return selectVaultField(fields, r.key)
}

// currentToken returns the cached token, a static VAULT_TOKEN(_FILE), or
// logs in once (cached for later calls and ticks).
func (b *vaultBackend) currentToken(ctx context.Context, client *http.Client, addr, k8sTokenPathOverride string) (string, error) {
	b.mu.Lock()
	cached := b.token
	b.mu.Unlock()
	if cached != "" {
		return cached, nil
	}
	if tok, err := readEnvOrFile("VAULT_TOKEN"); err != nil {
		return "", err
	} else if tok != "" {
		b.mu.Lock()
		b.token = tok
		b.mu.Unlock()
		return tok, nil
	}
	tok, err := b.login(ctx, client, addr, k8sTokenPathOverride)
	if err != nil {
		return "", err
	}
	b.mu.Lock()
	b.token = tok
	b.mu.Unlock()
	return tok, nil
}

// login authenticates with Vault per VAULT_AUTH (kubernetes or approle) and
// returns the issued client token.
func (b *vaultBackend) login(ctx context.Context, client *http.Client, addr, k8sTokenPathOverride string) (string, error) {
	switch auth := os.Getenv("VAULT_AUTH"); auth {
	case "kubernetes":
		return b.loginKubernetes(ctx, client, addr, k8sTokenPathOverride)
	case "approle":
		return b.loginAppRole(ctx, client, addr)
	case "":
		return "", errors.New("no VAULT_TOKEN(_FILE) and no VAULT_AUTH login method configured")
	default:
		return "", fmt.Errorf("unknown VAULT_AUTH %q", auth)
	}
}

func (b *vaultBackend) loginKubernetes(ctx context.Context, client *http.Client, addr, tokenPathOverride string) (string, error) {
	role := os.Getenv("VAULT_K8S_ROLE")
	if role == "" {
		return "", errors.New("VAULT_K8S_ROLE is not set")
	}
	mount := cmp.Or(os.Getenv("VAULT_K8S_MOUNT"), "kubernetes")
	tokenPath := cmp.Or(tokenPathOverride, defaultVaultK8STokenPath)
	jwt, err := os.ReadFile(filepath.Clean(tokenPath))
	if err != nil {
		return "", fmt.Errorf("kubernetes service account token: %w", err)
	}
	return b.vaultLogin(ctx, client, addr, "auth/"+mount+"/login", map[string]string{
		"role": role,
		"jwt":  strings.TrimSpace(string(jwt)),
	})
}

func (b *vaultBackend) loginAppRole(ctx context.Context, client *http.Client, addr string) (string, error) {
	roleID := os.Getenv("VAULT_ROLE_ID")
	if roleID == "" {
		return "", errors.New("VAULT_ROLE_ID is not set")
	}
	secretID, err := readEnvOrFile("VAULT_SECRET_ID")
	if err != nil {
		return "", err
	}
	if secretID == "" {
		return "", errors.New("VAULT_SECRET_ID(_FILE) is not set")
	}
	mount := cmp.Or(os.Getenv("VAULT_APPROLE_MOUNT"), "approle")
	return b.vaultLogin(ctx, client, addr, "auth/"+mount+"/login", map[string]string{
		"role_id":   roleID,
		"secret_id": secretID,
	})
}

func (b *vaultBackend) vaultLogin(ctx context.Context, client *http.Client, addr, path string, body map[string]string) (string, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, addr+"/v1/"+path, bytes.NewReader(payload)) //nolint:gosec // G704: VAULT_ADDR is operator infrastructure, resolved before the outbound policy exists
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	applyVaultNamespace(req)
	resp, err := client.Do(req) //nolint:gosec // G704: VAULT_ADDR is operator infrastructure
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("login: HTTP %d", resp.StatusCode)
	}
	var out struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("login: invalid response: %w", err)
	}
	if out.Auth.ClientToken == "" {
		return "", errors.New("login: no client_token in response")
	}
	return out.Auth.ClientToken, nil
}

// readSecret performs GET {addr}/v1/{path} and returns the raw body and
// status; the caller decides whether a 403 warrants a re-login retry.
func (b *vaultBackend) readSecret(ctx context.Context, client *http.Client, addr, token, path string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, addr+"/v1/"+strings.TrimLeft(path, "/"), nil) //nolint:gosec // G704: VAULT_ADDR is operator infrastructure, resolved before the outbound policy exists
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("X-Vault-Token", token)
	applyVaultNamespace(req)
	resp, err := client.Do(req) //nolint:gosec // G704: VAULT_ADDR is operator infrastructure
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, 0, err
	}
	return data, resp.StatusCode, nil
}

func applyVaultNamespace(req *http.Request) {
	if ns := os.Getenv("VAULT_NAMESPACE"); ns != "" {
		req.Header.Set("X-Vault-Namespace", ns)
	}
}

// vaultFields extracts the secret's named fields from a read response,
// handling both KV v2 (`data.data`) and KV v1 (`data`).
func vaultFields(body []byte) (map[string]json.RawMessage, error) {
	var outer struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &outer); err != nil {
		return nil, fmt.Errorf("invalid response: %w", err)
	}
	if outer.Data == nil {
		return nil, errors.New("response has no data")
	}
	if nested, ok := outer.Data["data"]; ok {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(nested, &fields); err == nil {
			return fields, nil
		}
	}
	return outer.Data, nil
}

// selectVaultField picks key's field, or the secret's only field when key is
// empty — required unless the secret has exactly one field.
func selectVaultField(fields map[string]json.RawMessage, key string) (string, error) {
	if key == "" {
		if len(fields) != 1 {
			return "", fmt.Errorf("secret has %d fields; #key is required", len(fields))
		}
		for _, v := range fields {
			return decodeJSONString(v), nil
		}
	}
	v, ok := fields[key]
	if !ok {
		return "", fmt.Errorf("field %q not found", key)
	}
	return decodeJSONString(v), nil
}

// readEnvOrFile reads name from the environment, or from the file named by
// name+"_FILE" (mirrors internal/config's NAME/NAME_FILE convention).
func readEnvOrFile(name string) (string, error) {
	if v, ok := os.LookupEnv(name); ok {
		return v, nil
	}
	path, ok := os.LookupEnv(name + "_FILE")
	if !ok {
		return "", nil
	}
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("%s_FILE: %w", name, err)
	}
	return strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r"), nil
}
