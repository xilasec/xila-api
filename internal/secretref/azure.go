package secretref

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// azureScope is the OAuth scope Key Vault needs.
const azureScope = "https://vault.azure.net/.default"

// azureAPIVersion is the Key Vault secrets REST API version.
const azureAPIVersion = "7.5"

// azureBackend resolves azure-kv:// references over plain HTTPS, authenticating
// with DefaultAzureCredential (managed identity, workload identity, env).
type azureBackend struct {
	cred onceValue[azcore.TokenCredential]
}

func (b *azureBackend) ensure() (azcore.TokenCredential, error) {
	return b.cred.get(func() (azcore.TokenCredential, error) {
		cred, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return nil, fmt.Errorf("default azure credential: %w", err)
		}
		return cred, nil
	})
}

func (b *azureBackend) resolve(ctx context.Context, r ref, credOverride azcore.TokenCredential, baseURLOverride string) (string, error) {
	segs := strings.Split(strings.Trim(r.path, "/"), "/")
	if len(segs) < 2 || segs[0] == "" || segs[1] == "" {
		return "", fmt.Errorf("%q is not <vault>/<secret>[/<version>]", r.path)
	}
	vaultHost, secretName := segs[0], segs[1]
	version := ""
	if len(segs) >= 3 {
		version = segs[2]
	}

	cred := credOverride
	if cred == nil {
		var err error
		if cred, err = b.ensure(); err != nil {
			return "", err
		}
	}
	tok, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{azureScope}})
	if err != nil {
		return "", fmt.Errorf("token: %w", err)
	}

	base := baseURLOverride
	if base == "" {
		base = "https://" + vaultHost
		if !strings.Contains(vaultHost, ".") {
			base = "https://" + vaultHost + ".vault.azure.net"
		}
	}
	u := base + "/secrets/" + secretName
	if version != "" {
		u += "/" + version
	}
	u += "?api-version=" + azureAPIVersion

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var out struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("invalid response: %w", err)
	}
	return out.Value, nil
}
