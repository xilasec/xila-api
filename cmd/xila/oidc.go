package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"time"
)

// Workload identity federation: with no XILA_TOKEN, the CLI trades the CI
// platform's OIDC identity token for a short-lived Xila session (RFC 8693
// token exchange at POST /api/v1/auth/token), so the pipeline stores no Xila
// secret.

const (
	grantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange" //nolint:gosec // G101: an OAuth grant-type URN, not a credential
	tokenTypeJWT       = "urn:ietf:params:oauth:token-type:jwt"            //nolint:gosec // G101: an OAuth token-type URN, not a credential
)

var errNoIdentity = errors.New("no Xila token and no CI identity token: set XILA_TOKEN, or pass --oidc-token / XILA_OIDC_TOKEN, " +
	"or run in GitHub Actions with `permissions: id-token: write`, or in GitLab CI with `id_tokens: XILA_ID_TOKEN`")

// identityToken finds the workload's OIDC token: an explicit one (--oidc-token
// or XILA_OIDC_TOKEN), GitLab's (`id_tokens: XILA_ID_TOKEN`), or one requested
// from GitHub Actions for the audience XILA_OIDC_AUDIENCE.
func identityToken(hc *http.Client, explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if t := os.Getenv("XILA_ID_TOKEN"); t != "" {
		return t, nil
	}
	reqURL, reqToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"), os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if reqURL != "" && reqToken != "" {
		return githubIDToken(hc, reqURL, reqToken, os.Getenv("XILA_OIDC_AUDIENCE"))
	}
	return "", errNoIdentity
}

// githubIDToken asks the Actions runtime for an ID token. Without an audience
// GitHub uses its default (https://github.com/<owner>).
func githubIDToken(hc *http.Client, reqURL, reqToken, audience string) (string, error) {
	u, err := neturl.Parse(reqURL)
	if err != nil {
		return "", fmt.Errorf("ACTIONS_ID_TOKEN_REQUEST_URL: %w", err)
	}
	if audience != "" {
		q := u.Query()
		q.Set("audience", audience)
		u.RawQuery = q.Encode()
	}
	req, err := http.NewRequest(http.MethodGet, u.String(), nil) //nolint:gosec // G704: the Actions runner's own token endpoint (ACTIONS_ID_TOKEN_REQUEST_URL)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+reqToken)
	resp, err := hc.Do(req) //nolint:gosec // G704: the Actions runner's own token endpoint (ACTIONS_ID_TOKEN_REQUEST_URL)
	if err != nil {
		return "", fmt.Errorf("request GitHub OIDC token: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("request GitHub OIDC token: %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Value == "" {
		return "", errors.New("request GitHub OIDC token: no token in the response")
	}
	return out.Value, nil
}

// exchangeToken trades an identity token for a Xila access token.
func exchangeToken(hc *http.Client, base, subject string) (string, time.Duration, error) {
	form := neturl.Values{
		"grant_type":         {grantTokenExchange},
		"subject_token":      {subject},
		"subject_token_type": {tokenTypeJWT},
	}
	resp, err := hc.PostForm(base+"/api/v1/auth/token", form)
	if err != nil {
		return "", 0, fmt.Errorf("token exchange: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &out)
	if resp.StatusCode != http.StatusOK || out.AccessToken == "" {
		msg := out.Description
		if msg == "" {
			msg = apiError(body)
		}
		return "", 0, fmt.Errorf("token exchange refused (%d %s): %s", resp.StatusCode, out.Error, msg)
	}
	return out.AccessToken, time.Duration(out.ExpiresIn) * time.Second, nil
}

// resolveToken returns the bearer token to use: the API token when given,
// else a federated session from the CI identity token.
func resolveToken(base, token, oidcToken string, out io.Writer) (string, error) {
	if token != "" {
		return token, nil
	}
	hc := &http.Client{Timeout: 30 * time.Second}
	subject, err := identityToken(hc, oidcToken)
	if err != nil {
		return "", err
	}
	access, ttl, err := exchangeToken(hc, base, subject)
	if err != nil {
		return "", err
	}
	fmt.Fprintf(out, "authenticated with the CI identity token (session valid %s)\n", ttl)
	return access, nil
}
