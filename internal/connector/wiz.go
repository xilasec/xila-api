package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
)

// Wiz authenticates with OAuth 2.0 client credentials and serves one GraphQL
// API, per the published integration guides that reproduce its request/response
// shapes (Wiz gates its full interactive GraphQL reference behind an
// authenticated tenant):
// https://docs.brinqa.com/docs/connectors/wiz/ (token endpoint + grant),
// https://docs.netskope.com/en/wiz-plugin-for-risk-exchange (the
// vulnerabilityFindings query), https://docs.port.io/.../wiz/ (per-tenant API
// URL, e.g. https://api.us17.app.wiz.io/graphql).
//
//   - POST {auth_url} (e.g. https://auth.app.wiz.io/oauth/token for a Cognito
//     tenant, https://auth.wiz.io/oauth/token for Auth0) —
//     grant_type=client_credentials&client_id&client_secret&audience=wiz-api,
//     form-encoded; returns {access_token, token_type, expires_in}.
//   - POST {base_url} (the tenant's GraphQL endpoint, …/graphql) —
//     `vulnerabilityFindings(filterBy, first, after)`, a Relay cursor
//     connection; Authorization: Bearer <access_token>.
//
// A `REJECTED` finding carries its status over as a remote triage verdict
// (Wiz's own rejection reason isn't part of the finding node); `RESOLVED` ones
// are excluded from the query, so the next pull auto-closes them.
const (
	wizPageSize = 100
	wizAudience = "wiz-api"
)

type wiz struct {
	base, authURL, scope, clientID, clientSecret string
	hc                                           *http.Client
	pageSize                                     int
}

type wizCredentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func parseWizCredentials(token string) (wizCredentials, error) {
	var c wizCredentials
	if err := json.Unmarshal([]byte(token), &c); err != nil || c.ClientID == "" || c.ClientSecret == "" {
		return wizCredentials{}, invalid(`token must be JSON {"client_id": "...", "client_secret": "..."}`)
	}
	return c, nil
}

// token obtains a fresh OAuth access token.
func (w *wiz) token(ctx context.Context) (string, error) {
	body := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {w.clientID},
		"client_secret": {w.clientSecret},
		"audience":      {wizAudience},
	}.Encode()
	var tok struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	if _, err := httpJSON(ctx, w.hc, http.MethodPost, w.authURL, headers, []byte(body), &tok); err != nil {
		return "", err
	}
	if tok.AccessToken == "" {
		return "", remoteErr("wiz: token response carried no access_token")
	}
	return tok.AccessToken, nil
}

const wizQuery = `query VulnerabilityFindingsPage($filterBy: VulnerabilityFindingFilters, $first: Int, $after: String) {
  vulnerabilityFindings(filterBy: $filterBy, first: $first, after: $after) {
    nodes {
      id
      name
      severity
      status
      vulnerableAsset {
        ... on VulnerableAssetBase {
          id
          name
          type
          providerUniqueId
        }
      }
    }
    pageInfo { hasNextPage endCursor }
  }
}`

type wizFinding struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Severity        string `json:"severity"`
	Status          string `json:"status"`
	VulnerableAsset *struct {
		ID               string `json:"id"`
		Name             string `json:"name"`
		Type             string `json:"type"`
		ProviderUniqueID string `json:"providerUniqueId"`
	} `json:"vulnerableAsset"`
}

type wizResponse struct {
	Data struct {
		VulnerabilityFindings struct {
			Nodes    []wizFinding `json:"nodes"`
			PageInfo struct {
				HasNextPage bool   `json:"hasNextPage"`
				EndCursor   string `json:"endCursor"`
			} `json:"pageInfo"`
		} `json:"vulnerabilityFindings"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func (w *wiz) graphQL(ctx context.Context, token string, variables map[string]any) (wizResponse, error) {
	body, err := json.Marshal(map[string]any{"query": wizQuery, "variables": variables})
	if err != nil {
		return wizResponse{}, remoteErr("wiz: encode query: %v", err)
	}
	headers := map[string]string{"Authorization": "Bearer " + token, "Content-Type": "application/json"}
	var resp wizResponse
	if _, err := httpJSON(ctx, w.hc, http.MethodPost, w.base, headers, body, &resp); err != nil {
		return wizResponse{}, err
	}
	if len(resp.Errors) > 0 {
		msgs := make([]string, len(resp.Errors))
		for i, e := range resp.Errors {
			msgs[i] = e.Message
		}
		return wizResponse{}, remoteErr("wiz: %s", strings.Join(msgs, "; "))
	}
	return resp, nil
}

func (w *wiz) Check(ctx context.Context) (string, error) {
	if _, err := w.token(ctx); err != nil {
		return "", err
	}
	return fmt.Sprintf("Wiz (client %s)", w.clientID), nil
}

func (w *wiz) filter() map[string]any {
	filter := map[string]any{"status": []string{"OPEN", "IN_PROGRESS", "REJECTED"}}
	if w.scope != "" {
		ids := strings.Split(w.scope, ",")
		for i := range ids {
			ids[i] = strings.TrimSpace(ids[i])
		}
		filter["projectId"] = ids
	}
	return filter
}

func (w *wiz) Fetch(ctx context.Context) ([]finding.Finding, error) {
	token, err := w.token(ctx)
	if err != nil {
		return nil, err
	}
	out := []finding.Finding{}
	var after any
	for page := 0; ; page++ {
		if page >= maxPages {
			return nil, remoteErr("wiz: more than %d pages of findings", maxPages)
		}
		resp, err := w.graphQL(ctx, token, map[string]any{"filterBy": w.filter(), "first": w.pageSize, "after": after})
		if err != nil {
			return nil, err
		}
		conn := resp.Data.VulnerabilityFindings
		for _, f := range conn.Nodes {
			out = append(out, w.toFinding(f))
		}
		if !conn.PageInfo.HasNextPage {
			break
		}
		after = conn.PageInfo.EndCursor
	}
	return uniqueByFingerprint(out), nil
}

// Category is Cloud (CNAPP) by default; a container or Kubernetes asset
// narrows it.
func (w *wiz) Category(fs []finding.Finding) domain.Category {
	return mostCommonCategory(fs, domain.CategoryCloud)
}

func wizAssetCategory(assetType string) domain.Category {
	switch {
	case strings.Contains(assetType, "CONTAINER"):
		return domain.CategoryContainer
	case strings.Contains(assetType, "KUBERNETES"):
		return domain.CategoryKubernetes
	}
	return domain.CategoryCloud
}

func (w *wiz) toFinding(f wizFinding) finding.Finding {
	sev, ok := mapSeverity(f.Severity)
	if !ok {
		sev = domain.SeverityInfo
	}
	category := domain.CategoryCloud
	pkgName, assetType, assetID := "", "", ""
	if f.VulnerableAsset != nil {
		pkgName = f.VulnerableAsset.Name
		assetType = f.VulnerableAsset.Type
		assetID = f.VulnerableAsset.ID
		category = wizAssetCategory(strings.ToUpper(assetType))
	}

	meta := map[string]any{"source": "wiz", "finding_id": f.ID, "status": f.Status}
	if assetType != "" {
		meta["asset_type"] = assetType
	}
	if assetID != "" {
		meta["asset_id"] = assetID
	}
	if strings.EqualFold(f.Status, "REJECTED") {
		meta["remote_triage"] = string(domain.FindingFalsePositive)
		meta["remote_triage_reason"] = "Wiz: rejected"
	}

	cves := addCVE(nil, f.Name)
	if cves == nil {
		cves = []string{}
	}
	return finding.Finding{
		Fingerprint: fingerprint(KindWiz, f.ID),
		Category:    category,
		RuleID:      f.Name,
		Title:       f.Name,
		Severity:    sev,
		CVE:         cves,
		PackageName: pkgName,
		Metadata:    meta,
	}
}
