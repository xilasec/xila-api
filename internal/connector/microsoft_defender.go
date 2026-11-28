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

// Microsoft Defender Vulnerability Management, per its published API
// reference (an Entra app with an application permission authenticates with
// OAuth 2.0 client credentials):
// https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-create-app-webapp
// (token request shape: POST {auth_url} with grant_type=client_credentials,
// client_id, client_secret, resource=https://api.security.microsoft.com),
// https://learn.microsoft.com/en-us/defender-endpoint/api/get-assessment-software-vulnerabilities
// (GET {base_url}/api/machines/SoftwareVulnerabilitiesByMachine?pageSize=…,
// one row per device+software+CVE, paged by the full URL in
// "@odata.nextLink"), https://learn.microsoft.com/en-us/defender-endpoint/api/get-machines
// (GET {base_url}/api/machines, each device's exposureLevel).
//
// A software inventory row with no cveId is installed software, not a
// vulnerability, and is skipped. The machine list is fetched once per pull
// (not paged — organizations large enough to need paging here are expected to
// use Defender's file-export API instead, like Tenable's chunked export) to
// join each finding's device to its exposureLevel; a failed machine list
// leaves exposure unset rather than failing the pull, since it only enriches
// metadata and never decides what's fetched or closed.
const defenderPageSize = 5000

type microsoftDefender struct {
	base, authURL, clientID, clientSecret string
	hc                                    *http.Client
	pageSize                              int
}

type defenderCredentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func parseDefenderCredentials(token string) (defenderCredentials, error) {
	var c defenderCredentials
	if err := json.Unmarshal([]byte(token), &c); err != nil || c.ClientID == "" || c.ClientSecret == "" {
		return defenderCredentials{}, invalid(`token must be JSON {"client_id": "...", "client_secret": "..."}`)
	}
	return c, nil
}

// token obtains a fresh OAuth access token via client credentials.
func (m *microsoftDefender) token(ctx context.Context) (string, error) {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {m.clientID},
		"client_secret": {m.clientSecret},
		"resource":      {"https://api.security.microsoft.com"},
	}
	var resp struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error_description"`
	}
	headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	if _, err := httpJSON(ctx, m.hc, http.MethodPost, m.authURL, headers, []byte(form.Encode()), &resp); err != nil {
		return "", err
	}
	if resp.AccessToken == "" {
		return "", remoteErr("defender: token endpoint returned no access_token: %s", resp.Error)
	}
	return resp.AccessToken, nil
}

type defenderVuln struct {
	ID                         string   `json:"id"`
	DeviceID                   string   `json:"deviceId"`
	DeviceName                 string   `json:"deviceName"`
	OSPlatform                 string   `json:"osPlatform"`
	SoftwareVendor             string   `json:"softwareVendor"`
	SoftwareName               string   `json:"softwareName"`
	SoftwareVersion            string   `json:"softwareVersion"`
	CveID                      string   `json:"cveId"`
	CvssScore                  *float64 `json:"cvssScore"`
	VulnerabilitySeverityLevel string   `json:"vulnerabilitySeverityLevel"`
	ExploitabilityLevel        string   `json:"exploitabilityLevel"`
	SecurityUpdateAvailable    bool     `json:"securityUpdateAvailable"`
	RecommendedSecurityUpdate  string   `json:"recommendedSecurityUpdate"`
}

type defenderVulnPage struct {
	Value    []defenderVuln `json:"value"`
	NextLink string         `json:"@odata.nextLink"`
}

type defenderMachine struct {
	ID            string `json:"id"`
	ExposureLevel string `json:"exposureLevel"`
}

type defenderMachinePage struct {
	Value []defenderMachine `json:"value"`
}

func (m *microsoftDefender) Check(ctx context.Context) (string, error) {
	token, err := m.token(ctx)
	if err != nil {
		return "", err
	}
	var resp defenderVulnPage
	url := fmt.Sprintf("%s/api/machines/SoftwareVulnerabilitiesByMachine?pageSize=1", m.base)
	if _, err := getJSON(ctx, m.hc, url, "Authorization", "Bearer "+token, &resp); err != nil {
		return "", err
	}
	return "Microsoft Defender Vulnerability Management", nil
}

// exposureByDevice maps deviceId to its exposureLevel ("Low"/"Medium"/"High");
// a failed or empty fetch returns an empty map, not an error.
func (m *microsoftDefender) exposureByDevice(ctx context.Context, token string) map[string]string {
	var resp defenderMachinePage
	url := fmt.Sprintf("%s/api/machines?$select=id,exposureLevel", m.base)
	if _, err := getJSON(ctx, m.hc, url, "Authorization", "Bearer "+token, &resp); err != nil {
		return nil
	}
	out := make(map[string]string, len(resp.Value))
	for _, d := range resp.Value {
		if d.ExposureLevel != "" {
			out[d.ID] = d.ExposureLevel
		}
	}
	return out
}

func (m *microsoftDefender) Fetch(ctx context.Context) ([]finding.Finding, error) {
	token, err := m.token(ctx)
	if err != nil {
		return nil, err
	}
	exposure := m.exposureByDevice(ctx, token)
	out := []finding.Finding{}
	next := fmt.Sprintf("%s/api/machines/SoftwareVulnerabilitiesByMachine?pageSize=%d", m.base, m.pageSize)
	for page := 0; next != ""; page++ {
		if page >= maxPages {
			return nil, remoteErr("defender: more than %d pages of software vulnerabilities", maxPages)
		}
		var resp defenderVulnPage
		if _, err := getJSON(ctx, m.hc, next, "Authorization", "Bearer "+token, &resp); err != nil {
			return nil, err
		}
		for _, v := range resp.Value {
			if v.CveID == "" {
				continue // installed software with no known vulnerability
			}
			out = append(out, m.toFinding(v, exposure[v.DeviceID]))
		}
		next = resp.NextLink
	}
	return uniqueByFingerprint(out), nil
}

// Category is SCA: software vulnerability assessment, like a dependency scan,
// but of installed host software rather than a project's manifest.
func (m *microsoftDefender) Category([]finding.Finding) domain.Category { return domain.CategorySCA }

func (m *microsoftDefender) toFinding(v defenderVuln, exposureLevel string) finding.Finding {
	sev, ok := mapSeverity(v.VulnerabilitySeverityLevel)
	if !ok {
		sev = severityFromScore(v.CvssScore)
	}
	desc := fmt.Sprintf("%s %s %s on %s (%s)", v.SoftwareVendor, v.SoftwareName, v.SoftwareVersion, v.DeviceName, v.OSPlatform)
	if v.ExploitabilityLevel != "" && v.ExploitabilityLevel != "NoExploit" {
		desc = withSection(desc, "Exploitability", v.ExploitabilityLevel)
	}
	if v.RecommendedSecurityUpdate != "" {
		desc = withSection(desc, "Recommended update", v.RecommendedSecurityUpdate)
	}
	meta := map[string]any{"source": "microsoft-defender", "device_id": v.DeviceID,
		"security_update_available": v.SecurityUpdateAvailable}
	if exposureLevel != "" {
		meta["exposure_level"] = exposureLevel
	}
	if v.ExploitabilityLevel != "" {
		meta["exploitability_level"] = v.ExploitabilityLevel
	}
	return finding.Finding{
		Fingerprint:    fingerprint(KindMicrosoftDefender, v.DeviceID+"|"+v.CveID+"|"+v.SoftwareVersion),
		Category:       domain.CategorySCA,
		RuleID:         strings.ToUpper(v.CveID),
		Title:          strings.ToUpper(v.CveID),
		Description:    desc,
		Severity:       sev,
		CVE:            addCVE(nil, v.CveID),
		PackageName:    v.SoftwareName,
		PackageVersion: v.SoftwareVersion,
		CVSS:           v.CvssScore,
		FilePath:       v.DeviceName,
		Metadata:       meta,
	}
}
