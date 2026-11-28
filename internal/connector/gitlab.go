package connector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
)

// GitLab, per its GraphQL reference
// (https://docs.gitlab.com/api/graphql/reference/queries/#vulnerabilities,
// the `Vulnerability` object's source at
// https://gitlab.com/gitlab-org/gitlab/-/blob/master/ee/app/graphql/types/vulnerability_type.rb,
// and the worked example in
// https://github.com/gitlabhq/gitlabhq/blob/master/doc/api/vulnerability_findings.md#graphql---project-vulnerability-findings,
// which replaces the removed REST Vulnerability Findings API):
//
//   - POST /api/graphql — `project(fullPath) { vulnerabilities(first, after,
//     state) { pageInfo { hasNextPage endCursor } nodes { ... } } }`, a Relay
//     cursor connection.
//   - GET /api/v4/projects/:id (REST, :id may be the URL-encoded namespaced
//     path) — the connection test.
//   - Auth: `PRIVATE-TOKEN` for REST, `Authorization: Bearer` for GraphQL (a
//     personal/project access token with at least `read_api` works for both).
//
// gitlab.com and GitLab Self-Managed share this client (base_url defaults to
// https://gitlab.com). A `DISMISSED` vulnerability carries its
// `dismissalReason` over as a remote triage verdict; `RESOLVED` ones are
// excluded from the query entirely, so the next pull auto-closes them.
const gitlabPageSize = 100

type gitLab struct {
	base, project, token string
	hc                   *http.Client
	pageSize             int
}

func (g *gitLab) Check(ctx context.Context) (string, error) {
	var p struct {
		Name              string `json:"name"`
		NameWithNamespace string `json:"name_with_namespace"`
	}
	u := g.base + "/api/v4/projects/" + url.QueryEscape(g.project)
	if _, err := httpJSON(ctx, g.hc, http.MethodGet, u, map[string]string{"PRIVATE-TOKEN": g.token}, nil, &p); err != nil {
		return "", err
	}
	if p.NameWithNamespace != "" {
		return p.NameWithNamespace, nil
	}
	return p.Name, nil
}

const gitlabQuery = `query ConnectorVulnerabilities($fullPath: ID!, $first: Int!, $after: String) {
  project(fullPath: $fullPath) {
    vulnerabilities(first: $first, after: $after, state: [DETECTED, CONFIRMED, DISMISSED]) {
      pageInfo { hasNextPage endCursor }
      nodes {
        id
        title
        description
        state
        severity
        reportType
        webUrl
        dismissalReason
        identifiers { externalType externalId name url }
        location {
          ... on VulnerabilityLocationSast { file startLine endLine }
          ... on VulnerabilityLocationDependencyScanning { file dependency { package { name } version } }
          ... on VulnerabilityLocationContainerScanning { image operatingSystem dependency { package { name } version } }
        }
      }
    }
  }
}`

type gitlabVulnerability struct {
	ID              string  `json:"id"`
	Title           string  `json:"title"`
	Description     string  `json:"description"`
	State           string  `json:"state"`
	Severity        string  `json:"severity"`
	ReportType      string  `json:"reportType"`
	WebURL          string  `json:"webUrl"`
	DismissalReason *string `json:"dismissalReason"`
	Identifiers     []struct {
		ExternalType string `json:"externalType"`
		ExternalID   string `json:"externalId"`
		Name         string `json:"name"`
	} `json:"identifiers"`
	Location struct {
		File            string `json:"file"`
		StartLine       *int   `json:"startLine"`
		Image           string `json:"image"`
		OperatingSystem string `json:"operatingSystem"`
		Dependency      *struct {
			Package *struct {
				Name string `json:"name"`
			} `json:"package"`
			Version string `json:"version"`
		} `json:"dependency"`
	} `json:"location"`
}

type gitlabGraphQLResponse struct {
	Data struct {
		Project *struct {
			Vulnerabilities struct {
				Nodes    []gitlabVulnerability `json:"nodes"`
				PageInfo struct {
					HasNextPage bool   `json:"hasNextPage"`
					EndCursor   string `json:"endCursor"`
				} `json:"pageInfo"`
			} `json:"vulnerabilities"`
		} `json:"project"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func (g *gitLab) graphQL(ctx context.Context, variables map[string]any) (gitlabGraphQLResponse, error) {
	body, err := json.Marshal(map[string]any{"query": gitlabQuery, "variables": variables})
	if err != nil {
		return gitlabGraphQLResponse{}, remoteErr("gitlab: encode query: %v", err)
	}
	var resp gitlabGraphQLResponse
	headers := map[string]string{"Authorization": "Bearer " + g.token, "Content-Type": "application/json"}
	if _, err := httpJSON(ctx, g.hc, http.MethodPost, g.base+"/api/graphql", headers, body, &resp); err != nil {
		return gitlabGraphQLResponse{}, err
	}
	if len(resp.Errors) > 0 {
		msgs := make([]string, len(resp.Errors))
		for i, e := range resp.Errors {
			msgs[i] = e.Message
		}
		return gitlabGraphQLResponse{}, remoteErr("gitlab: %s", strings.Join(msgs, "; "))
	}
	if resp.Data.Project == nil {
		return gitlabGraphQLResponse{}, remoteErr("gitlab: project %q not found or not visible", g.project)
	}
	return resp, nil
}

func (g *gitLab) Fetch(ctx context.Context) ([]finding.Finding, error) {
	out := []finding.Finding{}
	var after any
	for page := 0; ; page++ {
		if page >= maxPages {
			return nil, remoteErr("gitlab: more than %d pages of vulnerabilities", maxPages)
		}
		resp, err := g.graphQL(ctx, map[string]any{"fullPath": g.project, "first": g.pageSize, "after": after})
		if err != nil {
			return nil, err
		}
		conn := resp.Data.Project.Vulnerabilities
		for _, v := range conn.Nodes {
			out = append(out, g.toFinding(v))
		}
		if !conn.PageInfo.HasNextPage {
			break
		}
		after = conn.PageInfo.EndCursor
	}
	return uniqueByFingerprint(out), nil
}

// Category is the most common report type, SAST when there are none.
func (g *gitLab) Category(fs []finding.Finding) domain.Category {
	return mostCommonCategory(fs, domain.CategorySAST)
}

func gitlabCategory(reportType string) domain.Category {
	switch strings.ToUpper(reportType) {
	case "SAST", "SAST_IAC":
		return domain.CategorySAST
	case "DAST", "API_FUZZING", "COVERAGE_FUZZING":
		return domain.CategoryDAST
	case "DEPENDENCY_SCANNING":
		return domain.CategorySCA
	case "CONTAINER_SCANNING", "CLUSTER_IMAGE_SCANNING":
		return domain.CategoryContainer
	case "SECRET_DETECTION":
		return domain.CategorySecret
	}
	return domain.CategorySAST
}

// gitlabTriage maps a vulnerability's state (and, when dismissed, its reason)
// onto a verdict; ok=false leaves it open (DETECTED, or an unrecognized
// dismissal reason GitLab adds later).
func gitlabTriage(state string, reason *string) (domain.FindingStatus, string, bool) {
	switch strings.ToUpper(state) {
	case "CONFIRMED":
		return domain.FindingConfirmed, "GitLab: confirmed", true
	case "DISMISSED":
		r := ""
		if reason != nil {
			r = strings.ToUpper(*reason)
		}
		switch r {
		case "ACCEPTABLE_RISK":
			return domain.FindingRiskAccepted, "GitLab dismissal: acceptable risk", true
		case "FALSE_POSITIVE":
			return domain.FindingFalsePositive, "GitLab dismissal: false positive", true
		case "MITIGATING_CONTROL", "USED_IN_TESTS", "NOT_APPLICABLE":
			return domain.FindingWontFix, "GitLab dismissal: " + strings.ToLower(r), true
		}
		return domain.FindingWontFix, "GitLab: dismissed", true
	}
	return "", "", false
}

// gitlabCWE parses a CWE identifier's external id, which GitLab scanners write
// as either a bare number or "CWE-79".
func gitlabCWE(externalID string) *int {
	if cwe := cweFromID(externalID); cwe != nil {
		return cwe
	}
	return cweFromID("CWE-" + externalID)
}

func (g *gitLab) toFinding(v gitlabVulnerability) finding.Finding {
	var cves []string
	var cwe *int
	ruleID := ""
	for _, id := range v.Identifiers {
		switch strings.ToLower(id.ExternalType) {
		case "cve":
			cves = addCVE(cves, id.ExternalID)
			if ruleID == "" {
				ruleID = id.ExternalID
			}
		case "cwe":
			if cwe == nil {
				cwe = gitlabCWE(id.ExternalID)
			}
		}
		if ruleID == "" {
			ruleID = id.ExternalID
		}
	}
	if cves == nil {
		cves = []string{}
	}
	if ruleID == "" {
		ruleID = v.ID
	}

	sev, ok := mapSeverity(v.Severity)
	if !ok {
		sev = domain.SeverityInfo
	}

	var filePath, pkgName, pkgVersion string
	var line *int
	loc := v.Location
	switch {
	case loc.Dependency != nil:
		filePath = loc.File
		pkgVersion = loc.Dependency.Version
		if loc.Dependency.Package != nil {
			pkgName = loc.Dependency.Package.Name
		}
	case loc.Image != "":
		pkgName = loc.Image
	default:
		filePath = loc.File
		line = loc.StartLine
	}

	meta := map[string]any{"source": "gitlab", "vulnerability_id": v.ID, "state": v.State, "report_type": v.ReportType}
	if st, reason, ok := gitlabTriage(v.State, v.DismissalReason); ok {
		meta["remote_triage"] = string(st)
		meta["remote_triage_reason"] = reason
	}

	return finding.Finding{
		Fingerprint:    fingerprint(KindGitLab, v.ID),
		Category:       gitlabCategory(v.ReportType),
		RuleID:         ruleID,
		Title:          v.Title,
		Description:    v.Description,
		Severity:       sev,
		CWE:            cwe,
		CVE:            cves,
		FilePath:       filePath,
		Line:           line,
		PackageName:    pkgName,
		PackageVersion: pkgVersion,
		URL:            v.WebURL,
		Metadata:       meta,
	}
}

// gitlabPathPattern validates a GitLab project's namespaced path, e.g.
// "group/subgroup/project".
func gitlabValidProject(path string) bool {
	if path == "" || strings.HasPrefix(path, "/") || strings.HasSuffix(path, "/") {
		return false
	}
	if slices.Contains(strings.Split(path, "/"), "") {
		return false
	}
	return strings.Contains(path, "/")
}
