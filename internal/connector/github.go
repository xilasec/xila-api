package connector

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
)

// GitHub REST API, per its reference
// (https://docs.github.com/en/rest/code-scanning/code-scanning and
// https://docs.github.com/en/rest/dependabot/alerts):
//
//   - GET /repos/{owner}/{repo}/code-scanning/alerts — code scanning (CodeQL and
//     third-party SARIF uploads) alerts for one repository; GET
//     /orgs/{org}/code-scanning/alerts for every eligible repository in an org.
//   - GET /repos/{owner}/{repo}/dependabot/alerts and
//     GET /orgs/{org}/dependabot/alerts — the open-source dependency alerts.
//   - Both paginate with `per_page` (max 100) and the classic `Link` response
//     header (`rel="next"`).
//   - Auth: `Authorization: Bearer <token>`, `Accept: application/vnd.github+json`,
//     `X-GitHub-Api-Version: 2022-11-28`.
//
// github.com and GitHub Enterprise Server share this client: base_url is
// normalized to "https://api.github.com" for the former, or the GHES host
// with "/api/v3" for the latter (Input.Normalize).
//
// A `dismissed` alert carries its reason over as a remote triage verdict; a
// `fixed` (code scanning) or `fixed`/`auto_dismissed` (Dependabot) alert is not
// fetched, so the next pull auto-closes it.
const githubPageSize = 100
const githubAPIVersion = "2022-11-28"

type gitHub struct {
	base, scope, token string
	hc                 *http.Client
	pageSize           int
}

// repoOrOrg splits the scope into the alerts path prefix ("repos/o/r" or
// "orgs/o") and whether every item needs its own repository looked up (true
// for the org-wide listing, which the response already carries on each item).
func (g *gitHub) scopePath() string {
	if org, ok := strings.CutPrefix(g.scope, "org:"); ok {
		return "orgs/" + org
	}
	return "repos/" + g.scope
}

func (g *gitHub) headers() map[string]string {
	return map[string]string{
		"Authorization":        "Bearer " + g.token,
		"Accept":               "application/vnd.github+json",
		"X-GitHub-Api-Version": githubAPIVersion,
	}
}

func (g *gitHub) Check(ctx context.Context) (string, error) {
	if org, ok := strings.CutPrefix(g.scope, "org:"); ok {
		var o struct {
			Login string `json:"login"`
			Name  string `json:"name"`
		}
		if _, err := httpJSON(ctx, g.hc, http.MethodGet, g.base+"/orgs/"+url.PathEscape(org), g.headers(), nil, &o); err != nil {
			return "", err
		}
		if o.Name != "" {
			return o.Name, nil
		}
		return o.Login, nil
	}
	var r struct {
		FullName string `json:"full_name"`
	}
	if _, err := httpJSON(ctx, g.hc, http.MethodGet, g.base+"/"+g.scopePath(), g.headers(), nil, &r); err != nil {
		return "", err
	}
	return r.FullName, nil
}

type githubRepoRef struct {
	FullName string `json:"full_name"`
}

type githubCodeScanAlert struct {
	Number           int     `json:"number"`
	HTMLURL          string  `json:"html_url"`
	State            string  `json:"state"`
	DismissedReason  *string `json:"dismissed_reason"`
	DismissedComment *string `json:"dismissed_comment"`
	Rule             struct {
		ID                    string   `json:"id"`
		Name                  string   `json:"name"`
		Severity              string   `json:"severity"`
		SecuritySeverityLevel string   `json:"security_severity_level"`
		Description           string   `json:"description"`
		FullDescription       string   `json:"full_description"`
		Tags                  []string `json:"tags"`
	} `json:"rule"`
	MostRecentInstance struct {
		CommitSHA string `json:"commit_sha"`
		Message   struct {
			Text string `json:"text"`
		} `json:"message"`
		Location struct {
			Path      string `json:"path"`
			StartLine int    `json:"start_line"`
		} `json:"location"`
		HTMLURL string `json:"html_url"`
	} `json:"most_recent_instance"`
	Repository githubRepoRef `json:"repository"`
}

type githubDependabotAlert struct {
	Number           int     `json:"number"`
	State            string  `json:"state"`
	HTMLURL          string  `json:"html_url"`
	DismissedReason  *string `json:"dismissed_reason"`
	DismissedComment *string `json:"dismissed_comment"`
	Dependency       struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		ManifestPath string `json:"manifest_path"`
	} `json:"dependency"`
	SecurityAdvisory struct {
		GHSAID         string `json:"ghsa_id"`
		CVEID          string `json:"cve_id"`
		Summary        string `json:"summary"`
		Description    string `json:"description"`
		Severity       string `json:"severity"`
		CVSSSeverities struct {
			CVSSV3 struct {
				Score *float64 `json:"score"`
			} `json:"cvss_v3"`
		} `json:"cvss_severities"`
		CWEs []struct {
			CWEID string `json:"cwe_id"`
		} `json:"cwes"`
	} `json:"security_advisory"`
	SecurityVulnerability struct {
		Severity               string `json:"severity"`
		VulnerableVersionRange string `json:"vulnerable_version_range"`
		FirstPatchedVersion    *struct {
			Identifier string `json:"identifier"`
		} `json:"first_patched_version"`
	} `json:"security_vulnerability"`
	Repository githubRepoRef `json:"repository"`
}

// nextLink extracts the rel="next" URL from a GitHub-style Link header, "" if
// there is no further page.
func nextLink(h http.Header) string {
	for part := range strings.SplitSeq(h.Get("Link"), ",") {
		seg := strings.Split(part, ";")
		if len(seg) < 2 {
			continue
		}
		u := strings.Trim(strings.TrimSpace(seg[0]), "<>")
		for _, p := range seg[1:] {
			if strings.TrimSpace(p) == `rel="next"` {
				return u
			}
		}
	}
	return ""
}

// fetchPages GETs path, decoding each page's JSON array body into T and
// following the Link header's rel="next" until it is absent.
func fetchPages[T any](ctx context.Context, g *gitHub, path string) ([]T, error) {
	out := []T{}
	u := g.base + "/" + path
	for page := 0; u != ""; page++ {
		if page >= maxPages {
			return nil, remoteErr("github: more than %d pages", maxPages)
		}
		var items []T
		hdr, err := httpJSON(ctx, g.hc, http.MethodGet, u, g.headers(), nil, &items)
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
		u = nextLink(hdr)
	}
	return out, nil
}

func (g *gitHub) Fetch(ctx context.Context) ([]finding.Finding, error) {
	out := []finding.Finding{}
	codeAlerts, err := fetchPages[githubCodeScanAlert](ctx, g, g.scopePath()+"/code-scanning/alerts?per_page="+strconv.Itoa(g.pageSize))
	if err != nil {
		return nil, err
	}
	for _, a := range codeAlerts {
		if a.State == "fixed" {
			continue
		}
		out = append(out, g.codeScanFinding(a))
	}
	depAlerts, err := fetchPages[githubDependabotAlert](ctx, g, g.scopePath()+"/dependabot/alerts?per_page="+strconv.Itoa(g.pageSize))
	if err != nil {
		return nil, err
	}
	for _, a := range depAlerts {
		if a.State == "fixed" || a.State == "auto_dismissed" {
			continue
		}
		out = append(out, g.dependabotFinding(a))
	}
	return uniqueByFingerprint(out), nil
}

// Category is the most common category across both alert sources, SCA when
// there are none (Dependabot usually outnumbers code scanning).
func (g *gitHub) Category(fs []finding.Finding) domain.Category {
	return mostCommonCategory(fs, domain.CategorySCA)
}

var githubCWETag = regexp.MustCompile(`(?i)cwe-(\d+)`)

// githubDismissedTriage maps a code scanning dismissal reason onto a verdict.
func githubCodeScanTriage(reason string) (domain.FindingStatus, bool) {
	switch reason {
	case "false positive", "used in tests":
		return domain.FindingFalsePositive, true
	case "won't fix", "mitigated":
		return domain.FindingWontFix, true
	}
	return "", false
}

// githubDependabotTriage maps a Dependabot dismissal reason onto a verdict;
// "fix_started" leaves the alert open (a fix is in progress, not a verdict).
func githubDependabotTriage(reason string) (domain.FindingStatus, bool) {
	switch reason {
	case "inaccurate", "not_used":
		return domain.FindingFalsePositive, true
	case "tolerable_risk":
		return domain.FindingRiskAccepted, true
	case "no_bandwidth":
		return domain.FindingWontFix, true
	}
	return "", false
}

func (g *gitHub) repoName(r githubRepoRef) string {
	if r.FullName != "" {
		return r.FullName
	}
	return strings.TrimPrefix(g.scope, "org:")
}

func (g *gitHub) codeScanFinding(a githubCodeScanAlert) finding.Finding {
	repo := g.repoName(a.Repository)
	sev, ok := mapSeverity(a.Rule.SecuritySeverityLevel)
	if !ok {
		switch a.Rule.Severity {
		case "error":
			sev = domain.SeverityHigh
		case "warning":
			sev = domain.SeverityMedium
		case "note":
			sev = domain.SeverityLow
		default:
			sev = domain.SeverityInfo
		}
	}
	var cwe *int
	for _, t := range a.Rule.Tags {
		if m := githubCWETag.FindStringSubmatch(t); m != nil {
			cwe = cweFromID("CWE-" + m[1])
			break
		}
	}
	ruleID := a.Rule.ID
	if ruleID == "" {
		ruleID = a.Rule.Name
	}
	desc := a.Rule.FullDescription
	if desc == "" {
		desc = a.Rule.Description
	}
	desc = withSection(desc, "Details", a.MostRecentInstance.Message.Text)

	meta := map[string]any{"source": "github", "repository": repo, "alert_number": a.Number, "state": a.State}
	if a.DismissedReason != nil {
		meta["dismissed_reason"] = *a.DismissedReason
		if st, ok := githubCodeScanTriage(*a.DismissedReason); ok {
			meta["remote_triage"] = string(st)
			reason := "GitHub code scanning: " + *a.DismissedReason
			if a.DismissedComment != nil && *a.DismissedComment != "" {
				reason += " — " + *a.DismissedComment
			}
			meta["remote_triage_reason"] = reason
		}
	}

	var line *int
	if a.MostRecentInstance.Location.StartLine > 0 {
		n := a.MostRecentInstance.Location.StartLine
		line = &n
	}
	return finding.Finding{
		Fingerprint: fingerprint(KindGitHub, "code:"+repo+":"+strconv.Itoa(a.Number)),
		Category:    domain.CategorySAST,
		RuleID:      ruleID,
		Title:       a.Rule.Name,
		Description: desc,
		Severity:    sev,
		CWE:         cwe,
		CVE:         []string{},
		FilePath:    a.MostRecentInstance.Location.Path,
		Line:        line,
		URL:         a.HTMLURL,
		Metadata:    meta,
	}
}

func (g *gitHub) dependabotFinding(a githubDependabotAlert) finding.Finding {
	repo := g.repoName(a.Repository)
	sa := a.SecurityAdvisory
	sev, ok := mapSeverity(a.SecurityVulnerability.Severity)
	if !ok {
		sev = severityFromScore(sa.CVSSSeverities.CVSSV3.Score)
	}
	cves := addCVE(nil, sa.CVEID)
	var cwe *int
	for _, c := range sa.CWEs {
		if cwe = cweFromID(c.CWEID); cwe != nil {
			break
		}
	}
	desc := withSection(sa.Description, "Vulnerable range", a.SecurityVulnerability.VulnerableVersionRange)
	if a.SecurityVulnerability.FirstPatchedVersion != nil {
		desc = withSection(desc, "Patched version", a.SecurityVulnerability.FirstPatchedVersion.Identifier)
	}
	ruleID := sa.GHSAID

	meta := map[string]any{"source": "github", "repository": repo, "alert_number": a.Number, "state": a.State,
		"ghsa_id": sa.GHSAID}
	if a.DismissedReason != nil {
		meta["dismissed_reason"] = *a.DismissedReason
		if st, ok := githubDependabotTriage(*a.DismissedReason); ok {
			meta["remote_triage"] = string(st)
			reason := "GitHub Dependabot: " + *a.DismissedReason
			if a.DismissedComment != nil && *a.DismissedComment != "" {
				reason += " — " + *a.DismissedComment
			}
			meta["remote_triage_reason"] = reason
		}
	}
	return finding.Finding{
		Fingerprint: fingerprint(KindGitHub, "dependabot:"+repo+":"+strconv.Itoa(a.Number)),
		Category:    domain.CategorySCA,
		RuleID:      ruleID,
		Title:       sa.Summary,
		Description: desc,
		Severity:    sev,
		CWE:         cwe,
		CVE:         cves,
		FilePath:    a.Dependency.ManifestPath,
		PackageName: a.Dependency.Package.Name,
		URL:         a.HTMLURL,
		Metadata:    meta,
	}
}
