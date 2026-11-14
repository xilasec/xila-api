package connector

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
)

// Dependency-Track REST API v1, per its OpenAPI spec
// (https://github.com/DependencyTrack/docs/blob/main/docs/reference/api/openapi-v1.yaml):
//
//   - GET /api/v1/project/{uuid}          (getProject) — the connection test.
//   - GET /api/v1/finding/project/{uuid}  (getFindingsByProject) — a JSON array of
//     findings; `suppressed=true` includes suppressed ones, `pageNumber` /
//     `pageSize` page it and the `X-Total-Count` header carries the total.
//     Requires the VIEW_VULNERABILITY permission.
//   - Auth: the `X-Api-Key` header (ApiKeyAuth).
//
// A finding is {component, vulnerability, analysis, attribution, matrix}; the
// field names follow the Finding Packaging Format
// (https://docs.dependencytrack.org/integrations/file-formats/) and the server's
// org.dependencytrack.model.Finding.
const dtPageSize = 500

type dependencyTrack struct {
	base, project, token string
	hc                   *http.Client
	pageSize             int
}

type dtFinding struct {
	Component struct {
		UUID    string `json:"uuid"`
		Name    string `json:"name"`
		Group   string `json:"group"`
		Version string `json:"version"`
		Purl    string `json:"purl"`
	} `json:"component"`
	Vulnerability struct {
		UUID            string   `json:"uuid"`
		Source          string   `json:"source"`
		VulnID          string   `json:"vulnId"`
		Title           string   `json:"title"`
		Description     string   `json:"description"`
		Recommendation  string   `json:"recommendation"`
		Severity        string   `json:"severity"`
		CVSSV2BaseScore *float64 `json:"cvssV2BaseScore"`
		CVSSV3BaseScore *float64 `json:"cvssV3BaseScore"`
		CWEID           *int     `json:"cweId"`
		CWEs            []struct {
			CWEID int    `json:"cweId"`
			Name  string `json:"name"`
		} `json:"cwes"`
		Aliases []struct {
			CveID  string `json:"cveId"`
			GhsaID string `json:"ghsaId"`
		} `json:"aliases"`
	} `json:"vulnerability"`
	Analysis struct {
		State        string `json:"state"`
		IsSuppressed bool   `json:"isSuppressed"`
	} `json:"analysis"`
	Attribution struct {
		ReferenceURL string `json:"referenceUrl"`
	} `json:"attribution"`
	Matrix string `json:"matrix"`
}

func (d *dependencyTrack) get(ctx context.Context, path string, q url.Values, dst any) (http.Header, error) {
	u := d.base + "/api/v1/" + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	return getJSON(ctx, d.hc, u, "X-Api-Key", d.token, dst)
}

func (d *dependencyTrack) Check(ctx context.Context) (string, error) {
	var p struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if _, err := d.get(ctx, "project/"+url.PathEscape(d.project), nil, &p); err != nil {
		return "", err
	}
	return strings.TrimSpace(p.Name + " " + p.Version), nil
}

func (d *dependencyTrack) Fetch(ctx context.Context) ([]finding.Finding, error) {
	seen := map[string]bool{}
	out := []finding.Finding{}
	total := -1
	for page := 1; ; page++ {
		if page > maxPages {
			return nil, remoteErr("dependency-track: more than %d pages of findings", maxPages)
		}
		q := url.Values{
			"suppressed": {"true"},
			"pageNumber": {strconv.Itoa(page)},
			"pageSize":   {strconv.Itoa(d.pageSize)},
		}
		var items []dtFinding
		hdr, err := d.get(ctx, "finding/project/"+url.PathEscape(d.project), q, &items)
		if err != nil {
			return nil, err
		}
		if n, err := strconv.Atoi(hdr.Get("X-Total-Count")); err == nil {
			total = n
		}
		added := 0
		for _, it := range items {
			key := it.Matrix
			if key == "" {
				key = it.Component.UUID + ":" + it.Vulnerability.UUID
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			added++
			out = append(out, d.toFinding(it))
		}
		// Stop at the reported total, on a short page, or when a page brings
		// nothing new (a server that ignores paging returns everything at once).
		if (total >= 0 && len(seen) >= total) || len(items) < d.pageSize || added == 0 {
			break
		}
	}
	if total >= 0 && len(seen) < total {
		return nil, remoteErr("dependency-track reported %d findings but returned %d", total, len(seen))
	}
	return uniqueByFingerprint(out), nil
}

func (d *dependencyTrack) Category([]finding.Finding) domain.Category { return domain.CategorySCA }

// dtPackageName names the component the way scanners do, so cross-tool dedup
// (CVE + package) groups it with their reports: Maven coordinates as
// group:artifact, other namespaces (npm scopes, Go modules…) as group/name.
func dtPackageName(group, name, purl string) string {
	switch {
	case group == "":
		return name
	case strings.HasPrefix(purl, "pkg:maven/"):
		return group + ":" + name
	}
	return group + "/" + name
}

// dtTriage maps an analysis state onto a Xila triage verdict, applied only to
// newly imported findings (see RemoteTriage).
func dtTriage(state string) (domain.FindingStatus, bool) {
	switch state {
	case "FALSE_POSITIVE", "NOT_AFFECTED":
		return domain.FindingFalsePositive, true
	case "EXPLOITABLE":
		return domain.FindingConfirmed, true
	}
	return "", false
}

func (d *dependencyTrack) toFinding(it dtFinding) finding.Finding {
	v, c := it.Vulnerability, it.Component
	pkg := dtPackageName(c.Group, c.Name, c.Purl)

	cves := addCVE(nil, v.VulnID)
	for _, a := range v.Aliases {
		cves = addCVE(cves, a.CveID)
	}
	if cves == nil {
		cves = []string{}
	}
	cvss := v.CVSSV3BaseScore
	if cvss == nil {
		cvss = v.CVSSV2BaseScore
	}
	sev, ok := mapSeverity(v.Severity)
	if !ok {
		sev = severityFromScore(cvss)
	}
	cwe := v.CWEID
	cweIDs := make([]int, 0, len(v.CWEs))
	for _, w := range v.CWEs {
		cweIDs = append(cweIDs, w.CWEID)
	}
	if cwe == nil && len(cweIDs) > 0 {
		cwe = new(cweIDs[0])
	}
	title := v.Title
	if title == "" {
		title = v.VulnID
	}

	meta := map[string]any{
		"source":         "dependency-track",
		"remote_id":      it.Matrix,
		"vuln_source":    v.Source,
		"component_uuid": c.UUID,
		"analysis_state": it.Analysis.State,
		"suppressed":     it.Analysis.IsSuppressed,
	}
	if len(cweIDs) > 1 {
		meta["cwes"] = cweIDs
	}
	if st, ok := dtTriage(it.Analysis.State); ok {
		meta["remote_triage"] = string(st)
		meta["remote_triage_reason"] = "Dependency-Track analysis: " + it.Analysis.State
	}

	identity := v.Source + ":" + v.VulnID + "|" + c.Purl
	if c.Purl == "" {
		identity = v.Source + ":" + v.VulnID + "|" + pkg + "@" + c.Version
	}
	return finding.Finding{
		Fingerprint:    fingerprint(KindDependencyTrack, identity),
		Category:       domain.CategorySCA,
		RuleID:         v.VulnID,
		Title:          fmt.Sprintf("%s (%s %s)", title, pkg, c.Version),
		Description:    withSection(v.Description, "Recommendation", v.Recommendation),
		Severity:       sev,
		CWE:            cwe,
		CVE:            cves,
		PackageName:    pkg,
		PackageVersion: c.Version,
		Purl:           c.Purl,
		URL:            it.Attribution.ReferenceURL,
		CVSS:           cvss,
		Metadata:       meta,
	}
}
