package connector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
)

// Snyk REST API, per its reference
// (https://docs.snyk.io/developer-tools/snyk-api/reference/issues and
// https://docs.snyk.io/developer-tools/snyk-api/about-the-rest-api):
//
//   - GET /orgs/{org_id}/issues?version=2024-10-15 — a JSON:API page of issues
//     (SCA "package_vulnerability", Snyk Code "code", IaC+ "config" and license
//     issues, all through the one unified endpoint since the GA Issues API).
//     `scan_item.id`/`scan_item.type=project` narrows to one project.
//     Pagination is cursor-based: follow `links.next` (a path carrying
//     `starting_after`) until it is absent.
//   - GET /orgs/{org_id} — the connection test.
//   - Auth: `Authorization: token <api token>`.
//
// Each issue's `attributes.ignored` flag (confirmed in Snyk's published
// examples, e.g. the Cloud/Code/Open Source list-issues responses) carries the
// ignore over as a remote triage verdict; `attributes.status` "resolved" means
// the issue is fixed and is not fetched, so the next pull auto-closes it.
const (
	snykVersion  = "2024-10-15"
	snykPageSize = 100
)

type snyk struct {
	base, scope, token string
	hc                 *http.Client
	pageSize           int
}

// scope splits "<org_id>" or "<org_id>:<project_id>".
func (s *snyk) org() string {
	org, _, _ := strings.Cut(s.scope, ":")
	return org
}

func (s *snyk) project() (id string, ok bool) {
	_, id, ok = strings.Cut(s.scope, ":")
	return id, ok
}

type snykIssue struct {
	ID         string `json:"id"`
	Attributes struct {
		Title                  string `json:"title"`
		Type                   string `json:"type"`
		Description            string `json:"description"`
		EffectiveSeverityLevel string `json:"effective_severity_level"`
		Ignored                bool   `json:"ignored"`
		Status                 string `json:"status"`
		Key                    string `json:"key"`
		Problems               []struct {
			ID     string `json:"id"`
			Source string `json:"source"`
			URL    string `json:"url"`
		} `json:"problems"`
		Severities []struct {
			Score *float64 `json:"score"`
			Type  string   `json:"type"`
		} `json:"severities"`
		Coordinates []struct {
			Representations []struct {
				Package *struct {
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
					Type      string `json:"type"`
					URL       string `json:"url"`
					Version   string `json:"version"`
				} `json:"package"`
				ResourcePath string `json:"resource_path"`
			} `json:"representations"`
			Remedies []struct {
				Description string `json:"description"`
				Details     struct {
					UpgradePackage string `json:"upgrade_package"`
				} `json:"details"`
			} `json:"remedies"`
		} `json:"coordinates"`
	} `json:"attributes"`
}

type snykPage struct {
	Data  []snykIssue `json:"data"`
	Links struct {
		Next json.RawMessage `json:"next"`
	} `json:"links"`
}

// snykLink decodes a JSON:API link, which is either a bare string or an
// {href, meta} object.
func snykLink(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var obj struct {
		Href string `json:"href"`
	}
	_ = json.Unmarshal(raw, &obj)
	return obj.Href
}

func (s *snyk) get(ctx context.Context, path string, q url.Values, dst any) error {
	if q == nil {
		q = url.Values{}
	}
	if q.Get("version") == "" {
		q.Set("version", snykVersion)
	}
	u := s.base + "/rest/" + path + "?" + q.Encode()
	_, err := httpJSON(ctx, s.hc, http.MethodGet, u, map[string]string{"Authorization": "token " + s.token}, nil, dst)
	return err
}

// resolveNext turns a `links.next` value (an absolute URL, or a path that may
// or may not already carry the "/rest" prefix the REST API's examples show
// inconsistently truncated) into the full request URL.
func (s *snyk) resolveNext(link string) string {
	if strings.HasPrefix(link, "http://") || strings.HasPrefix(link, "https://") {
		return link
	}
	if !strings.HasPrefix(link, "/") {
		link = "/" + link
	}
	if strings.HasPrefix(link, "/rest/") {
		return s.base + link
	}
	return s.base + "/rest" + link
}

func (s *snyk) Check(ctx context.Context) (string, error) {
	var org struct {
		Data struct {
			Attributes struct {
				Name string `json:"name"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := s.get(ctx, "orgs/"+url.PathEscape(s.org()), nil, &org); err != nil {
		return "", err
	}
	return org.Data.Attributes.Name, nil
}

func (s *snyk) Fetch(ctx context.Context) ([]finding.Finding, error) {
	out := []finding.Finding{}
	next := ""
	for page := 0; ; page++ {
		if page >= maxPages {
			return nil, remoteErr("snyk: more than %d pages of issues", maxPages)
		}
		var p snykPage
		if next == "" {
			q := url.Values{"limit": {strconv.Itoa(s.pageSize)}}
			if projectID, ok := s.project(); ok && projectID != "" {
				q.Set("scan_item.id", projectID)
				q.Set("scan_item.type", "project")
			}
			if err := s.get(ctx, "orgs/"+url.PathEscape(s.org())+"/issues", q, &p); err != nil {
				return nil, err
			}
		} else {
			if _, err := httpJSON(ctx, s.hc, http.MethodGet, s.resolveNext(next),
				map[string]string{"Authorization": "token " + s.token}, nil, &p); err != nil {
				return nil, err
			}
		}
		for _, it := range p.Data {
			if it.Attributes.Status == "resolved" {
				continue
			}
			out = append(out, s.toFinding(it))
		}
		next = snykLink(p.Links.Next)
		if next == "" {
			break
		}
	}
	return uniqueByFingerprint(out), nil
}

// Category is the most common issue type (SCA, code, IaC+, license all share
// one org), SCA when there are none — most Snyk orgs are open-source heavy.
func (s *snyk) Category(fs []finding.Finding) domain.Category {
	return mostCommonCategory(fs, domain.CategorySCA)
}

// snykCategory maps an issue's `attributes.type` onto ours.
func snykCategory(packageType, issueType string) domain.Category {
	switch issueType {
	case "code":
		return domain.CategorySAST
	case "config":
		return domain.CategoryIaC
	case "license":
		return domain.CategoryLicense
	case "cloud":
		return domain.CategoryCloud
	}
	switch packageType {
	case "deb", "rpm", "apk":
		return domain.CategoryContainer
	}
	return domain.CategorySCA
}

func (s *snyk) toFinding(it snykIssue) finding.Finding {
	a := it.Attributes

	var cves []string
	var cwe *int
	for _, p := range a.Problems {
		cves = addCVE(cves, p.ID)
		if cwe == nil {
			cwe = cweFromID(p.ID)
		}
	}
	if cves == nil {
		cves = []string{}
	}

	sev, ok := mapSeverity(a.EffectiveSeverityLevel)
	var cvss *float64
	for _, sc := range a.Severities {
		if sc.Score == nil {
			continue
		}
		if sc.Type == "primary" || cvss == nil {
			cvss = sc.Score
		}
	}
	if !ok {
		sev = severityFromScore(cvss)
	}

	var pkgName, pkgVersion, purl, filePath, fix string
	packageType := ""
	for _, c := range a.Coordinates {
		for _, r := range c.Representations {
			if r.Package != nil && pkgName == "" {
				pkgName = r.Package.Namespace
				if pkgName != "" {
					pkgName += "/"
				}
				pkgName += r.Package.Name
				pkgVersion = r.Package.Version
				purl = r.Package.URL
				packageType = r.Package.Type
			}
			if r.ResourcePath != "" && filePath == "" {
				filePath = r.ResourcePath
			}
		}
		for _, r := range c.Remedies {
			if fix == "" {
				fix = r.Details.UpgradePackage
				if fix == "" {
					fix = r.Description
				}
			}
		}
	}

	meta := map[string]any{
		"source":   "snyk",
		"issue_id": it.ID,
		"key":      a.Key,
		"type":     a.Type,
		"status":   a.Status,
		"ignored":  a.Ignored,
	}
	if a.Ignored {
		meta["remote_triage"] = string(domain.FindingWontFix)
		meta["remote_triage_reason"] = "Snyk: ignored"
	}

	identity := a.Key
	if identity == "" {
		identity = it.ID
	}
	title := a.Title
	if pkgName != "" {
		title = title + " (" + pkgName
		if pkgVersion != "" {
			title += " " + pkgVersion
		}
		title += ")"
	}
	return finding.Finding{
		Fingerprint:    fingerprint(KindSnyk, identity),
		Category:       snykCategory(packageType, a.Type),
		RuleID:         it.ID,
		Title:          title,
		Description:    withSection(a.Description, "Fix", fix),
		Severity:       sev,
		CWE:            cwe,
		CVE:            cves,
		FilePath:       filePath,
		PackageName:    pkgName,
		PackageVersion: pkgVersion,
		Purl:           purl,
		CVSS:           cvss,
		Metadata:       meta,
	}
}

// snykProjectFilter validates the optional ":<project_id>" suffix of a scope.
func snykProjectFilter(scope string) error {
	org, proj, ok := strings.Cut(scope, ":")
	if _, err := uuid.Parse(org); err != nil {
		return invalid("remote_project must be the Snyk org id, optionally \":<project id>\"")
	}
	if ok {
		if _, err := uuid.Parse(proj); err != nil {
			return invalid("remote_project's project id must be a UUID")
		}
	}
	return nil
}
