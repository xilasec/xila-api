package connector

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
)

// DefectDojo API v2, per its source
// (https://github.com/DefectDojo/django-DefectDojo):
//
//   - GET /api/v2/findings/ — filters from dojo/finding/api/filters.py
//     (ApiFindingFilter): `test__engagement__product`, `test__engagement`,
//     `duplicate`, `is_mitigated`, and ordering `o=id`. DRF LimitOffsetPagination:
//     `limit` / `offset` in, {count, next, previous, results} out.
//   - Result fields from dojo/finding/api/serializer.py (FindingSerializer: every
//     Finding model field except `cve`, plus `vulnerability_ids` as
//     [{"vulnerability_id": "CVE-…"}]).
//   - GET /api/v2/products/{id}/ and /api/v2/engagements/{id}/ — the connection test.
//   - Auth: `Authorization: Token <api key>`.
//
// The scope is a product id ("42") or an engagement id ("engagement:42").
//
// A pull asks for every non-duplicate, non-mitigated finding and keeps the
// active ones plus the inactive ones DefectDojo triaged (false positive, risk
// accepted), which carry that verdict over to newly imported findings. Anything
// else — mitigated, out of scope, otherwise inactive — is not reported, so a
// finding resolved in DefectDojo is auto-closed in Xila.
const ddPageSize = 250

type defectDojo struct {
	base, scope, token string
	hc                 *http.Client
	pageSize           int
}

type ddFinding struct {
	ID               int      `json:"id"`
	Title            string   `json:"title"`
	Severity         string   `json:"severity"`
	Description      string   `json:"description"`
	Mitigation       string   `json:"mitigation"`
	CWE              *int     `json:"cwe"`
	CVE              string   `json:"cve"` // DefectDojo < 2.x; newer releases use vulnerability_ids
	VulnerabilityIDs []any    `json:"vulnerability_ids"`
	CVSSV3Score      *float64 `json:"cvssv3_score"`
	ComponentName    string   `json:"component_name"`
	ComponentVersion string   `json:"component_version"`
	FilePath         string   `json:"file_path"`
	Line             *int     `json:"line"`
	UniqueIDFromTool string   `json:"unique_id_from_tool"`
	VulnIDFromTool   string   `json:"vuln_id_from_tool"`
	HashCode         string   `json:"hash_code"`
	Active           bool     `json:"active"`
	Verified         bool     `json:"verified"`
	FalseP           bool     `json:"false_p"`
	RiskAccepted     bool     `json:"risk_accepted"`
	OutOfScope       bool     `json:"out_of_scope"`
	StaticFinding    bool     `json:"static_finding"`
	Test             int      `json:"test"`
}

type ddPage struct {
	Count   int         `json:"count"`
	Results []ddFinding `json:"results"`
}

// scopeFilter is the findings filter and detail path for the configured scope.
func (d *defectDojo) scopeFilter() (param, detail string) {
	if id, ok := strings.CutPrefix(d.scope, "engagement:"); ok {
		return "test__engagement", "engagements/" + id + "/"
	}
	return "test__engagement__product", "products/" + d.scope + "/"
}

func (d *defectDojo) get(ctx context.Context, path string, q url.Values, dst any) error {
	u := d.base + "/api/v2/" + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	_, err := getJSON(ctx, d.hc, u, "Authorization", "Token "+d.token, dst)
	return err
}

func (d *defectDojo) Check(ctx context.Context) (string, error) {
	_, detail := d.scopeFilter()
	var p struct {
		Name string `json:"name"`
	}
	if err := d.get(ctx, detail, nil, &p); err != nil {
		return "", err
	}
	return p.Name, nil
}

func (d *defectDojo) Fetch(ctx context.Context) ([]finding.Finding, error) {
	param, _ := d.scopeFilter()
	id := strings.TrimPrefix(d.scope, "engagement:")
	out := []finding.Finding{}
	seen := map[int]bool{}
	offset := 0
	for page := 0; ; page++ {
		if page >= maxPages {
			return nil, remoteErr("defectdojo: more than %d pages of findings", maxPages)
		}
		q := url.Values{
			param:          {id},
			"duplicate":    {"false"},
			"is_mitigated": {"false"},
			"o":            {"id"},
			"limit":        {strconv.Itoa(d.pageSize)},
			"offset":       {strconv.Itoa(offset)},
		}
		var p ddPage
		if err := d.get(ctx, "findings/", q, &p); err != nil {
			return nil, err
		}
		for _, it := range p.Results {
			if seen[it.ID] {
				continue
			}
			seen[it.ID] = true
			if it.OutOfScope || !(it.Active || it.FalseP || it.RiskAccepted) {
				continue
			}
			out = append(out, d.toFinding(it))
		}
		offset += len(p.Results)
		if len(p.Results) == 0 || offset >= p.Count {
			if len(seen) < p.Count {
				return nil, remoteErr("defectdojo reported %d findings but returned %d", p.Count, len(seen))
			}
			break
		}
	}
	return uniqueByFingerprint(out), nil
}

// Category is the most common finding category (a DefectDojo product mixes
// tools), SAST when there are none.
func (d *defectDojo) Category(fs []finding.Finding) domain.Category {
	return mostCommonCategory(fs, domain.CategorySAST)
}

// ddTriage maps DefectDojo's triage flags onto a Xila verdict, applied only to
// newly imported findings (see RemoteTriage).
func ddTriage(it ddFinding) (domain.FindingStatus, string, bool) {
	switch {
	case it.FalseP:
		return domain.FindingFalsePositive, "DefectDojo: false positive", true
	case it.RiskAccepted:
		return domain.FindingRiskAccepted, "DefectDojo: risk accepted", true
	case it.Active && it.Verified:
		return domain.FindingConfirmed, "DefectDojo: verified", true
	}
	return "", "", false
}

func (d *defectDojo) toFinding(it ddFinding) finding.Finding {
	cves := addCVE(nil, it.CVE)
	ids := []string{}
	for _, raw := range it.VulnerabilityIDs {
		var v string
		switch x := raw.(type) {
		case string:
			v = x
		case map[string]any:
			v, _ = x["vulnerability_id"].(string)
		}
		if v = strings.TrimSpace(v); v != "" {
			ids = append(ids, v)
			cves = addCVE(cves, v)
		}
	}
	if cves == nil {
		cves = []string{}
	}

	category := domain.CategoryDAST
	switch {
	case it.ComponentName != "":
		category = domain.CategorySCA
	case it.StaticFinding || it.FilePath != "":
		category = domain.CategorySAST
	}
	sev, ok := mapSeverity(it.Severity)
	if !ok {
		sev = severityFromScore(it.CVSSV3Score)
	}
	var cwe *int
	if it.CWE != nil && *it.CWE > 0 {
		cwe = it.CWE
	}
	var line *int
	if it.Line != nil && *it.Line > 0 {
		line = it.Line
	}
	rule := it.VulnIDFromTool
	if rule == "" && len(ids) > 0 {
		rule = ids[0]
	}
	link := d.base + "/finding/" + strconv.Itoa(it.ID)

	meta := map[string]any{
		"source":    "defectdojo",
		"remote_id": it.ID,
		"test_id":   it.Test,
		"active":    it.Active,
		"verified":  it.Verified,
	}
	if it.UniqueIDFromTool != "" {
		meta["unique_id_from_tool"] = it.UniqueIDFromTool
	}
	if len(ids) > 0 {
		meta["vulnerability_ids"] = ids
	}
	if st, reason, ok := ddTriage(it); ok {
		meta["remote_triage"] = string(st)
		meta["remote_triage_reason"] = reason
	}

	// hash_code is DefectDojo's own identity for "the same finding" (it survives
	// re-imports, which mint new ids); the id is the fallback.
	key := "id:" + strconv.Itoa(it.ID)
	if it.HashCode != "" {
		key = "hash:" + it.HashCode
	}
	return finding.Finding{
		Fingerprint:    fingerprint(KindDefectDojo, key),
		Category:       category,
		RuleID:         rule,
		Title:          it.Title,
		Description:    withSection(it.Description, "Mitigation", it.Mitigation),
		Severity:       sev,
		CWE:            cwe,
		CVE:            cves,
		FilePath:       it.FilePath,
		Line:           line,
		PackageName:    it.ComponentName,
		PackageVersion: it.ComponentVersion,
		URL:            link,
		CVSS:           it.CVSSV3Score,
		Metadata:       meta,
	}
}
