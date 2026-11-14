package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// maxListed caps how many findings the comment enumerates. A PR comment is read
// in about five seconds; a list of 200 findings is a wall of text people learn to
// scroll past. Show the worst, link to the rest.
const maxListed = 10

// prFinding is the subset of a finding the comment renders.
type prFinding struct {
	ID             string   `json:"id"`
	Title          string   `json:"title"`
	Severity       string   `json:"severity"`
	Priority       float64  `json:"priority"`
	Scanner        string   `json:"scanner"`
	CVE            []string `json:"cve"`
	KEV            bool     `json:"kev"`
	EPSS           *float64 `json:"epss"`
	Package        string   `json:"package_name"`
	PackageVersion string   `json:"package_version"`
	FixedVersion   string   `json:"fixed_version"`
	FilePath       string   `json:"file_path"`
	Line           *int     `json:"line"`
	DepScope       string   `json:"dep_scope"`
	DepDirect      *bool    `json:"dep_direct"`
}

// newFindings fetches what this scan introduced — findings first seen in it,
// worst first. That is the only question a pull request asks: not "how bad is the
// backlog", but "did I make it worse".
func (c *client) newFindings(project, scanID string) ([]prFinding, int, error) {
	q := url.Values{
		"project_id": {project},
		"scan_id":    {scanID},
		"new":        {"true"},
		"sort":       {"priority"},
		"limit":      {fmt.Sprint(maxListed)},
	}
	status, body, err := c.do(http.MethodGet, "/api/v1/findings", "?"+q.Encode(), nil)
	if err != nil {
		return nil, 0, err
	}
	if status != http.StatusOK {
		return nil, 0, fmt.Errorf("findings returned %d: %s", status, apiError(body))
	}
	var resp struct {
		Findings   []prFinding `json:"findings"`
		Pagination struct {
			Count   int  `json:"count"`
			HasMore bool `json:"has_more"`
		} `json:"pagination"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, 0, err
	}
	total := resp.Pagination.Count
	if resp.Pagination.HasMore {
		total = -1 // "more than we listed" — the exact number isn't worth a second call
	}
	return resp.Findings, total, nil
}

// renderComment builds the PR comment. It leads with the verdict, because that is
// the only line most people read.
func renderComment(baseURL, project string, gate *gateResult, findings []prFinding, total int) string {
	var b strings.Builder

	switch {
	case gate == nil:
		b.WriteString("## 🛡️ Xila security report\n\n")
	case gate.Passed:
		b.WriteString("## ✅ Xila security gate passed\n\n")
	default:
		b.WriteString("## ❌ Xila security gate failed\n\n")
	}

	if gate != nil && !gate.Passed {
		for _, v := range gate.Violations {
			b.WriteString("- **" + v.Message + "**\n")
		}
		b.WriteString("\n")
	}

	if len(findings) == 0 {
		b.WriteString("This change introduces **no new findings**. 🎉\n")
	} else {
		noun := "findings"
		if len(findings) == 1 {
			noun = "finding"
		}
		fmt.Fprintf(&b, "This change introduces **%d new %s**", len(findings), noun)
		if total < 0 || total > len(findings) {
			b.WriteString(" (showing the highest priority)")
		}
		b.WriteString(":\n\n")

		b.WriteString("| Severity | Finding | Package | Fix |\n")
		b.WriteString("| --- | --- | --- | --- |\n")
		for _, f := range findings {
			b.WriteString("| " + severityBadge(f.Severity) + flags(f) +
				" | " + findingLink(baseURL, f) +
				" | " + packageCell(f) +
				" | " + fixCell(f) + " |\n")
		}
		b.WriteString("\n")
	}

	if gate != nil {
		s := gate.Stats
		fmt.Fprintf(&b, "<sub>Backlog: %d critical · %d high · %d KEV · %d license · max EPSS %.1f%% · risk %.1f",
			s.OpenCritical, s.OpenHigh, s.OpenKEV, s.OpenLicense, s.MaxEPSS*100, s.RiskScore)
		if gate.NewOnly {
			b.WriteString(" · gate scoped to new findings")
			if gate.Baseline != "" {
				b.WriteString(" (baseline: " + gate.Baseline + ")")
			}
		}
		b.WriteString("</sub>\n")
	}
	if baseURL != "" && project != "" {
		fmt.Fprintf(&b, "\n<sub>[Open in Xila](%s/projects/%s)</sub>\n",
			strings.TrimSuffix(baseURL, "/"), project)
	}
	return b.String()
}

func severityBadge(sev string) string {
	switch sev {
	case "critical":
		return "🔴 critical"
	case "high":
		return "🟠 high"
	case "medium":
		return "🟡 medium"
	case "low":
		return "⚪ low"
	}
	return sev
}

// flags surface the two facts that change what a developer does *right now*:
// the vulnerability is being exploited in the wild, or the dependency can't
// actually reach production.
func flags(f prFinding) string {
	var out strings.Builder
	if f.KEV {
		out.WriteString(" **KEV**")
	} else if f.EPSS != nil && *f.EPSS >= 0.1 {
		fmt.Fprintf(&out, " EPSS %.0f%%", *f.EPSS*100)
	}
	if f.DepScope == "dev" {
		out.WriteString(" · dev-only")
	} else if f.DepDirect != nil && !*f.DepDirect {
		out.WriteString(" · transitive")
	}
	return out.String()
}

func findingLink(baseURL string, f prFinding) string {
	title := escapePipes(f.Title)
	if len(f.CVE) > 0 && !strings.Contains(title, f.CVE[0]) {
		title = f.CVE[0] + ": " + title
	}
	if f.FilePath != "" && f.Package == "" {
		loc := f.FilePath
		if f.Line != nil {
			loc = fmt.Sprintf("%s:%d", loc, *f.Line)
		}
		title += "<br><sub>`" + escapePipes(loc) + "`</sub>"
	}
	if baseURL == "" {
		return title
	}
	return fmt.Sprintf("[%s](%s/findings/%s)", title, strings.TrimSuffix(baseURL, "/"), f.ID)
}

func packageCell(f prFinding) string {
	if f.Package == "" {
		return "—"
	}
	if f.PackageVersion == "" {
		return "`" + escapePipes(f.Package) + "`"
	}
	return "`" + escapePipes(f.Package+"@"+f.PackageVersion) + "`"
}

// fixCell is the most actionable cell in the table: the version to upgrade to.
func fixCell(f prFinding) string {
	if f.FixedVersion == "" {
		return "—"
	}
	return "`" + escapePipes(f.FixedVersion) + "`"
}

// escapePipes keeps a title containing "|" from breaking the markdown table.
func escapePipes(s string) string { return strings.ReplaceAll(s, "|", "\\|") }
