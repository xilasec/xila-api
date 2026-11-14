package scanner

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Burp parses Burp Suite's XML issue export (Target → Site map → "Report
// selected issues" → XML, or Burp Enterprise/DAST's XML report). Each <issue>
// is one finding; Burp's numeric issue type ("1049088" = SQL injection) is the
// rule id, stable across scans and Burp versions. Issues the tester marked as
// "False positive" are dropped. The request/response pairs are not stored —
// they are large, base64 and frequently carry session tokens.
type Burp struct{}

// NewBurp constructs a Burp Suite parser.
func NewBurp() Burp { return Burp{} }

// Scanner returns the tool identifier.
func (Burp) Scanner() string { return "burp" }

// PrimaryCategory is the scan-level category for Burp reports.
func (Burp) PrimaryCategory() domain.Category { return domain.CategoryDAST }

type burpReport struct {
	XMLName     xml.Name `xml:"issues"`
	BurpVersion string   `xml:"burpVersion,attr"`
	Issues      []struct {
		SerialNumber string `xml:"serialNumber"`
		Type         string `xml:"type"`
		Name         string `xml:"name"`
		Host         struct {
			URL string `xml:",chardata"`
			IP  string `xml:"ip,attr"`
		} `xml:"host"`
		Path                  string   `xml:"path"`
		Location              string   `xml:"location"`
		Severity              string   `xml:"severity"`
		Confidence            string   `xml:"confidence"`
		IssueBackground       string   `xml:"issueBackground"`
		RemediationBackground string   `xml:"remediationBackground"`
		References            string   `xml:"references"`
		VulnClassifications   string   `xml:"vulnerabilityClassifications"`
		IssueDetail           string   `xml:"issueDetail"`
		IssueDetailItems      []string `xml:"issueDetailItems>issueDetailItem"`
		RemediationDetail     string   `xml:"remediationDetail"`
	} `xml:"issue"`
}

// Parse implements Parser.
func (Burp) Parse(r io.Reader) ([]ParsedFinding, error) {
	var rep burpReport
	if err := xml.NewDecoder(r).Decode(&rep); err != nil {
		return nil, fmt.Errorf("decode burp xml: %w", err)
	}

	out := make([]ParsedFinding, 0, len(rep.Issues))
	for _, is := range rep.Issues {
		if strings.EqualFold(strings.TrimSpace(is.Severity), "false positive") {
			continue
		}
		host := strings.TrimRight(strings.TrimSpace(is.Host.URL), "/")
		detail := strings.TrimSpace(stripTags(is.IssueDetail) + "\n" + strings.Join(is.IssueDetailItems, "\n"))
		f := ParsedFinding{
			Category:    domain.CategoryDAST,
			RuleID:      strings.TrimSpace(is.Type),
			Title:       strings.TrimSpace(is.Name),
			Description: strings.TrimSpace(detail + "\n\n" + stripTags(is.IssueBackground)),
			Severity:    normalizeSeverity(is.Severity), // High / Medium / Low / Information
			CVE:         cvesInText(is.IssueDetail, strings.Join(is.IssueDetailItems, " "), is.References, is.VulnClassifications),
			// The URL the issue was proven on. Burp's location adds the insertion
			// point ("/basket.jsp [b_id cookie]"), which keeps one issue type found
			// in two parameters of the same page as two findings.
			FilePath: host + firstNonEmpty(strings.TrimSpace(is.Location), strings.TrimSpace(is.Path)),
			URL:      host,
			Metadata: map[string]any{
				"confidence":  strings.TrimSpace(is.Confidence),
				"path":        strings.TrimSpace(is.Path),
				"remediation": stripTags(firstNonEmpty(is.RemediationDetail, is.RemediationBackground)),
				"ip":          is.Host.IP,
			},
		}
		if m := cweRe.FindStringSubmatch(is.VulnClassifications); m != nil {
			f.CWE = cweFrom(m[1])
		}
		out = append(out, f)
	}
	return mergeSameLocation(out), nil
}
