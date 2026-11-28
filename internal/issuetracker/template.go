package issuetracker

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"text/template" // nosemgrep: go.lang.security.audit.xss.import-text-template.import-text-template -- renders plain issue text sent as JSON to tracker APIs, never served as HTML; html/template would put &amp; / &#39; into every ticket

	"github.com/xilasec/xila-api/internal/finding"
)

// maxTemplate bounds a stored template's source; maxRendered bounds what one
// renders, so a template looping over its data can't build a huge issue.
const (
	maxTemplate = 10000
	maxRendered = 64 << 10
)

// TemplateData is what a ticket template sees (M13 13.18): flat strings and
// numbers, never the finding struct, so a template can't reach a method or a
// field added later. Default is the built-in body, for templates that only
// add to it.
type TemplateData struct {
	ID, Title, Description, Severity, Status, Scanner, RuleID  string
	Package, PackageVersion, FixedVersion, FilePath, Reference string
	Line, CWE                                                  int
	CVEs                                                       []string
	CVSS, EPSS                                                 float64
	KEV                                                        bool
	XilaURL, Default                                           string
}

func templateData(f finding.Finding, publicURL, defaultBody string) TemplateData {
	d := TemplateData{
		ID: f.ID, Title: f.Title, Description: f.Description, Severity: string(f.Severity), Status: string(f.Status),
		Scanner: f.Scanner, RuleID: f.RuleID, Package: f.PackageName, PackageVersion: f.PackageVersion,
		FixedVersion: f.FixedVersion, FilePath: f.FilePath, Reference: f.URL, CVEs: f.CVE, KEV: f.KEV,
		Default: defaultBody,
	}
	if d.CVEs == nil {
		d.CVEs = []string{}
	}
	if f.Line != nil {
		d.Line = *f.Line
	}
	if f.CWE != nil {
		d.CWE = *f.CWE
	}
	if f.CVSS != nil {
		d.CVSS = *f.CVSS
	}
	if f.EPSS != nil {
		d.EPSS = *f.EPSS
	}
	if publicURL != "" {
		d.XilaURL = publicURL + "/findings/" + f.ID
	}
	return d
}

var templateFuncs = template.FuncMap{
	"join": strings.Join,
	"default": func(fallback, v string) string {
		if strings.TrimSpace(v) == "" {
			return fallback
		}
		return v
	},
}

// parseTemplate compiles one ticket template ("" = none).
func parseTemplate(name, src string) (*template.Template, error) {
	if strings.TrimSpace(src) == "" {
		return nil, nil
	}
	if len(src) > maxTemplate {
		return nil, errors.New("at most " + strconv.Itoa(maxTemplate) + " characters")
	}
	return template.New(name).Funcs(templateFuncs).Option("missingkey=error").Parse(src)
}

// errTooLong stops a render that outgrew maxRendered.
var errTooLong = errors.New("renders more than " + strconv.Itoa(maxRendered>>10) + " KiB")

type cappedBuffer struct{ bytes.Buffer }

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > maxRendered {
		return 0, errTooLong
	}
	return b.Buffer.Write(p)
}

func render(t *template.Template, d TemplateData) (string, error) {
	var b cappedBuffer
	if err := t.Execute(&b, d); err != nil {
		return "", err
	}
	return b.String(), nil
}

// sampleFinding is what a template is checked against when it is saved: every
// field set, so a template that fails here fails on a real finding too.
func sampleFinding() finding.Finding {
	line, cwe, cvss, epss := 42, 79, 7.5, 0.12
	return finding.Finding{
		ID: "00000000-0000-4000-8000-000000000000", Title: "Sample finding", Description: "Sample description.",
		Severity: "high", Status: "open", Scanner: "trivy", RuleID: "CVE-2024-0001", PackageName: "lodash",
		PackageVersion: "4.17.20", FixedVersion: "4.17.21", FilePath: "package-lock.json", Line: &line,
		CVE: []string{"CVE-2024-0001"}, CWE: &cwe, CVSS: &cvss, EPSS: &epss, KEV: true, URL: "https://example.com/advisory",
	}
}

// checkTemplates validates a tracker's templates by rendering the sample.
func checkTemplates(t Tracker) error {
	for _, tpl := range []struct{ name, src string }{{"title_template", t.TitleTemplate}, {"body_template", t.BodyTemplate}} {
		parsed, err := parseTemplate(tpl.name, tpl.src)
		if err != nil {
			return invalid("%s: %v", tpl.name, err)
		}
		if parsed == nil {
			continue
		}
		if _, err := render(parsed, templateData(sampleFinding(), "https://xila.example", "")); err != nil {
			return invalid("%s: %v", tpl.name, err)
		}
	}
	return nil
}
