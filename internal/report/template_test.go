package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
)

func TestTemplateValidate(t *testing.T) {
	ok := func() Template {
		return Template{Name: " Pentest ", Sections: []string{SectionDetails, SectionFindings}, AccentColor: "#7C3AED",
			Logo: "data:image/png;base64,iVBORw0KGgo="}
	}
	tpl := ok()
	if err := tpl.Validate(); err != nil {
		t.Fatalf("valid template: %v", err)
	}
	if tpl.Name != "Pentest" || tpl.MinSeverity != domain.SeverityInfo || tpl.MaxFindings != topN {
		t.Errorf("normalized = %q %q %d", tpl.Name, tpl.MinSeverity, tpl.MaxFindings)
	}
	for name, mutate := range map[string]func(*Template){
		"no sections":      func(t *Template) { t.Sections = nil },
		"unknown section":  func(t *Template) { t.Sections = []string{"appendix"} },
		"repeated section": func(t *Template) { t.Sections = []string{SectionSummary, SectionSummary} },
		"css in colour":    func(t *Template) { t.AccentColor = "red;}body{display:none" },
		"html logo":        func(t *Template) { t.Logo = "data:text/html;base64,PHNjcmlwdD4=" },
		"remote logo":      func(t *Template) { t.Logo = "https://evil.example/logo.png" },
		"huge logo":        func(t *Template) { t.Logo = "data:image/png;base64," + strings.Repeat("A", MaxLogoBytes) },
		"bad severity":     func(t *Template) { t.MinSeverity = "urgent" },
		"too many":         func(t *Template) { t.MaxFindings = 501 },
	} {
		tpl := ok()
		mutate(&tpl)
		if tpl.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A row that bypassed validation (hand-edited database) still can't inject
// CSS, a non-image URL or markup: the template funcs re-check every value.
func TestRenderNeutralizesUnvalidatedTemplate(t *testing.T) {
	rep := Report{
		Title: "r",
		Template: Template{
			Sections:       []string{SectionDetails},
			AccentColor:    "red;}body{display:none",
			Logo:           "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
			Classification: "<b>Confidential</b>",
			MaxFindings:    5,
		},
		Top: []TopFinding{{Finding: finding.Finding{Title: "IDOR", Severity: domain.SeverityHigh,
			Metadata: map[string]any{"steps_to_reproduce": "<img src=x onerror=alert(1)>", "impact": 42}}}},
	}
	var buf bytes.Buffer
	if err := Render(&buf, rep); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, bad := range []string{"display:none", "data:text/html", "<b>Confidential", "<img src=x"} {
		if strings.Contains(out, bad) {
			t.Errorf("rendered report contains %q", bad)
		}
	}
	for _, want := range []string{"&lt;b&gt;Confidential&lt;/b&gt;", "Steps to reproduce", "&lt;img src=x"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered report lacks %q", want)
		}
	}
	if strings.Contains(out, "<h4>Impact</h4>") {
		t.Error("a non-string metadata value rendered as a section")
	}
	if strings.Contains(out, "Compliance posture") {
		t.Error("rendered a section the template leaves out")
	}
}
