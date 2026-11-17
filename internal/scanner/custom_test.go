package scanner

import (
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

func TestCustomParserCSV(t *testing.T) {
	def := CustomDefinition{
		Name:     "custom-csv",
		Category: domain.CategorySCA,
		Format:   CustomFormatCSV,
		Fields: map[CustomFieldKey]CustomFieldMap{
			CFTitle:    {Path: "Name"},
			CFSeverity: {Path: "Sev", ValueMap: map[string]string{"4": "critical", "Sev3": "medium"}},
			CFCVE:      {Path: "Notes"},
			CFFilePath: {Path: "File"},
		},
	}
	p, err := NewCustomParser(def)
	if err != nil {
		t.Fatalf("NewCustomParser: %v", err)
	}
	csv := "Name,Sev,Notes,File\n" +
		"Outdated lib,4,see CVE-2021-44228,package.json\n" +
		"Weak cipher,Sev3,no CVE here,config.yaml\n" +
		"Unranked,strange,,other.txt\n"
	findings, err := p.Parse(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("len(findings) = %d, want 3: %+v", len(findings), findings)
	}
	if findings[0].Severity != domain.SeverityCritical || findings[0].Title != "Outdated lib" {
		t.Errorf("row0 = %+v", findings[0])
	}
	if len(findings[0].CVE) != 1 || findings[0].CVE[0] != "CVE-2021-44228" {
		t.Errorf("row0 CVE = %v, want [CVE-2021-44228]", findings[0].CVE)
	}
	if findings[1].Severity != domain.SeverityMedium {
		t.Errorf("row1 severity = %v, want medium (value map Sev3)", findings[1].Severity)
	}
	// "strange" isn't in the value map, so it falls through to normalizeSeverity,
	// which defaults unknown text to medium.
	if findings[2].Severity != domain.SeverityMedium {
		t.Errorf("row2 severity = %v, want medium (normalizeSeverity fallback)", findings[2].Severity)
	}
}

func TestCustomParserJSONNestedArray(t *testing.T) {
	def := CustomDefinition{
		Name:           "custom-json-nested",
		Category:       domain.CategorySAST,
		Format:         CustomFormatJSON,
		RecordSelector: "runs.0.results",
		Fields: map[CustomFieldKey]CustomFieldMap{
			CFTitle:    {Template: "{rule} in {component}"},
			CFSeverity: {Path: "severity"},
			CFRuleID:   {Path: "rule"},
			CFCWE:      {Path: "cwe"},
		},
	}
	p, err := NewCustomParser(def)
	if err != nil {
		t.Fatalf("NewCustomParser: %v", err)
	}
	body := `{
		"runs": [
			{"results": [
				{"rule": "no-eval", "component": "app.js", "severity": "high", "cwe": "CWE-95"},
				{"rule": "sql-injection", "component": "db.go", "severity": "critical", "cwe": "89"}
			]}
		]
	}`
	findings, err := p.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("len(findings) = %d, want 2: %+v", len(findings), findings)
	}
	if findings[0].Title != "no-eval in app.js" {
		t.Errorf("title = %q, want template expansion", findings[0].Title)
	}
	if findings[0].Severity != domain.SeverityHigh {
		t.Errorf("severity = %v, want high", findings[0].Severity)
	}
	if findings[0].CWE == nil || *findings[0].CWE != 95 {
		t.Errorf("cwe = %v, want 95", findings[0].CWE)
	}
	if findings[1].Severity != domain.SeverityCritical {
		t.Errorf("severity = %v, want critical", findings[1].Severity)
	}
	if findings[1].CWE == nil || *findings[1].CWE != 89 {
		t.Errorf("cwe = %v, want 89", findings[1].CWE)
	}
}

func TestCustomParserJSONTopLevelArray(t *testing.T) {
	def := CustomDefinition{
		Name:           "custom-json-top",
		Category:       domain.CategorySCA,
		Format:         CustomFormatJSON,
		RecordSelector: "$",
		Fields: map[CustomFieldKey]CustomFieldMap{
			CFTitle: {Path: "name"},
			CFCVSS:  {Path: "score"},
		},
	}
	p, err := NewCustomParser(def)
	if err != nil {
		t.Fatalf("NewCustomParser: %v", err)
	}
	body := `[{"name": "finding A", "score": 9.5}, {"name": "finding B", "score": 3.1}]`
	findings, err := p.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("len(findings) = %d, want 2", len(findings))
	}
	if findings[0].Severity != domain.SeverityCritical {
		t.Errorf("severity = %v, want critical (from cvss 9.5)", findings[0].Severity)
	}
	if findings[0].CVSS == nil || *findings[0].CVSS != 9.5 {
		t.Errorf("cvss = %v, want 9.5", findings[0].CVSS)
	}
	if findings[1].Severity != domain.SeverityLow {
		t.Errorf("severity = %v, want low (from cvss 3.1)", findings[1].Severity)
	}
}

func TestCustomParserXML(t *testing.T) {
	def := CustomDefinition{
		Name:           "custom-xml",
		Category:       domain.CategoryDAST,
		Format:         CustomFormatXML,
		RecordSelector: "report/item",
		Fields: map[CustomFieldKey]CustomFieldMap{
			CFTitle:    {Path: "name"},
			CFSeverity: {Path: "@level"},
			CFURL:      {Path: "url"},
			CFCVE:      {Path: "refs"},
		},
	}
	p, err := NewCustomParser(def)
	if err != nil {
		t.Fatalf("NewCustomParser: %v", err)
	}
	body := `<report>
		<item level="High">
			<name>XSS in search</name>
			<url>https://example.test/search</url>
			<refs>see CVE-2020-1234 and CVE-2020-5678</refs>
		</item>
		<item level="Low">
			<name>Missing header</name>
			<url>https://example.test/</url>
			<refs></refs>
		</item>
	</report>`
	findings, err := p.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("len(findings) = %d, want 2: %+v", len(findings), findings)
	}
	if findings[0].Title != "XSS in search" || findings[0].Severity != domain.SeverityHigh {
		t.Errorf("item0 = %+v", findings[0])
	}
	if len(findings[0].CVE) != 2 {
		t.Errorf("item0 CVE = %v, want 2 ids lifted from prose", findings[0].CVE)
	}
	if findings[1].Severity != domain.SeverityLow {
		t.Errorf("item1 severity = %v, want low", findings[1].Severity)
	}
}

// A report that tries to declare an external entity never gets it resolved:
// Go's encoding/xml has no DTD/external-entity support at all, so this fails
// to decode (a safe failure) rather than leaking anything.
func TestCustomParserXMLNoExternalEntities(t *testing.T) {
	def := CustomDefinition{
		Name:           "custom-xxe",
		Category:       domain.CategoryDAST,
		Format:         CustomFormatXML,
		RecordSelector: "report/item",
		Fields:         map[CustomFieldKey]CustomFieldMap{CFTitle: {Path: "name"}},
	}
	p, err := NewCustomParser(def)
	if err != nil {
		t.Fatalf("NewCustomParser: %v", err)
	}
	body := `<?xml version="1.0"?>
	<!DOCTYPE report [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
	<report><item><name>&xxe;</name></item></report>`
	if _, err := p.Parse(strings.NewReader(body)); err == nil {
		t.Fatal("Parse: want a decode error for an undefined external entity, not silent resolution")
	}
}

func TestCustomParserInvalidDefinitions(t *testing.T) {
	cases := map[string]CustomDefinition{
		"bad name": {
			Name: "Not-A-Slug", Category: domain.CategorySCA, Format: CustomFormatCSV,
			Fields: map[CustomFieldKey]CustomFieldMap{CFTitle: {Path: "x"}},
		},
		"unknown category": {
			Name: "my-parser", Category: domain.Category("nope"), Format: CustomFormatCSV,
			Fields: map[CustomFieldKey]CustomFieldMap{CFTitle: {Path: "x"}},
		},
		"unknown format": {
			Name: "my-parser", Category: domain.CategorySCA, Format: CustomFormat("yaml"),
			Fields: map[CustomFieldKey]CustomFieldMap{CFTitle: {Path: "x"}},
		},
		"missing title": {
			Name: "my-parser", Category: domain.CategorySCA, Format: CustomFormatCSV,
			Fields: map[CustomFieldKey]CustomFieldMap{CFSeverity: {Path: "x"}},
		},
		"unknown field": {
			Name: "my-parser", Category: domain.CategorySCA, Format: CustomFormatCSV,
			Fields: map[CustomFieldKey]CustomFieldMap{CFTitle: {Path: "x"}, "bogus": {Path: "y"}},
		},
		"value_map on non-severity": {
			Name: "my-parser", Category: domain.CategorySCA, Format: CustomFormatCSV,
			Fields: map[CustomFieldKey]CustomFieldMap{CFTitle: {Path: "x", ValueMap: map[string]string{"a": "b"}}},
		},
		"missing record_selector for json": {
			Name: "my-parser", Category: domain.CategorySCA, Format: CustomFormatJSON,
			Fields: map[CustomFieldKey]CustomFieldMap{CFTitle: {Path: "x"}},
		},
		"record_selector set for csv": {
			Name: "my-parser", Category: domain.CategorySCA, Format: CustomFormatCSV, RecordSelector: "results",
			Fields: map[CustomFieldKey]CustomFieldMap{CFTitle: {Path: "x"}},
		},
		"path too deep": {
			Name: "my-parser", Category: domain.CategorySCA, Format: CustomFormatJSON, RecordSelector: "results",
			Fields: map[CustomFieldKey]CustomFieldMap{CFTitle: {Path: strings.Repeat("a.", 25) + "b"}},
		},
	}
	for name, def := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewCustomParser(def); err == nil {
				t.Fatalf("NewCustomParser(%s): want error, got nil", name)
			}
		})
	}
}

func TestCustomParserValidDefinitionAccepted(t *testing.T) {
	def := CustomDefinition{
		Name: "my-parser", Category: domain.CategorySCA, Format: CustomFormatJSON, RecordSelector: "results",
		Fields: map[CustomFieldKey]CustomFieldMap{CFTitle: {Path: "name"}},
	}
	if _, err := NewCustomParser(def); err != nil {
		t.Fatalf("NewCustomParser: unexpected error: %v", err)
	}
}

func TestCustomParserRecordErrorsDoNotFailTheWholeReport(t *testing.T) {
	def := CustomDefinition{
		Name:           "custom-partial",
		Category:       domain.CategorySCA,
		Format:         CustomFormatJSON,
		RecordSelector: "$",
		Fields:         map[CustomFieldKey]CustomFieldMap{CFTitle: {Path: "name"}},
	}
	p, err := NewCustomParser(def)
	if err != nil {
		t.Fatalf("NewCustomParser: %v", err)
	}
	body := `[{"name": "good"}, {"nope": "missing title"}, {"name": ""}]`
	findings, recErrs, err := p.ParseDetailed(strings.NewReader(body))
	if err != nil {
		t.Fatalf("ParseDetailed: %v", err)
	}
	if len(findings) != 1 || findings[0].Title != "good" {
		t.Fatalf("findings = %+v, want exactly the valid record", findings)
	}
	if len(recErrs) != 2 || recErrs[0].Index != 1 || recErrs[1].Index != 2 {
		t.Fatalf("recErrs = %+v, want indices 1 and 2", recErrs)
	}
}

func TestCustomParserBadRecordSelectorIsAStructuralError(t *testing.T) {
	def := CustomDefinition{
		Name:           "custom-badsel",
		Category:       domain.CategorySCA,
		Format:         CustomFormatJSON,
		RecordSelector: "nonexistent",
		Fields:         map[CustomFieldKey]CustomFieldMap{CFTitle: {Path: "name"}},
	}
	p, err := NewCustomParser(def)
	if err != nil {
		t.Fatalf("NewCustomParser: %v", err)
	}
	if _, err := p.Parse(strings.NewReader(`{"results": []}`)); err == nil {
		t.Fatal("Parse: want error for a selector that matches nothing")
	}
}
