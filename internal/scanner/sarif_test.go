package scanner

import (
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

// A trimmed Semgrep SARIF report: one high-severity XSS (via security-severity),
// one secret (via level + tag), exercising rule lookup by index and by id.
const sampleSarif = `{
  "version": "2.1.0",
  "runs": [
    {
      "tool": { "driver": {
        "name": "Semgrep",
        "rules": [
          {
            "id": "js.xss.direct-response-write",
            "shortDescription": { "text": "Reflected XSS in response" },
            "fullDescription": { "text": "User input written to the response without encoding." },
            "helpUri": "https://semgrep.dev/r/js.xss",
            "defaultConfiguration": { "level": "error" },
            "properties": { "security-severity": "8.6", "tags": ["security", "external/cwe/cwe-79"] }
          },
          {
            "id": "generic.secrets.aws-key",
            "shortDescription": { "text": "Hardcoded AWS key" },
            "defaultConfiguration": { "level": "error" },
            "properties": { "tags": ["secret"] }
          }
        ]
      } },
      "results": [
        {
          "ruleId": "js.xss.direct-response-write",
          "ruleIndex": 0,
          "level": "error",
          "message": { "text": "Untrusted input reaches res.send" },
          "locations": [
            { "physicalLocation": {
              "artifactLocation": { "uri": "src/handlers/user.js" },
              "region": { "startLine": 42 }
            } }
          ]
        },
        {
          "ruleId": "generic.secrets.aws-key",
          "message": { "text": "AWS key committed" },
          "locations": [
            { "physicalLocation": { "artifactLocation": { "uri": ".env" }, "region": { "startLine": 3 } } }
          ]
        }
      ]
    }
  ]
}`

func TestSarifParse(t *testing.T) {
	findings, err := Sarif{}.Parse(strings.NewReader(sampleSarif))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}

	xss := findings[0]
	if xss.Category != domain.CategorySAST {
		t.Errorf("category = %q, want sast", xss.Category)
	}
	if xss.Severity != domain.SeverityHigh { // 8.6 -> high
		t.Errorf("severity = %q, want high", xss.Severity)
	}
	if xss.CWE == nil || *xss.CWE != 79 {
		t.Errorf("cwe = %v, want 79", xss.CWE)
	}
	if xss.FilePath != "src/handlers/user.js" || xss.Line == nil || *xss.Line != 42 {
		t.Errorf("location wrong: %s:%v", xss.FilePath, xss.Line)
	}
	if xss.Title != "Reflected XSS in response" || xss.Metadata["tool"] != "Semgrep" {
		t.Errorf("metadata wrong: %+v", xss)
	}

	secret := findings[1] // resolved by ruleId (no ruleIndex)
	if secret.Category != domain.CategorySecret {
		t.Errorf("category = %q, want secret", secret.Category)
	}
	if secret.Severity != domain.SeverityHigh { // level error -> high
		t.Errorf("severity = %q, want high", secret.Severity)
	}
}

func TestSarifSeverityFallbackToLevel(t *testing.T) {
	doc := `{"runs":[{"tool":{"driver":{"name":"t","rules":[]}},"results":[
	  {"ruleId":"x","level":"warning","message":{"text":"m"}}]}]}`
	f, err := Sarif{}.Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 1 || f[0].Severity != domain.SeverityMedium {
		t.Errorf("warning should map to medium, got %+v", f)
	}
}
