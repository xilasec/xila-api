package vex

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Parse reads a VEX document — OpenVEX, CycloneDX VEX or CSAF 2.0 VEX — and
// flattens it into statements. The format is sniffed from the content, so
// callers just POST the file.
func Parse(data []byte) ([]Statement, error) {
	var probe struct {
		Context  string `json:"@context"`
		Document *struct {
			CSAFVersion string `json:"csaf_version"`
		} `json:"document"`
		BomFormat       string          `json:"bomFormat"`
		Statements      json.RawMessage `json:"statements"`
		Vulnerabilities json.RawMessage `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("decode vex: %w", err)
	}
	switch {
	// Before CycloneDX: a CSAF document has "vulnerabilities" too.
	case probe.Document != nil && probe.Document.CSAFVersion != "":
		return parseCSAF(data)
	case strings.Contains(probe.Context, "openvex") || len(probe.Statements) > 0:
		return parseOpenVEX(data)
	case strings.EqualFold(probe.BomFormat, "CycloneDX") || len(probe.Vulnerabilities) > 0:
		return parseCycloneVEX(data)
	}
	return nil, fmt.Errorf("unrecognized VEX document (expected OpenVEX, CycloneDX or CSAF)")
}

// --- OpenVEX ---

type openVexDoc struct {
	Statements []struct {
		Vulnerability struct {
			Name string `json:"name"`
		} `json:"vulnerability"`
		Products []struct {
			ID string `json:"@id"`
		} `json:"products"`
		Status          string `json:"status"`
		Justification   string `json:"justification"`
		ImpactStatement string `json:"impact_statement"`
		ActionStatement string `json:"action_statement"`
		StatusNotes     string `json:"status_notes"`
	} `json:"statements"`
}

func parseOpenVEX(data []byte) ([]Statement, error) {
	var doc openVexDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decode openvex: %w", err)
	}
	var out []Statement
	for _, st := range doc.Statements {
		vuln := st.Vulnerability.Name
		status := openVexStatus(st.Status)
		if vuln == "" || status == "" {
			continue // a statement without a vulnerability or a verdict says nothing
		}
		detail := firstNonEmpty(st.ImpactStatement, st.StatusNotes, st.ActionStatement)

		// A statement with no products applies to everything in the project.
		if len(st.Products) == 0 {
			out = append(out, Statement{VulnID: vuln, Status: status,
				Justification: st.Justification, Detail: detail, Source: "openvex"})
			continue
		}
		for _, p := range st.Products {
			out = append(out, Statement{VulnID: vuln, Product: p.ID, Status: status,
				Justification: st.Justification, Detail: detail, Source: "openvex"})
		}
	}
	return out, nil
}

// openVexStatus maps OpenVEX's status vocabulary. Unknown values are dropped
// rather than guessed — a misread verdict would silently suppress a real finding.
func openVexStatus(s string) Status {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "not_affected":
		return StatusNotAffected
	case "affected":
		return StatusAffected
	case "fixed":
		return StatusFixed
	case "under_investigation":
		return StatusUnderInvestigation
	}
	return ""
}

// --- CycloneDX VEX ---

type cycloneVexDoc struct {
	Vulnerabilities []struct {
		ID       string `json:"id"`
		Analysis struct {
			State         string   `json:"state"`
			Justification string   `json:"justification"`
			Detail        string   `json:"detail"`
			Response      []string `json:"response"`
		} `json:"analysis"`
		Affects []struct {
			Ref string `json:"ref"`
		} `json:"affects"`
	} `json:"vulnerabilities"`
}

func parseCycloneVEX(data []byte) ([]Statement, error) {
	var doc cycloneVexDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decode cyclonedx vex: %w", err)
	}
	var out []Statement
	for _, v := range doc.Vulnerabilities {
		status := cycloneVexStatus(v.Analysis.State)
		if v.ID == "" || status == "" {
			continue
		}
		response := knownResponses(v.Analysis.Response)
		if len(v.Affects) == 0 {
			out = append(out, Statement{VulnID: v.ID, Status: status,
				Justification: v.Analysis.Justification, Detail: v.Analysis.Detail, Response: response, Source: "cyclonedx"})
			continue
		}
		for _, a := range v.Affects {
			out = append(out, Statement{VulnID: v.ID, Product: a.Ref, Status: status,
				Justification: v.Analysis.Justification, Detail: v.Analysis.Detail, Response: response, Source: "cyclonedx"})
		}
	}
	return out, nil
}

// knownResponses keeps only the recognized CycloneDX response codes — never
// invented, so an unrecognized one is dropped rather than guessed.
func knownResponses(ss []string) []string {
	var out []string
	for _, s := range ss {
		s = strings.ToLower(strings.TrimSpace(s))
		if domain.VexResponse(s).Valid() {
			out = append(out, s)
		}
	}
	return out
}

// cycloneVexStatus maps CycloneDX's analysis states onto the VEX four. Note
// "false_positive" and "not_affected" both mean "this doesn't apply to us", and
// "resolved" means the build already carries the fix.
func cycloneVexStatus(s string) Status {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "not_affected", "false_positive":
		return StatusNotAffected
	case "exploitable", "in_triage_affected":
		return StatusAffected
	case "resolved", "resolved_with_pedigree":
		return StatusFixed
	case "in_triage":
		return StatusUnderInvestigation
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
