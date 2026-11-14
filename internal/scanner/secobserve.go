package scanner

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// SecObserve imports observations exported from a SecObserve instance, for
// migrating a backlog — assessments included — into Xila. SecObserve exports to
// files only as CSV/Excel (for humans); the machine-readable export is its REST
// API, so this parser reads what a user can actually pull from it:
//
//   - the observation list, GET /api/observations/?product=<id>&branch=<id>:
//     one page ({"count":…,"results":[…]}) or the pages' results concatenated
//     into a JSON array (e.g. `jq -s '[.[].results[]]'`);
//   - SecObserve's own import format ({"format":"SecObserve","observations":[…]}),
//     which tools integrated with SecObserve already write.
//
// current_status carries the assessment: Affected → confirmed; False positive,
// Not affected and Not security → false_positive; Risk accepted → risk_accepted
// (with its expiry). Resolved and Duplicate observations are skipped — the
// first is history, the second's primary is in the same export.
type SecObserve struct{}

// NewSecObserve constructs a SecObserve parser.
func NewSecObserve() SecObserve { return SecObserve{} }

// Scanner returns the tool identifier.
func (SecObserve) Scanner() string { return "secobserve" }

// PrimaryCategory is the scan-level default; each observation is categorized
// by its parser type and origin.
func (SecObserve) PrimaryCategory() domain.Category { return domain.CategorySCA }

type secObserveObservation struct {
	Title                  string      `json:"title"`
	Description            string      `json:"description"`
	Recommendation         string      `json:"recommendation"`
	CurrentSeverity        string      `json:"current_severity"`
	ParserSeverity         string      `json:"parser_severity"`
	CurrentStatus          string      `json:"current_status"`
	VEXJustification       string      `json:"current_vex_justification"`
	RiskAcceptanceExpiry   string      `json:"risk_acceptance_expiry_date"`
	VulnerabilityID        string      `json:"vulnerability_id"`
	VulnerabilityIDAliases flexStrings `json:"vulnerability_id_aliases"`
	ScannerObservationID   string      `json:"scanner_observation_id"`
	ComponentName          string      `json:"origin_component_name"`
	ComponentVersion       string      `json:"origin_component_version"`
	ComponentPurl          string      `json:"origin_component_purl"`
	DockerImage            string      `json:"origin_docker_image_name_tag"`
	EndpointURL            string      `json:"origin_endpoint_url"`
	SourceFile             string      `json:"origin_source_file"`
	SourceLine             flexInt     `json:"origin_source_line_start"`
	CloudResource          string      `json:"origin_cloud_qualified_resource"`
	KubernetesResource     string      `json:"origin_kubernetes_qualified_resource"`
	CVSS3Score             flexFloat   `json:"cvss3_score"`
	CVSS3Vector            string      `json:"cvss3_vector"`
	CVSS4Score             flexFloat   `json:"cvss4_score"`
	CWE                    flexInt     `json:"cwe"`
	EPSSScore              flexFloat   `json:"epss_score"`
	Scanner                string      `json:"scanner"`
	ScannerName            string      `json:"scanner_name"`
	BranchName             string      `json:"branch_name"`
	ServiceName            string      `json:"origin_service_name"`
	Reference              string      `json:"reference"`
	ID                     json.Number `json:"id"`
	ParserData             *struct {
		Type string `json:"type"`
	} `json:"parser_data"`
}

// Parse converts SecObserve observations into findings.
func (SecObserve) Parse(r io.Reader) ([]ParsedFinding, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read secobserve export: %w", err)
	}
	observations, err := secObserveObservations(data)
	if err != nil {
		return nil, err
	}

	out := make([]ParsedFinding, 0, len(observations))
	for i, o := range observations {
		if o.Title == "" {
			return nil, fmt.Errorf("secobserve export: observation %d has no title", i)
		}
		status, keep := secObserveStatus(o.CurrentStatus)
		if !keep {
			continue
		}
		ids := append([]string{o.VulnerabilityID}, o.VulnerabilityIDAliases...)
		pf := ParsedFinding{
			Category:       secObserveCategory(o),
			RuleID:         firstNonEmpty(o.VulnerabilityID, o.ScannerObservationID, o.Title),
			Title:          o.Title,
			Description:    strings.TrimSpace(strings.Join(nonEmpty([]string{o.Description, o.Recommendation}), "\n\n")),
			Severity:       normalizeSeverity(firstNonEmpty(o.CurrentSeverity, o.ParserSeverity)),
			CWE:            o.CWE.ptr(),
			CVE:            cvesFrom(ids...),
			FilePath:       firstNonEmpty(o.SourceFile, o.EndpointURL, o.CloudResource, o.KubernetesResource, o.DockerImage),
			Line:           o.SourceLine.ptr(),
			Package:        o.ComponentName,
			PackageVersion: o.ComponentVersion,
			Purl:           o.ComponentPurl,
			URL:            firstNonEmpty(o.EndpointURL, o.Reference),
			CVSS:           secObserveCVSS(o),
			Metadata:       map[string]any{},
		}
		meta := pf.Metadata
		for k, v := range map[string]string{
			"secobserve_id": o.ID.String(), "secobserve_status": o.CurrentStatus,
			"scanner": firstNonEmpty(o.Scanner, o.ScannerName), "branch": o.BranchName,
			"service": o.ServiceName, "container": o.DockerImage, "cvss3_vector": o.CVSS3Vector,
			"vex_justification": o.VEXJustification,
		} {
			if v != "" {
				meta[k] = v
			}
		}
		if p := o.EPSSScore.ptr(); p != nil {
			meta["epss_score"] = *p
		}
		reason := "imported from SecObserve: " + o.CurrentStatus
		if o.VEXJustification != "" {
			reason += " (" + o.VEXJustification + ")"
		}
		setImportedStatus(meta, status, reason, parseLooseTime(o.RiskAcceptanceExpiry))
		out = append(out, pf)
	}
	return mergeSameLocation(out), nil
}

// secObserveObservations accepts an API page, a concatenated array of
// observations, or SecObserve's own import format.
func secObserveObservations(data []byte) ([]secObserveObservation, error) {
	data = bytes.TrimSpace(data)
	if len(data) > 0 && data[0] == '[' {
		var list []secObserveObservation
		if err := json.Unmarshal(data, &list); err != nil {
			return nil, fmt.Errorf("decode secobserve export: %w", err)
		}
		return list, nil
	}
	var doc struct {
		Format       string                   `json:"format"`
		Results      *[]secObserveObservation `json:"results"`
		Observations *[]secObserveObservation `json:"observations"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("decode secobserve export: %w", err)
	}
	switch {
	case doc.Results != nil:
		return *doc.Results, nil
	case doc.Observations != nil && doc.Format == "SecObserve":
		return *doc.Observations, nil
	}
	return nil, errors.New(`decode secobserve export: expected an observation list ("results") or {"format":"SecObserve","observations":[…]}`)
}

// secObserveStatus maps SecObserve's current_status onto a verdict, and
// reports whether the observation should be imported at all.
func secObserveStatus(s string) (domain.FindingStatus, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "resolved", "duplicate":
		return "", false
	case "affected":
		return domain.FindingConfirmed, true
	case "false positive", "not affected", "not security":
		return domain.FindingFalsePositive, true
	case "risk accepted":
		return domain.FindingRiskAccepted, true
	}
	return domain.FindingOpen, true // Open, In review, or absent (import format)
}

// secObserveCategory uses the observation's parser type when SecObserve
// recorded one, else infers the class from the origin.
func secObserveCategory(o secObserveObservation) domain.Category {
	if o.ParserData != nil {
		switch strings.ToUpper(o.ParserData.Type) {
		case "SCA":
			return domain.CategorySCA
		case "SAST":
			return domain.CategorySAST
		case "DAST":
			return domain.CategoryDAST
		case "SECRETS":
			return domain.CategorySecret
		case "INFRASTRUCTURE":
			return domain.CategoryIaC
		}
	}
	switch {
	case o.ComponentName != "" || o.ComponentPurl != "":
		return domain.CategorySCA
	case o.CloudResource != "":
		return domain.CategoryCloud
	case o.KubernetesResource != "":
		return domain.CategoryKubernetes
	case o.EndpointURL != "":
		return domain.CategoryDAST
	case o.DockerImage != "":
		return domain.CategoryContainer
	}
	return domain.CategorySAST
}

func secObserveCVSS(o secObserveObservation) *float64 {
	if p := o.CVSS3Score.ptr(); p != nil && *p > 0 {
		return p
	}
	if s, ok := cvss3BaseScore(o.CVSS3Vector); ok {
		return floatPtr(s)
	}
	if p := o.CVSS4Score.ptr(); p != nil && *p > 0 {
		return p
	}
	return nil
}
