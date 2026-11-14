package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// AWSSecurityHub parses AWS Security Hub findings in the AWS Security Finding
// Format (ASFF), as exported by `aws securityhub get-findings --output json`
// (`{"Findings": [...]}`; a lower-case `findings` key is accepted too). Security
// Hub aggregates several products, and each maps differently:
//
//   - control/Config findings (CSPM): one cloud finding per failing resource,
//     RuleID = the GeneratorId (the standard's control, e.g.
//     ".../v/1.0.0/IAM.5"). Compliance status PASSED is not a finding.
//   - Inspector findings with Vulnerabilities: one finding per vulnerable
//     package, RuleID = the vulnerability id, container on an ECR image and
//     SCA elsewhere.
//   - GuardDuty and other products whose GeneratorId is a detector, not a
//     check: RuleID = the finding type (Types[0]).
//
// Archived (RecordState ARCHIVED) and resolved (Workflow RESOLVED) findings are
// skipped; Workflow SUPPRESSED is carried as a risk acceptance.
type AWSSecurityHub struct{}

// NewAWSSecurityHub constructs an AWS Security Hub (ASFF) parser.
func NewAWSSecurityHub() AWSSecurityHub { return AWSSecurityHub{} }

// Scanner returns the tool identifier.
func (AWSSecurityHub) Scanner() string { return "aws-security-hub" }

// PrimaryCategory is the scan-level category for Security Hub exports.
func (AWSSecurityHub) PrimaryCategory() domain.Category { return domain.CategoryCloud }

type securityHubFinding struct {
	ID            string   `json:"Id"`
	ProductArn    string   `json:"ProductArn"`
	ProductName   string   `json:"ProductName"`
	GeneratorID   string   `json:"GeneratorId"`
	AWSAccountID  string   `json:"AwsAccountId"`
	Region        string   `json:"Region"`
	Types         []string `json:"Types"`
	Title         string   `json:"Title"`
	Description   string   `json:"Description"`
	SourceURL     string   `json:"SourceUrl"`
	RecordState   string   `json:"RecordState"`
	WorkflowState string   `json:"WorkflowState"`
	Severity      struct {
		Label      string   `json:"Label"`
		Normalized *float64 `json:"Normalized"`
	} `json:"Severity"`
	Compliance *struct {
		Status              string   `json:"Status"`
		RelatedRequirements []string `json:"RelatedRequirements"`
		SecurityControlID   string   `json:"SecurityControlId"`
	} `json:"Compliance"`
	Workflow *struct {
		Status string `json:"Status"`
	} `json:"Workflow"`
	Note *struct {
		Text string `json:"Text"`
	} `json:"Note"`
	Remediation struct {
		Recommendation struct {
			Text string `json:"Text"`
			URL  string `json:"Url"`
		} `json:"Recommendation"`
	} `json:"Remediation"`
	ProductFields map[string]string `json:"ProductFields"`
	Resources     []struct {
		ID     string `json:"Id"`
		Type   string `json:"Type"`
		Region string `json:"Region"`
	} `json:"Resources"`
	Vulnerabilities []struct {
		ID                     string   `json:"Id"`
		RelatedVulnerabilities []string `json:"RelatedVulnerabilities"`
		ReferenceURLs          []string `json:"ReferenceUrls"`
		CVSS                   []struct {
			BaseScore  float64 `json:"BaseScore"`
			BaseVector string  `json:"BaseVector"`
		} `json:"Cvss"`
		Vendor *struct {
			URL string `json:"Url"`
		} `json:"Vendor"`
		VulnerablePackages []struct {
			Name           string `json:"Name"`
			Version        string `json:"Version"`
			Release        string `json:"Release"`
			FixedInVersion string `json:"FixedInVersion"`
			PackageManager string `json:"PackageManager"`
			FilePath       string `json:"FilePath"`
			Remediation    string `json:"Remediation"`
		} `json:"VulnerablePackages"`
	} `json:"Vulnerabilities"`
}

// Parse converts an ASFF export into findings.
func (AWSSecurityHub) Parse(r io.Reader) ([]ParsedFinding, error) {
	var doc struct {
		Upper *[]securityHubFinding `json:"Findings"`
		Lower *[]securityHubFinding `json:"findings"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode aws security hub report: %w", err)
	}
	list := doc.Upper
	if list == nil {
		list = doc.Lower
	}
	if list == nil {
		return nil, errors.New(`decode aws security hub report: no "Findings" array (expected ASFF from aws securityhub get-findings)`)
	}
	out := []ParsedFinding{}
	for _, f := range *list {
		if f.ID == "" || f.GeneratorID == "" {
			return nil, errors.New("aws security hub report: finding without Id/GeneratorId (not ASFF?)")
		}
		if securityHubSkip(f) {
			continue
		}
		out = append(out, securityHubFindings(f)...)
	}
	return mergeSameLocation(out), nil
}

// securityHubSkip reports findings that are not open issues: passed controls,
// archived records, findings someone resolved, and Inspector findings Inspector
// itself has closed.
func securityHubSkip(f securityHubFinding) bool {
	if f.Compliance != nil && strings.EqualFold(f.Compliance.Status, "PASSED") {
		return true
	}
	if strings.EqualFold(f.RecordState, "ARCHIVED") {
		return true
	}
	if f.Workflow != nil && strings.EqualFold(f.Workflow.Status, "RESOLVED") {
		return true
	}
	if s := f.ProductFields["aws/inspector/FindingStatus"]; s != "" && !strings.EqualFold(s, "ACTIVE") {
		return true
	}
	return false
}

func securityHubFindings(f securityHubFinding) []ParsedFinding {
	product := firstNonEmpty(f.ProductName, f.ProductFields["aws/securityhub/ProductName"])
	meta := map[string]any{
		"finding_id":   f.ID,
		"generator_id": f.GeneratorID,
	}
	if product != "" {
		meta["product"] = product
	}
	if f.AWSAccountID != "" {
		meta["aws_account"] = f.AWSAccountID
	}
	if f.Region != "" {
		meta["region"] = f.Region
	}
	if len(f.Types) > 0 {
		meta["types"] = f.Types
	}
	if f.Compliance != nil {
		if len(f.Compliance.RelatedRequirements) > 0 {
			meta["compliance_requirements"] = f.Compliance.RelatedRequirements
		}
		if f.Compliance.SecurityControlID != "" {
			meta["control_id"] = f.Compliance.SecurityControlID
		}
	}
	if t := f.Remediation.Recommendation.Text; t != "" {
		meta["mitigation"] = t
	}
	if u := f.Remediation.Recommendation.URL; u != "" {
		meta["references"] = []string{u}
	}
	if f.Workflow != nil && strings.EqualFold(f.Workflow.Status, "SUPPRESSED") {
		reason := "suppressed in AWS Security Hub"
		if f.Note != nil && f.Note.Text != "" {
			reason = f.Note.Text
		}
		setImportedStatus(meta, domain.FindingRiskAccepted, reason, zeroTime)
	}

	base := ParsedFinding{
		Category:    domain.CategoryCloud,
		RuleID:      f.GeneratorID,
		Title:       f.Title,
		Description: f.Description,
		Severity:    securityHubSeverity(f),
		URL:         f.SourceURL,
		Metadata:    meta,
	}
	// GuardDuty (and similar detectors) use the detector ARN as GeneratorId,
	// which is the same for every finding; the finding type is the check.
	if strings.HasPrefix(f.GeneratorID, "arn:") && len(f.Types) > 0 {
		base.RuleID = f.Types[0]
	}

	if len(f.Vulnerabilities) > 0 {
		return securityHubVulnFindings(f, base)
	}

	var out []ParsedFinding
	for _, res := range f.Resources {
		rf := base
		rf.Metadata = maps.Clone(meta)
		rf.FilePath = res.ID
		rf.Metadata["resource_arn"] = res.ID
		rf.Metadata["resource_type"] = res.Type
		out = append(out, rf)
	}
	if out == nil {
		out = append(out, base)
	}
	return out
}

func securityHubVulnFindings(f securityHubFinding, base ParsedFinding) []ParsedFinding {
	resourceID, resourceType := "", ""
	if len(f.Resources) > 0 {
		resourceID, resourceType = f.Resources[0].ID, f.Resources[0].Type
	}
	category := domain.CategorySCA
	if resourceType == "AwsEcrContainerImage" {
		category = domain.CategoryContainer
	}
	var out []ParsedFinding
	for _, v := range f.Vulnerabilities {
		vf := base
		vf.Category = category
		vf.RuleID = v.ID
		vf.CVE = cvesFrom(append([]string{v.ID}, v.RelatedVulnerabilities...)...)
		vf.FilePath = resourceID
		vf.Metadata = maps.Clone(base.Metadata)
		vf.Metadata["resource_arn"] = resourceID
		vf.Metadata["resource_type"] = resourceType
		if len(v.ReferenceURLs) > 0 {
			vf.Metadata["references"] = v.ReferenceURLs
		}
		if v.Vendor != nil && v.Vendor.URL != "" && vf.URL == "" {
			vf.URL = v.Vendor.URL
		}
		for _, c := range v.CVSS {
			if c.BaseScore > 0 {
				vf.CVSS = floatPtr(c.BaseScore)
				vf.Metadata["cvss_vector"] = c.BaseVector
				break
			}
		}
		if len(v.VulnerablePackages) == 0 {
			out = append(out, vf)
			continue
		}
		for _, p := range v.VulnerablePackages {
			pf := vf
			pf.Metadata = maps.Clone(vf.Metadata)
			pf.Package = p.Name
			pf.PackageVersion = p.Version
			if p.FixedInVersion != "" && p.FixedInVersion != "NotAvailable" {
				pf.FixedVersion = p.FixedInVersion
			}
			pf.Purl = ecosystemPurl(awsPackageEcosystem(p.PackageManager), p.Name, p.Version)
			if p.FilePath != "" {
				// One image can carry the same package in several manifests.
				pf.FilePath = resourceID + "/" + p.FilePath
				pf.Metadata["package_path"] = p.FilePath
			}
			if p.PackageManager != "" {
				pf.Metadata["package_manager"] = p.PackageManager
			}
			if p.Remediation != "" {
				pf.Metadata["mitigation"] = p.Remediation
			}
			out = append(out, pf)
		}
	}
	return out
}

// securityHubSeverity uses the ASFF label, falling back to the normalized
// 0–100 score when a product sets only that.
func securityHubSeverity(f securityHubFinding) domain.Severity {
	if f.Severity.Label != "" {
		return normalizeSeverity(f.Severity.Label)
	}
	if n := f.Severity.Normalized; n != nil {
		switch {
		case *n >= 90:
			return domain.SeverityCritical
		case *n >= 70:
			return domain.SeverityHigh
		case *n >= 40:
			return domain.SeverityMedium
		case *n >= 1:
			return domain.SeverityLow
		}
		return domain.SeverityInfo
	}
	return domain.SeverityMedium
}
