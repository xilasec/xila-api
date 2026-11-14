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

// AWSInspector2 parses Amazon Inspector (v2) findings as JSON, the output of
// `aws inspector2 list-findings --output json` (`{"findings": [...]}`).
// Package vulnerabilities become one finding per vulnerable package — on an ECR
// image they are container findings, on EC2 instances and Lambda functions
// dependency (SCA) findings; Lambda code vulnerabilities are SAST findings on the
// reported file and line; network reachability findings are cloud findings.
// Every finding is located at its resource ARN, so the same CVE on two
// instances stays two findings. CLOSED findings (no longer observed) are
// skipped; SUPPRESSED ones (hidden by a suppression rule) are carried as a
// risk acceptance.
type AWSInspector2 struct{}

// NewAWSInspector2 constructs an Amazon Inspector v2 parser.
func NewAWSInspector2() AWSInspector2 { return AWSInspector2{} }

// Scanner returns the tool identifier.
func (AWSInspector2) Scanner() string { return "aws-inspector2" }

// PrimaryCategory is the scan-level category for Inspector reports.
func (AWSInspector2) PrimaryCategory() domain.Category { return domain.CategoryCloud }

type inspector2Report struct {
	Findings *[]inspector2Finding `json:"findings"`
}

type inspector2Finding struct {
	FindingArn      string   `json:"findingArn"`
	AWSAccountID    string   `json:"awsAccountId"`
	Type            string   `json:"type"`
	Title           string   `json:"title"`
	Description     string   `json:"description"`
	Severity        string   `json:"severity"`
	Status          string   `json:"status"`
	InspectorScore  *float64 `json:"inspectorScore"`
	ExploitAvail    string   `json:"exploitAvailable"`
	FixAvailable    string   `json:"fixAvailable"`
	FirstObservedAt string   `json:"firstObservedAt"`
	LastObservedAt  string   `json:"lastObservedAt"`
	EPSS            *struct {
		Score float64 `json:"score"`
	} `json:"epss"`
	InspectorScoreDetails struct {
		AdjustedCvss struct {
			ScoringVector string `json:"scoringVector"`
		} `json:"adjustedCvss"`
	} `json:"inspectorScoreDetails"`
	Remediation struct {
		Recommendation struct {
			Text string `json:"text"`
			URL  string `json:"Url"`
		} `json:"recommendation"`
	} `json:"remediation"`
	Resources []struct {
		ID     string `json:"id"`
		Type   string `json:"type"`
		Region string `json:"region"`
	} `json:"resources"`
	PackageVulnerabilityDetails *struct {
		VulnerabilityID        string   `json:"vulnerabilityId"`
		Source                 string   `json:"source"`
		SourceURL              string   `json:"sourceUrl"`
		ReferenceURLs          []string `json:"referenceUrls"`
		RelatedVulnerabilities []string `json:"relatedVulnerabilities"`
		CVSS                   []struct {
			BaseScore float64 `json:"baseScore"`
			Version   string  `json:"version"`
		} `json:"cvss"`
		VulnerablePackages []struct {
			Name           string `json:"name"`
			Version        string `json:"version"`
			Release        string `json:"release"`
			FixedInVersion string `json:"fixedInVersion"`
			FilePath       string `json:"filePath"`
			PackageManager string `json:"packageManager"`
			Remediation    string `json:"remediation"`
		} `json:"vulnerablePackages"`
	} `json:"packageVulnerabilityDetails"`
	CodeVulnerabilityDetails *struct {
		FilePath struct {
			FileName  string `json:"fileName"`
			FilePath  string `json:"filePath"`
			StartLine int    `json:"startLine"`
			EndLine   int    `json:"endLine"`
		} `json:"filePath"`
		CWEs          []string `json:"cwes"`
		DetectorID    string   `json:"detectorId"`
		DetectorName  string   `json:"detectorName"`
		DetectorTags  []string `json:"detectorTags"`
		RuleID        string   `json:"ruleId"`
		ReferenceURLs []string `json:"referenceUrls"`
	} `json:"codeVulnerabilityDetails"`
	NetworkReachabilityDetails *struct {
		Protocol      string `json:"protocol"`
		OpenPortRange struct {
			Begin int `json:"begin"`
			End   int `json:"end"`
		} `json:"openPortRange"`
		NetworkPath struct {
			Steps []struct {
				ComponentID   string `json:"componentId"`
				ComponentType string `json:"componentType"`
			} `json:"steps"`
		} `json:"networkPath"`
	} `json:"networkReachabilityDetails"`
}

// Parse converts an Inspector list-findings JSON document into findings.
func (AWSInspector2) Parse(r io.Reader) ([]ParsedFinding, error) {
	var rep inspector2Report
	if err := json.NewDecoder(r).Decode(&rep); err != nil {
		return nil, fmt.Errorf("decode aws inspector2 report: %w", err)
	}
	if rep.Findings == nil {
		return nil, errors.New(`decode aws inspector2 report: no "findings" array (expected aws inspector2 list-findings output)`)
	}
	out := []ParsedFinding{}
	for _, f := range *rep.Findings {
		if f.FindingArn == "" || f.Type == "" {
			return nil, errors.New("aws inspector2 report: finding without findingArn/type (not list-findings output?)")
		}
		if strings.EqualFold(f.Status, "CLOSED") {
			continue
		}
		out = append(out, inspector2Findings(f)...)
	}
	return mergeSameLocation(out), nil
}

func inspector2Findings(f inspector2Finding) []ParsedFinding {
	resourceID, resourceType := "", ""
	if len(f.Resources) > 0 {
		resourceID, resourceType = f.Resources[0].ID, f.Resources[0].Type
	}
	meta := map[string]any{
		"finding_arn":   f.FindingArn,
		"resource_arn":  resourceID,
		"resource_type": resourceType,
		"finding_type":  f.Type,
	}
	if f.AWSAccountID != "" {
		meta["aws_account"] = f.AWSAccountID
	}
	if len(f.Resources) > 0 && f.Resources[0].Region != "" {
		meta["region"] = f.Resources[0].Region
	}
	if f.EPSS != nil {
		meta["epss"] = f.EPSS.Score
	}
	if f.ExploitAvail != "" {
		meta["exploit_available"] = strings.EqualFold(f.ExploitAvail, "YES")
	}
	if v := f.InspectorScoreDetails.AdjustedCvss.ScoringVector; v != "" {
		meta["cvss_vector"] = v
	}
	if t := f.Remediation.Recommendation.Text; t != "" && t != "None Provided" {
		meta["mitigation"] = t
	}
	if strings.EqualFold(f.Status, "SUPPRESSED") {
		setImportedStatus(meta, domain.FindingRiskAccepted, "suppressed in Amazon Inspector", zeroTime)
	}

	base := ParsedFinding{
		Category:    domain.CategoryCloud,
		RuleID:      f.FindingArn,
		Title:       f.Title,
		Description: f.Description,
		Severity:    inspector2Severity(f),
		FilePath:    resourceID,
		Metadata:    meta,
	}
	if f.InspectorScore != nil && *f.InspectorScore > 0 {
		base.CVSS = floatPtr(*f.InspectorScore)
	}

	switch f.Type {
	case "PACKAGE_VULNERABILITY":
		d := f.PackageVulnerabilityDetails
		if d == nil {
			return []ParsedFinding{base}
		}
		base.Category = domain.CategorySCA
		if resourceType == "AWS_ECR_CONTAINER_IMAGE" {
			base.Category = domain.CategoryContainer
		}
		base.RuleID = d.VulnerabilityID
		base.CVE = cvesFrom(append([]string{d.VulnerabilityID}, d.RelatedVulnerabilities...)...)
		base.URL = d.SourceURL
		if len(d.ReferenceURLs) > 0 {
			meta["references"] = d.ReferenceURLs
		}
		if d.Source != "" {
			meta["advisory_source"] = d.Source
		}
		if base.CVSS == nil {
			for _, c := range d.CVSS {
				if c.BaseScore > 0 && strings.HasPrefix(c.Version, "3") {
					base.CVSS = floatPtr(c.BaseScore)
					break
				}
			}
		}
		if len(d.VulnerablePackages) == 0 {
			return []ParsedFinding{base}
		}
		out := make([]ParsedFinding, 0, len(d.VulnerablePackages))
		for _, p := range d.VulnerablePackages {
			pf := base
			pf.Metadata = maps.Clone(meta)
			pf.Package = p.Name
			pf.PackageVersion = p.Version
			if fixed := p.FixedInVersion; fixed != "" && fixed != "NotAvailable" {
				pf.FixedVersion = fixed
			}
			pf.Purl = ecosystemPurl(awsPackageEcosystem(p.PackageManager), p.Name, p.Version)
			if p.FilePath != "" {
				// The same package can sit in several manifests of one resource.
				pf.FilePath = resourceID + "/" + p.FilePath
				pf.Metadata["package_path"] = p.FilePath
			}
			if p.PackageManager != "" {
				pf.Metadata["package_manager"] = p.PackageManager
			}
			if p.Release != "" {
				pf.Metadata["release"] = p.Release
			}
			if p.Remediation != "" {
				pf.Metadata["mitigation"] = p.Remediation
			}
			out = append(out, pf)
		}
		return out
	case "CODE_VULNERABILITY":
		d := f.CodeVulnerabilityDetails
		base.Category = domain.CategorySAST
		if d == nil {
			return []ParsedFinding{base}
		}
		base.RuleID = firstNonEmpty(d.RuleID, d.DetectorID, f.FindingArn)
		base.CWE = cweFirst(d.CWEs...)
		path := d.FilePath.FilePath
		if name := d.FilePath.FileName; name != "" && !strings.HasSuffix(path, name) {
			path = strings.TrimSuffix(path, "/") + "/" + name
		}
		if path != "" {
			base.FilePath = path
		}
		if d.FilePath.StartLine > 0 {
			base.Line = intPtr(d.FilePath.StartLine)
		}
		meta["detector"] = firstNonEmpty(d.DetectorName, d.DetectorID)
		if len(d.CWEs) > 1 {
			meta["cwes"] = d.CWEs
		}
		if len(d.DetectorTags) > 0 {
			meta["tags"] = d.DetectorTags
		}
		if len(d.ReferenceURLs) > 0 {
			meta["references"] = d.ReferenceURLs
		}
	case "NETWORK_REACHABILITY":
		if d := f.NetworkReachabilityDetails; d != nil {
			// The open port range is what makes two reachability findings on
			// one instance different.
			base.RuleID = fmt.Sprintf("NETWORK_REACHABILITY/%s/%d-%d",
				d.Protocol, d.OpenPortRange.Begin, d.OpenPortRange.End)
			meta["protocol"] = d.Protocol
			meta["open_ports"] = fmt.Sprintf("%d-%d", d.OpenPortRange.Begin, d.OpenPortRange.End)
			var steps []string
			for _, s := range d.NetworkPath.Steps {
				steps = append(steps, s.ComponentType+" "+s.ComponentID)
			}
			if len(steps) > 0 {
				meta["network_path"] = steps
			}
		}
	}
	return []ParsedFinding{base}
}

// inspector2Severity uses Inspector's rating; UNTRIAGED (the vendor has not
// rated it yet) falls back to the Inspector score, and stays visible as medium
// without one.
func inspector2Severity(f inspector2Finding) domain.Severity {
	if s := strings.ToUpper(f.Severity); s != "UNTRIAGED" && s != "" {
		return normalizeSeverity(s)
	}
	if f.InspectorScore != nil && *f.InspectorScore > 0 {
		return severityFromCVSS(*f.InspectorScore)
	}
	return domain.SeverityMedium
}

// awsPackageEcosystem maps the package managers Inspector (and Security Hub's
// copy of its findings) report onto purl ecosystems; OS and generic packages
// have none we can name.
func awsPackageEcosystem(pm string) string {
	switch strings.ToUpper(pm) {
	case "NODE", "NODEPKG", "NPM", "YARN", "PNPM":
		return "npm"
	case "PYTHON", "PYTHONPKG", "PIP", "PIPENV", "POETRY":
		return "pypi"
	case "GO", "GOMOD", "GOBINARY":
		return "go"
	case "BUNDLER", "GEMSPEC":
		return "rubygems"
	case "JAR", "POM", "GRADLE", "MAVEN", "SBT":
		return "maven"
	case "NUGET", "DOTNET_CORE":
		return "nuget"
	case "CARGO":
		return "cargo"
	case "COMPOSER":
		return "composer"
	}
	return ""
}
