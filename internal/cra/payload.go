package cra

import (
	"slices"
	"time"

	"github.com/xilasec/xila-api/internal/domain"
)

// PayloadSchema identifies the payload layout. It is Xila's draft structure,
// modelled on the information Article 14(2) requires: the Commission has not
// yet specified the single reporting platform's format (Art. 14(10)), so map
// these fields onto the platform's forms when submitting.
const PayloadSchema = "xila.cra-art14.draft-1"

// Manufacturer is the instance's manufacturer identity (CRA_MANUFACTURER_*).
type Manufacturer struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Contact string `json:"contact"`
	// MainEstablishment is the Member State of the main establishment in the
	// Union; its CSIRT designated as coordinator receives the notification
	// (Art. 14(7)).
	MainEstablishment string `json:"main_establishment"`
}

// Payload is one Article 14(2) submission, structured after what the
// regulation asks each stage to contain.
type Payload struct {
	Schema      string    `json:"schema"`
	Draft       bool      `json:"draft"`
	Notice      string    `json:"notice"`
	Stage       Stage     `json:"stage"`
	Article     string    `json:"article"`
	CaseID      string    `json:"case_id"`
	GeneratedAt time.Time `json:"generated_at"`
	// DueAt is this stage's deadline (nil: the final report's clock hasn't
	// started — no corrective measure yet).
	DueAt        *time.Time       `json:"due_at"`
	Recipients   PayloadRecipient `json:"recipients"`
	Manufacturer Manufacturer     `json:"manufacturer"`
	Product      PayloadProduct   `json:"product"`
	// Vulnerability: identity at every stage; the general nature (notification)
	// and description with severity and impact (final) as the stages require.
	Vulnerability PayloadVulnerability `json:"vulnerability"`
	Exploitation  PayloadExploitation  `json:"exploitation"`
	Measures      *PayloadMeasures     `json:"measures,omitempty"`
	Impact        *PayloadImpact       `json:"impact,omitempty"`
	// Sensitivity is how sensitive the manufacturer considers the notified
	// information (Art. 14(2)(b)), as a TLP label.
	Sensitivity string `json:"sensitivity,omitempty"`
	// Missing names the fields this stage asks for that are still empty.
	Missing []string `json:"missing"`
}

// PayloadRecipient is where the submission goes: the coordinator CSIRT of the
// main establishment, simultaneously accessible to ENISA (Art. 14(1), (7)).
type PayloadRecipient struct {
	Platform              string `json:"platform"`
	CSIRTCoordinatorState string `json:"csirt_coordinator_member_state"`
	ENISA                 bool   `json:"enisa"`
}

// PayloadProduct is the product with digital elements concerned.
type PayloadProduct struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Project string `json:"project"`
	// MemberStates where the manufacturer is aware the product has been made
	// available (Art. 14(2)(a)).
	MemberStates []string `json:"member_states"`
}

// PayloadComponent is the affected component, when the finding names one.
type PayloadComponent struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Purl    string `json:"purl"`
}

// PayloadVulnerability identifies (and, later, describes) the vulnerability.
type PayloadVulnerability struct {
	ID          string            `json:"id"`
	Aliases     []string          `json:"aliases"`
	Title       string            `json:"title"`
	AwareAt     time.Time         `json:"aware_at"`
	Description string            `json:"description,omitempty"`
	CWE         *int              `json:"cwe,omitempty"`
	Component   *PayloadComponent `json:"component,omitempty"`
}

// PayloadExploitation is the evidence of active exploitation and, from the
// notification on, its general nature.
type PayloadExploitation struct {
	ActivelyExploited bool     `json:"actively_exploited"`
	Evidence          []string `json:"evidence"`
	Nature            string   `json:"nature,omitempty"`
	// MaliciousActor: where available, who exploited it (final report).
	MaliciousActor string `json:"malicious_actor,omitempty"`
}

// PayloadMeasures are the corrective or mitigating measures taken and those
// users can take; in the final report, the security update details.
type PayloadMeasures struct {
	CorrectiveAvailableAt *time.Time `json:"corrective_available_at"`
	Corrective            string     `json:"corrective"`
	UserMitigations       string     `json:"user_mitigations"`
	FixedVersion          string     `json:"fixed_version,omitempty"`
}

// PayloadImpact is the severity and impact (final report).
type PayloadImpact struct {
	Severity    string   `json:"severity"`
	CVSS        *float64 `json:"cvss,omitempty"`
	CVSSVector  string   `json:"cvss_vector,omitempty"`
	Description string   `json:"description"`
}

var articles = map[Stage]string{
	StageEarlyWarning: "Regulation (EU) 2024/2847, Article 14(2)(a) — early warning notification",
	StageNotification: "Regulation (EU) 2024/2847, Article 14(2)(b) — vulnerability notification",
	StageFinal:        "Regulation (EU) 2024/2847, Article 14(2)(c) — final report",
}

// BuildPayload assembles the stage's submission from the case at now. Pure.
// Each stage carries what the earlier ones did plus its own requirements.
func BuildPayload(c Case, stage Stage, m Manufacturer, now time.Time) Payload {
	p := Payload{
		Schema: PayloadSchema, Draft: true,
		Notice: "Draft structure for the ENISA single reporting platform (Art. 16), modelled on the information " +
			"Article 14(2) requires. The platform's format is set by Commission implementing acts (Art. 14(10)); " +
			"transfer these fields to it when submitting.",
		Stage: stage, Article: articles[stage], CaseID: c.ID, GeneratedAt: now.UTC(),
		Recipients: PayloadRecipient{
			Platform:              "ENISA single reporting platform (Regulation (EU) 2024/2847, Article 16)",
			CSIRTCoordinatorState: m.MainEstablishment, ENISA: true,
		},
		Manufacturer: m,
		Product: PayloadProduct{Name: c.ProductName, Version: c.ProductVersion, Project: c.ProjectName,
			MemberStates: append([]string{}, c.MemberStates...)},
		Vulnerability: PayloadVulnerability{ID: c.VulnID, Aliases: []string{}, Title: c.Title, AwareAt: c.AwareAt.UTC()},
		Exploitation:  PayloadExploitation{ActivelyExploited: true, Evidence: evidence(c)},
		Missing:       []string{},
	}
	if p.Product.Name == "" {
		p.Product.Name = c.ProjectName
	}
	switch stage {
	case StageEarlyWarning:
		p.DueAt = new(c.EarlyWarningDueAt.UTC())
	case StageNotification:
		p.DueAt = new(c.NotificationDueAt.UTC())
	case StageFinal:
		if c.FinalReportDueAt != nil {
			p.DueAt = new(c.FinalReportDueAt.UTC())
		}
	}
	f := c.Finding
	if f != nil {
		for _, cve := range f.CVE {
			if cve != c.VulnID && !slices.Contains(p.Vulnerability.Aliases, cve) {
				p.Vulnerability.Aliases = append(p.Vulnerability.Aliases, cve)
			}
		}
	}

	need := func(field, value string) {
		if value == "" {
			p.Missing = append(p.Missing, field)
		}
	}
	need("manufacturer.name", m.Name)
	need("manufacturer.contact", m.Contact)
	need("recipients.csirt_coordinator_member_state", m.MainEstablishment)
	if len(p.Product.MemberStates) == 0 {
		p.Missing = append(p.Missing, "product.member_states")
	}
	if stage == StageEarlyWarning {
		return p
	}

	// Notification: general information about the product, the nature of the
	// exploit and of the vulnerability, measures taken and for users, and
	// the information's sensitivity.
	if f != nil {
		p.Vulnerability.Description = f.Description
		p.Vulnerability.CWE = f.CWE
		if f.PackageName != "" || f.Purl != "" {
			p.Vulnerability.Component = &PayloadComponent{Name: f.PackageName, Version: f.PackageVersion, Purl: f.Purl}
		}
	}
	p.Exploitation.Nature = c.Exploitation
	p.Measures = &PayloadMeasures{CorrectiveAvailableAt: c.CorrectiveAvailableAt, Corrective: c.CorrectiveMeasures,
		UserMitigations: c.UserMitigations}
	p.Sensitivity = c.Sensitivity
	need("exploitation.nature", c.Exploitation)
	need("measures.corrective", c.CorrectiveMeasures)
	need("measures.user_mitigations", c.UserMitigations)
	need("sensitivity", c.Sensitivity)
	if stage == StageNotification {
		return p
	}

	// Final report: description with severity and impact, the malicious actor
	// where known, and the security update or other corrective measures.
	p.Exploitation.MaliciousActor = c.MaliciousActor
	p.Impact = &PayloadImpact{Severity: c.Severity, Description: c.Impact}
	if f != nil {
		p.Impact.CVSS = f.CVSS
		if f.CVSSVector != nil {
			p.Impact.CVSSVector = *f.CVSSVector
		}
		p.Measures.FixedVersion = f.FixedVersion
	}
	need("impact.description", c.Impact)
	if c.CorrectiveAvailableAt == nil {
		p.Missing = append(p.Missing, "measures.corrective_available_at")
	}
	return p
}

// kevCatalogNames are the publishers of the KEV catalogs (enrichment KEV_SOURCES).
var kevCatalogNames = map[string]string{domain.KEVCISA: "CISA", domain.KEVENISA: "ENISA (EU)", domain.KEVVulnCheck: "VulnCheck"}

// evidence describes why the vulnerability counts as actively exploited.
func evidence(c Case) []string {
	out := []string{}
	if c.Trigger == TriggerManual {
		out = append(out, "Reported as actively exploited by the manufacturer")
	}
	if c.Trigger == TriggerKEV || (c.Finding != nil && c.Finding.KEV) {
		var sources []string
		if c.Finding != nil {
			sources = c.Finding.KEVSources
		}
		if len(sources) == 0 {
			out = append(out, "Listed in a Known Exploited Vulnerabilities catalog")
		}
		for _, s := range sources {
			out = append(out, "Listed in the "+kevCatalogNames[s]+" Known Exploited Vulnerabilities catalog")
		}
	}
	if c.Trigger == TriggerWeaponized || (c.Finding != nil && c.Finding.ExploitMaturity == "weaponized") {
		out = append(out, "A weaponized public exploit is available")
	}
	return out
}
