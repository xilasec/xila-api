package psirt

import (
	"cmp"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Publisher is the CSAF document publisher (PSIRT_PUBLISHER_*).
type Publisher struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Contact   string `json:"contact_details,omitempty"`
}

// Configured reports whether documents can be rendered.
func (p Publisher) Configured() bool { return p.Name != "" && p.Namespace != "" }

// --- CSAF 2.0 security advisory (document.category csaf_security_advisory) ---
//
// The shapes follow the CSAF 2.0 JSON schema
// (https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json); the
// VEX export in internal/vex renders the same standard with a smaller subset.

type csafDoc struct {
	Document        csafDocument `json:"document"`
	ProductTree     csafTree     `json:"product_tree"`
	Vulnerabilities []csafVuln   `json:"vulnerabilities"`
}

type csafDocument struct {
	Acknowledgments []csafAck       `json:"acknowledgments,omitempty"`
	Category        string          `json:"category"`
	CSAFVersion     string          `json:"csaf_version"`
	Distribution    csafDistrib     `json:"distribution"`
	Lang            string          `json:"lang"`
	Notes           []csafNote      `json:"notes"`
	Publisher       csafPublisher   `json:"publisher"`
	References      []csafReference `json:"references"`
	Title           string          `json:"title"`
	Tracking        csafTracking    `json:"tracking"`
}

type csafAck struct {
	Names        []string `json:"names,omitempty"`
	Organization string   `json:"organization,omitempty"`
	Summary      string   `json:"summary,omitempty"`
	URLs         []string `json:"urls,omitempty"`
}

type csafDistrib struct {
	TLP struct {
		Label string `json:"label"`
		URL   string `json:"url"`
	} `json:"tlp"`
}

type csafNote struct {
	Category string `json:"category"`
	Text     string `json:"text"`
	Title    string `json:"title,omitempty"`
}

type csafPublisher struct {
	Category       string `json:"category"`
	ContactDetails string `json:"contact_details,omitempty"`
	Name           string `json:"name"`
	Namespace      string `json:"namespace"`
}

type csafReference struct {
	Category string `json:"category"`
	Summary  string `json:"summary"`
	URL      string `json:"url"`
}

type csafTracking struct {
	CurrentReleaseDate string         `json:"current_release_date"`
	Generator          csafGenerator  `json:"generator"`
	ID                 string         `json:"id"`
	InitialReleaseDate string         `json:"initial_release_date"`
	RevisionHistory    []csafRevision `json:"revision_history"`
	Status             string         `json:"status"`
	Version            string         `json:"version"`
}

type csafGenerator struct {
	Date   string `json:"date"`
	Engine struct {
		Name string `json:"name"`
	} `json:"engine"`
}

type csafRevision struct {
	Date    string `json:"date"`
	Number  string `json:"number"`
	Summary string `json:"summary"`
}

type csafTree struct {
	Branches []csafBranch `json:"branches"`
}

type csafBranch struct {
	Category string       `json:"category"`
	Name     string       `json:"name"`
	Branches []csafBranch `json:"branches,omitempty"`
	Product  *csafProduct `json:"product,omitempty"`
}

type csafProduct struct {
	Name      string `json:"name"`
	ProductID string `json:"product_id"`
}

type csafVuln struct {
	CVE           string            `json:"cve,omitempty"`
	CWE           *csafCWE          `json:"cwe,omitempty"`
	IDs           []csafID          `json:"ids,omitempty"`
	Notes         []csafNote        `json:"notes"`
	ProductStatus csafProductStatus `json:"product_status"`
	Remediations  []csafRemediation `json:"remediations,omitempty"`
	Scores        []csafScore       `json:"scores,omitempty"`
	Title         string            `json:"title"`
}

type csafCWE struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type csafID struct {
	SystemName string `json:"system_name"`
	Text       string `json:"text"`
}

type csafProductStatus struct {
	Fixed         []string `json:"fixed,omitempty"`
	KnownAffected []string `json:"known_affected,omitempty"`
}

type csafRemediation struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids"`
}

type csafScore struct {
	CVSSv3   csafCVSS3 `json:"cvss_v3"`
	Products []string  `json:"products"`
}

type csafCVSS3 struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	VectorString string  `json:"vectorString"`
	Version      string  `json:"version"`
}

// FileName is the CSAF distribution file name of a tracking id (CSAF 2.0
// §5.1): lowercase, every character outside [a-z0-9+-] replaced by "_", plus
// ".json".
func FileName(trackingID string) string {
	return fileNameRe.ReplaceAllString(strings.ToLower(trackingID), "_") + ".json"
}

var fileNameRe = regexp.MustCompile(`[^a-z0-9+\-]`)

// DocumentPath is where a released document lives under the advisories
// directory: <year of initial release>/<file name>.
func DocumentPath(trackingID string, initial time.Time) string {
	return strconv.Itoa(initial.UTC().Year()) + "/" + FileName(trackingID)
}

func csafDate(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// Render builds the CSAF document for a. status is "final" for a release and
// "draft" for a preview. baseURL is where the provider directory is served
// (PUBLIC_URL; the publisher namespace without one): the self reference
// points into it.
func Render(a Advisory, pub Publisher, baseURL, status string, now time.Time) (csafDoc, error) {
	if !pub.Configured() {
		return csafDoc{}, ErrPublisher
	}
	if len(a.Revisions) == 0 || a.InitialReleaseAt == nil || a.CurrentReleaseAt == nil {
		return csafDoc{}, fmt.Errorf("render: advisory %s has no revision", a.TrackingID)
	}
	d := csafDoc{Vulnerabilities: []csafVuln{}}
	doc := &d.Document
	doc.Category = "csaf_security_advisory"
	doc.CSAFVersion = "2.0"
	doc.Lang = "en"
	doc.Distribution.TLP.Label = "WHITE"
	doc.Distribution.TLP.URL = "https://www.first.org/tlp/"
	doc.Publisher = csafPublisher{Category: "vendor", Name: pub.Name, Namespace: pub.Namespace, ContactDetails: pub.Contact}
	doc.Title = a.Title
	doc.Notes = []csafNote{{Category: "summary", Title: "Summary", Text: a.Summary}}
	if a.Details != "" {
		doc.Notes = append(doc.Notes, csafNote{Category: "details", Title: "Details", Text: a.Details})
	}
	if a.State == StateWithdrawn {
		doc.Notes = append(doc.Notes, csafNote{Category: "general", Title: "Withdrawn",
			Text: "This advisory has been withdrawn. " + a.Revisions[len(a.Revisions)-1].Summary})
	}
	base := strings.TrimRight(cmp.Or(baseURL, pub.Namespace), "/")
	doc.References = []csafReference{{Category: "self", Summary: "Canonical URL",
		URL: base + "/csaf/advisories/" + DocumentPath(a.TrackingID, *a.InitialReleaseAt)}}
	for _, ack := range a.Acknowledgments {
		doc.Acknowledgments = append(doc.Acknowledgments, csafAck(ack))
	}
	t := &doc.Tracking
	t.ID = a.TrackingID
	t.Status = status
	t.Version = strconv.Itoa(a.Version)
	t.InitialReleaseDate = csafDate(*a.InitialReleaseAt)
	t.CurrentReleaseDate = csafDate(*a.CurrentReleaseAt)
	t.Generator.Date = csafDate(now)
	t.Generator.Engine.Name = "Xila"
	for _, r := range a.Revisions {
		t.RevisionHistory = append(t.RevisionHistory, csafRevision{Date: csafDate(r.Date), Number: strconv.Itoa(r.Number), Summary: r.Summary})
	}

	// Product tree: vendor → product name → one branch per version or range.
	var versions []csafBranch
	productID := map[string]string{}
	id := func(r VersionRef) string {
		cat, name := "product_version", r.Version
		if r.Range != "" {
			cat, name = "product_version_range", r.Range
		}
		key := cat + "|" + name
		if pid, ok := productID[key]; ok {
			return pid
		}
		pid := fmt.Sprintf("CSAFPID-%04d", len(productID)+1)
		productID[key] = pid
		versions = append(versions, csafBranch{Category: cat, Name: name,
			Product: &csafProduct{Name: a.ProductName + " " + name, ProductID: pid}})
		return pid
	}
	v := csafVuln{Title: a.Title, Notes: []csafNote{{Category: "description", Title: "Description", Text: a.Summary}}}
	for _, r := range a.Affected {
		v.ProductStatus.KnownAffected = appendNew(v.ProductStatus.KnownAffected, id(r))
	}
	var fixedNames []string
	for _, r := range a.Fixed {
		v.ProductStatus.Fixed = appendNew(v.ProductStatus.Fixed, id(r))
		fixedNames = append(fixedNames, cmp.Or(r.Version, r.Range))
	}
	d.ProductTree.Branches = []csafBranch{{Category: "vendor", Name: pub.Name, Branches: []csafBranch{
		{Category: "product_name", Name: a.ProductName, Branches: versions},
	}}}
	if a.CVE != "" {
		v.CVE = a.CVE
	} else {
		v.IDs = []csafID{{SystemName: pub.Name, Text: a.TrackingID}}
	}
	if a.CWE != "" {
		v.CWE = &csafCWE{ID: a.CWE, Name: a.CWEName}
	}
	// Every known_affected product needs a remediation (CSAF 2.0 §6.1.27.6).
	switch {
	case a.Remediation != "":
		v.Remediations = []csafRemediation{{Category: "vendor_fix", Details: a.Remediation, ProductIDs: v.ProductStatus.KnownAffected}}
	case len(fixedNames) > 0:
		v.Remediations = []csafRemediation{{Category: "vendor_fix",
			Details: "Update to " + strings.Join(fixedNames, ", ") + ".", ProductIDs: v.ProductStatus.KnownAffected}}
	default:
		v.Remediations = []csafRemediation{{Category: "none_available", Details: "No remediation is available yet.",
			ProductIDs: v.ProductStatus.KnownAffected}}
	}
	if a.CVSSVector != "" {
		c, err := parseCVSS3(a.CVSSVector)
		if err != nil {
			return csafDoc{}, err
		}
		v.Scores = []csafScore{{Products: v.ProductStatus.KnownAffected,
			CVSSv3: csafCVSS3{BaseScore: c.Score, BaseSeverity: c.Severity, VectorString: c.Vector, Version: c.Version}}}
	}
	d.Vulnerabilities = append(d.Vulnerabilities, v)
	return d, nil
}

func appendNew(list []string, s string) []string {
	if slices.Contains(list, s) {
		return list
	}
	return append(list, s)
}

// Marshal renders the document as indented JSON (what is frozen and served).
func Marshal(d csafDoc) (json.RawMessage, error) {
	return json.MarshalIndent(d, "", "  ")
}
