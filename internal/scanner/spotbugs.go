package scanner

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/xilasec/xila-api/internal/domain"
)

// SpotBugs parses SpotBugs' native XML report (`spotbugs -xml -output
// report.xml`, or the Maven/Gradle plugin's spotbugsXml goal) — the successor
// to FindBugs. CodeQL/SpotBugs already work through the generic SARIF import,
// but SpotBugs' native XML carries the exact bug pattern id and, when a
// security plugin like FindSecBugs annotated the pattern, a CWE id that SARIF
// conversion often drops.
//
// Severity comes from the bug's own priority (1 = High, 2 = Medium, 3 = Low) —
// SpotBugs' own ranking, not invented.
type SpotBugs struct{}

// NewSpotBugs constructs a SpotBugs parser.
func NewSpotBugs() SpotBugs { return SpotBugs{} }

// Scanner returns the tool identifier.
func (SpotBugs) Scanner() string { return "spotbugs" }

// PrimaryCategory is the scan-level category for SpotBugs reports.
func (SpotBugs) PrimaryCategory() domain.Category { return domain.CategorySAST }

type spotBugsCollection struct {
	XMLName     xml.Name `xml:"BugCollection"`
	BugPatterns []struct {
		Type  string `xml:"type,attr"`
		CWEID string `xml:"cweid,attr"`
	} `xml:"BugPattern"`
	BugInstances []spotBugsInstance `xml:"BugInstance"`
}

type spotBugsInstance struct {
	Type         string `xml:"type,attr"`
	Priority     string `xml:"priority,attr"`
	Category     string `xml:"category,attr"`
	Abbrev       string `xml:"abbrev,attr"`
	CWEID        string `xml:"cweid,attr"`
	ShortMessage string `xml:"ShortMessage"`
	LongMessage  string `xml:"LongMessage"`
	Class        struct {
		ClassName string `xml:"classname,attr"`
	} `xml:"Class"`
	SourceLines []struct {
		SourcePath string `xml:"sourcepath,attr"`
		ClassName  string `xml:"classname,attr"`
		Start      string `xml:"start,attr"`
	} `xml:"SourceLine"`
}

var spotBugsSeverity = map[string]domain.Severity{
	"1": domain.SeverityHigh,
	"2": domain.SeverityMedium,
	"3": domain.SeverityLow,
}

// Parse implements Parser.
func (SpotBugs) Parse(r io.Reader) ([]ParsedFinding, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read spotbugs report: %w", err)
	}
	raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))
	var coll spotBugsCollection
	if err := xml.Unmarshal(raw, &coll); err != nil {
		if _, ok := errors.AsType[xml.UnmarshalError](err); ok {
			return nil, errors.New("decode spotbugs report: no <BugCollection> root — not a SpotBugs XML report")
		}
		return nil, fmt.Errorf("decode spotbugs report: %w", err)
	}

	// Core SpotBugs doesn't carry a CWE on the instance; a security plugin
	// (FindSecBugs) sometimes adds a cweid to the pattern definition instead.
	cweByType := make(map[string]string, len(coll.BugPatterns))
	for _, p := range coll.BugPatterns {
		if p.CWEID != "" {
			cweByType[p.Type] = p.CWEID
		}
	}

	out := make([]ParsedFinding, 0, len(coll.BugInstances))
	for _, bug := range coll.BugInstances {
		sev, ok := spotBugsSeverity[bug.Priority]
		if !ok {
			sev = domain.SeverityMedium // unrecognized priority stays visible, not info
		}
		f := ParsedFinding{
			Category:    domain.CategorySAST,
			RuleID:      bug.Type,
			Title:       firstNonEmpty(bug.ShortMessage, bug.Type),
			Description: firstNonEmpty(bug.LongMessage, bug.ShortMessage),
			Severity:    sev,
			CWE:         cweFrom(firstNonEmpty(bug.CWEID, cweByType[bug.Type])),
			Metadata: map[string]any{
				"category": bug.Category,
				"abbrev":   bug.Abbrev,
				"class":    bug.Class.ClassName,
			},
		}
		// The last direct SourceLine child of a BugInstance is the bug's own
		// location; the ones nested under Class/Method/Field describe those
		// elements, not where the bug itself was found.
		if n := len(bug.SourceLines); n > 0 {
			sl := bug.SourceLines[n-1]
			f.FilePath = firstNonEmpty(sl.SourcePath, sl.ClassName)
			if line, err := strconv.Atoi(sl.Start); err == nil && line > 0 {
				f.Line = new(line)
			}
		}
		out = append(out, f)
	}
	return out, nil
}
