package scanner

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Checkmarx parses the Checkmarx CxSAST XML report (<CxXMLResults>), as
// exported from the CxSAST web portal (Reports → XML) or produced by the CxSAST
// CLI / Jenkins plugin with an XML report option.
//
// Every <Result> is one data-flow path through a <Query>; the finding is placed
// at the path's sink (its last <PathNode>), so several paths of one query that
// reach the same sink line — e.g. two tainted parameters flowing into one
// executeQuery() — are folded into one finding. The rule id is the query id, the
// CWE comes from the query's cweId. A result's triage state is carried: Not
// Exploitable (state 1, or FalsePositive="True") → false positive, Confirmed /
// Urgent → confirmed. A folded finding only keeps the verdict when every path
// folded into it has it.
type Checkmarx struct{}

// NewCheckmarx constructs a Checkmarx parser.
func NewCheckmarx() Checkmarx { return Checkmarx{} }

// Scanner returns the tool identifier.
func (Checkmarx) Scanner() string { return "checkmarx" }

// PrimaryCategory is the scan-level category for Checkmarx reports.
func (Checkmarx) PrimaryCategory() domain.Category { return domain.CategorySAST }

type checkmarxReport struct {
	XMLName     xml.Name `xml:"CxXMLResults"`
	ProjectName string   `xml:"ProjectName,attr"`
	ScanID      string   `xml:"ScanId,attr"`
	Queries     []struct {
		ID         string            `xml:"id,attr"`
		Name       string            `xml:"name,attr"`
		CWE        string            `xml:"cweId,attr"`
		Group      string            `xml:"group,attr"`
		Severity   string            `xml:"Severity,attr"`
		Language   string            `xml:"Language,attr"`
		Categories string            `xml:"categories,attr"`
		Results    []checkmarxResult `xml:"Result"`
	} `xml:"Query"`
}

type checkmarxResult struct {
	FileName      string `xml:"FileName,attr"`
	Line          string `xml:"Line,attr"`
	Status        string `xml:"Status,attr"`
	Severity      string `xml:"Severity,attr"`
	FalsePositive string `xml:"FalsePositive,attr"`
	State         string `xml:"state,attr"`
	Remark        string `xml:"Remark,attr"`
	DeepLink      string `xml:"DeepLink,attr"`
	Path          struct {
		PathID       string              `xml:"PathId,attr"`
		SimilarityID string              `xml:"SimilarityId,attr"`
		Nodes        []checkmarxPathNode `xml:"PathNode"`
	} `xml:"Path"`
}

type checkmarxPathNode struct {
	FileName string `xml:"FileName"`
	Line     string `xml:"Line"`
	Name     string `xml:"Name"`
}

// Parse implements Parser.
func (Checkmarx) Parse(r io.Reader) ([]ParsedFinding, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read checkmarx report: %w", err)
	}
	raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))
	var rep checkmarxReport
	if err := xml.Unmarshal(raw, &rep); err != nil {
		if _, ok := errors.AsType[xml.UnmarshalError](err); ok {
			return nil, errors.New("decode checkmarx report: no <CxXMLResults> root — not a CxSAST XML report")
		}
		return nil, fmt.Errorf("decode checkmarx report: %w", err)
	}

	out := []ParsedFinding{}
	// untriaged records, per folded location, that some path has no verdict.
	untriaged := map[string]bool{}
	for _, q := range rep.Queries {
		title := strings.ReplaceAll(q.Name, "_", " ")
		for _, res := range q.Results {
			file, line := res.FileName, res.Line
			var source, sink checkmarxPathNode
			if n := len(res.Path.Nodes); n > 0 {
				source, sink = res.Path.Nodes[0], res.Path.Nodes[n-1]
				file, line = firstNonEmpty(sink.FileName, file), firstNonEmpty(sink.Line, line)
			}
			meta := map[string]any{
				"query":         q.Name,
				"query_group":   q.Group,
				"language":      q.Language,
				"status":        res.Status,
				"state":         res.State,
				"deep_link":     res.DeepLink,
				"similarity_id": res.Path.SimilarityID,
				"project":       rep.ProjectName,
			}
			if q.Categories != "" {
				meta["references"] = q.Categories
			}
			desc := title
			if source.FileName != "" {
				meta["source_file"] = source.FileName
				meta["source_line"] = source.Line
				desc = fmt.Sprintf("%s: %s (%s:%s) flows to %s (%s:%s)",
					title, source.Name, source.FileName, source.Line, sink.Name, sink.FileName, sink.Line)
			}
			switch {
			case res.State == "1" || strings.EqualFold(res.FalsePositive, "true"):
				setImportedStatus(meta, domain.FindingFalsePositive, firstNonEmpty(res.Remark, "Checkmarx: not exploitable"), zeroTime)
			case res.State == "2" || res.State == "3":
				setImportedStatus(meta, domain.FindingConfirmed, firstNonEmpty(res.Remark, "Checkmarx: confirmed"), zeroTime)
			}
			f := ParsedFinding{
				Category:    domain.CategorySAST,
				RuleID:      q.ID,
				Title:       title,
				Description: desc,
				Severity:    normalizeSeverity(firstNonEmpty(res.Severity, q.Severity)),
				CWE:         cweFrom(q.CWE),
				FilePath:    file,
				Metadata:    meta,
			}
			if n, err := strconv.Atoi(line); err == nil && n > 0 {
				f.Line = new(n)
			}
			if _, triaged := meta[metaRemoteTriage]; !triaged {
				untriaged[checkmarxLocation(f)] = true
			}
			out = append(out, f)
		}
	}
	out = mergeSameLocation(out)
	for _, f := range out {
		if untriaged[checkmarxLocation(f)] {
			delete(f.Metadata, metaRemoteTriage)
			delete(f.Metadata, metaRemoteTriageReason)
		}
	}
	return out, nil
}

// checkmarxLocation is the folding key of mergeSameLocation for one query.
func checkmarxLocation(f ParsedFinding) string {
	line := ""
	if f.Line != nil {
		line = strconv.Itoa(*f.Line)
	}
	return f.RuleID + "\x00" + f.FilePath + "\x00" + line
}
