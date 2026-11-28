package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// GoVulnCheck parses `govulncheck -json ./...` output.
//
// This one is special. govulncheck does real **call-graph analysis**: it reports
// not just that a vulnerable module is in your dependency tree, but whether your
// code actually calls the vulnerable symbol. That is the reachability signal we
// deliberately don't compute ourselves (it requires program analysis, i.e. a
// scanner) — so we ingest it from the tool that does.
//
// Findings whose trace reaches a symbol are the ones that can actually execute;
// findings without one are "the module is present, but you never call the
// vulnerable function". We record that distinction on the finding, and it lands in
// the same `dep_scope`/priority machinery as SBOM-derived reachability.
type GoVulnCheck struct{}

// NewGoVulnCheck constructs a GoVulnCheck parser.
func NewGoVulnCheck() GoVulnCheck { return GoVulnCheck{} }

// Scanner returns the tool identifier.
func (GoVulnCheck) Scanner() string { return "govulncheck" }

// PrimaryCategory is the scan-level category for govulncheck reports.
func (GoVulnCheck) PrimaryCategory() domain.Category { return domain.CategorySCA }

// govulncheck streams one JSON object per message, each with exactly one key.
type govulnMessage struct {
	OSV     *govulnOSV     `json:"osv"`
	Finding *govulnFinding `json:"finding"`
}

type govulnOSV struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Aliases  []string `json:"aliases"`
	Affected []struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Events []struct {
				Fixed string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

type govulnFinding struct {
	OSV          string `json:"osv"`
	FixedVersion string `json:"fixed_version"`
	Trace        []struct {
		Module   string `json:"module"`
		Version  string `json:"version"`
		Package  string `json:"package"`
		Function string `json:"function"`
		Position *struct {
			Filename string `json:"filename"`
			Line     int    `json:"line"`
		} `json:"position"`
	} `json:"trace"`
}

// Parse converts a govulncheck JSON stream into findings.
func (GoVulnCheck) Parse(r io.Reader) ([]ParsedFinding, error) {
	advisories := map[string]govulnOSV{}
	// govulncheck emits several findings per vulnerability, one per trace depth
	// (module-level, package-level, symbol-level). Keep the most specific one: a
	// symbol-level hit proves the vulnerable code is reachable.
	best := map[string]govulnFinding{}
	order := []string{}

	err := decodeJSONLines(r, func(raw json.RawMessage) error {
		var msg govulnMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			return fmt.Errorf("decode govulncheck message: %w", err)
		}
		switch {
		case msg.OSV != nil:
			advisories[msg.OSV.ID] = *msg.OSV
		case msg.Finding != nil:
			id := msg.Finding.OSV
			prev, seen := best[id]
			if !seen {
				order = append(order, id)
				best[id] = *msg.Finding
				return nil
			}
			if traceDepth(*msg.Finding) > traceDepth(prev) {
				best[id] = *msg.Finding
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	out := make([]ParsedFinding, 0, len(order))
	for _, id := range order {
		fnd := best[id]
		osv := advisories[id]
		called := calledSymbol(fnd)

		// Not called = the vulnerable function is never reached from your code.
		// govulncheck is authoritative about this, so we downgrade rather than
		// report it as an equal.
		severity := domain.SeverityHigh
		title := id
		if osv.Summary != "" {
			title = fmt.Sprintf("%s: %s", id, osv.Summary)
		}
		if called == "" {
			severity = domain.SeverityLow
			title += " (vulnerable code not called)"
		}

		f := ParsedFinding{
			Category:       domain.CategorySCA,
			RuleID:         id,
			Title:          title,
			Description:    osv.Details,
			Severity:       severity,
			CVE:            cvesFrom(append([]string{id}, osv.Aliases...)...),
			FixedVersion:   firstNonEmptyStr(fnd.FixedVersion, govulnFixed(osv)),
			URL:            "https://pkg.go.dev/vuln/" + id,
			Package:        traceModule(fnd),
			PackageVersion: traceVersion(fnd),
			Metadata: map[string]any{
				"called":        called != "",
				"called_symbol": called,
				"reachable_by":  "govulncheck",
			},
		}
		if len(f.CVE) > 0 {
			f.Purl = "pkg:golang/" + f.Package
		}
		if pos := lastPosition(fnd); pos != nil {
			f.FilePath = pos.Filename
			f.Line = new(pos.Line)
		}
		out = append(out, f)
	}
	return out, nil
}

// traceDepth ranks how specific a finding's trace is: a symbol beats a package
// beats a module.
func traceDepth(f govulnFinding) int {
	if calledSymbol(f) != "" {
		return 3
	}
	for _, t := range f.Trace {
		if t.Package != "" {
			return 2
		}
	}
	return 1
}

// calledSymbol returns the vulnerable function your code reaches, if any.
func calledSymbol(f govulnFinding) string {
	for _, t := range f.Trace {
		if t.Function != "" {
			return strings.TrimPrefix(t.Package+"."+t.Function, ".")
		}
	}
	return ""
}

func traceModule(f govulnFinding) string {
	for _, t := range f.Trace {
		if t.Module != "" {
			return t.Module
		}
	}
	return ""
}

func traceVersion(f govulnFinding) string {
	for _, t := range f.Trace {
		if t.Version != "" {
			return t.Version
		}
	}
	return ""
}

// lastPosition is the call site in *your* code — the last frame with a position,
// which is where a developer has to go and look.
func lastPosition(f govulnFinding) *struct {
	Filename string `json:"filename"`
	Line     int    `json:"line"`
} {
	for _, v := range slices.Backward(f.Trace) {
		if v.Position != nil {
			return v.Position
		}
	}
	return nil
}

func govulnFixed(osv govulnOSV) string {
	for _, a := range osv.Affected {
		for _, rng := range a.Ranges {
			for _, e := range rng.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}
