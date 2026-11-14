// Package compliance turns findings into framework posture: each control is
// satisfied unless an open finding maps to it, and the score is the share of
// passing controls. Mappings are by CWE (tool-agnostic), by scanner rule, by an
// open finding's exploit / SLA state (kev, sla), by an open finding's kind
// (category, severity) or by a project fact (sbom, vex). A manual control (a
// process requirement) is never scored: it is neither passing nor failing until
// someone attests to it, and while that attestation is live it counts as met.
package compliance

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/archive"
)

// Sentinel errors.
var (
	ErrFrameworkNotFound = errors.New("framework not found")
	ErrControlNotFound   = errors.New("control not found")
	ErrNotManual         = errors.New("only manual controls are attested")
	ErrNoAttestation     = errors.New("control has no attestation")
)

// Framework is a compliance standard (e.g. OWASP Top 10).
type Framework struct {
	ID          string `json:"id"`
	Key         string `json:"key"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
}

// ControlResult is a control's evaluated posture for a project.
type ControlResult struct {
	Code         string `json:"code"`
	Title        string `json:"title"`
	Description  string `json:"description"`
	OpenFindings int    `json:"open_findings"`
	Passing      bool   `json:"passing"`
	// Status is "passing", "failing", or "manual" (not machine-assessable).
	Status string `json:"status"`
	// Evidence says what decided the status ("2 open findings", "no SBOM on
	// the default version", "attested by …"); empty for unattested manual
	// controls.
	Evidence string `json:"evidence"`
	// Manual marks a process requirement no scan can judge; Attestation is its
	// record (also when expired, which returns the control to manual).
	Manual      bool         `json:"manual"`
	Attestation *Attestation `json:"attestation"`
}

// Attestation is a project's record of how a manual control is met.
type Attestation struct {
	Note        string     `json:"note"`
	EvidenceURL string     `json:"evidence_url"`
	AttestedBy  string     `json:"attested_by"` // the attester's email
	AttestedAt  time.Time  `json:"attested_at"`
	ExpiresAt   *time.Time `json:"expires_at"`
	Expired     bool       `json:"expired"`
}

// Control statuses. An attested control is a manual one with a live
// attestation: scored as met.
const (
	StatusPassing  = "passing"
	StatusFailing  = "failing"
	StatusManual   = "manual"
	StatusAttested = "attested"
)

// Result is a framework's posture for one project.
type Result struct {
	Framework        string          `json:"framework"`
	Name             string          `json:"name"`
	Version          string          `json:"version"`
	TotalControls    int             `json:"total_controls"`   // scored controls: measured + attested (unattested manual excluded)
	PassingControls  int             `json:"passing_controls"` // measured passing + attested
	FailingControls  int             `json:"failing_controls"`
	AttestedControls int             `json:"attested_controls"`
	ManualControls   int             `json:"manual_controls"` // manual controls still to attest
	Score            float64         `json:"score"`           // percent of scored controls met
	Controls         []ControlResult `json:"controls"`
}

// Repository provides access to frameworks and compliance evaluation.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

// ListFrameworks returns the available compliance frameworks.
func (r *Repository) ListFrameworks(ctx context.Context) ([]Framework, error) {
	const q = `SELECT id, key, name, version, description FROM frameworks ORDER BY name`
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list frameworks: %w", err)
	}
	defer rows.Close()

	frameworks := []Framework{}
	for rows.Next() {
		var f Framework
		if err := rows.Scan(&f.ID, &f.Key, &f.Name, &f.Version, &f.Description); err != nil {
			return nil, fmt.Errorf("scan framework: %w", err)
		}
		frameworks = append(frameworks, f)
	}
	return frameworks, rows.Err()
}

// FindingMatchesSQL is THE rule for "an open finding fails a control": a
// relation of (finding_id, project_id, control_id) for every open finding
// whose projects satisfy projectPred (a condition on f.project_id, e.g.
// "f.project_id = $1"). Evaluate and ControlFindings read it, and the
// portfolio rollup reads its per-project form, ProjectFailingControlsSQL, built
// from the same matchBranches — so they can't disagree.
//
// A finding is judged when it is open or confirmed, on its project's default
// version, not a cross-tool duplicate and not archived. It fails a control
// when one of the control's mappings matches it: by CWE, by scanner rule, by
// category or severity (its kind), or by its own state (kev: on a KEV list;
// sla: past its remediation deadline). sbom and vex mappings are project facts
// (ProjectFactFailingSQL), never matched by a finding.
//
// Written as one equi-join per match type over the open findings, read once:
// a single OR-ed join condition can only be evaluated pair by pair (every
// mapping × every open finding), which took seconds per project at 100k
// findings (docs/SCALE.md).
func FindingMatchesSQL(projectPred string) string {
	return findingMatches(projectPred, "control_mappings", false)
}

// ProjectFailingControlsSQL is FindingMatchesSQL reduced to (project_id,
// control_id): the controls an open finding fails, per project. Each branch
// collapses to its distinct keys before joining, so a portfolio of a million
// findings yields thousands of rows instead of millions.
func ProjectFailingControlsSQL(projectPred string) string {
	return findingMatches(projectPred, "control_mappings", true)
}

// matchBranch is one match type of the rule: the open-finding columns it
// joins on, the join condition against mapping m, and a condition on the
// finding alone.
type matchBranch struct {
	matchType, keys, on, where string
}

var matchBranches = []matchBranch{
	{"cwe", "f.cwe", "m.cwe = f.cwe", "f.cwe IS NOT NULL"},
	{"rule", "f.scanner, f.rule_id", "m.scanner = f.scanner AND m.rule_id = f.rule_id", "true"},
	{"category", "f.category", "m.category = f.category", "true"},
	{"severity", "f.severity", "m.severity = f.severity", "true"},
	{"kev", "", "true", "f.kev"},
	{"sla", "", "true", "f.sla_due_at < now()"},
}

// findingMatches builds the rule over the mappings in relation mappings
// (control_mappings, or a CTE of some frameworks' mappings, so a query scoped
// to them never matches the others'). perProject projects it to distinct
// (project_id, control_id) pairs.
func findingMatches(projectPred, mappings string, perProject bool) string {
	var b strings.Builder
	b.WriteString(`(WITH open_f AS MATERIALIZED (
			SELECT f.id, f.project_id, f.cwe, f.scanner, f.rule_id, f.category, f.severity, f.kev, f.sla_due_at
			FROM findings f
			WHERE ` + projectPred + `
			  AND f.status IN ('open', 'confirmed') AND f.duplicate_of IS NULL
			  AND f.version_id IN (SELECT id FROM project_versions WHERE is_default)
			  AND` + archive.Finding("f") + `
		)`)
	for i, br := range matchBranches {
		if i > 0 {
			if perProject {
				b.WriteString("\n\t\tUNION")
			} else {
				b.WriteString("\n\t\tUNION ALL")
			}
		}
		join := ` JOIN ` + mappings + ` m ON m.match_type = '` + br.matchType + `' AND ` + br.on
		switch {
		case !perProject:
			b.WriteString("\n\t\tSELECT f.id AS finding_id, f.project_id, m.control_id FROM open_f f" + join +
				" WHERE " + br.where)
		case br.keys == "":
			// Matched by the finding's own state: reduce to the projects that
			// have such a finding first, or every KEV finding × every kev
			// mapping would be produced only to be de-duplicated.
			b.WriteString("\n\t\tSELECT f.project_id, m.control_id FROM (SELECT DISTINCT f.project_id FROM open_f f WHERE " +
				br.where + ") f" + join)
		default:
			// Matched by a key: the join against the (small) mapping set
			// filters first; UNION de-duplicates the few matches.
			b.WriteString("\n\t\tSELECT f.project_id, m.control_id FROM open_f f" + join + " WHERE " + br.where)
		}
	}
	b.WriteString(")")
	return b.String()
}

// AttestedSQL is whether manual control %[2]s has a live attestation for
// project %[1]s — shared with the portfolio rollup, which scores it as met.
const AttestedSQL = `EXISTS (SELECT 1 FROM control_attestations ca
	WHERE ca.project_id = %[1]s AND ca.control_id = %[2]s AND (ca.expires_at IS NULL OR ca.expires_at > now()))`

// FactMappingsSQL is the mappings ProjectFactFailingSQL can fail — the project
// facts, one row per control and fact type. A query that only needs the facts
// joins this instead of every mapping (a control may have dozens of CWE or
// rule mappings, for which ProjectFactFailingSQL is always false).
const FactMappingsSQL = `(SELECT DISTINCT control_id, match_type FROM control_mappings WHERE match_type IN ('sbom', 'vex'))`

// ProjectFactFailingSQL is whether mapping m fails on project %s's facts: no
// SBOM on its default version (sbom), no documented vulnerability analysis —
// no VEX statement or finding assessment — (vex). Format with the project id
// expression.
const ProjectFactFailingSQL = `CASE m.match_type
	WHEN 'sbom' THEN NOT EXISTS (SELECT 1 FROM sboms sb WHERE sb.project_id = %[1]s
	                              AND sb.version_id IN (SELECT id FROM project_versions WHERE is_default))
	WHEN 'vex' THEN NOT EXISTS (SELECT 1 FROM vex_statements vx WHERE vx.project_id = %[1]s)
	           AND NOT EXISTS (SELECT 1 FROM finding_assessments fa WHERE fa.project_id = %[1]s)
	ELSE false END`

// Evaluate computes a project's posture against one framework. A control fails
// when an open/confirmed finding on the default version maps to it, or a
// project fact it depends on is missing; a manual control is scored only while
// attested.
func (r *Repository) Evaluate(ctx context.Context, projectID, frameworkKey string) (Result, error) {
	res, err := r.EvaluateAll(ctx, projectID, []string{frameworkKey})
	if err != nil {
		return Result{}, err
	}
	return res[0], nil
}

// EvaluateAll is Evaluate for several frameworks at once, in the order given:
// the project's open findings are matched once for all of them (the project
// page shows every framework). ErrFrameworkNotFound if any key is unknown.
func (r *Repository) EvaluateAll(ctx context.Context, projectID string, frameworkKeys []string) ([]Result, error) {
	q := `
		WITH fw AS (SELECT id, key, name, version FROM frameworks WHERE key = ANY($2)),
		fw_mappings AS (
			SELECT m.* FROM control_mappings m JOIN controls c ON c.id = m.control_id JOIN fw ON fw.id = c.framework_id
		)
		SELECT fw.key, fw.name, fw.version, c.code, c.title, c.description, c.assessment,
		       COALESCE(max(fc.n), 0),
		       COALESCE(bool_or(` + fmt.Sprintf(ProjectFactFailingSQL, "$1") + `), false),
		       COALESCE(array_agg(DISTINCT m.match_type) FILTER (WHERE m.match_type IS NOT NULL), '{}'),
		       a.note, a.evidence_url, a.attested_by_email, a.attested_at, a.expires_at
		FROM fw
		JOIN controls c ON c.framework_id = fw.id
		LEFT JOIN control_attestations a ON a.project_id = $1 AND a.control_id = c.id
		LEFT JOIN control_mappings m ON m.control_id = c.id
		LEFT JOIN (SELECT control_id, count(DISTINCT finding_id) AS n
		           FROM ` + findingMatches("f.project_id = $1", "fw_mappings", false) + ` x GROUP BY control_id) fc ON fc.control_id = c.id
		GROUP BY fw.key, fw.name, fw.version, c.id, c.code, c.title, c.description, c.assessment,
		         a.note, a.evidence_url, a.attested_by_email, a.attested_at, a.expires_at`

	rows, err := r.db.Query(ctx, q, projectID, frameworkKeys)
	if err != nil {
		return nil, fmt.Errorf("evaluate compliance: %w", err)
	}
	defer rows.Close()

	byKey := map[string]*Result{}
	now := time.Now()
	for rows.Next() {
		var (
			res        Result
			ctrl       ControlResult
			assessment string
			factFails  bool
			kinds      []string
			note, url  *string
			by         *string
			at         *time.Time
			expires    *time.Time
		)
		if err := rows.Scan(&res.Framework, &res.Name, &res.Version, &ctrl.Code, &ctrl.Title, &ctrl.Description,
			&assessment, &ctrl.OpenFindings, &factFails, &kinds, &note, &url, &by, &at, &expires); err != nil {
			return nil, fmt.Errorf("scan control: %w", err)
		}
		ctrl.Manual = assessment == "manual"
		if note != nil {
			ctrl.Attestation = &Attestation{Note: *note, EvidenceURL: *url, AttestedBy: *by, AttestedAt: *at,
				ExpiresAt: expires, Expired: expires != nil && !expires.After(now)}
		}
		ctrl.Status, ctrl.Evidence = controlStatus(assessment, ctrl.OpenFindings, factFails, kinds, ctrl.Attestation)
		ctrl.Passing = ctrl.Status == StatusPassing || ctrl.Status == StatusAttested
		acc, ok := byKey[res.Framework]
		if !ok {
			acc = &res
			byKey[res.Framework] = acc
		}
		acc.Controls = append(acc.Controls, ctrl)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]Result, 0, len(frameworkKeys))
	for _, key := range frameworkKeys {
		res, ok := byKey[key]
		if !ok {
			return nil, ErrFrameworkNotFound
		}
		slices.SortStableFunc(res.Controls, func(x, y ControlResult) int { return CompareCodes(x.Code, y.Code) })
		for _, c := range res.Controls {
			switch c.Status {
			case StatusPassing:
				res.PassingControls++
			case StatusFailing:
				res.FailingControls++
			case StatusAttested:
				res.AttestedControls++
				res.PassingControls++
			default:
				res.ManualControls++
			}
		}
		res.TotalControls = res.PassingControls + res.FailingControls
		if res.TotalControls > 0 {
			res.Score = math.Round(float64(res.PassingControls)/float64(res.TotalControls)*1000) / 10
		}
		out = append(out, *res)
	}
	return out, nil
}

// controlStatus decides a control's status and states the evidence for it.
func controlStatus(assessment string, openFindings int, factFails bool, kinds []string, att *Attestation) (string, string) {
	if assessment == "manual" {
		if att == nil {
			return StatusManual, ""
		}
		if att.Expired {
			return StatusManual, "attestation by " + att.AttestedBy + " expired " + att.ExpiresAt.UTC().Format(time.DateOnly)
		}
		return StatusAttested, "attested by " + att.AttestedBy + " on " + att.AttestedAt.UTC().Format(time.DateOnly)
	}
	var why []string
	if openFindings > 0 {
		why = append(why, fmt.Sprintf("%d open finding(s)", openFindings))
	}
	if factFails {
		for _, k := range kinds {
			switch k {
			case "sbom":
				why = append(why, "no SBOM on the default version")
			case "vex":
				why = append(why, "no VEX statement or finding assessment")
			}
		}
	}
	if len(why) > 0 {
		return StatusFailing, strings.Join(why, "; ")
	}
	switch {
	case slices.Contains(kinds, "sbom"):
		return StatusPassing, "an SBOM is on the default version"
	case slices.Contains(kinds, "vex"):
		return StatusPassing, "vulnerability analysis is documented"
	case slices.Contains(kinds, "kev"):
		return StatusPassing, "no open known-exploited finding"
	case slices.Contains(kinds, "sla"):
		return StatusPassing, "no open finding past its SLA"
	case slices.Contains(kinds, "severity"):
		return StatusPassing, "no open finding of the mapped severities"
	case slices.Contains(kinds, "category"):
		return StatusPassing, "no open finding of the mapped kinds"
	case len(kinds) > 0:
		return StatusPassing, "no open finding in the mapped weakness classes"
	}
	return StatusPassing, "no mapped signal"
}

// CompareCodes orders control codes naturally: digit runs by value, the rest
// as text ("V1.2" < "V1.2.1" < "V1.10", "A.8.9" < "A.8.10").
func CompareCodes(a, b string) int {
	for a != "" && b != "" {
		ta, ra := codeToken(a)
		tb, rb := codeToken(b)
		if c := compareToken(ta, tb); c != 0 {
			return c
		}
		a, b = ra, rb
	}
	return len(a) - len(b)
}

func codeToken(s string) (string, string) {
	digit := s[0] >= '0' && s[0] <= '9'
	i := 1
	for i < len(s) && (s[i] >= '0' && s[i] <= '9') == digit {
		i++
	}
	return s[:i], s[i:]
}

func compareToken(a, b string) int {
	ad, bd := a[0] >= '0' && a[0] <= '9', b[0] >= '0' && b[0] <= '9'
	if ad && bd {
		a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
		if len(a) != len(b) {
			return len(a) - len(b)
		}
	}
	return strings.Compare(a, b)
}
