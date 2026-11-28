package finding

import (
	"context"
	"errors"
	"fmt"

	"github.com/xilasec/xila-api/internal/domain"
)

// PriorityScope selects the findings Reprioritize recomputes: the ones a scan
// last reported, the ones on an asset, or these findings. Exactly one must be
// set.
type PriorityScope struct {
	ScanID     string
	AssetID    string
	ProjectID  string // every finding of a project (its priority weights changed)
	FindingIDs []string
}

// Reprioritize recomputes priority from every stored input — severity, EPSS,
// KEV, exploit maturity, dependency reachability and the asset's exposure — for
// the scoped findings, writing only the rows whose number moves. It returns the
// projects whose priorities moved (they have to regroup: priority elects a dedup
// group's primary) and how many findings changed.
//
// Unlike the single-signal writers it reads every input from the row, so it is
// also how a severity reset by a triage rule regains its other factors.
func (r *Repository) Reprioritize(ctx context.Context, s PriorityScope) ([]string, int, error) {
	set := 0
	for _, ok := range []bool{s.ScanID != "", s.AssetID != "", s.ProjectID != "", s.FindingIDs != nil} {
		if ok {
			set++
		}
	}
	if set != 1 {
		return nil, 0, errors.New("reprioritize: exactly one of scan, asset, project or findings is required")
	}
	if s.FindingIDs != nil && len(s.FindingIDs) == 0 {
		return nil, 0, nil
	}
	var scan, asset, project *string
	if s.ScanID != "" {
		scan = &s.ScanID
	}
	if s.ProjectID != "" {
		project = &s.ProjectID
	}
	if s.AssetID != "" {
		asset = &s.AssetID
	}
	rows, err := r.db.Query(ctx, `
		SELECT id, severity, epss, kev, malicious, COALESCE(exploit_maturity, ''), dep_direct, dep_scope, `+assetExposureSQL+`,
			(SELECT priority_weights FROM projects pw WHERE pw.id = findings.project_id)
		FROM findings
		WHERE ($1::uuid IS NULL OR last_scan_id = $1) AND ($2::uuid IS NULL OR asset_id = $2)
		  AND ($3::uuid[] IS NULL OR id = ANY($3)) AND ($4::uuid IS NULL OR project_id = $4)`, scan, asset, s.FindingIDs, project)
	if err != nil {
		return nil, 0, fmt.Errorf("priority inputs: %w", err)
	}
	var ids []string
	var prios []float64
	for rows.Next() {
		var (
			id       string
			sev      domain.Severity
			epss     *float64
			kev      bool
			bad      bool
			maturity domain.ExploitMaturity
			direct   *bool
			scope    domain.DepScope
			exposure domain.Exposure
			weights  []byte
		)
		if err := rows.Scan(&id, &sev, &epss, &kev, &bad, &maturity, &direct, &scope, &exposure, &weights); err != nil {
			rows.Close()
			return nil, 0, fmt.Errorf("scan priority inputs: %w", err)
		}
		x := domain.Exploitability{KEV: kev, Maturity: maturity, Malicious: bad}
		if epss != nil {
			x.EPSS = *epss
		}
		ids = append(ids, id)
		prios = append(prios, domain.WeightsFromJSON(weights).Priority(sev, x, domain.Reachability{Direct: direct, Scope: scope}, exposure))
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if len(ids) == 0 {
		return nil, 0, nil
	}

	changed, err := r.db.Query(ctx, `
		UPDATE findings f SET priority = u.p, updated_at = now()
		FROM (SELECT unnest($1::uuid[]) AS id, unnest($2::float8[]) AS p) u
		WHERE f.id = u.id AND f.priority IS DISTINCT FROM u.p::real
		RETURNING f.project_id`, ids, prios)
	if err != nil {
		return nil, 0, fmt.Errorf("set priorities: %w", err)
	}
	defer changed.Close()
	n := 0
	seen := map[string]bool{}
	projects := []string{}
	for changed.Next() {
		var pid string
		if err := changed.Scan(&pid); err != nil {
			return nil, 0, err
		}
		n++
		if !seen[pid] {
			seen[pid] = true
			projects = append(projects, pid)
		}
	}
	return projects, n, changed.Err()
}
