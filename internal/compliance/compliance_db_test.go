package compliance_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/compliance"
	"github.com/xilasec/xila-api/internal/pgtest"
)

func seedProject(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	ctx := context.Background()
	var teamID, projectID string
	if err := pool.QueryRow(ctx, `WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-cmp','o') RETURNING id) INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id`).Scan(&teamID); err != nil {
		t.Fatalf("seed team: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO projects (team_id, slug, name) VALUES ($1,'p','p') RETURNING id`, teamID).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	return projectID
}

func addFinding(t *testing.T, pool *pgxpool.Pool, projectID, fp string, cwe int, status string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO findings (project_id, fingerprint, scanner, category, title, severity, cwe, status)
		 VALUES ($1, $2, 'semgrep', 'sast', 't', 'high', $3, $4)`, projectID, fp, cwe, status); err != nil {
		t.Fatalf("insert finding: %v", err)
	}
}

func TestEvaluateOWASP(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := compliance.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)

	// Clean project: everything passes.
	res, err := repo.Evaluate(ctx, projectID, "owasp-top-10-2021")
	if err != nil {
		t.Fatalf("evaluate clean: %v", err)
	}
	if res.TotalControls != 10 || res.FailingControls != 0 || res.Score != 100 {
		t.Fatalf("clean posture = %+v, want 10 controls / 0 failing / 100", res)
	}

	// CWE-89 (SQL injection) -> A03 fails. CWE-502 (deserialization) -> A08 fails.
	addFinding(t, pool, projectID, "fp-sqli", 89, "open")
	addFinding(t, pool, projectID, "fp-deser", 502, "confirmed")
	// A resolved finding must NOT fail its control.
	addFinding(t, pool, projectID, "fp-fixed", 79, "remediated")

	res, err = repo.Evaluate(ctx, projectID, "owasp-top-10-2021")
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if res.FailingControls != 2 || res.PassingControls != 8 {
		t.Errorf("posture = %d failing / %d passing, want 2 / 8", res.FailingControls, res.PassingControls)
	}
	if res.Score != 80 {
		t.Errorf("score = %v, want 80", res.Score)
	}

	failing := map[string]int{}
	for _, c := range res.Controls {
		if !c.Passing {
			failing[c.Code] = c.OpenFindings
		}
	}
	if failing["A03"] != 1 || failing["A08"] != 1 {
		t.Errorf("failing controls = %v, want A03:1 A08:1", failing)
	}
}

func TestEvaluateCISByProwlerRule(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := compliance.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)

	// A failing Prowler check (rule-typed mapping) fails its CIS control.
	if _, err := pool.Exec(ctx,
		`INSERT INTO findings (project_id, fingerprint, scanner, category, rule_id, title, severity, status)
		 VALUES ($1, 'fp-cis', 'prowler', 'cloud', 'iam_root_mfa_enabled', 'root mfa', 'critical', 'open')`,
		projectID); err != nil {
		t.Fatalf("insert prowler finding: %v", err)
	}

	res, err := repo.Evaluate(ctx, projectID, "cis-aws-3.0")
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if res.FailingControls != 1 {
		t.Errorf("failing = %d, want 1", res.FailingControls)
	}
	var found bool
	for _, c := range res.Controls {
		if c.Code == "1.5" {
			found = true
			if c.Passing {
				t.Error("CIS 1.5 should be failing (root MFA)")
			}
		}
	}
	if !found {
		t.Fatal("CIS control 1.5 not present in framework")
	}
}

func TestEvaluateUnknownFramework(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := compliance.NewRepository(pool)
	projectID := seedProject(t, pool)

	if _, err := repo.Evaluate(context.Background(), projectID, "nope-1.0"); err != compliance.ErrFrameworkNotFound {
		t.Errorf("err = %v, want ErrFrameworkNotFound", err)
	}
}

func TestListFrameworks(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := compliance.NewRepository(pool)

	frameworks, err := repo.ListFrameworks(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var found bool
	for _, f := range frameworks {
		if f.Key == "owasp-top-10-2021" {
			found = true
		}
	}
	if !found {
		t.Error("expected owasp-top-10-2021 to be seeded")
	}
}

// The EU CRA pack: measurable requirements pass or fail on findings and
// project facts; process requirements are manual — never scored, never shown
// as passing.
func TestEvaluateEUCRA(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := compliance.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)
	status := func(res compliance.Result) map[string]compliance.ControlResult {
		m := map[string]compliance.ControlResult{}
		for _, c := range res.Controls {
			m[c.Code] = c
		}
		return m
	}

	// A fresh project: no SBOM and no documented analysis fail II.1 / II.4;
	// with no findings, everything else measurable passes.
	res, err := repo.Evaluate(ctx, projectID, "eu-cra")
	if err != nil {
		t.Fatal(err)
	}
	c := status(res)
	if res.ManualControls != 10 || res.TotalControls != 12 || res.FailingControls != 2 {
		t.Fatalf("fresh posture = %d assessable, %d failing, %d manual; want 12 / 2 / 10", res.TotalControls, res.FailingControls, res.ManualControls)
	}
	if c["II.1"].Status != "failing" || c["II.1"].Evidence != "no SBOM on the default version" ||
		c["II.4"].Status != "failing" || c["I.2(a)"].Status != "passing" || c["II.5"].Status != "manual" || c["II.5"].Passing {
		t.Errorf("fresh controls = %+v", c)
	}

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	// An SBOM, a VEX statement, and three findings: one on KEV, one past its
	// SLA, one in a mapped weakness class (CWE-798 hard-coded credentials).
	exec(`INSERT INTO sboms (project_id, format, spec_version, component_count, artifact) VALUES ($1, 'cyclonedx', '1.5', 0, 'web')`, projectID)
	exec(`INSERT INTO vex_statements (project_id, vuln_id, status) VALUES ($1, 'CVE-2021-44228', 'not_affected')`, projectID)
	exec(`INSERT INTO findings (project_id, fingerprint, scanner, category, title, severity, status, kev)
		VALUES ($1, 'kev', 'trivy', 'sca', 'log4shell', 'critical', 'open', true)`, projectID)
	exec(`INSERT INTO findings (project_id, fingerprint, scanner, category, title, severity, status)
		VALUES ($1, 'late', 'trivy', 'sca', 'old', 'high', 'open')`, projectID)
	exec(`UPDATE findings SET first_seen_at = now() - interval '400 days' WHERE fingerprint = 'late'`)
	exec(`UPDATE findings SET severity = 'medium' WHERE fingerprint = 'late'`) // re-dates the SLA clock from first seen
	addFinding(t, pool, projectID, "creds", 798, "open")

	res, err = repo.Evaluate(ctx, projectID, "eu-cra")
	if err != nil {
		t.Fatal(err)
	}
	c = status(res)
	if c["II.1"].Status != "passing" || c["II.4"].Status != "passing" {
		t.Errorf("with an SBOM and a VEX statement: II.1 %+v, II.4 %+v", c["II.1"], c["II.4"])
	}
	if c["I.2(a)"].Status != "failing" || c["I.2(a)"].OpenFindings != 1 {
		t.Errorf("I.2(a) with an open KEV finding = %+v", c["I.2(a)"])
	}
	if c["II.2"].Status != "failing" {
		t.Errorf("II.2 with a finding past its SLA = %+v", c["II.2"])
	}
	if c["I.2(d)"].Status != "failing" || c["I.2(d)"].Evidence != "1 open finding(s)" {
		t.Errorf("I.2(d) with hard-coded credentials = %+v", c["I.2(d)"])
	}
	if c["I.2(e)"].Status != "passing" {
		t.Errorf("I.2(e) without a confidentiality weakness = %+v", c["I.2(e)"])
	}

	// Remediating the KEV finding passes I.2(a) again.
	exec(`UPDATE findings SET status = 'remediated' WHERE fingerprint = 'kev'`)
	if res, _ = repo.Evaluate(ctx, projectID, "eu-cra"); status(res)["I.2(a)"].Status != "passing" {
		t.Errorf("I.2(a) after remediation = %+v", status(res)["I.2(a)"])
	}

	// Other frameworks are unaffected: OWASP has no manual controls.
	if owasp, err := repo.Evaluate(ctx, projectID, "owasp-top-10-2021"); err != nil || owasp.ManualControls != 0 || owasp.TotalControls != 10 {
		t.Errorf("owasp = %+v %v", owasp, err)
	}
}

// referenceMatches is the matching rule as it was originally written — one
// OR-ed join condition — kept here only as the oracle for FindingMatchesSQL,
// which states the same rule as one equi-join per match type for speed.
const referenceMatches = `
	SELECT f.id::text, m.control_id::text FROM findings f
	JOIN control_mappings m ON
	     ((m.match_type = 'cwe' AND f.cwe = m.cwe)
	   OR (m.match_type = 'rule' AND f.scanner = m.scanner AND f.rule_id = m.rule_id)
	   OR (m.match_type = 'category' AND f.category = m.category)
	   OR (m.match_type = 'severity' AND f.severity = m.severity)
	   OR (m.match_type = 'kev' AND f.kev)
	   OR (m.match_type = 'sla' AND f.sla_due_at < now()))
	WHERE f.project_id = $1
	  AND f.status IN ('open', 'confirmed') AND f.duplicate_of IS NULL
	  AND f.version_id IN (SELECT id FROM project_versions WHERE is_default)
	  AND f.archived_at IS NULL`

func TestFindingMatchesIsTheRule(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	projectID := seedProject(t, pool)
	var otherTeam, other string
	if err := pool.QueryRow(ctx, `SELECT team_id FROM projects WHERE id = $1`, projectID).Scan(&otherTeam); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO projects (team_id, slug, name) VALUES ($1,'other','other') RETURNING id`, otherTeam).Scan(&other); err != nil {
		t.Fatal(err)
	}
	// Real mapping values from the seeded frameworks, one per match type.
	var ruleScanner, ruleID, category, severity string
	if err := pool.QueryRow(ctx, `SELECT scanner, rule_id FROM control_mappings WHERE match_type = 'rule' LIMIT 1`).Scan(&ruleScanner, &ruleID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT category FROM control_mappings WHERE match_type = 'category' LIMIT 1`).Scan(&category); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT severity FROM control_mappings WHERE match_type = 'severity' LIMIT 1`).Scan(&severity); err != nil {
		t.Fatal(err)
	}
	insert := func(project, fp, scanner, cat, sev, rule string, cwe *int, kev bool, status string) string {
		t.Helper()
		var id string
		if err := pool.QueryRow(ctx, `INSERT INTO findings (project_id, fingerprint, scanner, category, title, severity, rule_id, cwe, kev, status)
			VALUES ($1,$2,$3,$4,'t',$5,$6,$7,$8,$9) RETURNING id`, project, fp, scanner, cat, sev, rule, cwe, kev, status).Scan(&id); err != nil {
			t.Fatalf("insert %s: %v", fp, err)
		}
		return id
	}
	cwe89 := 89
	insert(projectID, "cwe", "semgrep", "sast", "low", "r1", &cwe89, false, "open")
	insert(projectID, "rule", ruleScanner, "cloud", "low", ruleID, nil, false, "confirmed")
	insert(projectID, "category", "x", category, "low", "r2", nil, false, "open")
	insert(projectID, "severity", "x", "sast", severity, "r3", nil, false, "open")
	insert(projectID, "kev", "x", "sca", "low", "r4", nil, true, "open")
	sla := insert(projectID, "sla", "x", "sca", "low", "r5", nil, false, "open")
	if _, err := pool.Exec(ctx, `UPDATE findings SET sla_due_at = now() - interval '1 day' WHERE id = $1`, sla); err != nil {
		t.Fatal(err)
	}
	// Never judged: resolved, a cross-tool duplicate, archived, on a branch,
	// or in another project.
	insert(projectID, "fixed", "semgrep", "sast", "high", "r6", &cwe89, true, "remediated")
	primary := insert(projectID, "primary", "x", "sast", "low", "r7", nil, false, "open")
	dup := insert(projectID, "dup", "semgrep", "sast", "low", "r8", &cwe89, false, "open")
	archived := insert(projectID, "archived", "semgrep", "sast", "low", "r9", &cwe89, false, "open")
	branch := insert(projectID, "branch", "semgrep", "sast", "low", "r10", &cwe89, false, "open")
	insert(other, "other", "semgrep", "sast", "low", "r11", &cwe89, true, "open")
	for _, q := range []string{
		`UPDATE findings SET duplicate_of = '` + primary + `' WHERE id = '` + dup + `'`,
		`UPDATE findings SET archived_at = now() WHERE id = '` + archived + `'`,
		`UPDATE findings SET version_id = project_version('` + projectID + `', 'feature', 'branch') WHERE id = '` + branch + `'`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	pairs := func(q string) map[string]bool {
		t.Helper()
		rows, err := pool.Query(ctx, q, projectID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]bool{}
		for rows.Next() {
			var f, c string
			if err := rows.Scan(&f, &c); err != nil {
				t.Fatal(err)
			}
			out[f+"/"+c] = true
		}
		return out
	}
	want := pairs(referenceMatches)
	got := pairs(`SELECT finding_id::text, control_id::text FROM ` + compliance.FindingMatchesSQL("f.project_id = $1") + ` x`)
	if len(want) < 6 {
		t.Fatalf("reference matched only %d pairs: the fixture no longer covers every match type", len(want))
	}
	for k := range want {
		if !got[k] {
			t.Errorf("missing match %s", k)
		}
	}
	for k := range got {
		if !want[k] {
			t.Errorf("extra match %s", k)
		}
	}

	// The portfolio's per-project form is the same rule reduced to (project,
	// control) pairs.
	byProject := func(q string) map[string]bool {
		t.Helper()
		rows, err := pool.Query(ctx, q, []string{projectID, other})
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]bool{}
		for rows.Next() {
			var p, c string
			if err := rows.Scan(&p, &c); err != nil {
				t.Fatal(err)
			}
			out[p+"/"+c] = true
		}
		return out
	}
	pred := "f.project_id = ANY($1::uuid[])"
	wantP := byProject(`SELECT DISTINCT project_id::text, control_id::text FROM ` + compliance.FindingMatchesSQL(pred) + ` x`)
	gotP := byProject(`SELECT project_id::text, control_id::text FROM ` + compliance.ProjectFailingControlsSQL(pred) + ` x`)
	if len(gotP) != len(wantP) {
		t.Errorf("per-project pairs = %d, want %d", len(gotP), len(wantP))
	}
	for k := range wantP {
		if !gotP[k] {
			t.Errorf("per-project form misses %s", k)
		}
	}
}
