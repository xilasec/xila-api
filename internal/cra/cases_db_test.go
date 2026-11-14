package cra_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/cra"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/notify"
	"github.com/xilasec/xila-api/internal/pgtest"
)

type fixture struct {
	pool     *pgxpool.Pool
	findings *finding.Repository
	repo     *cra.Repository
	svc      *cra.Service
	now      time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pool := pgtest.Pool(t)
	notifyRepo := notify.NewRepository(pool)
	// Every event reaches the outbox through one global channel.
	if _, err := notifyRepo.Create(context.Background(), notify.Channel{Name: "all", Type: "webhook",
		URL: "https://hooks.example.test/x", Events: []string{"*"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	repo := cra.NewRepository(pool)
	fx := &fixture{pool: pool, findings: finding.NewRepository(pool), repo: repo,
		svc: cra.NewService(repo, notify.NewService(notifyRepo, notify.SMTPConfig{}),
			cra.Manufacturer{Name: "Acme GmbH", Contact: "psirt@acme.test", MainEstablishment: "DE"}),
		now: time.Date(2026, 10, 24, 22, 30, 0, 0, time.UTC)} // DST ends in the EU that night
	fx.svc.SetClock(func() time.Time { return fx.now })
	return fx
}

func (fx *fixture) project(t *testing.T, slug string, inScope bool) string {
	t.Helper()
	var id string
	if err := fx.pool.QueryRow(context.Background(), `
		WITH o AS (INSERT INTO organizations (slug, name) VALUES ($1, $1) RETURNING id),
		t AS (INSERT INTO teams (org_id, slug, name) SELECT id, $1, $1 FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name, cra_in_scope, cra_product_name, cra_member_states)
		SELECT id, $1, $1, $2, 'Widget OS', '{DE,FR}' FROM t RETURNING id`, slug, inScope).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func (fx *fixture) finding(t *testing.T, projectID, fp, cve, fixed string) string {
	t.Helper()
	f, err := fx.findings.Upsert(context.Background(), finding.Finding{ProjectID: projectID, Fingerprint: fp, Scanner: "trivy",
		Category: domain.CategorySCA, RuleID: cve, Title: "flaw in " + fp, Severity: domain.SeverityCritical,
		CVE: []string{cve}, PackageName: "pkg-" + fp, PackageVersion: "1.0", FixedVersion: fixed, Metadata: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	return f.ID
}

func (fx *fixture) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	if _, err := fx.pool.Exec(context.Background(), q, args...); err != nil {
		t.Fatal(err)
	}
}

func (fx *fixture) outbox(t *testing.T, eventType string) int {
	t.Helper()
	var n int
	if err := fx.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM notification_outbox WHERE event->>'type' = $1`, eventType).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A KEV-listed (or weaponized) open finding of an in-scope project opens one
// case with the Article 14 clock from awareness; out-of-scope projects,
// duplicates, closed findings and other branches never do, and re-sweeping
// opens nothing twice.
func TestCasesOpenForActivelyExploitedInScopeFindings(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()
	in := fx.project(t, "in", true)
	out := fx.project(t, "out", false)

	kev := fx.finding(t, in, "a", "CVE-2024-0001", "")
	kevAgain := fx.finding(t, in, "a2", "cve-2024-0001", "") // same CVE from another location
	weaponized := fx.finding(t, in, "b", "CVE-2024-0002", "2.0")
	dup := fx.finding(t, in, "c", "CVE-2024-0003", "")
	fixed := fx.finding(t, in, "d", "CVE-2024-0004", "")
	quiet := fx.finding(t, in, "e", "CVE-2024-0005", "")
	outKEV := fx.finding(t, out, "f", "CVE-2024-0001", "")
	fx.exec(t, `UPDATE findings SET kev = true WHERE id = ANY($1)`, []string{kev, kevAgain, dup, fixed, outKEV})
	fx.exec(t, `UPDATE findings SET exploit_maturity = 'weaponized' WHERE id = $1`, weaponized)
	fx.exec(t, `UPDATE findings SET exploit_maturity = 'poc' WHERE id = $1`, quiet)
	fx.exec(t, `UPDATE findings SET duplicate_of = $1 WHERE id = $2`, kev, dup)
	fx.exec(t, `UPDATE findings SET status = 'remediated' WHERE id = $1`, fixed)

	res, err := fx.svc.Sweep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Opened != 2 {
		t.Fatalf("opened %d cases, want 2 (CVE-2024-0001 once, CVE-2024-0002)", res.Opened)
	}
	cases, err := fx.svc.List(ctx, cra.CaseFilter{})
	if err != nil || len(cases) != 2 {
		t.Fatalf("cases = %d, %v", len(cases), err)
	}
	byVuln := map[string]cra.Case{}
	for _, c := range cases {
		if c.ProjectID != in {
			t.Errorf("case %s opened on the out-of-scope project", c.VulnID)
		}
		byVuln[c.VulnID] = c
	}
	k, ok := byVuln["CVE-2024-0001"]
	if !ok {
		t.Fatalf("no case for the KEV finding: %+v", byVuln)
	}
	if k.Trigger != cra.TriggerKEV || k.State != cra.StateOpen || !k.AwareAt.Equal(fx.now) {
		t.Errorf("kev case = trigger %s state %s aware %v", k.Trigger, k.State, k.AwareAt)
	}
	// Exactly +24 h and +72 h, even across the DST change in between.
	if !k.EarlyWarningDueAt.Equal(fx.now.Add(24*time.Hour)) || !k.NotificationDueAt.Equal(fx.now.Add(72*time.Hour)) {
		t.Errorf("due = %v / %v, want %v / %v", k.EarlyWarningDueAt, k.NotificationDueAt, fx.now.Add(24*time.Hour), fx.now.Add(72*time.Hour))
	}
	if k.FinalReportDueAt != nil || k.Deadlines[2].Status != cra.DeadlineNotStarted {
		t.Errorf("final report clock started without a fix: %v %s", k.FinalReportDueAt, k.Deadlines[2].Status)
	}
	// A fix already available starts the final-report clock at awareness.
	w := byVuln["CVE-2024-0002"]
	if w.Trigger != cra.TriggerWeaponized || w.FinalReportDueAt == nil || !w.FinalReportDueAt.Equal(fx.now.Add(14*24*time.Hour)) {
		t.Errorf("weaponized case = trigger %s final due %v", w.Trigger, w.FinalReportDueAt)
	}
	if n := fx.outbox(t, notify.EventCRACaseOpened); n != 2 {
		t.Errorf("cra.case_opened queued %d times, want 2", n)
	}

	// Re-sweeping (and the enrichment hook) opens nothing twice.
	fx.now = fx.now.Add(time.Hour)
	if res, err := fx.svc.Sweep(ctx); err != nil || res.Opened != 0 {
		t.Fatalf("re-sweep opened %d, %v", res.Opened, err)
	}
	if n, err := fx.svc.OpenExploited(ctx, in); err != nil || n != 0 {
		t.Fatalf("hook re-open = %d, %v", n, err)
	}
	if n := fx.outbox(t, notify.EventCRACaseOpened); n != 2 {
		t.Errorf("cra.case_opened queued %d times after re-sweeps, want 2", n)
	}

	// A fix appearing later starts the final clock at the sweep that sees it —
	// on whichever finding of the vulnerability it shows up (the case was
	// opened from one of kev / kevAgain; the fix lands on the other one too).
	fx.exec(t, `UPDATE findings SET fixed_version = '1.1' WHERE id = $1`, kevAgain)
	if res, err := fx.svc.Sweep(ctx); err != nil || res.Corrective != 1 {
		t.Fatalf("corrective sweep = %+v, %v", res, err)
	}
	if k, _ = fx.svc.Get(ctx, k.ID); k.FinalReportDueAt == nil || !k.FinalReportDueAt.Equal(fx.now.Add(14*24*time.Hour)) {
		t.Errorf("final due after the fix = %v, want %v", k.FinalReportDueAt, fx.now.Add(14*24*time.Hour))
	}

	// Manual opening: refused out of scope, refused twice, fine otherwise.
	if _, err := fx.svc.Open(ctx, out, outKEV, "", "", nil); !errors.Is(err, cra.ErrNotInScope) {
		t.Errorf("manual open out of scope = %v", err)
	}
	if _, err := fx.svc.Open(ctx, in, kevAgain, "", "", nil); !errors.Is(err, cra.ErrDuplicate) {
		t.Errorf("manual open of a vulnerability with a case = %v", err)
	}
	if _, err := fx.svc.Open(ctx, in, outKEV, "", "", nil); !errors.Is(err, cra.ErrFindingNotFound) {
		t.Errorf("manual open of another project's finding = %v", err)
	}
	aware := fx.now.Add(-30 * time.Hour)
	m, err := fx.svc.Open(ctx, in, quiet, "", "seen in an incident", &aware)
	if err != nil || m.Trigger != cra.TriggerManual || !m.EarlyWarningDueAt.Equal(aware.Add(24*time.Hour)) ||
		m.Deadlines[0].Status != cra.DeadlineMissed || m.Deadlines[1].Status != cra.DeadlinePending {
		t.Fatalf("manual case = %+v, %v", m, err)
	}
}

// Due-soon and missed alerts go through the outbox exactly once per case and
// stage, however often the sweep runs.
func TestDeadlineAlertsQueuedOnce(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()
	p := fx.project(t, "p", true)
	fx.exec(t, `UPDATE findings SET kev = true WHERE id = $1`, fx.finding(t, p, "a", "CVE-2024-1111", ""))
	start := fx.now
	if res, err := fx.svc.Sweep(ctx); err != nil || res.Opened != 1 || res.DueSoon != 0 || res.Missed != 0 {
		t.Fatalf("opening sweep = %+v, %v", res, err)
	}

	sweep := func(at time.Duration, wantSoon, wantMissed int) {
		t.Helper()
		fx.now = start.Add(at)
		res, err := fx.svc.Sweep(ctx)
		if err != nil || res.DueSoon != wantSoon || res.Missed != wantMissed {
			t.Fatalf("sweep at +%v = %+v, %v; want due_soon %d missed %d", at, res, err, wantSoon, wantMissed)
		}
	}
	sweep(17*time.Hour, 0, 0)  // 7 h before the early warning: quiet
	sweep(18*time.Hour, 1, 0)  // 6 h before: due soon
	sweep(20*time.Hour, 0, 0)  // again: already alerted
	sweep(24*time.Hour, 0, 1)  // the deadline: missed
	sweep(30*time.Hour, 0, 0)  // again: already alerted
	sweep(66*time.Hour, 1, 0)  // the notification's 6 h window
	sweep(80*time.Hour, 0, 1)  // the notification missed
	sweep(200*time.Hour, 0, 0) // nothing left (no final clock yet)
	if soon, missed := fx.outbox(t, notify.EventCRADeadlineDue), fx.outbox(t, notify.EventCRADeadlineMissed); soon != 2 || missed != 2 {
		t.Errorf("outbox: due_soon %d, missed %d; want 2 and 2 (one per stage)", soon, missed)
	}
	var stages string
	if err := fx.pool.QueryRow(ctx, `SELECT string_agg(event->'fields'->>'stages', '|' ORDER BY id) FROM notification_outbox
		WHERE event->>'type' = $1`, notify.EventCRADeadlineMissed).Scan(&stages); err != nil || stages != "early_warning|notification" {
		t.Errorf("missed stages = %q, %v", stages, err)
	}

	// A sweep that first runs after two deadlines passed alerts both at once,
	// as one event.
	q := fx.project(t, "q", true)
	fx.exec(t, `UPDATE findings SET kev = true WHERE id = $1`, fx.finding(t, q, "b", "CVE-2024-2222", ""))
	fx.now = start.Add(300 * time.Hour)
	if _, err := fx.svc.OpenExploited(ctx, q); err != nil {
		t.Fatal(err)
	}
	fx.now = fx.now.Add(100 * time.Hour)
	if res, err := fx.svc.Sweep(ctx); err != nil || res.Missed != 1 {
		t.Fatalf("late sweep = %+v, %v", res, err)
	}
	if missed := fx.outbox(t, notify.EventCRADeadlineMissed); missed != 3 {
		t.Errorf("missed events = %d, want 3", missed)
	}
}

// The workflow moves forward one submission at a time; each transition is
// recorded with who, when and (for submissions) the payload as sent.
func TestCaseTransitionsRecorded(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()
	p := fx.project(t, "p", true)
	fx.exec(t, `UPDATE findings SET kev = true WHERE id = $1`, fx.finding(t, p, "a", "CVE-2024-3333", ""))
	var alice string
	if err := fx.pool.QueryRow(ctx, `INSERT INTO users (email, password_hash) VALUES ('alice@acme.test', 'x') RETURNING id`).Scan(&alice); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.svc.OpenExploited(ctx, ""); err != nil {
		t.Fatal(err)
	}
	cases, _ := fx.svc.List(ctx, cra.CaseFilter{ProjectID: p})
	id := cases[0].ID

	if _, err := fx.svc.Submit(ctx, id, alice, cra.StageNotification, "", ""); !errors.Is(err, cra.ErrTransition) {
		t.Errorf("notification before the early warning = %v", err)
	}
	fx.now = fx.now.Add(3 * time.Hour)
	c, err := fx.svc.Submit(ctx, id, alice, cra.StageEarlyWarning, "SRP-1", "sent via the platform")
	if err != nil || c.State != cra.StateEarlyWarningSent || !c.EarlyWarningSentAt.Equal(fx.now) || c.Deadlines[0].Status != cra.DeadlineMet {
		t.Fatalf("early warning = %+v, %v", c, err)
	}
	if _, err := fx.svc.Update(ctx, id, alice, cra.Edit{Sensitivity: new("secret")}); !errors.Is(err, cra.ErrInvalid) {
		t.Errorf("bad sensitivity = %v", err)
	}
	if _, err := fx.svc.Update(ctx, id, alice, cra.Edit{Exploitation: new("RCE via crafted header"), Sensitivity: new("TLP:AMBER")}); err != nil {
		t.Fatal(err)
	}
	fx.now = fx.now.Add(80 * time.Hour) // past the 72 h notification deadline
	if c, err = fx.svc.Submit(ctx, id, alice, cra.StageNotification, "SRP-2", ""); err != nil || c.Deadlines[1].Status != cra.DeadlineLate {
		t.Fatalf("late notification = %+v, %v", c.Deadlines, err)
	}
	if _, err := fx.svc.Submit(ctx, id, alice, cra.StageFinal, "", ""); !errors.Is(err, cra.ErrTransition) {
		t.Errorf("final report without a corrective measure = %v", err)
	}
	fixedAt := fx.now.Add(-time.Hour)
	if c, err = fx.svc.Update(ctx, id, alice, cra.Edit{CorrectiveAvailableAt: &fixedAt}); err != nil ||
		!c.FinalReportDueAt.Equal(fixedAt.Add(14*24*time.Hour)) {
		t.Fatalf("corrective measure = %v, %v", c.FinalReportDueAt, err)
	}
	if _, err := fx.svc.Dismiss(ctx, id, alice, ""); !errors.Is(err, cra.ErrInvalid) {
		t.Errorf("dismiss without a reason = %v", err)
	}
	if c, err = fx.svc.Submit(ctx, id, alice, cra.StageFinal, "SRP-3", ""); err != nil || c.State != cra.StateFinalReportSent {
		t.Fatalf("final = %+v, %v", c, err)
	}
	if _, err := fx.svc.Dismiss(ctx, id, alice, "changed our mind"); !errors.Is(err, cra.ErrTransition) {
		t.Errorf("dismissing a reported case = %v", err)
	}
	if c, err = fx.svc.Close(ctx, id, alice, ""); err != nil || c.State != cra.StateClosed || c.Compliant() {
		t.Fatalf("close = %s compliant %v, %v (the notification was late)", c.State, c.Compliant(), err)
	}

	events, err := fx.svc.Events(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	want := []cra.State{cra.StateOpen, cra.StateEarlyWarningSent, cra.StateEarlyWarningSent, cra.StateNotificationSent,
		cra.StateNotificationSent, cra.StateFinalReportSent, cra.StateClosed}
	if len(events) != len(want) {
		t.Fatalf("events = %d, want %d: %+v", len(events), len(want), events)
	}
	for i, e := range events {
		if e.ToState != want[i] {
			t.Errorf("event %d to %s, want %s", i, e.ToState, want[i])
		}
		if i > 0 && e.ActorEmail != "alice@acme.test" {
			t.Errorf("event %d actor %q", i, e.ActorEmail)
		}
	}
	if events[0].ActorID != nil {
		t.Errorf("an automatically opened case names an actor: %v", *events[0].ActorID)
	}
	ew := events[1]
	if ew.Stage != cra.StageEarlyWarning || ew.Reference != "SRP-1" || ew.Payload == nil ||
		ew.Payload.Manufacturer.Name != "Acme GmbH" || ew.Payload.Vulnerability.ID != "CVE-2024-3333" {
		t.Errorf("early warning event = %+v", ew)
	}
	if n := events[3].Payload; n == nil || n.Exploitation.Nature != "RCE via crafted header" || n.Sensitivity != "TLP:AMBER" {
		t.Errorf("notification payload = %+v", n)
	}
	if f := events[5].Payload; f == nil || f.Impact == nil || f.Measures == nil || f.Measures.CorrectiveAvailableAt == nil {
		t.Errorf("final payload = %+v", f)
	}
}

// switches is a feature store with one switch.
type switches map[string]bool

func (s switches) Enabled(_ context.Context, key string) bool { on, ok := s[key]; return !ok || on }

// With the "cra" feature off nothing opens or alerts; the first sweep after it
// is switched back on catches up.
func TestSweepSkipsWhileCRAFeatureOff(t *testing.T) {
	fx := newFixture(t)
	ctx := context.Background()
	in := fx.project(t, "in", true)
	fx.exec(t, `UPDATE findings SET kev = true WHERE id = $1`, fx.finding(t, in, "a", "CVE-2024-0001", ""))
	sw := switches{"cra": false}
	fx.svc.WithFeatures(sw)

	if res, err := fx.svc.Sweep(ctx); err != nil || res != (cra.SweepResult{}) {
		t.Fatalf("sweep while off = %+v, %v", res, err)
	}
	if n, err := fx.svc.OpenExploited(ctx, in); err != nil || n != 0 {
		t.Fatalf("OpenExploited while off = %d, %v", n, err)
	}
	if n := fx.outbox(t, notify.EventCRACaseOpened); n != 0 {
		t.Errorf("%d case-opened alerts while off", n)
	}
	sw["cra"] = true
	if res, err := fx.svc.Sweep(ctx); err != nil || res.Opened != 1 {
		t.Errorf("first sweep back on = %+v, %v; want the missed case opened", res, err)
	}
}
