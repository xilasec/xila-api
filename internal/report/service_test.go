package report

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/compliance"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/portfolio"
	"github.com/xilasec/xila-api/internal/project"
)

type fakeOverview struct {
	ov   portfolio.Overview
	pids [][]string
}

func (f *fakeOverview) Overview(_ context.Context, pids []string) (portfolio.Overview, error) {
	f.pids = append(f.pids, pids)
	return f.ov, nil
}

// fakeFindings serves List per status, honoring Limit, and records filters.
type fakeFindings struct {
	byStatus map[domain.FindingStatus][]finding.Finding
	filters  []finding.Filter
}

func (f *fakeFindings) List(_ context.Context, flt finding.Filter) ([]finding.Finding, error) {
	f.filters = append(f.filters, flt)
	out := f.byStatus[flt.Status]
	return out[:min(flt.Limit, len(out))], nil
}

type fakeCompliance struct{}

func (fakeCompliance) ListFrameworks(context.Context) ([]compliance.Framework, error) {
	return []compliance.Framework{{Key: "owasp"}, {Key: "empty"}}, nil
}

func (fakeCompliance) Evaluate(_ context.Context, _, key string) (compliance.Result, error) {
	if key == "empty" {
		return compliance.Result{}, compliance.ErrFrameworkNotFound
	}
	return compliance.Result{Name: "OWASP Top 10", Version: "2021", Score: 80, PassingControls: 8, TotalControls: 10}, nil
}

type fakeProjects struct{}

func (fakeProjects) Get(_ context.Context, id string) (project.Project, error) {
	if id != "p1" {
		return project.Project{}, project.ErrNotFound
	}
	return project.Project{ID: "p1", Name: "Payments <API>", Slug: "payments", BusinessCriticality: domain.CriticalityHigh}, nil
}

func (fakeProjects) ListVersions(context.Context, string) ([]project.Version, error) {
	return []project.Version{{Name: "main", IsDefault: true}, {Name: "feature/x"}}, nil
}

type fakeRows struct{ rows []ProjectRow }

func (f fakeRows) ProjectRows(context.Context, []string) ([]ProjectRow, error) { return f.rows, nil }

func newTestService(ff *fakeFindings, rows []ProjectRow) (*Service, *fakeOverview) {
	ov := &fakeOverview{ov: portfolio.Overview{
		Projects:        1,
		TotalOpen:       5,
		RiskScore:       123.4,
		KEVOpen:         1,
		ExploitableOpen: 2,
		OpenBySeverity:  map[domain.Severity]int{domain.SeverityCritical: 2, domain.SeverityHigh: 3},
		Compliance:      []portfolio.FrameworkAverage{{Name: "CIS AWS", AvgScore: 66.7, ProjectsAssessed: 3}},
		SLA: finding.SLAStats{
			Breached: 4, DueSoon: 2, Met: 3, Missed: 1, Compliance: new(0.75), WindowDays: 90,
			MTTRDays: map[domain.Severity]float64{domain.SeverityHigh: 12.25},
		},
	}}
	svc := NewService(ov, ff, fakeCompliance{}, fakeProjects{}, fakeRows{rows: rows})
	svc.now = func() time.Time { return time.Date(2026, 10, 27, 9, 30, 0, 0, time.UTC) }
	return svc, ov
}

func render(t *testing.T, r Report) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Render(&buf, r); err != nil {
		t.Fatalf("render: %v", err)
	}
	return buf.String()
}

func TestProjectReportNumbersAndEscaping(t *testing.T) {
	malicious := `<script>alert("x")</script><img src=x onerror=alert(1)>`
	ff := &fakeFindings{byStatus: map[domain.FindingStatus][]finding.Finding{
		domain.FindingOpen: {{
			ID: "f1", ProjectID: "p1", Title: malicious, Severity: domain.SeverityCritical,
			Status: domain.FindingOpen, Priority: 42.5, KEV: true, EPSS: new(0.934),
			CVE: []string{"CVE-2024-0001"}, PackageName: "openssl", PackageVersion: "1.0", FixedVersion: "1.1",
		}},
	}}
	svc, ov := newTestService(ff, nil)
	rep, err := svc.Project(context.Background(), "p1", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(ov.pids) != 1 || len(ov.pids[0]) != 1 || ov.pids[0][0] != "p1" {
		t.Errorf("overview should be scoped to the project, got %v", ov.pids)
	}
	html := render(t, rep)

	for _, want := range []string{
		"Payments &lt;API&gt;",           // project name escaped in the title
		"123.4",                          // risk score
		"Generated 2026-10-27 09:30 UTC", // generated at
		`<strong>main</strong>`,          // default branch covered
		"Not included: feature/x",        // other branches named as excluded
		"75.0%",                          // SLA compliance
		"3 of 4",                         // fixed on time of fixed
		"high 12.2d",                     // MTTR
		"OWASP Top 10 2021",              // framework posture…
		"8 of 10 controls passing",
		"80.0%",
		"CVE-2024-0001",
		`<span class="flag">KEV</span>`,
		"93.4%", // EPSS
		"&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt;&lt;img src=x onerror=alert(1)&gt;",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("report missing %q", want)
		}
	}
	if strings.Contains(html, "<script") || strings.Contains(html, "<img") {
		t.Error("finding title was rendered as markup")
	}
	if len(rep.Compliance) != 1 {
		t.Errorf("a framework without controls should be skipped, got %+v", rep.Compliance)
	}
	// Open by severity, with counts in the fixed order.
	crit := strings.Index(html, `sev-critical">critical</span></td>`)
	high := strings.Index(html, `sev-high">high</span></td>`)
	if crit < 0 || high < 0 || crit > high {
		t.Error("severity table should list critical before high")
	}
	if !strings.Contains(html, `<td class="n">2</td>`) || !strings.Contains(html, `<td class="n">3</td>`) {
		t.Error("severity counts missing")
	}
}

func TestProjectReportUnknownProject(t *testing.T) {
	svc, _ := newTestService(&fakeFindings{}, nil)
	if _, err := svc.Project(context.Background(), "nope", Options{}); err != ErrProjectNotFound {
		t.Fatalf("err = %v, want ErrProjectNotFound", err)
	}
}

// TestTopMergesLiveStatuses checks the priority list: open and confirmed
// findings merged by priority, capped at topN, read the way the inbox reads
// them (default version, duplicates collapsed).
func TestTopMergesLiveStatuses(t *testing.T) {
	mk := func(id string, prio float64, st domain.FindingStatus) finding.Finding {
		return finding.Finding{ID: id, ProjectID: "p2", Priority: prio, Status: st, Severity: domain.SeverityHigh}
	}
	var open, confirmed []finding.Finding
	for i := range 15 {
		open = append(open, mk("o"+string(rune('a'+i)), float64(100-2*i), domain.FindingOpen))               // 100, 98, …
		confirmed = append(confirmed, mk("c"+string(rune('a'+i)), float64(99-2*i), domain.FindingConfirmed)) // 99, 97, …
	}
	ff := &fakeFindings{byStatus: map[domain.FindingStatus][]finding.Finding{
		domain.FindingOpen: open, domain.FindingConfirmed: confirmed,
	}}
	svc, _ := newTestService(ff, []ProjectRow{{ID: "p2", Name: "Billing"}})
	rep, err := svc.Portfolio(context.Background(), []string{"p2"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Top) != topN {
		t.Fatalf("top has %d findings, want %d", len(rep.Top), topN)
	}
	for i, f := range rep.Top {
		if want := float64(100 - i); f.Priority != want {
			t.Fatalf("top[%d] priority = %v, want %v (merged order)", i, f.Priority, want)
		}
		if f.ProjectName != "Billing" {
			t.Fatalf("top[%d] project = %q", i, f.ProjectName)
		}
	}
	for _, flt := range ff.filters {
		if flt.AllVersions || flt.VersionID != "" || flt.IncludeDuplicates || flt.Sort != "priority" {
			t.Errorf("top must read default-version, deduplicated, priority-sorted findings: %+v", flt)
		}
		if len(flt.ProjectIDs) != 1 || flt.ProjectIDs[0] != "p2" {
			t.Errorf("top must be scoped to the visible projects: %+v", flt.ProjectIDs)
		}
	}

	html := render(t, rep)
	for _, want := range []string{"Portfolio security report", "Billing", "average over 3 projects", "66.7%", "Covers each project's default branch"} {
		if !strings.Contains(html, want) {
			t.Errorf("portfolio report missing %q", want)
		}
	}
}

// A portfolio the actor can't see anything of is an empty report, not an
// unscoped one: an empty (non-nil) scope must reach the queries as-is.
func TestPortfolioEmptyScopeStaysEmpty(t *testing.T) {
	ff := &fakeFindings{}
	svc, ov := newTestService(ff, nil)
	if _, err := svc.Portfolio(context.Background(), []string{}, Options{}); err != nil {
		t.Fatal(err)
	}
	if ov.pids[0] == nil {
		t.Error("empty scope reached the rollup as nil (= every project)")
	}
	for _, flt := range ff.filters {
		if flt.ProjectIDs == nil {
			t.Error("empty scope reached the findings query as nil (= every project)")
		}
	}
}
