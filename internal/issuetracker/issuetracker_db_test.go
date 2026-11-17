package issuetracker_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/issuetracker"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/secretbox"
)

const ghToken = "ghp_integration_secret"

// fakeGitHub is a stateful GitHub Issues API for one repo.
type fakeGitHub struct {
	*httptest.Server
	mu     sync.Mutex
	issues map[string]string // number → "open" | "closed"
	titles []string
	calls  map[string]int // "METHOD" → count
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	f := &fakeGitHub{issues: map[string]string{}, calls: map[string]int{}}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls[r.Method]++
		if r.Header.Get("Authorization") != "Bearer "+ghToken {
			http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/web":
			fmt.Fprint(w, `{"full_name":"acme/web"}`)
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/web/issues":
			n := strconv.Itoa(len(f.titles) + 1)
			f.titles = append(f.titles, body["title"].(string))
			f.issues[n] = "open"
			fmt.Fprintf(w, `{"number":%s,"html_url":"https://github.com/acme/web/issues/%s"}`, n, n)
		case strings.HasPrefix(r.URL.Path, "/repos/acme/web/issues/"):
			n := strings.TrimPrefix(r.URL.Path, "/repos/acme/web/issues/")
			if _, ok := f.issues[n]; !ok {
				http.NotFound(w, r)
				return
			}
			if r.Method == http.MethodPatch {
				f.issues[n], _ = body["state"].(string)
			}
			fmt.Fprintf(w, `{"number":%s,"state":%q}`, n, f.issues[n])
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeGitHub) set(number, state string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issues[number] = state
}

func (f *fakeGitHub) state(number string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.issues[number]
}

func (f *fakeGitHub) title(i int) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.titles[i]
}

func (f *fakeGitHub) created() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.titles)
}

type env struct {
	pool     *pgxpool.Pool
	repo     *issuetracker.Repository
	findings *finding.Repository
	svc      *issuetracker.Service
	gh       *fakeGitHub
}

func setup(t *testing.T) env {
	t.Helper()
	pool := pgtest.Pool(t)
	cipher, err := secretbox.NewKeyring(bytes.Repeat([]byte{42}, 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	repo := issuetracker.NewRepository(pool)
	findings := finding.NewRepository(pool)
	return env{
		pool: pool, repo: repo, findings: findings, gh: newFakeGitHub(t),
		svc: issuetracker.NewService(repo, findings, cipher, "https://xila.example.com"),
	}
}

var seq int

func (e env) project(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	seq++
	var orgID, teamID, projectID string
	if err := e.pool.QueryRow(ctx, `INSERT INTO organizations (slug, name) VALUES ($1, 'o') RETURNING id`,
		fmt.Sprintf("o-it-%d", seq)).Scan(&orgID); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if err := e.pool.QueryRow(ctx, `INSERT INTO teams (org_id, slug, name) VALUES ($1, $2, 'T') RETURNING id`,
		orgID, fmt.Sprintf("t-it-%d", seq)).Scan(&teamID); err != nil {
		t.Fatalf("seed team: %v", err)
	}
	if err := e.pool.QueryRow(ctx, `INSERT INTO projects (team_id, slug, name) VALUES ($1, 'p', 'P') RETURNING id`, teamID).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	return projectID
}

func (e env) finding(t *testing.T, projectID, fp string, sev domain.Severity) string {
	t.Helper()
	f, err := e.findings.Upsert(context.Background(), finding.Finding{
		ProjectID: projectID, Fingerprint: fp, Scanner: "trivy", Category: domain.CategorySCA,
		Title: fp, Severity: sev, Metadata: map[string]any{}, PackageName: "pkg", PackageVersion: "1.0",
	})
	if err != nil {
		t.Fatalf("upsert %s: %v", fp, err)
	}
	return f.ID
}

func (e env) tracker(t *testing.T, projectID string, in issuetracker.Input) issuetracker.Tracker {
	t.Helper()
	if in.Kind == "" {
		in.Kind = issuetracker.KindGitHub
	}
	if in.BaseURL == "" {
		in.BaseURL = e.gh.URL
	}
	if in.Target == "" {
		in.Target = "acme/web"
	}
	tr, err := e.svc.Put(context.Background(), projectID, in)
	if err != nil {
		t.Fatalf("put tracker: %v", err)
	}
	return tr
}

func (e env) status(t *testing.T, id string) domain.FindingStatus {
	t.Helper()
	f, err := e.findings.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return f.Status
}

func (e env) setStatus(t *testing.T, id string, s domain.FindingStatus) {
	t.Helper()
	if s == domain.FindingRiskAccepted { // only an approved risk acceptance sets it
		ctx := context.Background()
		f, err := e.findings.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		a, _, err := e.findings.CreateAcceptance(ctx, finding.AcceptanceInput{ProjectID: f.ProjectID,
			Title: "test", Justification: "test", FindingIDs: []string{id}}, "requester")
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := e.findings.ApproveAcceptance(ctx, "", a.ID, "approver", "", true); err != nil {
			t.Fatal(err)
		}
		return
	}
	if _, err := e.findings.SetStatus(context.Background(), id, finding.Triage{Status: s, Reason: "test"}); err != nil {
		t.Fatal(err)
	}
}

func TestTokenEncryptedAtRest(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	projectID := e.project(t)

	tr := e.tracker(t, projectID, issuetracker.Input{Token: ghToken})
	if !tr.HasToken {
		t.Fatal("has_token = false after storing a token")
	}
	var raw []byte
	if err := e.pool.QueryRow(ctx, `SELECT token_enc FROM issue_trackers WHERE project_id = $1`, projectID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) <= len(ghToken) || bytes.Contains(raw, []byte(ghToken)) {
		t.Errorf("token_enc = %q: not encrypted", raw)
	}
	out, _ := json.Marshal(tr)
	if bytes.Contains(out, []byte(ghToken)) || bytes.Contains(out, []byte(`"token"`)) || !bytes.Contains(out, []byte(`"has_token":true`)) {
		t.Errorf("tracker JSON = %s: must expose has_token only", out)
	}

	// The stored token decrypts and works; an update without one keeps it.
	if err := e.svc.Test(ctx, projectID); err != nil {
		t.Fatalf("test with stored token: %v", err)
	}
	e.tracker(t, projectID, issuetracker.Input{MinSeverity: domain.SeverityLow})
	if err := e.svc.Test(ctx, projectID); err != nil {
		t.Fatalf("token lost on update without one: %v", err)
	}
	// A wrong token fails the check with the tracker's reason.
	e.tracker(t, projectID, issuetracker.Input{Token: "wrong"})
	if err := e.svc.Test(ctx, projectID); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("test with a bad token = %v, want 401", err)
	}

	// A ciphertext copied into another project's row doesn't decrypt there.
	other := e.project(t)
	e.tracker(t, other, issuetracker.Input{Token: "other-token"})
	if _, err := e.pool.Exec(ctx, `UPDATE issue_trackers SET token_enc = $1 WHERE project_id = $2`, raw, other); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Test(ctx, other); err == nil || !strings.Contains(err.Error(), "decrypt") {
		t.Errorf("moved ciphertext = %v, want a decrypt error", err)
	}

	// Without INTEGRATION_SECRET_KEY nothing can be stored.
	noKey := issuetracker.NewService(e.repo, e.findings, nil, "")
	if _, err := noKey.Put(ctx, projectID, issuetracker.Input{Kind: issuetracker.KindGitHub, Target: "a/b", Token: "x"}); !errors.Is(err, secretbox.ErrNoKey) {
		t.Errorf("put without key = %v, want ErrNoKey", err)
	}
	// Creating needs a token; a missing project is reported as such.
	fresh := e.project(t)
	var verr issuetracker.ValidationError
	if _, err := e.svc.Put(ctx, fresh, issuetracker.Input{Kind: issuetracker.KindGitHub, Target: "a/b"}); !errors.As(err, &verr) {
		t.Errorf("create without token = %v, want a validation error", err)
	}
	if _, err := e.svc.Put(ctx, "00000000-0000-0000-0000-000000000000",
		issuetracker.Input{Kind: issuetracker.KindGitHub, Target: "a/b", Token: "x"}); !errors.Is(err, issuetracker.ErrNoProject) {
		t.Errorf("put for missing project = %v, want ErrNoProject", err)
	}
}

func TestCreateIssueIdempotent(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	projectID := e.project(t)
	id := e.finding(t, projectID, "CVE-1", domain.SeverityLow)

	if _, _, err := e.svc.CreateIssue(ctx, id); !errors.Is(err, issuetracker.ErrNoTracker) {
		t.Fatalf("create without tracker = %v, want ErrNoTracker", err)
	}
	// The manual action ignores the auto-create threshold.
	e.tracker(t, projectID, issuetracker.Input{Token: ghToken, MinSeverity: domain.SeverityCritical, Labels: []string{"sec"}})

	var wg sync.WaitGroup
	links := make([]issuetracker.Link, 8)
	createdN := make([]bool, 8)
	for i := range 8 {
		wg.Go(func() {
			l, created, err := e.svc.CreateIssue(ctx, id)
			if err != nil {
				t.Errorf("create %d: %v", i, err)
			}
			links[i], createdN[i] = l, created
		})
	}
	wg.Wait()
	if e.gh.created() != 1 {
		t.Fatalf("external issues = %d, want exactly 1", e.gh.created())
	}
	nCreated := 0
	for i, l := range links {
		if l.ID != links[0].ID || l.ExternalID != "1" {
			t.Errorf("link %d = %+v, want the same link to issue 1", i, l)
		}
		if createdN[i] {
			nCreated++
		}
	}
	if nCreated != 1 {
		t.Errorf("created=true reported %d times, want 1", nCreated)
	}
	got, err := e.svc.Link(ctx, id)
	if err != nil || got.URL != "https://github.com/acme/web/issues/1" || got.State != issuetracker.StateOpen ||
		got.Kind != issuetracker.KindGitHub {
		t.Errorf("Link = %+v, %v", got, err)
	}
	if got := e.gh.title(0); got != "[low] CVE-1" {
		t.Errorf("title = %q", got)
	}

	// Disabling the tracker stops new issues but keeps the link readable.
	off := false
	e.tracker(t, projectID, issuetracker.Input{Enabled: &off})
	other := e.finding(t, projectID, "CVE-2", domain.SeverityHigh)
	if _, _, err := e.svc.CreateIssue(ctx, other); !errors.Is(err, issuetracker.ErrNoTracker) {
		t.Errorf("create on disabled tracker = %v, want ErrNoTracker", err)
	}
	if _, err := e.svc.Link(ctx, id); err != nil {
		t.Errorf("link after disabling = %v", err)
	}
	// Re-pointing the tracker elsewhere drops links into the old system.
	e.tracker(t, projectID, issuetracker.Input{Target: "acme/other", Token: ghToken})
	if _, err := e.svc.Link(ctx, id); !errors.Is(err, issuetracker.ErrNoLink) {
		t.Errorf("link after re-pointing = %v, want ErrNoLink", err)
	}
}

func TestAutoCreateThresholdAndCap(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	projectID := e.project(t)

	eligible := map[string]bool{}
	for i := range issuetracker.AutoCreateCap + 2 {
		eligible[e.finding(t, projectID, fmt.Sprintf("high-%02d", i), domain.SeverityHigh)] = true
	}
	eligible[e.finding(t, projectID, "crit", domain.SeverityCritical)] = true
	low := e.finding(t, projectID, "low", domain.SeverityLow)
	medium := e.finding(t, projectID, "medium", domain.SeverityMedium)
	accepted := e.finding(t, projectID, "accepted", domain.SeverityCritical)
	e.setStatus(t, accepted, domain.FindingRiskAccepted)
	dup := e.finding(t, projectID, "dup", domain.SeverityCritical)
	if _, err := e.pool.Exec(ctx, `UPDATE findings SET duplicate_of = (SELECT id FROM findings WHERE title = 'crit') WHERE id = $1`, dup); err != nil {
		t.Fatal(err)
	}

	// auto_create off: sync files nothing.
	e.tracker(t, projectID, issuetracker.Input{Token: ghToken, MinSeverity: domain.SeverityHigh})
	if res, err := e.svc.Sync(ctx); err != nil || res.Created != 0 || res.Trackers != 1 {
		t.Fatalf("sync without auto-create = %+v, %v", res, err)
	}

	e.tracker(t, projectID, issuetracker.Input{MinSeverity: domain.SeverityHigh, AutoCreate: true})
	res, err := e.svc.Sync(ctx)
	if err != nil || res.Created != issuetracker.AutoCreateCap || res.Errors != 0 {
		t.Fatalf("first auto-create = %+v, %v; want %d created", res, err, issuetracker.AutoCreateCap)
	}
	if got := e.gh.title(0); got != "[critical] crit" {
		t.Errorf("first issue = %q, want the most severe first", got)
	}
	res, _ = e.svc.Sync(ctx)
	if res.Created != 3 {
		t.Errorf("second auto-create = %+v, want the remaining 3", res)
	}
	res, _ = e.svc.Sync(ctx)
	if res.Created != 0 || res.ClosedIssues+res.ReopenedIssues+res.ResolvedFindings+res.ReopenedFindings != 0 {
		t.Errorf("third sync = %+v, want a no-op", res)
	}
	for id := range eligible {
		if _, err := e.svc.Link(ctx, id); err != nil {
			t.Errorf("eligible finding %s has no issue: %v", id, err)
		}
	}
	for name, id := range map[string]string{"low": low, "medium": medium, "accepted": accepted, "duplicate": dup} {
		if _, err := e.svc.Link(ctx, id); !errors.Is(err, issuetracker.ErrNoLink) {
			t.Errorf("%s finding got an issue (err=%v)", name, err)
		}
	}
}

func TestSyncBothDirections(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	projectID := e.project(t)
	e.tracker(t, projectID, issuetracker.Input{Token: ghToken})
	ids := map[string]string{}
	issue := map[string]string{}
	for _, name := range []string{"fixed-in-xila", "closed-in-tracker", "accepted", "untouched"} {
		ids[name] = e.finding(t, projectID, name, domain.SeverityHigh)
		l, _, err := e.svc.CreateIssue(ctx, ids[name])
		if err != nil {
			t.Fatal(err)
		}
		issue[name] = l.ExternalID
	}

	// Xila → tracker, tracker → Xila, an exception, and nothing.
	e.setStatus(t, ids["fixed-in-xila"], domain.FindingRemediated)
	e.gh.set(issue["closed-in-tracker"], "closed")
	e.setStatus(t, ids["accepted"], domain.FindingRiskAccepted)

	res, err := e.svc.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := issuetracker.SyncResult{Trackers: 1, ClosedIssues: 2, ResolvedFindings: 1}
	if res != want {
		t.Errorf("sync = %+v, want %+v", res, want)
	}
	if e.gh.state(issue["fixed-in-xila"]) != "closed" || e.gh.state(issue["accepted"]) != "closed" {
		t.Error("issues of resolved findings not closed")
	}
	if got := e.status(t, ids["closed-in-tracker"]); got != domain.FindingRemediated {
		t.Errorf("finding of an externally closed issue = %s, want remediated", got)
	}
	if got := e.status(t, ids["untouched"]); got != domain.FindingOpen || e.gh.state(issue["untouched"]) != "open" {
		t.Errorf("untouched pair moved: finding %s, issue %s", got, e.gh.state(issue["untouched"]))
	}
	if l, _ := e.svc.Link(ctx, ids["closed-in-tracker"]); l.State != issuetracker.StateClosed {
		t.Errorf("stored state = %s, want closed", l.State)
	}

	// Steady state: nothing to do, and no direction undoes the other.
	if res, _ := e.svc.Sync(ctx); res != (issuetracker.SyncResult{Trackers: 1}) {
		t.Errorf("second sync = %+v, want a no-op", res)
	}

	// The reverse moves: a scan reopening the finding reopens its issue; an
	// issue reopened in the tracker reopens the remediated finding; one reopened
	// over a risk acceptance is closed again.
	e.setStatus(t, ids["fixed-in-xila"], domain.FindingOpen)
	e.gh.set(issue["closed-in-tracker"], "open")
	e.gh.set(issue["accepted"], "open")
	res, _ = e.svc.Sync(ctx)
	want = issuetracker.SyncResult{Trackers: 1, ReopenedIssues: 1, ReopenedFindings: 1, ClosedIssues: 1}
	if res != want {
		t.Errorf("reverse sync = %+v, want %+v", res, want)
	}
	if e.gh.state(issue["fixed-in-xila"]) != "open" {
		t.Error("issue of a reopened finding not reopened")
	}
	if got := e.status(t, ids["closed-in-tracker"]); got != domain.FindingOpen {
		t.Errorf("finding of an externally reopened issue = %s, want open", got)
	}
	if got := e.status(t, ids["accepted"]); got != domain.FindingRiskAccepted || e.gh.state(issue["accepted"]) != "closed" {
		t.Errorf("exception overturned by the tracker: finding %s, issue %s", got, e.gh.state(issue["accepted"]))
	}
	if res, _ := e.svc.Sync(ctx); res != (issuetracker.SyncResult{Trackers: 1}) {
		t.Errorf("final sync = %+v, want a no-op", res)
	}
}

// One broken tracker (or link) is logged and counted; the others still sync.
func TestSyncIsolatesFailures(t *testing.T) {
	e := setup(t)
	ctx := context.Background()

	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close() // connection refused
	broken := e.project(t)
	e.tracker(t, broken, issuetracker.Input{BaseURL: dead.URL, Token: ghToken, AutoCreate: true, MinSeverity: domain.SeverityInfo})
	e.finding(t, broken, "b", domain.SeverityHigh)

	healthy := e.project(t)
	e.tracker(t, healthy, issuetracker.Input{Token: ghToken, AutoCreate: true, MinSeverity: domain.SeverityInfo})
	linked := e.finding(t, healthy, "linked", domain.SeverityHigh)
	if _, _, err := e.svc.CreateIssue(ctx, linked); err != nil {
		t.Fatal(err)
	}
	// The linked issue vanished from the tracker: that link errors, the rest syncs.
	if _, err := e.pool.Exec(ctx, `UPDATE finding_issues SET external_id = '999' WHERE finding_id = $1`, linked); err != nil {
		t.Fatal(err)
	}
	e.finding(t, healthy, "new", domain.SeverityHigh)

	res, err := e.svc.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Trackers != 2 || res.Created != 1 || res.Errors != 2 {
		t.Errorf("sync = %+v, want 2 trackers, 1 created, 2 errors (dead tracker + vanished issue)", res)
	}
}
