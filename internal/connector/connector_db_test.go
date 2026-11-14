package connector_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/connector"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/project"
	"github.com/xilasec/xila-api/internal/scan"
	"github.com/xilasec/xila-api/internal/scanner"
	"github.com/xilasec/xila-api/internal/secretbox"
)

const (
	dtToken   = "odt_secret_api_key"
	dtProject = "ca4f2da9-0fad-4a13-92d7-f627f3168a56"
)

// fakeDT is a stateful Dependency-Track: findings keyed by vulnId, each with an
// analysis state; it can be told to fail or to under-deliver.
type fakeDT struct {
	*httptest.Server
	mu      sync.Mutex
	vulns   map[string]string // vulnId → analysis state
	fail    bool
	partial bool
}

func newFakeDT(t *testing.T, vulns ...string) *fakeDT {
	t.Helper()
	f := &fakeDT{vulns: map[string]string{}}
	for _, v := range vulns {
		f.vulns[v] = "NOT_SET"
	}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Header.Get("X-Api-Key") != dtToken {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if f.fail {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == "/api/v1/project/"+dtProject {
			fmt.Fprint(w, `{"name":"Acme","version":"main"}`)
			return
		}
		if r.URL.Path != "/api/v1/finding/project/"+dtProject {
			http.NotFound(w, r)
			return
		}
		items := []string{}
		for id, state := range f.vulns {
			items = append(items, fmt.Sprintf(`{"component":{"uuid":"c-%[1]s","name":"pkg-%[1]s","version":"1.0.0","purl":"pkg:npm/pkg-%[1]s@1.0.0"},
				"vulnerability":{"uuid":"v-%[1]s","source":"NVD","vulnId":"%[1]s","title":"Vuln %[1]s","severity":"HIGH","cvssV3BaseScore":7.5},
				"analysis":{"state":"%[2]s","isSuppressed":false},"matrix":"%[3]s:c-%[1]s:v-%[1]s"}`, id, state, dtProject))
		}
		total := len(items)
		if f.partial {
			items = items[:len(items)/2]
		}
		w.Header().Set("X-Total-Count", strconv.Itoa(total))
		fmt.Fprint(w, "["+strings.Join(items, ",")+"]")
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeDT) set(fn func(f *fakeDT)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

type env struct {
	pool     *pgxpool.Pool
	repo     *connector.Repository
	findings *finding.Repository
	svc      *connector.Service
}

func setup(t *testing.T) env {
	t.Helper()
	pool := pgtest.Pool(t)
	cipher, err := secretbox.New(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	repo := connector.NewRepository(pool)
	findings := finding.NewRepository(pool)
	scans := scan.NewRepository(pool)
	ingest := scan.NewService(scans, findings, project.NewRepository(pool), scanner.NewRegistry(), nil,
		[]scan.Applier{connector.NewRemoteTriage(repo, findings)}, scans)
	return env{pool: pool, repo: repo, findings: findings, svc: connector.NewService(repo, ingest, cipher)}
}

var seq int

func (e env) project(t *testing.T) string {
	t.Helper()
	seq++
	var id string
	if err := e.pool.QueryRow(context.Background(), `
		WITH o AS (INSERT INTO organizations (slug, name) VALUES ($1, 'o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id, slug, name) SELECT id, $1, 't' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id, 'p', 'p' FROM tm RETURNING id`,
		fmt.Sprintf("o-conn-%d", seq)).Scan(&id); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	return id
}

func (e env) dtConnector(t *testing.T, projectID, baseURL string) connector.Connector {
	t.Helper()
	c, err := e.svc.Create(context.Background(), projectID, connector.Input{
		Kind: connector.KindDependencyTrack, BaseURL: baseURL, RemoteProject: dtProject, Token: dtToken,
	})
	if err != nil {
		t.Fatalf("create connector: %v", err)
	}
	return c
}

// statuses maps each of the project's dependency-track findings' rule id to
// its status.
func (e env) statuses(t *testing.T, projectID string) map[string]domain.FindingStatus {
	t.Helper()
	rows, err := e.pool.Query(context.Background(),
		`SELECT rule_id, status FROM findings WHERE project_id = $1 AND scanner = 'dependency-track'`, projectID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]domain.FindingStatus{}
	for rows.Next() {
		var id string
		var st domain.FindingStatus
		if err := rows.Scan(&id, &st); err != nil {
			t.Fatal(err)
		}
		out[id] = st
	}
	return out
}

func TestPullKeepsFindingsInSync(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	projectID := e.project(t)
	dt := newFakeDT(t, "CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003")
	c := e.dtConnector(t, projectID, dt.URL)

	res, err := e.svc.Pull(ctx, projectID, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if res.Imported != 3 || res.New != 3 || res.Closed != 0 || res.Connector.LastCount != 3 ||
		res.Connector.LastError != "" || res.Connector.LastSuccessAt == nil || res.Summary["high"] != 3 {
		t.Fatalf("first pull = %+v", res)
	}
	var versionDefault bool
	if err := e.pool.QueryRow(ctx, `SELECT v.is_default FROM scans s JOIN project_versions v ON v.id = s.version_id
		WHERE s.id = $1 AND s.scanner = 'dependency-track' AND s.status = 'completed'`, res.ScanID).Scan(&versionDefault); err != nil || !versionDefault {
		t.Fatalf("pull scan not recorded on the default version: %v", err)
	}

	// One finding fixed upstream: the next pull auto-closes it, the rest stay.
	dt.set(func(f *fakeDT) { delete(f.vulns, "CVE-2024-0001") })
	res, err = e.svc.Pull(ctx, projectID, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if res.Imported != 2 || res.New != 0 || res.Closed != 1 {
		t.Fatalf("second pull = %+v", res)
	}
	want := map[string]domain.FindingStatus{"CVE-2024-0001": "remediated", "CVE-2024-0002": "open", "CVE-2024-0003": "open"}
	if got := e.statuses(t, projectID); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("after second pull = %v, want %v", got, want)
	}

	// The remote goes down, then answers with half its findings: neither pull
	// may close anything, and both are recorded on the connector.
	dt.set(func(f *fakeDT) { f.vulns = map[string]string{}; f.fail = true })
	if _, err := e.svc.Pull(ctx, projectID, c.ID); !errors.As(err, new(connector.RemoteError)) {
		t.Fatalf("failed pull err = %v, want RemoteError", err)
	}
	got, _ := e.repo.Get(ctx, projectID, c.ID)
	if !strings.Contains(got.LastError, "503") || got.LastCount != 2 || got.LastPulledAt == nil ||
		!got.LastPulledAt.After(*got.LastSuccessAt) {
		t.Errorf("after failed pull connector = %+v", got)
	}
	dt.set(func(f *fakeDT) {
		f.fail, f.partial = false, true
		f.vulns = map[string]string{"CVE-2024-0002": "NOT_SET", "CVE-2024-0003": "NOT_SET"}
	})
	if _, err := e.svc.Pull(ctx, projectID, c.ID); !errors.As(err, new(connector.RemoteError)) {
		t.Fatalf("partial pull err = %v, want RemoteError", err)
	}
	if got := e.statuses(t, projectID); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("a failed pull changed findings: %v, want %v", got, want)
	}
	var scans int
	_ = e.pool.QueryRow(ctx, `SELECT count(*) FROM scans WHERE project_id = $1`, projectID).Scan(&scans)
	if scans != 2 {
		t.Errorf("scans = %d, want 2 (failed pulls record no scan)", scans)
	}

	// Back to normal: the error clears.
	dt.set(func(f *fakeDT) { f.partial = false })
	if res, err := e.svc.Pull(ctx, projectID, c.ID); err != nil || res.Connector.LastError != "" || res.Closed != 0 {
		t.Fatalf("recovered pull = %+v, %v", res, err)
	}
}

func TestPullIntoNamedVersion(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	projectID := e.project(t)
	dt := newFakeDT(t, "CVE-2024-0100")
	main := e.dtConnector(t, projectID, dt.URL)
	rel, err := e.svc.Create(ctx, projectID, connector.Input{
		Kind: connector.KindDependencyTrack, BaseURL: dt.URL, RemoteProject: dtProject, Token: dtToken, Version: "release-2",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Same kind into the same version would make two connectors close each
	// other's findings.
	if _, err := e.svc.Create(ctx, projectID, connector.Input{
		Kind: connector.KindDependencyTrack, BaseURL: dt.URL, RemoteProject: dtProject, Token: dtToken, Version: "release-2",
	}); !errors.Is(err, connector.ErrDuplicate) {
		t.Fatalf("duplicate connector err = %v", err)
	}
	for _, c := range []connector.Connector{main, rel} {
		if _, err := e.svc.Pull(ctx, projectID, c.ID); err != nil {
			t.Fatal(err)
		}
	}
	var versions []string
	rows, _ := e.pool.Query(ctx, `SELECT v.name FROM findings f JOIN project_versions v ON v.id = f.version_id
		WHERE f.project_id = $1 ORDER BY v.name`, projectID)
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		versions = append(versions, n)
	}
	rows.Close()
	if fmt.Sprint(versions) != "[main release-2]" {
		t.Fatalf("finding versions = %v, want one per version", versions)
	}
}

func TestRemoteTriageOnlyForNewFindings(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	projectID := e.project(t)
	dt := newFakeDT(t, "CVE-2024-0201", "CVE-2024-0202")
	dt.set(func(f *fakeDT) { f.vulns["CVE-2024-0201"] = "NOT_AFFECTED" })
	c := e.dtConnector(t, projectID, dt.URL)
	if _, err := e.svc.Pull(ctx, projectID, c.ID); err != nil {
		t.Fatal(err)
	}
	st := e.statuses(t, projectID)
	if st["CVE-2024-0201"] != domain.FindingFalsePositive || st["CVE-2024-0202"] != domain.FindingOpen {
		t.Fatalf("after first pull = %v", st)
	}
	var actor, reason string
	_ = e.pool.QueryRow(ctx, `SELECT exception_by, exception_reason FROM findings WHERE project_id = $1 AND rule_id = 'CVE-2024-0201'`,
		projectID).Scan(&actor, &reason)
	if actor != "dependency-track" || !strings.Contains(reason, "NOT_AFFECTED") {
		t.Errorf("verdict attribution = %q / %q", actor, reason)
	}

	// Xila's own triage wins afterwards: the analyst confirms 0201 (overruling
	// the import) and the remote now calls 0202 a false positive — neither
	// existing finding changes.
	var id0201 string
	_ = e.pool.QueryRow(ctx, `SELECT id FROM findings WHERE project_id = $1 AND rule_id = 'CVE-2024-0201'`, projectID).Scan(&id0201)
	if _, err := e.findings.SetStatus(ctx, id0201, finding.Triage{Status: domain.FindingConfirmed, Actor: "alice"}); err != nil {
		t.Fatal(err)
	}
	dt.set(func(f *fakeDT) {
		f.vulns["CVE-2024-0202"] = "FALSE_POSITIVE"
		f.vulns["CVE-2024-0203"] = "EXPLOITABLE"
	})
	if _, err := e.svc.Pull(ctx, projectID, c.ID); err != nil {
		t.Fatal(err)
	}
	want := map[string]domain.FindingStatus{"CVE-2024-0201": "confirmed", "CVE-2024-0202": "open", "CVE-2024-0203": "confirmed"}
	if got := e.statuses(t, projectID); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("after second pull = %v, want %v", got, want)
	}
	var state string
	_ = e.pool.QueryRow(ctx, `SELECT metadata->>'analysis_state' FROM findings WHERE project_id = $1 AND rule_id = 'CVE-2024-0202'`,
		projectID).Scan(&state)
	if state != "FALSE_POSITIVE" {
		t.Errorf("remote verdict not kept in metadata: %q", state)
	}
}

func TestTokenEncryptedAndWriteOnly(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	projectID := e.project(t)
	dt := newFakeDT(t, "CVE-2024-0301")
	c := e.dtConnector(t, projectID, dt.URL)
	if !c.HasToken {
		t.Error("has_token = false")
	}

	var raw []byte
	if err := e.pool.QueryRow(ctx, `SELECT token_enc FROM connectors WHERE id = $1`, c.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || bytes.Contains(raw, []byte(dtToken)) {
		t.Fatalf("token stored in plaintext: %q", raw)
	}
	if name, err := e.svc.Test(ctx, projectID, c.ID); err != nil || name != "Acme main" {
		t.Fatalf("test = %q, %v", name, err)
	}

	// Updating without a token keeps it; pointing at another host requires a
	// new one (the stored credential must not follow the URL).
	up, err := e.svc.Update(ctx, projectID, c.ID, connector.Input{BaseURL: dt.URL, RemoteProject: dtProject, Name: "renamed"})
	if err != nil || up.Name != "renamed" || !up.HasToken {
		t.Fatalf("update = %+v, %v", up, err)
	}
	if _, err := e.svc.Test(ctx, projectID, c.ID); err != nil {
		t.Fatalf("token lost on update: %v", err)
	}
	if _, err := e.svc.Update(ctx, projectID, c.ID, connector.Input{BaseURL: "https://evil.example.com", RemoteProject: dtProject}); !errors.As(err, new(connector.ValidationError)) {
		t.Fatalf("url change without token err = %v", err)
	}
	if _, err := e.svc.Update(ctx, projectID, c.ID, connector.Input{Kind: connector.KindDefectDojo, BaseURL: dt.URL, RemoteProject: "3"}); !errors.As(err, new(connector.ValidationError)) {
		t.Fatalf("kind change err = %v", err)
	}

	// A ciphertext copied into another project's connector doesn't decrypt.
	other := e.project(t)
	oc := e.dtConnector(t, other, dt.URL)
	if _, err := e.pool.Exec(ctx, `UPDATE connectors SET token_enc = $1 WHERE id = $2`, raw, oc.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Test(ctx, other, oc.ID); err == nil || !strings.Contains(err.Error(), "decrypt") {
		t.Errorf("moved ciphertext = %v, want a decrypt error", err)
	}
	// Connectors are project-scoped: another project's id is not found.
	if _, err := e.svc.Pull(ctx, other, c.ID); !errors.Is(err, connector.ErrNotFound) {
		t.Errorf("cross-project pull err = %v", err)
	}

	// Without INTEGRATION_SECRET_KEY nothing can be stored.
	noKey := connector.NewService(e.repo, nil, nil)
	if _, err := noKey.Create(ctx, projectID, connector.Input{Kind: connector.KindDependencyTrack, BaseURL: dt.URL,
		RemoteProject: dtProject, Token: "x"}); !errors.Is(err, secretbox.ErrNoKey) {
		t.Errorf("create without key = %v", err)
	}
}

func TestPullDueIsolatesFailures(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	up := newFakeDT(t, "CVE-2024-0401")
	down := newFakeDT(t, "CVE-2024-0402")
	down.set(func(f *fakeDT) { f.fail = true })
	okConn := e.dtConnector(t, e.project(t), up.URL)
	badConn := e.dtConnector(t, e.project(t), down.URL)
	disabled := e.dtConnector(t, e.project(t), up.URL)
	if _, err := e.svc.Update(ctx, disabled.ProjectID, disabled.ID, connector.Input{BaseURL: up.URL, RemoteProject: dtProject,
		Enabled: new(false)}); err != nil {
		t.Fatal(err)
	}

	res, err := e.svc.PullDue(ctx, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if res.Pulled != 1 || res.Failed != 1 {
		t.Fatalf("run = %+v, want 1 pulled, 1 failed", res)
	}
	if c, _ := e.repo.Get(ctx, okConn.ProjectID, okConn.ID); c.LastCount != 1 || c.LastError != "" {
		t.Errorf("ok connector = %+v", c)
	}
	if c, _ := e.repo.Get(ctx, badConn.ProjectID, badConn.ID); c.LastError == "" {
		t.Errorf("failing connector recorded no error: %+v", c)
	}
	if c, _ := e.repo.Get(ctx, disabled.ProjectID, disabled.ID); c.LastPulledAt != nil {
		t.Error("disabled connector was pulled")
	}

	// Within the interval nothing is due — not even the failed one, which waits
	// for its next slot instead of hammering the remote every tick.
	if res, err := e.svc.PullDue(ctx, time.Hour); err != nil || res.Pulled+res.Failed != 0 {
		t.Fatalf("second run = %+v, %v; want nothing due", res, err)
	}
}
