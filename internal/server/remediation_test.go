package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/config"
)

func remediationFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("../scanner/testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// remediationFakeGitHub is a GitHub Issues API for acme/web that records the
// issues filed and lets a test close one "in the tracker".
type remediationFakeGitHub struct {
	*httptest.Server
	mu      sync.Mutex
	created []map[string]any
	states  map[string]string
}

func newRemediationFakeGitHub(t *testing.T) *remediationFakeGitHub {
	f := &remediationFakeGitHub{states: map[string]string{}}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/web/issues":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.created = append(f.created, body)
			n := strconv.Itoa(len(f.created))
			f.states[n] = "open"
			_, _ = w.Write([]byte(`{"number":` + n + `,"html_url":"https://github.test/acme/web/issues/` + n + `"}`))
		case strings.HasPrefix(r.URL.Path, "/repos/acme/web/issues/"):
			n := strings.TrimPrefix(r.URL.Path, "/repos/acme/web/issues/")
			if r.Method == http.MethodPatch {
				var body map[string]any
				_ = json.NewDecoder(r.Body).Decode(&body)
				f.states[n], _ = body["state"].(string)
			}
			_, _ = w.Write([]byte(`{"number":` + n + `,"state":"` + f.states[n] + `"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *remediationFakeGitHub) state(n string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.states[n]
}

func (f *remediationFakeGitHub) set(n, s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.states[n] = s
}

// changesByKind indexes a proposals response.
func changesByKind(body map[string]any) map[string][]map[string]any {
	out := map[string][]map[string]any{}
	ps, _ := body["proposals"].([]any)
	for _, p := range ps {
		m := p.(map[string]any)
		out[m["kind"].(string)] = append(out[m["kind"].(string)], m)
	}
	return out
}

// Real scanner reports uploaded over HTTP group into one action per change:
// an image's distro packages into a base-image rebuild, its Python packages
// into upgrades, KICS by rule + file, semgrep by file. Accepting a proposal
// makes a tracked action whose due date is its findings' earliest SLA
// deadline and whose owner follows their assignee; it files as one ticket,
// closes when its findings are gone (closing the ticket), and closes when its
// ticket is closed. The portfolio list is scoped to visible projects.
func TestRemediationActions(t *testing.T) {
	app := newTestApp(t)
	admin := rbacUser(t, app, "founder@xila.io")
	lead := rbacUser(t, app, "lead@xila.io")
	viewer := rbacUser(t, app, "viewer@xila.io")
	outsider := rbacUser(t, app, "outsider@xila.io")

	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", lead, `{"slug":"acme","name":"Acme"}`)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgBody["id"].(string)+"/teams", lead, `{"slug":"core","name":"Core"}`)
	project := func(slug string) string {
		_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+teamBody["id"].(string)+"/projects", lead, `{"slug":"`+slug+`","name":"`+slug+`"}`)
		return p["id"].(string)
	}
	web, api := project("web"), project("api")
	req(t, app, http.MethodPost, "/api/v1/projects/"+web+"/members", lead, `{"email":"viewer@xila.io","role":"viewer"}`)
	scan := func(pid, scanner, body string) {
		t.Helper()
		if resp, b := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/scans?scanner="+scanner, lead, body); resp.StatusCode != http.StatusCreated {
			t.Fatalf("upload %s = %d %v", scanner, resp.StatusCode, b)
		}
	}
	trivyImage := remediationFixture(t, "trivy_image.json")
	scan(web, "trivy", trivyImage)
	scan(web, "kics", remediationFixture(t, "kics_many.json"))
	scan(web, "hadolint", remediationFixture(t, "hadolint_many.json"))
	scan(web, "semgrep", remediationFixture(t, "semgrep.json"))
	scan(api, "semgrep", remediationFixture(t, "semgrep.json"))

	// Proposals, per kind.
	resp, props := req(t, app, http.MethodGet, "/api/v1/projects/"+web+"/remediation/proposals", viewer, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("proposals = %d %v", resp.StatusCode, props)
	}
	kinds := changesByKind(props)
	bi := kinds["base_image"]
	if len(bi) != 1 || bi[0]["closes"] != float64(3) || bi[0]["key"] != "python:3.11-slim|debian 12.5" ||
		bi[0]["title"] != "Rebuild python:3.11-slim on a patched base image (debian 12.5)" {
		t.Fatalf("base-image proposals = %v (libc6, libssl3, openssl; zlib1g has no fix)", bi)
	}
	upgrades := map[string]string{}
	for _, c := range kinds["package_upgrade"] {
		upgrades[c["package"].(string)] = c["target"].(string)
	}
	if len(upgrades) != 2 || upgrades["pip"] != "23.3" || upgrades["setuptools"] != "70.0.0" {
		t.Errorf("package upgrades = %v, want pip → 23.3, setuptools → 70.0.0 (distro packages go to the rebuild)", upgrades)
	}
	// KICS: every finding is its own rule + file (15 changes); hadolint
	// reports DL3008 twice in each of two Dockerfiles (9 findings, 7 changes).
	iacTotal, kicsChanges, nginxPins := 0, 0, 0
	for _, c := range kinds["iac_rule"] {
		iacTotal += int(c["closes"].(float64))
		if strings.HasPrefix(c["file_path"].(string), "test/charts/") {
			kicsChanges++
		}
		if c["rule_id"] == "DL3008" && c["file_path"] == `django-DefectDojo\Dockerfile.nginx` {
			nginxPins = int(c["closes"].(float64))
		}
	}
	if iacTotal != 24 || len(kinds["iac_rule"]) != 22 || kicsChanges != 15 || nginxPins != 2 {
		t.Errorf("iac changes = %d closing %d (KICS %d, DL3008 in Dockerfile.nginx closes %d); want 22 over 24 findings, 15 KICS, 2",
			len(kinds["iac_rule"]), iacTotal, kicsChanges, nginxPins)
	}
	var files []string
	for _, c := range kinds["code_location"] {
		files = append(files, c["file_path"].(string))
	}
	slices.Sort(files)
	if len(files) != 2 || !strings.HasSuffix(files[0], "BenchmarkTest02194.java") || !strings.HasSuffix(files[1], "BenchmarkTest02195.java") {
		t.Errorf("code-location changes = %v, want one per semgrep file", files)
	}

	// The fix plan reads the same grouping: package upgrades only.
	_, plan := req(t, app, http.MethodGet, "/api/v1/projects/"+web+"/fix-plan", viewer, "")
	var planned []string
	for _, f := range plan["fixes"].([]any) {
		planned = append(planned, f.(map[string]any)["package"].(string))
	}
	slices.Sort(planned)
	if !slices.Contains(planned, "pip") || !slices.Contains(planned, "setuptools") || !slices.Contains(planned, "libssl3") {
		t.Errorf("fix plan packages = %v", planned)
	}

	// Accepting: editors only.
	accept := `{"kind":"base_image","key":"python:3.11-slim|debian 12.5"}`
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+web+"/remediation", viewer, accept); resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer accepting = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+web+"/remediation", lead, `{"kind":"base_image","key":"nope"}`); resp.StatusCode != http.StatusNotFound {
		t.Errorf("accepting an unknown proposal = %d, want 404", resp.StatusCode)
	}
	resp, action := req(t, app, http.MethodPost, "/api/v1/projects/"+web+"/remediation", lead, accept)
	if resp.StatusCode != http.StatusCreated || action["kind"] != "base_image" || action["findings"] != float64(3) ||
		action["open_findings"] != float64(3) || action["max_severity"] != "high" || action["status"] != "open" ||
		action["created_by_email"] != "lead@xila.io" {
		t.Fatalf("accept = %d %v", resp.StatusCode, action)
	}
	actionID := action["id"].(string)
	if _, again := req(t, app, http.MethodGet, "/api/v1/projects/"+web+"/remediation/proposals", viewer, ""); len(changesByKind(again)["base_image"]) != 0 {
		t.Errorf("accepted change still proposed: %v", again)
	}

	// Due date = the earliest SLA deadline among its findings.
	_, fl := req(t, app, http.MethodGet, "/api/v1/remediation/"+actionID+"/findings", viewer, "")
	var earliest time.Time
	var libcID string
	for _, f := range fl["findings"].([]any) {
		m := f.(map[string]any)
		if m["package_name"] == "libc6" {
			libcID = m["id"].(string)
		}
		due, err := time.Parse(time.RFC3339Nano, m["sla_due_at"].(string))
		if err != nil {
			t.Fatalf("finding sla_due_at %v: %v", m["sla_due_at"], err)
		}
		if earliest.IsZero() || due.Before(earliest) {
			earliest = due
		}
	}
	if got, err := time.Parse(time.RFC3339Nano, action["due_at"].(string)); err != nil || !got.Equal(earliest) {
		t.Errorf("due_at = %v, want the earliest finding deadline %v", action["due_at"], earliest)
	}
	if libcID == "" || len(fl["findings"].([]any)) != 3 {
		t.Fatalf("action findings = %v", fl)
	}

	// Owner follows the findings' assignee.
	_, me := req(t, app, http.MethodGet, "/api/v1/me", lead, "")
	leadID := me["id"].(string)
	req(t, app, http.MethodPut, "/api/v1/findings/"+libcID+"/assignee", lead, `{"assignee_id":"`+leadID+`"}`)
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/remediation/sweep", lead, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin sweep = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/remediation/sweep", admin, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("sweep = %d", resp.StatusCode)
	}
	if _, a := req(t, app, http.MethodGet, "/api/v1/remediation/"+actionID, viewer, ""); a["owner_email"] != "lead@xila.io" || a["owner_manual"] != false {
		t.Errorf("owner after assignment = %v", a["owner_email"])
	}
	_, outsiderMe := req(t, app, http.MethodGet, "/api/v1/me", outsider, "")
	if resp, _ := req(t, app, http.MethodPatch, "/api/v1/remediation/"+actionID, lead, `{"owner_id":"`+outsiderMe["id"].(string)+`"}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("owner without project access = %d, want 400", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPatch, "/api/v1/remediation/"+actionID, viewer, `{"status":"in_progress"}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer update = %d, want 403", resp.StatusCode)
	}
	if resp, a := req(t, app, http.MethodPatch, "/api/v1/remediation/"+actionID, lead, `{"status":"in_progress"}`); resp.StatusCode != http.StatusOK || a["status"] != "in_progress" {
		t.Errorf("start work = %d %v", resp.StatusCode, a)
	}

	// One ticket for the whole action.
	gh := newRemediationFakeGitHub(t)
	if resp, b := req(t, app, http.MethodPut, "/api/v1/projects/"+web+"/issue-tracker", lead,
		`{"kind":"github","base_url":"`+gh.URL+`","target":"acme/web","token":"ghp_x","labels":["security"]}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("put tracker = %d %v", resp.StatusCode, b)
	}
	resp, link := req(t, app, http.MethodPost, "/api/v1/remediation/"+actionID+"/issue", lead, "")
	if resp.StatusCode != http.StatusCreated || link["external_id"] != "1" || link["state"] != "open" {
		t.Fatalf("file action = %d %v", resp.StatusCode, link)
	}
	if resp, again := req(t, app, http.MethodPost, "/api/v1/remediation/"+actionID+"/issue", lead, ""); resp.StatusCode != http.StatusOK || again["id"] != link["id"] {
		t.Errorf("second filing = %d %v, want the same link", resp.StatusCode, again)
	}
	gh.mu.Lock()
	if len(gh.created) != 1 {
		t.Fatalf("tickets filed = %d, want 1", len(gh.created))
	}
	issue := gh.created[0]
	gh.mu.Unlock()
	if issue["title"] != "[high] Rebuild python:3.11-slim on a patched base image (debian 12.5) (3 findings)" {
		t.Errorf("ticket title = %q", issue["title"])
	}
	body, _ := issue["body"].(string)
	for _, want := range []string{
		"Change: base image rebuild", "Owner: lead@xila.io", "Closes: 3 findings",
		"Due: " + earliest.UTC().Format(time.DateOnly),
		"- [high] glibc: buffer overflow in ld.so leading to privilege escalation (CVE-2023-4911) — libc6@2.36-9+deb12u1 https://xila.test/findings/" + libcID,
		"View in Xila: https://xila.test/projects/" + web + "?tab=remediation",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("ticket body lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "zlib1g") || strings.Contains(body, "pip") {
		t.Errorf("ticket body lists findings outside the action:\n%s", body)
	}
	if labels, _ := issue["labels"].([]any); len(labels) != 1 || labels[0] != "security" {
		t.Errorf("ticket labels = %v", issue["labels"])
	}

	// Rebuilt on a patched base: the image's distro findings are gone, the
	// ingest closes the action, and the sync closes its ticket.
	var rep map[string]any
	_ = json.Unmarshal([]byte(trivyImage), &rep)
	rep["Results"] = rep["Results"].([]any)[1:]
	rebuilt, _ := json.Marshal(rep)
	scan(web, "trivy", string(rebuilt))
	_, a := req(t, app, http.MethodGet, "/api/v1/remediation/"+actionID, viewer, "")
	if a["status"] != "done" || a["close_reason"] != "findings_resolved" || a["closed_by"] != nil || a["open_findings"] != float64(0) {
		t.Errorf("after the rebuild = %v, want done (findings_resolved, by the system)", a)
	}
	if _, res := req(t, app, http.MethodPost, "/api/v1/issue-trackers/sync", admin, ""); res["closed_issues"] != float64(1) || res["errors"] != float64(0) {
		t.Errorf("sync after auto-close = %v", res)
	}
	if gh.state("1") != "closed" {
		t.Errorf("ticket state = %q, want closed", gh.state("1"))
	}

	// The other way: a ticket closed in the tracker closes its action.
	resp, pip := req(t, app, http.MethodPost, "/api/v1/projects/"+web+"/remediation", lead, `{"kind":"package_upgrade","key":"pkg:pypi/pip|pip@23.2.1"}`)
	if resp.StatusCode != http.StatusCreated || pip["target"] != "23.3" {
		t.Fatalf("accept pip = %d %v", resp.StatusCode, pip)
	}
	pipID := pip["id"].(string)
	req(t, app, http.MethodPost, "/api/v1/remediation/"+pipID+"/issue", lead, "")
	gh.set("2", "closed")
	if _, res := req(t, app, http.MethodPost, "/api/v1/issue-trackers/sync", admin, ""); res["resolved_actions"] != float64(1) {
		t.Errorf("sync after closing the ticket = %v", res)
	}
	if _, a := req(t, app, http.MethodGet, "/api/v1/remediation/"+pipID, viewer, ""); a["status"] != "done" || a["close_reason"] != "issue_closed" {
		t.Errorf("pip action after its ticket closed = %v", a)
	}

	// Portfolio list: scoped to visible projects.
	resp, apiAccept := req(t, app, http.MethodPost, "/api/v1/projects/"+api+"/remediation", lead,
		`{"kind":"code_location","key":"src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02194.java"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("accept on api = %d %v", resp.StatusCode, apiAccept)
	}
	ids := func(token, query string) map[string]string {
		_, l := req(t, app, http.MethodGet, "/api/v1/remediation"+query, token, "")
		out := map[string]string{}
		for _, x := range l["actions"].([]any) {
			m := x.(map[string]any)
			out[m["id"].(string)] = m["project_id"].(string)
		}
		return out
	}
	if all := ids(lead, "?status=all"); len(all) != 3 || all[apiAccept["id"].(string)] != api || all[actionID] != web {
		t.Errorf("lead's portfolio = %v, want both projects' 3 actions", all)
	}
	if live := ids(lead, ""); len(live) != 1 {
		t.Errorf("lead's live actions = %v, want only the api one (the others are done)", live)
	}
	for id, pid := range ids(viewer, "?status=all") {
		if pid != web {
			t.Errorf("viewer sees action %s of a project they can't see", id)
		}
	}
	if n := len(ids(viewer, "?status=all")); n != 2 {
		t.Errorf("viewer's portfolio = %d actions, want web's 2", n)
	}
	if n := len(ids(outsider, "?status=all")); n != 0 {
		t.Errorf("outsider's portfolio = %d actions, want 0", n)
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/remediation/"+apiAccept["id"].(string), viewer, ""); resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusNotFound {
		t.Errorf("viewer reading another project's action = %d", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/projects/"+api+"/remediation", viewer, ""); resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusNotFound {
		t.Errorf("viewer listing another project's actions = %d", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/remediation?status=bogus", lead, ""); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad status filter = %d, want 400", resp.StatusCode)
	}
}

// With REMEDIATION_AUTO_CREATE every proposal becomes an action at ingest;
// an action closes once its findings are false positives.
func TestRemediationAutoCreate(t *testing.T) {
	app := newTestApp(t, func(c *config.Config) { c.RemediationAutoCreate = true })
	admin := rbacUser(t, app, "founder@xila.io")
	lead := rbacUser(t, app, "lead@xila.io")
	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", lead, `{"slug":"acme","name":"Acme"}`)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgBody["id"].(string)+"/teams", lead, `{"slug":"core","name":"Core"}`)
	_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+teamBody["id"].(string)+"/projects", lead, `{"slug":"infra","name":"infra"}`)
	pid := p["id"].(string)
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/scans?scanner=hadolint", lead, remediationFixture(t, "hadolint_many.json")); resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload = %d", resp.StatusCode)
	}
	_, list := req(t, app, http.MethodGet, "/api/v1/projects/"+pid+"/remediation?limit=100", lead, "")
	actions := list["actions"].([]any)
	if len(actions) != 7 {
		t.Fatalf("auto-created actions = %d, want 7 (one per hadolint rule and Dockerfile)", len(actions))
	}
	var pinID string
	for _, x := range actions {
		a := x.(map[string]any)
		if a["kind"] != "iac_rule" || a["created_by"] != nil {
			t.Errorf("auto-created action = %v, want iac_rule by the system", a)
		}
		if a["key"] == `DL3008|django-DefectDojo\Dockerfile.nginx|` {
			pinID = a["id"].(string)
		}
	}
	if _, props := req(t, app, http.MethodGet, "/api/v1/projects/"+pid+"/remediation/proposals", lead, ""); len(props["proposals"].([]any)) != 0 {
		t.Errorf("proposals left after auto-create = %v", props["proposals"])
	}

	_, fl := req(t, app, http.MethodGet, "/api/v1/remediation/"+pinID+"/findings", lead, "")
	findings := fl["findings"].([]any)
	if len(findings) != 2 {
		t.Fatalf("DL3008 action findings = %d, want 2", len(findings))
	}
	for i, f := range findings {
		id := f.(map[string]any)["id"].(string)
		// One false positive leaves it open; the second closes it.
		req(t, app, http.MethodPatch, "/api/v1/findings/"+id, lead, `{"status":"false_positive","reason":"pinned by the base image"}`)
		req(t, app, http.MethodPost, "/api/v1/remediation/sweep", admin, "")
		_, a := req(t, app, http.MethodGet, "/api/v1/remediation/"+pinID, lead, "")
		if want := map[bool]string{true: "done", false: "open"}[i == 1]; a["status"] != want {
			t.Errorf("after %d false positive(s) status = %v, want %s", i+1, a["status"], want)
		}
	}
}
