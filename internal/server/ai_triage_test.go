package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/config"
)

// fakeModel is an OpenAI-compatible model server for tests: it answers every
// chat completion with answer and records what it was sent.
type fakeModel struct {
	*httptest.Server
	mu     sync.Mutex
	answer string
	sent   []string // user messages received
	auth   []string
}

func newFakeModel(t *testing.T) *fakeModel {
	t.Helper()
	m := &fakeModel{}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []struct{ Role, Content string } `json:"messages"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		m.mu.Lock()
		defer m.mu.Unlock()
		if r.URL.Path != "/v1/chat/completions" || len(body.Messages) != 2 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		m.sent = append(m.sent, body.Messages[1].Content)
		m.auth = append(m.auth, r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": m.answer}}}})
	}))
	t.Cleanup(m.Close)
	return m
}

func (m *fakeModel) say(answer string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.answer = answer
}

func (m *fakeModel) requests() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.sent...)
}

func (m *fakeModel) firstAuth() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.auth) == 0 {
		return ""
	}
	return m.auth[0]
}

func withAI(m *fakeModel, limit int) func(*config.Config) {
	return func(c *config.Config) {
		c.AI = config.AI{Enabled: true, Provider: config.AIProviderOpenAI, BaseURL: m.URL + "/v1",
			Model: "fake-llm-1", APIKey: "test-ai-key", RateLimit: limit, Timeout: 10 * time.Second} // gitleaks:allow -- fake key for a loopback test server
	}
}

const aiFPAnswer = `{"verdict":"false_positive","rationale":"The value is a placeholder in a test settings file.","confidence":0.86,"proposed_status":"false_positive","proposed_severity":null,"fix":""}`

// Bandit B105 report (hand-written to bandit's -f json format) whose code
// snippet holds a hardcoded password, plus a semgrep result without snippet.
const aiPassword = "hunter2-Pr0d-S3cret" // gitleaks:allow -- fake credential for the redaction test

const aiBandit = `{"results":[{"code":"11 DEBUG = False\n12 DB_PASSWORD = \"` + aiPassword + `\"\n","filename":"app/settings.py",
	"issue_confidence":"MEDIUM","issue_severity":"LOW","issue_cwe":{"id":259,"link":"https://cwe.mitre.org/data/definitions/259.html"},
	"issue_text":"Possible hardcoded password: '` + aiPassword + `'","line_number":12,"more_info":"https://bandit.readthedocs.io/en/latest/plugins/b105_hardcoded_password_string.html",
	"test_id":"B105","test_name":"hardcoded_password_string"}]}`

type aiFixture struct {
	app                   *fiber.App
	admin, editor, viewer string
	project, findingID    string
}

func setupAI(t *testing.T, opts ...func(*config.Config)) aiFixture {
	t.Helper()
	app := newTestApp(t, opts...)
	fx := aiFixture{app: app}
	fx.admin = rbacUser(t, app, "founder@xila.io")
	fx.editor = rbacUser(t, app, "editor@xila.io")
	fx.viewer = rbacUser(t, app, "viewer@xila.io")
	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", fx.admin, `{"slug":"acme","name":"Acme"}`)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgBody["id"].(string)+"/teams", fx.admin, `{"slug":"core","name":"Core"}`)
	_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+teamBody["id"].(string)+"/projects", fx.admin, `{"slug":"web","name":"web"}`)
	fx.project = p["id"].(string)
	req(t, app, http.MethodPost, "/api/v1/projects/"+fx.project+"/members", fx.admin, `{"email":"editor@xila.io","role":"editor"}`)
	req(t, app, http.MethodPost, "/api/v1/projects/"+fx.project+"/members", fx.admin, `{"email":"viewer@xila.io","role":"viewer"}`)
	if res, body := req(t, app, http.MethodPost, "/api/v1/projects/"+fx.project+"/scans?scanner=bandit", fx.admin, aiBandit); res.StatusCode != http.StatusCreated {
		t.Fatalf("upload: %d %v", res.StatusCode, body)
	}
	_, list := req(t, app, http.MethodGet, "/api/v1/projects/"+fx.project+"/findings", fx.admin, "")
	fx.findingID = list["findings"].([]any)[0].(map[string]any)["id"].(string)
	return fx
}

func (fx aiFixture) path(suffix string) string {
	return "/api/v1/findings/" + fx.findingID + "/ai-proposals" + suffix
}

// statusEvents is the finding's status changes in its history.
func statusEvents(t *testing.T, app *fiber.App, token, id string) []map[string]any {
	t.Helper()
	_, h := req(t, app, http.MethodGet, "/api/v1/findings/"+id+"/history", token, "")
	var out []map[string]any
	for _, e := range h["events"].([]any) {
		if ev := e.(map[string]any); ev["kind"] == "status" {
			out = append(out, ev)
		}
	}
	return out
}

// A proposal is recorded without touching the finding; the prompt previewed
// is exactly the one sent, with the snippet's password redacted; accepting
// applies it as the person, whose history names them and the model; invalid
// model output is recorded as invalid and can't be accepted; a fix becomes
// the accepter's comment; a viewer can't ask or decide.
func TestAITriageProposals(t *testing.T) {
	model := newFakeModel(t)
	fx := setupAI(t, withAI(model, 50))
	app := fx.app

	res, prev := req(t, app, http.MethodGet, fx.path("/prompt?kind=false_positive"), fx.viewer, "")
	if res.StatusCode != http.StatusOK || prev["model"] != "fake-llm-1" {
		t.Fatalf("preview: %d %v", res.StatusCode, prev)
	}
	user := prev["prompt"].(map[string]any)["user"].(string)
	if strings.Contains(user, aiPassword) || !strings.Contains(user, "DB_PASSWORD = [REDACTED]") || !strings.Contains(user, "code snippet") {
		t.Fatalf("preview prompt:\n%s", user)
	}
	if len(model.requests()) != 0 {
		t.Fatal("previewing sent something to the model")
	}

	model.say(aiFPAnswer)
	if res, _ := req(t, app, http.MethodPost, fx.path(""), fx.viewer, `{"kind":"false_positive"}`); res.StatusCode != http.StatusForbidden {
		t.Errorf("viewer asking = %d, want 403", res.StatusCode)
	}
	if res, _ := req(t, app, http.MethodPost, fx.path(""), fx.editor, `{"kind":"guess"}`); res.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown kind = %d, want 400", res.StatusCode)
	}
	res, prop := req(t, app, http.MethodPost, fx.path(""), fx.editor, `{"kind":"false_positive"}`)
	if res.StatusCode != http.StatusCreated || prop["state"] != "proposed" || prop["proposed_status"] != "false_positive" ||
		prop["model"] != "fake-llm-1" || prop["confidence"] != 0.86 || prop["prompt_hash"] != prev["prompt_hash"] ||
		prop["created_by_email"] != "editor@xila.io" {
		t.Fatalf("ask: %d %v", res.StatusCode, prop)
	}
	sent := model.requests()
	if len(sent) != 1 || sent[0] != user || model.firstAuth() != "Bearer test-ai-key" {
		t.Fatalf("model got %d requests; first equals preview: %v", len(sent), len(sent) == 1 && sent[0] == user)
	}
	_, f := req(t, app, http.MethodGet, "/api/v1/findings/"+fx.findingID, fx.editor, "")
	if f["status"] != "open" || len(statusEvents(t, app, fx.editor, fx.findingID)) != 0 {
		t.Fatalf("asking changed the finding: %v", f["status"])
	}
	pid := prop["id"].(string)

	if res, _ := req(t, app, http.MethodPost, fx.path("/"+pid+"/accept"), fx.viewer, ""); res.StatusCode != http.StatusForbidden {
		t.Errorf("viewer accepting = %d, want 403", res.StatusCode)
	}
	res, acc := req(t, app, http.MethodPost, fx.path("/"+pid+"/accept"), fx.editor, `{"note":"checked the file"}`)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("accept: %d %v", res.StatusCode, acc)
	}
	if p := acc["proposal"].(map[string]any); p["state"] != "accepted" || p["decided_by_email"] != "editor@xila.io" || p["outcome"] != "applied" {
		t.Errorf("accepted proposal = %v", p)
	}
	if fa := acc["finding"].(map[string]any); fa["status"] != "false_positive" {
		t.Errorf("finding after accept = %v", fa["status"])
	}
	evs := statusEvents(t, app, fx.editor, fx.findingID)
	if len(evs) != 1 || evs[0]["to"] != "false_positive" || evs[0]["actor_name"] != "editor@xila.io" ||
		!strings.Contains(evs[0]["note"].(string), "fake-llm-1") || !strings.Contains(evs[0]["note"].(string), pid) {
		t.Fatalf("history = %v", evs)
	}
	if res, _ := req(t, app, http.MethodPost, fx.path("/"+pid+"/accept"), fx.editor, ""); res.StatusCode != http.StatusConflict {
		t.Errorf("accepting twice = %d, want 409", res.StatusCode)
	}

	// Out-of-set status: recorded as invalid, 502, can't be accepted.
	model.say(strings.Replace(aiFPAnswer, `"proposed_status":"false_positive"`, `"proposed_status":"remediated"`, 1))
	res, inv := req(t, app, http.MethodPost, fx.path(""), fx.editor, `{"kind":"false_positive"}`)
	bad, _ := inv["proposal"].(map[string]any)
	if res.StatusCode != http.StatusBadGateway || bad == nil || bad["state"] != "invalid" || bad["proposed_status"] != nil ||
		!strings.Contains(bad["invalid_reason"].(string), "remediated") {
		t.Fatalf("invalid answer: %d %v", res.StatusCode, inv)
	}
	if res, _ := req(t, app, http.MethodPost, fx.path("/"+bad["id"].(string)+"/accept"), fx.editor, ""); res.StatusCode != http.StatusConflict {
		t.Errorf("accepting an invalid proposal = %d, want 409", res.StatusCode)
	}

	// A newer proposal of a kind supersedes the open one; rejecting changes nothing.
	exp := `{"verdict":"not_exploitable","rationale":"Only read by the test runner.","confidence":0.6,"proposed_status":null,"proposed_severity":"info","fix":""}`
	model.say(exp)
	_, first := req(t, app, http.MethodPost, fx.path(""), fx.editor, `{"kind":"exploitability"}`)
	_, second := req(t, app, http.MethodPost, fx.path(""), fx.editor, `{"kind":"exploitability"}`)
	res, rej := req(t, app, http.MethodPost, fx.path("/"+second["id"].(string)+"/reject"), fx.editor, `{"note":"it ships"}`)
	if res.StatusCode != http.StatusOK || rej["state"] != "rejected" || rej["decision_note"] != "it ships" {
		t.Errorf("reject: %d %v", res.StatusCode, rej)
	}
	_, f = req(t, app, http.MethodGet, "/api/v1/findings/"+fx.findingID, fx.editor, "")
	if f["severity"] != "low" {
		t.Errorf("rejected proposal changed severity to %v", f["severity"])
	}

	// A fix suggestion, accepted, is the accepter's comment.
	model.say(`{"verdict":"fix_available","rationale":"Read it from the environment.","confidence":0.9,"proposed_status":null,"proposed_severity":null,"fix":"Use os.environ[\"DB_PASSWORD\"] and rotate the value."}`)
	_, fix := req(t, app, http.MethodPost, fx.path(""), fx.editor, `{"kind":"fix"}`)
	res, acc = req(t, app, http.MethodPost, fx.path("/"+fix["id"].(string)+"/accept"), fx.editor, "")
	if p := acc["proposal"].(map[string]any); res.StatusCode != http.StatusOK || p["outcome"] != "comment_added" || p["outcome_ref"] == nil {
		t.Fatalf("accept fix: %d %v", res.StatusCode, acc)
	}
	_, cs := req(t, app, http.MethodGet, "/api/v1/findings/"+fx.findingID+"/comments", fx.editor, "")
	comments, _ := cs["comments"].([]any)
	if len(comments) != 1 || !strings.Contains(comments[0].(map[string]any)["body"].(string), "rotate the value") ||
		comments[0].(map[string]any)["author"] != "editor@xila.io" {
		t.Errorf("comments = %v", cs)
	}

	_, list := req(t, app, http.MethodGet, fx.path(""), fx.viewer, "")
	states := map[string]string{}
	for _, x := range list["proposals"].([]any) {
		p := x.(map[string]any)
		states[p["id"].(string)] = p["state"].(string)
	}
	if len(states) != 5 || states[pid] != "accepted" || states[first["id"].(string)] != "superseded" ||
		states[second["id"].(string)] != "rejected" || list["opted_out"] != false {
		t.Errorf("list = %v", states)
	}
}

// Off → every route 404s. A project that opted out sends nothing (403); the
// per-project hourly limit answers 429.
func TestAITriageDisabledOptOutAndRateLimit(t *testing.T) {
	off := setupAI(t)
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, off.path("")}, {http.MethodPost, off.path("")}, {http.MethodGet, off.path("/prompt?kind=fix")},
	} {
		if res, _ := req(t, off.app, c.method, c.path, off.admin, `{"kind":"fix"}`); res.StatusCode != http.StatusNotFound {
			t.Errorf("disabled %s %s = %d, want 404", c.method, c.path, res.StatusCode)
		}
	}

	model := newFakeModel(t)
	model.say(aiFPAnswer)
	fx := setupAI(t, withAI(model, 1))
	app := fx.app
	if res, p := req(t, app, http.MethodPatch, "/api/v1/projects/"+fx.project, fx.editor, `{"ai_triage_opt_out":true}`); res.StatusCode != http.StatusOK || p["ai_triage_opt_out"] != true {
		t.Fatalf("opt out: %d %v", res.StatusCode, p)
	}
	if res, _ := req(t, app, http.MethodPost, fx.path(""), fx.editor, `{"kind":"false_positive"}`); res.StatusCode != http.StatusForbidden {
		t.Errorf("opted-out ask = %d, want 403", res.StatusCode)
	}
	if res, _ := req(t, app, http.MethodGet, fx.path("/prompt?kind=fix"), fx.editor, ""); res.StatusCode != http.StatusForbidden {
		t.Errorf("opted-out preview = %d, want 403", res.StatusCode)
	}
	if _, l := req(t, app, http.MethodGet, fx.path(""), fx.viewer, ""); l["opted_out"] != true {
		t.Errorf("list opted_out = %v", l["opted_out"])
	}
	if n := len(model.requests()); n != 0 {
		t.Fatalf("an opted-out project sent %d requests", n)
	}

	req(t, app, http.MethodPatch, "/api/v1/projects/"+fx.project, fx.editor, `{"ai_triage_opt_out":false}`)
	if res, _ := req(t, app, http.MethodPost, fx.path(""), fx.editor, `{"kind":"false_positive"}`); res.StatusCode != http.StatusCreated {
		t.Fatalf("first ask = %d", res.StatusCode)
	}
	res, _ := req(t, app, http.MethodPost, fx.path(""), fx.editor, `{"kind":"fix"}`)
	if res.StatusCode != http.StatusTooManyRequests || res.Header.Get("Retry-After") == "" {
		t.Errorf("second ask within the hour = %d (Retry-After %q), want 429", res.StatusCode, res.Header.Get("Retry-After"))
	}
	if n := len(model.requests()); n != 1 {
		t.Errorf("model got %d requests, want 1", n)
	}
}

// With ASSESSMENT_REQUIRES_APPROVAL, accepting files a pending assessment;
// a risk_accepted proposal files a risk acceptance request. Neither changes
// the finding yet.
func TestAITriageAcceptGoesThroughApprovals(t *testing.T) {
	model := newFakeModel(t)
	fx := setupAI(t, withAI(model, 50), func(c *config.Config) { c.AssessmentRequiresApproval = true })
	app := fx.app

	model.say(`{"verdict":"exploitable","rationale":"Reachable from the login form.","confidence":0.7,"proposed_status":"confirmed","proposed_severity":"high","fix":""}`)
	_, p := req(t, app, http.MethodPost, fx.path(""), fx.editor, `{"kind":"exploitability"}`)
	res, acc := req(t, app, http.MethodPost, fx.path("/"+p["id"].(string)+"/accept"), fx.editor, "")
	a, _ := acc["assessment"].(map[string]any)
	if res.StatusCode != http.StatusAccepted || a == nil || a["state"] != "pending" || a["severity"] != "high" ||
		!strings.Contains(a["reason"].(string), "fake-llm-1") || acc["proposal"].(map[string]any)["outcome"] != "assessment_requested" {
		t.Fatalf("accept with approval: %d %v", res.StatusCode, acc)
	}

	model.say(`{"verdict":"not_exploitable","rationale":"Dev-only settings.","confidence":0.55,"proposed_status":"risk_accepted","proposed_severity":null,"fix":""}`)
	_, p = req(t, app, http.MethodPost, fx.path(""), fx.editor, `{"kind":"exploitability"}`)
	res, acc = req(t, app, http.MethodPost, fx.path("/"+p["id"].(string)+"/accept"), fx.editor, "")
	ra, _ := acc["risk_acceptance"].(map[string]any)
	if res.StatusCode != http.StatusAccepted || ra == nil || ra["state"] != "requested" ||
		!strings.Contains(ra["justification"].(string), p["id"].(string)) {
		t.Fatalf("accept risk: %d %v", res.StatusCode, acc)
	}
	_, f := req(t, app, http.MethodGet, "/api/v1/findings/"+fx.findingID, fx.editor, "")
	if f["status"] != "open" || f["severity"] != "low" {
		t.Errorf("finding changed before approval: %v %v", f["status"], f["severity"])
	}
}

// GET /ai-proposals is the cross-project queue of open proposals: visible
// projects only, mine=true narrows to what the caller asked for or is
// assigned, and a decided proposal leaves the queue.
func TestAIProposalQueue(t *testing.T) {
	model := newFakeModel(t)
	fx := setupAI(t, withAI(model, 50))
	app := fx.app
	outsider := rbacUser(t, app, "outsider@xila.io")

	model.say(aiFPAnswer)
	res, prop := req(t, app, http.MethodPost, fx.path(""), fx.editor, `{"kind":"false_positive"}`)
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("ask: %d %v", res.StatusCode, prop)
	}
	queue := func(token, query string) []any {
		t.Helper()
		res, body := req(t, app, http.MethodGet, "/api/v1/ai-proposals"+query, token, "")
		if res.StatusCode != http.StatusOK {
			t.Fatalf("queue %s: %d %v", query, res.StatusCode, body)
		}
		items, _ := body["proposals"].([]any)
		return items
	}
	q := queue(fx.editor, "?mine=true")
	if len(q) != 1 {
		t.Fatalf("editor's own queue = %v, want the proposal", q)
	}
	if p := q[0].(map[string]any); p["id"] != prop["id"] || p["finding_title"] == "" || p["project_name"] != "web" || p["finding_severity"] == "" {
		t.Errorf("queue item = %v, want the finding's title, severity and project", p)
	}
	if q := queue(fx.viewer, ""); len(q) != 1 {
		t.Errorf("viewer's visible queue = %v, want the proposal", q)
	}
	if q := queue(fx.viewer, "?mine=true"); len(q) != 0 {
		t.Errorf("viewer's own queue = %v, want empty (not asked, not assigned)", q)
	}
	if q := queue(outsider, ""); len(q) != 0 {
		t.Errorf("outsider's queue = %v, want empty", q)
	}
	if res, _ := req(t, app, http.MethodPost, fx.path("/"+prop["id"].(string)+"/reject"), fx.editor, ""); res.StatusCode != http.StatusOK {
		t.Fatalf("reject = %d", res.StatusCode)
	}
	if q := queue(fx.editor, "?mine=true"); len(q) != 0 {
		t.Errorf("queue after the decision = %v, want empty", q)
	}
}
