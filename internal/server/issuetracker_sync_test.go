package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/pgtest"
)

// fakeGitHub is a GitHub issues API: issues, their state, and comments.
type fakeGitHub struct {
	mu       sync.Mutex
	issues   int
	filed    []map[string]any
	state    map[string]string
	comments []string
}

func (g *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	rest, _ := strings.CutPrefix(r.URL.Path, "/repos/acme/web")
	num, sub, _ := strings.Cut(strings.TrimPrefix(rest, "/issues/"), "/")
	switch {
	case rest == "":
		_, _ = w.Write([]byte(`{"full_name":"acme/web"}`))
	case r.Method == http.MethodPost && rest == "/issues":
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		g.filed = append(g.filed, body)
		g.issues++
		n := strconv.Itoa(g.issues)
		g.state[n] = "open"
		_, _ = w.Write([]byte(`{"number":` + n + `,"html_url":"https://github.test/acme/web/issues/` + n + `"}`))
	case r.Method == http.MethodPost && sub == "comments":
		var body struct {
			Body string `json:"body"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		g.comments = append(g.comments, body.Body)
		_, _ = w.Write([]byte(`{"id":` + strconv.Itoa(900+len(g.comments)) + `}`))
	case sub == "":
		if r.Method == http.MethodPatch {
			var body struct {
				State string `json:"state"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			g.state[num] = body.State
		}
		_, _ = w.Write([]byte(`{"number":` + num + `,"state":"` + g.state[num] + `"}`))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (g *fakeGitHub) pushed() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.comments...)
}

// M13 13.18: finding comments reach the issue once, tracker comments and
// state changes come back by a verified webhook, and nothing loops.
func TestIssueTrackerCommentsAndWebhook(t *testing.T) {
	pool := pgtest.Pool(t)
	app := newTestAppOn(t, pool)
	gh := &fakeGitHub{state: map[string]string{}}
	srv := httptest.NewServer(gh)
	defer srv.Close()

	token := rbacUser(t, app, "tracker@xila.io")
	_, org := req(t, app, http.MethodPost, "/api/v1/orgs", token, `{"slug":"acme","name":"Acme"}`)
	_, team := req(t, app, http.MethodPost, "/api/v1/orgs/"+org["id"].(string)+"/teams", token, `{"slug":"core","name":"Core"}`)
	_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+team["id"].(string)+"/projects", token, `{"slug":"web","name":"Web"}`)
	pid := p["id"].(string)
	req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/scans?scanner=trivy", token, smokeTrivyReport)
	fid := projectFindingIDs(t, app, token, pid)[0]

	trackerPath := "/api/v1/projects/" + pid + "/issue-tracker"
	// A template that can't render is refused on save.
	if resp, body := req(t, app, http.MethodPut, trackerPath, token, `{"kind":"github","base_url":"`+srv.URL+`","target":"acme/web","token":"ghp_x","title_template":"{{.Nope}}"}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad template = %d %v, want 400", resp.StatusCode, body)
	}
	resp, tr := req(t, app, http.MethodPut, trackerPath, token, `{"kind":"github","base_url":"`+srv.URL+`","target":"acme/web","token":"ghp_x",
		"sync_comments":true,"title_template":"SEC {{.Severity}}: {{.Title}}","body_template":"{{.Default}}\nTeam: core"}`)
	if resp.StatusCode != http.StatusOK || tr["sync_comments"] != true || tr["has_webhook_secret"] != false {
		t.Fatalf("put tracker = %d %v", resp.StatusCode, tr)
	}
	trackerID := tr["id"].(string)
	if resp, issue := req(t, app, http.MethodPost, "/api/v1/findings/"+fid+"/issue", token, ""); resp.StatusCode != http.StatusCreated {
		t.Fatalf("create issue = %d %v", resp.StatusCode, issue)
	}
	// The templates shaped the ticket; .Default is the built-in body.
	filed := gh.filed[0]
	if title, _ := filed["title"].(string); !strings.HasPrefix(title, "SEC ") || strings.Contains(title, "{{") {
		t.Errorf("issue title = %q, want the template's", title)
	}
	if body, _ := filed["body"].(string); !strings.HasSuffix(body, "\nTeam: core") || !strings.Contains(body, "Scanner: trivy") {
		t.Errorf("issue body = %q, want the built-in body then the template's line", body)
	}

	// A Xila comment is pushed once, whether the immediate push or the sync
	// run gets there first.
	req(t, app, http.MethodPost, "/api/v1/findings/"+fid+"/comments", token, `{"body":"Upgrading in the next sprint."}`)
	req(t, app, http.MethodPost, "/api/v1/issue-trackers/sync", token, "")
	deadline := time.Now().Add(5 * time.Second)
	for len(gh.pushed()) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	req(t, app, http.MethodPost, "/api/v1/issue-trackers/sync", token, "")
	if got := gh.pushed(); len(got) != 1 || !strings.Contains(got[0], "Upgrading in the next sprint.") || !strings.Contains(got[0], "tracker@xila.io") {
		t.Fatalf("pushed comments = %q, want the one comment once", got)
	}

	// The receiver is off until a secret is issued.
	hook := "/api/v1/issue-trackers/" + trackerID + "/webhook"
	if code := deliver(t, app, hook, "issues", "", `{}`); code != http.StatusNotFound {
		t.Errorf("webhook without a secret = %d, want 404", code)
	}
	_, sec := req(t, app, http.MethodPost, trackerPath+"/webhook-secret", token, "")
	secret, _ := sec["secret"].(string)
	if secret == "" || !strings.HasSuffix(sec["webhook_url"].(string), hook) {
		t.Fatalf("webhook secret = %v", sec)
	}
	if code := deliver(t, app, hook, "issues", "wrong-secret", `{"action":"closed","issue":{"number":1}}`); code != http.StatusUnauthorized {
		t.Errorf("forged delivery = %d, want 401", code)
	}
	// Deliveries are audited: a forged one proved nothing (anonymous).
	if rows := auditRows(t, pool, http.MethodPost, hook); len(rows) != 2 || rows[1].ActorKind != "anonymous" || rows[1].Status != http.StatusUnauthorized ||
		rows[1].ProjectID == nil || *rows[1].ProjectID != pid {
		t.Errorf("audit after a forged delivery = %+v", rows)
	}
	// A tracker's own secret can be stored instead (too short is refused).
	if resp, _ := req(t, app, http.MethodPost, trackerPath+"/webhook-secret", token, `{"secret":"short"}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("short secret = %d, want 400", resp.StatusCode)
	}
	// Built, not a literal: a secret-shaped string trips the secret scanner.
	provided := strings.Repeat("linear", 4)
	_, own := req(t, app, http.MethodPost, trackerPath+"/webhook-secret", token, `{"secret":"`+provided+`"}`)
	if own["secret"] != provided {
		t.Fatalf("provided secret = %v", own)
	}
	if code := deliver(t, app, hook, "issues", secret, `{"action":"closed","issue":{"number":1}}`); code != http.StatusUnauthorized {
		t.Errorf("the replaced secret still works: %d", code)
	}
	secret = provided

	comment := `{"action":"created","issue":{"number":1},"comment":{"id":77,"body":"Fixed in #12","user":{"login":"octocat"}}}`
	for range 2 { // a redelivery adds nothing
		if code := deliver(t, app, hook, "issue_comment", secret, comment); code != http.StatusOK {
			t.Fatalf("comment delivery = %d", code)
		}
	}
	// Xila's own comment coming back is not taken in, even when the webhook
	// beats the push recording the comment's id (5555 is not recorded).
	echo := `{"action":"created","issue":{"number":1},"comment":{"id":5555,"body":` + jsonString(gh.pushed()[0]) + `,"user":{"login":"xila-bot"}}}`
	deliver(t, app, hook, "issue_comment", secret, echo)
	_, list := req(t, app, http.MethodGet, "/api/v1/findings/"+fid+"/comments", token, "")
	var fromTracker []string
	for _, c := range list["comments"].([]any) {
		c := c.(map[string]any)
		if strings.HasPrefix(c["author"].(string), "github") {
			fromTracker = append(fromTracker, c["author"].(string)+"|"+c["body"].(string))
		}
	}
	if len(fromTracker) != 1 || fromTracker[0] != "github: octocat|Fixed in #12" {
		t.Errorf("tracker comments on the finding = %q, want octocat's once", fromTracker)
	}
	if got := gh.pushed(); len(got) != 1 {
		t.Errorf("an inbound comment was pushed back: %q", got)
	}

	// A state change: the receiver re-reads the issue and resolves the finding.
	gh.mu.Lock()
	gh.state["1"] = "closed"
	gh.mu.Unlock()
	if code := deliver(t, app, hook, "issues", secret, `{"action":"closed","issue":{"number":1}}`); code != http.StatusOK {
		t.Fatalf("state delivery = %d", code)
	}
	rows := auditRows(t, pool, http.MethodPost, hook)
	if last := rows[len(rows)-1]; last.ActorKind != "system" || last.ActorEmail != "issue-tracker:github" || last.Outcome != "success" ||
		last.ResourceID != trackerID {
		t.Errorf("audit of a verified delivery = %+v", last)
	}
	if _, f := req(t, app, http.MethodGet, "/api/v1/findings/"+fid, token, ""); f["status"] != "remediated" {
		t.Errorf("finding after the issue closed = %v, want remediated", f["status"])
	}

	// Turning the receiver off makes it disappear again.
	req(t, app, http.MethodDelete, trackerPath+"/webhook-secret", token, "")
	if code := deliver(t, app, hook, "issues", secret, `{"action":"closed","issue":{"number":1}}`); code != http.StatusNotFound {
		t.Errorf("webhook after the secret was cleared = %d, want 404", code)
	}
}

// deliver posts a GitHub webhook signed with secret ("" = unsigned).
func deliver(t *testing.T, app interface {
	Test(*http.Request, ...int) (*http.Response, error)
}, path, event, secret, body string,
) int {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-GitHub-Event", event)
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(body))
		r.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := app.Test(r, -1)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
