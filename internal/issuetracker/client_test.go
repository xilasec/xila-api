package issuetracker

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// recorded is one request the fake tracker saw.
type recorded struct {
	Method, Path string // Path is the escaped path plus query
	Header       http.Header
	Body         map[string]any
}

// fakeAPI answers "METHOD /escaped/path?query" with a canned status + JSON and
// records every request.
type fakeAPI struct {
	mu        sync.Mutex
	responses map[string]string
	status    map[string]int
	got       []recorded
}

func newFake(t *testing.T, responses map[string]string) (*fakeAPI, *httptest.Server) {
	t.Helper()
	f := &fakeAPI{responses: responses, status: map[string]int{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.EscapedPath()
		if r.URL.RawQuery != "" {
			path += "?" + r.URL.RawQuery
		}
		rec := recorded{Method: r.Method, Path: path, Header: r.Header.Clone()}
		if b, _ := io.ReadAll(r.Body); len(b) > 0 {
			if err := json.Unmarshal(b, &rec.Body); err != nil {
				t.Errorf("%s %s: body is not JSON: %s", r.Method, path, b)
			}
		}
		key := r.Method + " " + path
		f.mu.Lock()
		f.got = append(f.got, rec)
		resp, ok := f.responses[key]
		code := f.status[key]
		f.mu.Unlock()
		if !ok {
			t.Errorf("unexpected request %s", key)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if code != 0 {
			w.WriteHeader(code)
		}
		_, _ = w.Write([]byte(resp))
	}))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeAPI) requests() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recorded(nil), f.got...)
}

func assertReq(t *testing.T, got recorded, method, path string, header map[string]string, body map[string]any) {
	t.Helper()
	if got.Method != method || got.Path != path {
		t.Errorf("request = %s %s, want %s %s", got.Method, got.Path, method, path)
	}
	for k, v := range header {
		if got.Header.Get(k) != v {
			t.Errorf("%s %s header %s = %q, want %q", method, path, k, got.Header.Get(k), v)
		}
	}
	if !reflect.DeepEqual(got.Body, body) {
		t.Errorf("%s %s body = %#v, want %#v", method, path, got.Body, body)
	}
}

var testIssue = Issue{Title: "[high] SQL injection", Body: "details", Labels: []string{"security", "xila"}}

func TestGitHubClient(t *testing.T) {
	ctx := context.Background()
	fake, srv := newFake(t, map[string]string{
		"POST /repos/acme/web/issues":     `{"number":42,"html_url":"https://github.com/acme/web/issues/42","state":"open"}`,
		"GET /repos/acme/web/issues/42":   `{"number":42,"state":"closed"}`,
		"PATCH /repos/acme/web/issues/42": `{"number":42}`,
		"GET /repos/acme/web":             `{"full_name":"acme/web"}`,
	})
	c, err := NewClient(Tracker{Kind: KindGitHub, BaseURL: srv.URL + "/", Target: "acme/web"}, "ghp_tok", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	ref, err := c.Create(ctx, testIssue)
	if err != nil || ref != (Ref{ExternalID: "42", URL: "https://github.com/acme/web/issues/42"}) {
		t.Fatalf("Create = %+v, %v", ref, err)
	}
	st, err := c.State(ctx, "42")
	if err != nil || st != StateClosed {
		t.Fatalf("State = %v, %v; want closed", st, err)
	}
	if err := c.Close(ctx, "42"); err != nil {
		t.Fatal(err)
	}
	if err := c.Reopen(ctx, "42"); err != nil {
		t.Fatal(err)
	}
	if err := c.Check(ctx); err != nil {
		t.Fatal(err)
	}

	auth := map[string]string{"Authorization": "Bearer ghp_tok", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
	got := fake.requests()
	if len(got) != 5 {
		t.Fatalf("requests = %d, want 5", len(got))
	}
	assertReq(t, got[0], "POST", "/repos/acme/web/issues", auth,
		map[string]any{"title": "[high] SQL injection", "body": "details", "labels": []any{"security", "xila"}})
	assertReq(t, got[1], "GET", "/repos/acme/web/issues/42", auth, nil)
	assertReq(t, got[2], "PATCH", "/repos/acme/web/issues/42", auth, map[string]any{"state": "closed", "state_reason": "completed"})
	assertReq(t, got[3], "PATCH", "/repos/acme/web/issues/42", auth, map[string]any{"state": "open"})
	assertReq(t, got[4], "GET", "/repos/acme/web", auth, nil)
}

func TestGitLabClient(t *testing.T) {
	ctx := context.Background()
	fake, srv := newFake(t, map[string]string{
		"POST /api/v4/projects/group%2Fsub%2Fweb/issues":  `{"iid":7,"web_url":"https://gitlab.com/group/sub/web/-/issues/7","state":"opened"}`,
		"GET /api/v4/projects/group%2Fsub%2Fweb/issues/7": `{"iid":7,"state":"opened"}`,
		"PUT /api/v4/projects/group%2Fsub%2Fweb/issues/7": `{"iid":7}`,
		"GET /api/v4/projects/group%2Fsub%2Fweb":          `{"id":1}`,
	})
	c, err := NewClient(Tracker{Kind: KindGitLab, BaseURL: srv.URL, Target: "group/sub/web"}, "glpat-tok", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	ref, err := c.Create(ctx, testIssue)
	if err != nil || ref != (Ref{ExternalID: "7", URL: "https://gitlab.com/group/sub/web/-/issues/7"}) {
		t.Fatalf("Create = %+v, %v", ref, err)
	}
	if st, err := c.State(ctx, "7"); err != nil || st != StateOpen {
		t.Fatalf("State = %v, %v; want open", st, err)
	}
	if err := c.Close(ctx, "7"); err != nil {
		t.Fatal(err)
	}
	if err := c.Reopen(ctx, "7"); err != nil {
		t.Fatal(err)
	}
	if err := c.Check(ctx); err != nil {
		t.Fatal(err)
	}

	auth := map[string]string{"PRIVATE-TOKEN": "glpat-tok", "Authorization": ""}
	got := fake.requests()
	if len(got) != 5 {
		t.Fatalf("requests = %d, want 5", len(got))
	}
	p := "/api/v4/projects/group%2Fsub%2Fweb"
	assertReq(t, got[0], "POST", p+"/issues", auth,
		map[string]any{"title": "[high] SQL injection", "description": "details", "labels": "security,xila"})
	assertReq(t, got[1], "GET", p+"/issues/7", auth, nil)
	assertReq(t, got[2], "PUT", p+"/issues/7", auth, map[string]any{"state_event": "close"})
	assertReq(t, got[3], "PUT", p+"/issues/7", auth, map[string]any{"state_event": "reopen"})
	assertReq(t, got[4], "GET", p, auth, nil)
}

const jiraTransitions = `{"transitions":[
	{"id":"11","name":"To Do","to":{"name":"To Do"}},
	{"id":"21","name":"Start","to":{"name":"In Progress"}},
	{"id":"31","name":"Resolve","to":{"name":"Done"}}]}`

func TestJiraClient(t *testing.T) {
	ctx := context.Background()
	fake, srv := newFake(t, map[string]string{
		"POST /rest/api/2/issue":                     `{"id":"10001","key":"SEC-12","self":"x"}`,
		"GET /rest/api/2/issue/SEC-12?fields=status": `{"fields":{"status":{"name":"Resolved","statusCategory":{"key":"done"}}}}`,
		"GET /rest/api/2/issue/SEC-12/transitions":   jiraTransitions,
		"POST /rest/api/2/issue/SEC-12/transitions":  ``,
		"GET /rest/api/2/project/SEC":                `{"key":"SEC"}`,
	})
	fake.status["POST /rest/api/2/issue/SEC-12/transitions"] = http.StatusNoContent
	tr := Tracker{Kind: KindJira, BaseURL: srv.URL, Target: "SEC", JiraEmail: "bot@acme.io",
		IssueType: "Bug", DoneTransition: "done", ReopenTransition: "To Do"}
	c, err := NewClient(tr, "jira-tok", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	ref, err := c.Create(ctx, testIssue)
	if err != nil || ref != (Ref{ExternalID: "SEC-12", URL: srv.URL + "/browse/SEC-12"}) {
		t.Fatalf("Create = %+v, %v", ref, err)
	}
	if st, err := c.State(ctx, "SEC-12"); err != nil || st != StateClosed {
		t.Fatalf("State = %v, %v; want closed", st, err)
	}
	// "done" matches the Resolve transition by its target status name.
	if err := c.Close(ctx, "SEC-12"); err != nil {
		t.Fatal(err)
	}
	if err := c.Reopen(ctx, "SEC-12"); err != nil {
		t.Fatal(err)
	}
	if err := c.Check(ctx); err != nil {
		t.Fatal(err)
	}

	// base64("bot@acme.io:jira-tok")
	auth := map[string]string{"Authorization": "Basic Ym90QGFjbWUuaW86amlyYS10b2s="}
	got := fake.requests()
	if len(got) != 7 {
		t.Fatalf("requests = %d, want 7", len(got))
	}
	assertReq(t, got[0], "POST", "/rest/api/2/issue", auth, map[string]any{"fields": map[string]any{
		"project": map[string]any{"key": "SEC"}, "summary": "[high] SQL injection", "description": "details",
		"issuetype": map[string]any{"name": "Bug"}, "labels": []any{"security", "xila"},
	}})
	assertReq(t, got[1], "GET", "/rest/api/2/issue/SEC-12?fields=status", auth, nil)
	assertReq(t, got[2], "GET", "/rest/api/2/issue/SEC-12/transitions", auth, nil)
	assertReq(t, got[3], "POST", "/rest/api/2/issue/SEC-12/transitions", auth, map[string]any{"transition": map[string]any{"id": "31"}})
	assertReq(t, got[4], "GET", "/rest/api/2/issue/SEC-12/transitions", auth, nil)
	assertReq(t, got[5], "POST", "/rest/api/2/issue/SEC-12/transitions", auth, map[string]any{"transition": map[string]any{"id": "11"}})
	assertReq(t, got[6], "GET", "/rest/api/2/project/SEC", auth, nil)
}

func TestJiraBearerAndMissingTransition(t *testing.T) {
	ctx := context.Background()
	fake, srv := newFake(t, map[string]string{
		"GET /rest/api/2/issue/SEC-1/transitions": jiraTransitions,
	})
	c, _ := NewClient(Tracker{Kind: KindJira, BaseURL: srv.URL, Target: "SEC", DoneTransition: "Close Issue"}, "pat", srv.Client())
	err := c.Close(ctx, "SEC-1")
	if err == nil || !strings.Contains(err.Error(), `no transition named "Close Issue"`) {
		t.Errorf("Close with unknown transition = %v", err)
	}
	if got := fake.requests(); len(got) != 1 || got[0].Header.Get("Authorization") != "Bearer pat" {
		t.Errorf("requests = %+v, want one GET with a Bearer PAT", got)
	}
}

// A tracker error carries the tracker's message but never the credential.
func TestClientErrorOmitsToken(t *testing.T) {
	fake, srv := newFake(t, map[string]string{"GET /repos/acme/web": `{"message":"Bad credentials"}`})
	fake.status["GET /repos/acme/web"] = http.StatusUnauthorized
	c, _ := NewClient(Tracker{Kind: KindGitHub, BaseURL: srv.URL, Target: "acme/web"}, "ghp_secret", srv.Client())
	err := c.Check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "Bad credentials") {
		t.Fatalf("Check = %v, want a 401 with the tracker's message", err)
	}
	if strings.Contains(err.Error(), "ghp_secret") {
		t.Errorf("error leaks the token: %v", err)
	}
}
