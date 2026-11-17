package issuetracker

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// linearRec is one GraphQL request a fake Linear server saw. Every Linear
// operation shares the single /graphql endpoint, so (unlike the REST
// trackers) routing is by matching a substring of the query text rather than
// by method+path: https://linear.app/developers/graphql
type linearRec struct {
	Query string
	Vars  map[string]any
	Auth  string
}

// newFakeLinear dispatches each request to the first route whose match string
// appears in the query. route order matters (first match wins).
func newFakeLinear(t *testing.T, routes []struct{ match, body string }) (*[]linearRec, *httptest.Server) {
	t.Helper()
	recs := &[]linearRec{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/graphql" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var body struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		b, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(b, &body); err != nil {
			t.Fatalf("body is not JSON: %s", b)
		}
		*recs = append(*recs, linearRec{Query: body.Query, Vars: body.Variables, Auth: r.Header.Get("Authorization")})
		for _, rt := range routes {
			if strings.Contains(body.Query, rt.match) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(rt.body))
				return
			}
		}
		t.Fatalf("unexpected graphql query: %s", body.Query)
	}))
	t.Cleanup(srv.Close)
	return recs, srv
}

// Response shapes follow Linear's own issueCreate / find-workflow-state
// examples: https://linear.app/developers/graphql#creating--editing-issues
// https://github.com/linear/linear-solutions/blob/main/integration_guides/scenarios/01-create-issue-with-labels/using-graphql.ts
func TestLinearClient(t *testing.T) {
	ctx := context.Background()
	recs, srv := newFakeLinear(t, []struct{ match, body string }{
		{"issueCreate", `{"data":{"issueCreate":{"success":true,"issue":{"identifier":"ENG-123","url":"https://linear.app/acme/issue/ENG-123/sql-injection"}}}}`},
		{"issue(id: $id)", `{"data":{"issue":{"state":{"type":"completed"}}}}`},
		{"workflowStates", `{"data":{"workflowStates":{"nodes":[{"id":"state-done","type":"completed"},{"id":"state-todo","type":"unstarted"}]}}}`},
		{"issueUpdate", `{"data":{"issueUpdate":{"success":true}}}`},
		{"team(id: $teamId)", `{"data":{"team":{"id":"team-eng"}}}`},
	})
	tr := Tracker{Kind: KindLinear, BaseURL: srv.URL, Target: "team-eng", DoneTransition: "completed", ReopenTransition: "unstarted"}
	c, err := NewClient(tr, "lin_api_secret", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	ref, err := c.Create(ctx, testIssue)
	if err != nil || ref != (Ref{ExternalID: "ENG-123", URL: "https://linear.app/acme/issue/ENG-123/sql-injection"}) {
		t.Fatalf("Create = %+v, %v", ref, err)
	}
	if st, err := c.State(ctx, "ENG-123"); err != nil || st != StateClosed {
		t.Fatalf("State = %v, %v; want closed", st, err)
	}
	if err := c.Close(ctx, "ENG-123"); err != nil {
		t.Fatal(err)
	}
	if err := c.Reopen(ctx, "ENG-123"); err != nil {
		t.Fatal(err)
	}
	if err := c.Check(ctx); err != nil {
		t.Fatal(err)
	}

	got := *recs
	if len(got) != 7 { // create, state, close(workflowStates+issueUpdate), reopen(workflowStates+issueUpdate), check
		t.Fatalf("requests = %d, want 7", len(got))
	}
	// A personal API key is sent as-is, with no "Bearer" prefix (that prefix
	// is for OAuth2 access tokens instead): https://linear.app/developers/graphql#authentication
	for _, r := range got {
		if r.Auth != "lin_api_secret" {
			t.Errorf("Authorization = %q, want the raw API key", r.Auth)
		}
	}
	wantCreateVars := map[string]any{"input": map[string]any{"teamId": "team-eng", "title": "[high] SQL injection", "description": "details"}}
	if got[0].Vars["input"] == nil {
		t.Fatalf("create vars = %+v", got[0].Vars)
	}
	gotInput, _ := json.Marshal(got[0].Vars)
	wantInput, _ := json.Marshal(wantCreateVars)
	if string(gotInput) != string(wantInput) {
		t.Errorf("create vars = %s, want %s", gotInput, wantInput)
	}
	if got[2].Vars["teamId"] != "team-eng" {
		t.Errorf("close workflowStates vars = %+v, want teamId team-eng", got[2].Vars)
	}
	if got[3].Vars["id"] != "ENG-123" || got[3].Vars["input"].(map[string]any)["stateId"] != "state-done" {
		t.Errorf("close issueUpdate vars = %+v", got[3].Vars)
	}
	if got[5].Vars["id"] != "ENG-123" || got[5].Vars["input"].(map[string]any)["stateId"] != "state-todo" {
		t.Errorf("reopen issueUpdate vars = %+v", got[5].Vars)
	}
}

// A GraphQL-level failure is returned with HTTP 200 and an "errors" array:
// https://linear.app/developers/graphql#error-handling
func TestLinearGraphQLError(t *testing.T) {
	_, srv := newFakeLinear(t, []struct{ match, body string }{
		{"team(id: $teamId)", `{"data":null,"errors":[{"message":"Entity not found: Team"}]}`},
	})
	c, _ := NewClient(Tracker{Kind: KindLinear, BaseURL: srv.URL, Target: "bad-team"}, "lin_api_secret", srv.Client())
	err := c.Check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "Entity not found: Team") {
		t.Fatalf("Check = %v, want the GraphQL error message", err)
	}
}

// A missing workflow state of the configured type is a clear error, not a
// silent no-op.
func TestLinearUnknownWorkflowStateType(t *testing.T) {
	_, srv := newFakeLinear(t, []struct{ match, body string }{
		{"workflowStates", `{"data":{"workflowStates":{"nodes":[{"id":"s1","type":"started"}]}}}`},
	})
	c, _ := NewClient(Tracker{Kind: KindLinear, BaseURL: srv.URL, Target: "team-eng", DoneTransition: "completed"}, "tok", srv.Client())
	err := c.Close(context.Background(), "ENG-1")
	if err == nil || !strings.Contains(err.Error(), `no workflow state of type "completed"`) {
		t.Errorf("Close with missing state type = %v", err)
	}
}

// Linear rate-limits with a 429 and Retry-After, same as every other tracked
// surfaces through RemoteError: https://linear.app/developers/rate-limiting
func TestLinearRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)
	c, _ := NewClient(Tracker{Kind: KindLinear, BaseURL: srv.URL, Target: "team-eng"}, "tok", srv.Client())
	err := c.Check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "429") || !strings.Contains(err.Error(), "Retry-After: 5s") {
		t.Fatalf("Check = %v, want a 429 error mentioning Retry-After", err)
	}
}
