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

// azureRec is one request a fake Azure DevOps server saw. Work item writes
// send a JSON Patch *array*, not an object, so this keeps the raw body
// instead of reusing fakeAPI's map[string]any assumption.
type azureRec struct {
	Method, Path string
	Auth         string
	Ops          []azurePatchOp
}

func newFakeAzure(t *testing.T, responses map[string]string, status map[string]int) (*[]azureRec, *httptest.Server) {
	t.Helper()
	recs := &[]azureRec{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.EscapedPath()
		if r.URL.RawQuery != "" {
			path += "?" + r.URL.RawQuery
		}
		rec := azureRec{Method: r.Method, Path: path, Auth: r.Header.Get("Authorization")}
		if b, _ := io.ReadAll(r.Body); len(b) > 0 {
			if err := json.Unmarshal(b, &rec.Ops); err != nil {
				t.Errorf("%s %s: body is not a JSON Patch array: %s", r.Method, path, b)
			}
		}
		*recs = append(*recs, rec)
		key := r.Method + " " + path
		if code, ok := status[key]; ok {
			w.WriteHeader(code)
		}
		resp, ok := responses[key]
		if !ok {
			t.Errorf("unexpected request %s", key)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(resp))
	}))
	t.Cleanup(srv.Close)
	return recs, srv
}

// Response shape from the official "Work Items - Create" example:
// https://learn.microsoft.com/en-us/rest/api/azure/devops/wit/work-items/create?view=azure-devops-rest-7.1
const azureCreateResponse = `{
  "id": 131489,
  "rev": 1,
  "fields": {
    "System.WorkItemType": "Task",
    "System.State": "New",
    "System.Title": "Sample task"
  },
  "_links": {
    "html": {
      "href": "https://dev.azure.com/fabrikam/web/wi.aspx?pcguid=20cda608-32f0-4e6e-9b7c-8def7b38d15a&id=131489"
    }
  },
  "url": "https://dev.azure.com/fabrikam/_apis/wit/workItems/131489"
}`

func TestAzureDevOpsClient(t *testing.T) {
	ctx := context.Background()
	recs, srv := newFakeAzure(t, map[string]string{
		"POST /Fabrikam/_apis/wit/workitems/$Bug?api-version=7.1":    azureCreateResponse,
		"GET /Fabrikam/_apis/wit/workitems/131489?api-version=7.1":   `{"id":131489,"fields":{"System.State":"Closed"}}`,
		"PATCH /Fabrikam/_apis/wit/workitems/131489?api-version=7.1": `{"id":131489}`,
		"GET /_apis/projects/Fabrikam?api-version=7.1":               `{"id":"abc","name":"Fabrikam"}`,
	}, nil)
	tr := Tracker{Kind: KindAzureDevOps, BaseURL: srv.URL, Target: "Fabrikam",
		IssueType: "Bug", DoneTransition: "Closed", ReopenTransition: "Active"}
	c, err := NewClient(tr, "pat-secret", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	ref, err := c.Create(ctx, testIssue)
	if err != nil || ref != (Ref{ExternalID: "131489", URL: "https://dev.azure.com/fabrikam/web/wi.aspx?pcguid=20cda608-32f0-4e6e-9b7c-8def7b38d15a&id=131489"}) {
		t.Fatalf("Create = %+v, %v", ref, err)
	}
	if st, err := c.State(ctx, "131489"); err != nil || st != StateClosed {
		t.Fatalf("State = %v, %v; want closed", st, err)
	}
	if err := c.Close(ctx, "131489"); err != nil {
		t.Fatal(err)
	}
	if err := c.Reopen(ctx, "131489"); err != nil {
		t.Fatal(err)
	}
	if err := c.Check(ctx); err != nil {
		t.Fatal(err)
	}

	got := *recs
	if len(got) != 5 {
		t.Fatalf("requests = %d, want 5", len(got))
	}
	// PATs authenticate as Basic with an empty username:
	// https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate
	wantAuth := "Basic " + "OnBhdC1zZWNyZXQ=" // base64(":pat-secret")
	for _, r := range got {
		if r.Auth != wantAuth {
			t.Errorf("%s %s: Authorization = %q, want %q", r.Method, r.Path, r.Auth, wantAuth)
		}
	}
	wantCreate := []azurePatchOp{
		{Op: "add", Path: "/fields/System.Title", Value: "[high] SQL injection"},
		{Op: "add", Path: "/fields/System.Description", Value: "details"},
		{Op: "add", Path: "/fields/System.Tags", Value: "security; xila"},
	}
	if got[0].Method != http.MethodPost || got[0].Path != "/Fabrikam/_apis/wit/workitems/$Bug?api-version=7.1" {
		t.Fatalf("request 0 = %s %s, want the create path", got[0].Method, got[0].Path)
	}
	if len(got[0].Ops) != len(wantCreate) {
		t.Fatalf("create ops = %+v, want %+v", got[0].Ops, wantCreate)
	}
	for i, op := range wantCreate {
		if got[0].Ops[i] != op {
			t.Errorf("create op[%d] = %+v, want %+v", i, got[0].Ops[i], op)
		}
	}
	if got[1].Method != http.MethodGet {
		t.Errorf("request 1 = %s, want GET", got[1].Method)
	}
	wantClose := []azurePatchOp{{Op: "add", Path: "/fields/System.State", Value: "Closed"}}
	if len(got[2].Ops) != 1 || got[2].Ops[0] != wantClose[0] {
		t.Errorf("close ops = %+v, want %+v", got[2].Ops, wantClose)
	}
	wantReopen := []azurePatchOp{{Op: "add", Path: "/fields/System.State", Value: "Active"}}
	if len(got[3].Ops) != 1 || got[3].Ops[0] != wantReopen[0] {
		t.Errorf("reopen ops = %+v, want %+v", got[3].Ops, wantReopen)
	}
	if got[4].Method != http.MethodGet || got[4].Path != "/_apis/projects/Fabrikam?api-version=7.1" {
		t.Errorf("request 4 = %s %s, want the project check", got[4].Method, got[4].Path)
	}
}

// A 401 carries Azure DevOps' own error message but never the PAT.
func TestAzureDevOpsErrorOmitsToken(t *testing.T) {
	_, srv := newFakeAzure(t,
		map[string]string{"GET /_apis/projects/Fabrikam?api-version=7.1": `{"message":"TF400813: The user is not authorized."}`},
		map[string]int{"GET /_apis/projects/Fabrikam?api-version=7.1": http.StatusUnauthorized})
	c, _ := NewClient(Tracker{Kind: KindAzureDevOps, BaseURL: srv.URL, Target: "Fabrikam"}, "pat-secret", srv.Client())
	err := c.Check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "TF400813") {
		t.Fatalf("Check = %v, want a 401 with Azure DevOps' message", err)
	}
	if strings.Contains(err.Error(), "pat-secret") {
		t.Errorf("error leaks the PAT: %v", err)
	}
}

// A 429 surfaces Retry-After so the caller can tell a throttled tracker apart
// from a broken one; Azure DevOps rate limiting:
// https://learn.microsoft.com/en-us/azure/devops/integrate/concepts/rate-limits
func TestAzureDevOpsRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)
	c, _ := NewClient(Tracker{Kind: KindAzureDevOps, BaseURL: srv.URL, Target: "Fabrikam"}, "pat", srv.Client())
	err := c.Check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "429") || !strings.Contains(err.Error(), "Retry-After: 30s") {
		t.Fatalf("Check = %v, want a 429 error mentioning Retry-After", err)
	}
}
