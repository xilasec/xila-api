package issuetracker

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ServiceNow Table API, used throughout: create/read/update one table record,
// wrapped in a uniform "result" envelope:
// https://developer.servicenow.com/dev.do#!/reference/api/latest/rest/c_TableAPI
func TestServiceNowClient(t *testing.T) {
	ctx := context.Background()
	fake, srv := newFake(t, map[string]string{
		"POST /api/now/table/incident": `{"result":{"sys_id":"9d385017c611228701d22104cc95c371","number":"INC0000001","state":"1"}}`,
		"GET /api/now/table/incident/9d385017c611228701d22104cc95c371?sysparm_fields=state": `{"result":{"state":"6"}}`,
		"PATCH /api/now/table/incident/9d385017c611228701d22104cc95c371":                    `{"result":{"sys_id":"9d385017c611228701d22104cc95c371","state":"6"}}`,
		"GET /api/now/table/incident?sysparm_limit=1&sysparm_fields=sys_id":                 `{"result":[{"sys_id":"9d385017c611228701d22104cc95c371"}]}`,
	})
	tr := Tracker{Kind: KindServiceNow, BaseURL: srv.URL, Target: "incident", AuthUser: "svc_acct",
		DoneTransition: "6", ReopenTransition: "1"}
	c, err := NewClient(tr, "s3cr3t", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	ref, err := c.Create(ctx, testIssue)
	sysID := "9d385017c611228701d22104cc95c371"
	if err != nil || ref != (Ref{ExternalID: sysID, URL: srv.URL + "/incident.do?sys_id=" + sysID}) {
		t.Fatalf("Create = %+v, %v", ref, err)
	}
	if st, err := c.State(ctx, sysID); err != nil || st != StateClosed {
		t.Fatalf("State = %v, %v; want closed", st, err)
	}
	if err := c.Close(ctx, sysID); err != nil {
		t.Fatal(err)
	}
	if err := c.Reopen(ctx, sysID); err != nil {
		t.Fatal(err)
	}
	if err := c.Check(ctx); err != nil {
		t.Fatal(err)
	}

	// Basic auth is user:password, the Table API's other documented scheme
	// besides a Bearer OAuth token (see TestServiceNowBearerAuth).
	auth := map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("svc_acct:s3cr3t"))}
	got := fake.requests()
	if len(got) != 5 {
		t.Fatalf("requests = %d, want 5", len(got))
	}
	assertReq(t, got[0], "POST", "/api/now/table/incident", auth,
		map[string]any{"short_description": "[high] SQL injection", "description": "details", "work_notes": "Labels: security, xila"})
	assertReq(t, got[1], "GET", "/api/now/table/incident/"+sysID+"?sysparm_fields=state", auth, nil)
	assertReq(t, got[2], "PATCH", "/api/now/table/incident/"+sysID, auth, map[string]any{"state": "6"})
	assertReq(t, got[3], "PATCH", "/api/now/table/incident/"+sysID, auth, map[string]any{"state": "1"})
	assertReq(t, got[4], "GET", "/api/now/table/incident?sysparm_limit=1&sysparm_fields=sys_id", auth, nil)
}

// With no auth_user the stored token is sent as an OAuth Bearer access token
// instead of Basic auth, the Table API's other documented authentication mode:
// https://developer.servicenow.com/dev.do#!/reference/api/latest/rest/c_TableAPI (Authentication)
func TestServiceNowBearerAuth(t *testing.T) {
	fake, srv := newFake(t, map[string]string{
		"GET /api/now/table/incident?sysparm_limit=1&sysparm_fields=sys_id": `{"result":[]}`,
	})
	c, _ := NewClient(Tracker{Kind: KindServiceNow, BaseURL: srv.URL, Target: "incident"}, "oauth-access-tok", srv.Client())
	if err := c.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := fake.requests()
	if len(got) != 1 || got[0].Header.Get("Authorization") != "Bearer oauth-access-tok" {
		t.Errorf("requests = %+v, want one GET with a Bearer token", got)
	}
}

// A failed Table API call carries ServiceNow's own error message but never
// the credential.
func TestServiceNowErrorOmitsToken(t *testing.T) {
	fake, srv := newFake(t, map[string]string{
		"GET /api/now/table/incident?sysparm_limit=1&sysparm_fields=sys_id": `{"error":{"message":"User Not Authenticated","detail":"Required to provide Auth information"}}`,
	})
	fake.status["GET /api/now/table/incident?sysparm_limit=1&sysparm_fields=sys_id"] = http.StatusUnauthorized
	c, _ := NewClient(Tracker{Kind: KindServiceNow, BaseURL: srv.URL, Target: "incident", AuthUser: "svc"}, "s3cr3t", srv.Client())
	err := c.Check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "User Not Authenticated") {
		t.Fatalf("Check = %v, want a 401 with ServiceNow's message", err)
	}
	if strings.Contains(err.Error(), "s3cr3t") {
		t.Errorf("error leaks the token: %v", err)
	}
}

// A throttled instance answers 429 with Retry-After:
// https://support.servicenow.com/kb/kb?id=kb_article_view&sysparm_article=KB3046852
func TestServiceNowRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)
	c, _ := NewClient(Tracker{Kind: KindServiceNow, BaseURL: srv.URL, Target: "incident", AuthUser: "svc"}, "s3cr3t", srv.Client())
	err := c.Check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "429") || !strings.Contains(err.Error(), "Retry-After: 60s") {
		t.Fatalf("Check = %v, want a 429 error mentioning Retry-After", err)
	}
}
