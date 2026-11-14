package xila

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

// The generated client must build requests the API understands (method, path,
// query, auth header) and decode the documented JSON response.
func TestClientRoundTrip(t *testing.T) {
	const projectID = "af938283-73e9-4d55-ba64-07a1658d69ce"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/projects/"+projectID+"/findings" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.URL.Query().Get("limit"); got != "5" {
			t.Errorf("limit = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"findings":[{"id":"0b0fe659-1ddf-44c3-97d5-0cd06376d4eb","title":"CVE-2021-44228 in log4j-core","severity":"critical"}],"pagination":{"limit":5,"offset":0,"count":1,"has_more":false}}`))
	}))
	defer srv.Close()

	c, err := NewClientWithResponses(srv.URL+"/api/v1", WithRequestEditorFn(func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer tok")
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	limit := 5
	res, err := c.ListProjectFindingsWithResponse(context.Background(), uuid.MustParse(projectID), &ListProjectFindingsParams{Limit: &limit})
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode() != http.StatusOK || res.JSON200 == nil {
		t.Fatalf("status %d, JSON200 %v, body %s", res.StatusCode(), res.JSON200, res.Body)
	}
	if res.JSON200.Findings == nil || len(*res.JSON200.Findings) != 1 {
		t.Fatalf("findings = %+v", res.JSON200.Findings)
	}
}
