package issuetracker

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/finding"
)

func sign(secret, body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	return hex.EncodeToString(mac.Sum(nil))
}

func headers(h map[string]string) func(string) string {
	return func(k string) string { return h[k] }
}

func TestVerifyWebhook(t *testing.T) {
	const secret, body = "s3cret", `{"a":1}`
	basic := func(pass string) string { return "Basic " + base64.StdEncoding.EncodeToString([]byte("xila:"+pass)) }
	tests := []struct {
		kind      Kind
		good, bad map[string]string
	}{
		{KindGitHub, map[string]string{"X-Hub-Signature-256": "sha256=" + sign(secret, body)},
			map[string]string{"X-Hub-Signature-256": "sha256=" + sign("other", body)}},
		{KindJira, map[string]string{"X-Hub-Signature": "sha256=" + sign(secret, body)},
			map[string]string{"X-Hub-Signature": sign(secret, body)}}, // no method prefix
		{KindLinear, map[string]string{"Linear-Signature": sign(secret, body)},
			map[string]string{"Linear-Signature": sign(secret, body+" ")}},
		{KindGitLab, map[string]string{"X-Gitlab-Token": secret}, map[string]string{"X-Gitlab-Token": "s3cre"}},
		{KindAzureDevOps, map[string]string{"Authorization": basic(secret)}, map[string]string{"Authorization": basic("nope")}},
		{KindServiceNow, map[string]string{"Authorization": "Bearer " + secret}, map[string]string{"Authorization": secret}},
	}
	for _, tt := range tests {
		if err := VerifyWebhook(tt.kind, headers(tt.good), []byte(body), secret); err != nil {
			t.Errorf("%s: genuine delivery refused: %v", tt.kind, err)
		}
		if err := VerifyWebhook(tt.kind, headers(tt.bad), []byte(body), secret); !errors.Is(err, ErrWebhookAuth) {
			t.Errorf("%s: forged delivery accepted", tt.kind)
		}
		if err := VerifyWebhook(tt.kind, headers(tt.good), []byte(body), ""); !errors.Is(err, ErrWebhookAuth) {
			t.Errorf("%s: accepted with no secret configured", tt.kind)
		}
	}
}

func TestParseWebhook(t *testing.T) {
	now := time.UnixMilli(1676056940508)
	ts := strconv.FormatInt(now.UnixMilli(), 10)
	comment := func(id, author, body string) *RemoteComment {
		return &RemoteComment{ID: id, Author: author, Body: body}
	}
	tests := []struct {
		name    string
		kind    Kind
		event   string // the event header, where the tracker has one
		body    string
		want    WebhookEvent
		ignored bool
	}{
		{"github issue closed", KindGitHub, "issues", `{"action":"closed","issue":{"number":42}}`, WebhookEvent{ExternalID: "42"}, false},
		{"github comment", KindGitHub, "issue_comment", `{"action":"created","issue":{"number":42},"comment":{"id":7,"body":"hi","user":{"login":"octocat"}}}`,
			WebhookEvent{ExternalID: "42", Comment: comment("7", "octocat", "hi")}, false},
		{"github edited comment", KindGitHub, "issue_comment", `{"action":"edited","issue":{"number":42},"comment":{"id":7}}`, WebhookEvent{}, true},
		{"github pull request comment", KindGitHub, "issue_comment", `{"action":"created","issue":{"number":42,"pull_request":{}},"comment":{"id":7}}`, WebhookEvent{}, true},
		{"github ping", KindGitHub, "ping", `{"zen":"..."}`, WebhookEvent{}, true},
		{"gitlab issue", KindGitLab, "Issue Hook", `{"object_attributes":{"iid":7,"action":"close"}}`, WebhookEvent{ExternalID: "7"}, false},
		{"gitlab note", KindGitLab, "Note Hook", `{"object_attributes":{"id":99,"note":"done","noteable_type":"Issue"},"issue":{"iid":7},"user":{"name":"Ada"}}`,
			WebhookEvent{ExternalID: "7", Comment: comment("99", "Ada", "done")}, false},
		{"gitlab merge request note", KindGitLab, "Note Hook", `{"object_attributes":{"id":99,"noteable_type":"MergeRequest"}}`, WebhookEvent{}, true},
		{"jira updated", KindJira, "", `{"webhookEvent":"jira:issue_updated","issue":{"key":"SEC-12"}}`, WebhookEvent{ExternalID: "SEC-12"}, false},
		{"jira comment", KindJira, "", `{"webhookEvent":"comment_created","issue":{"key":"SEC-12"},"comment":{"id":"10001","body":"ok","author":{"displayName":"Dana"}}}`,
			WebhookEvent{ExternalID: "SEC-12", Comment: comment("10001", "Dana", "ok")}, false},
		{"jira other", KindJira, "", `{"webhookEvent":"jira:issue_deleted","issue":{"key":"SEC-12"}}`, WebhookEvent{}, true},
		{"azure updated", KindAzureDevOps, "", `{"eventType":"workitem.updated","resource":{"workItemId":131489}}`, WebhookEvent{ExternalID: "131489"}, false},
		{"azure comment", KindAzureDevOps, "", `{"eventType":"workitem.commented","resource":{"id":131489,"rev":5,"fields":{"System.History":"<div>Patched <b>today</b></div>","System.ChangedBy":"Jamal Hartnett <jamal@fabrikam.com>"}}}`,
			WebhookEvent{ExternalID: "131489", Comment: comment("rev-5", "Jamal Hartnett", "Patched today")}, false},
		{"linear issue", KindLinear, "", `{"action":"update","type":"Issue","url":"https://linear.app/acme/issue/ENG-123/fix-it","webhookTimestamp":` + ts + `}`,
			WebhookEvent{ExternalID: "ENG-123"}, false},
		{"linear comment", KindLinear, "", `{"action":"create","type":"Comment","actor":{"name":"Linear Orbit"},"data":{"id":"c-1","body":"Indeed"},"url":"https://linear.app/issue/LIN-1778/foo-bar#comment-77217de3","webhookTimestamp":` + ts + `}`,
			WebhookEvent{ExternalID: "LIN-1778", Comment: comment("c-1", "Linear Orbit", "Indeed")}, false},
		{"linear project", KindLinear, "", `{"action":"update","type":"Project","url":"https://linear.app/acme/project/x","webhookTimestamp":` + ts + `}`, WebhookEvent{}, true},
		{"servicenow change", KindServiceNow, "", `{"sys_id":"abc"}`, WebhookEvent{ExternalID: "abc"}, false},
		{"servicenow note", KindServiceNow, "", `{"sys_id":"abc","comment":{"id":"j1","author":"Sam","body":"Done"}}`,
			WebhookEvent{ExternalID: "abc", Comment: comment("j1", "Sam", "Done")}, false},
	}
	for _, tt := range tests {
		h := headers(map[string]string{"X-GitHub-Event": tt.event, "X-Gitlab-Event": tt.event})
		got, ok, err := ParseWebhook(tt.kind, h, []byte(tt.body), now)
		if err != nil {
			t.Errorf("%s: %v", tt.name, err)
			continue
		}
		if ok == tt.ignored {
			t.Errorf("%s: ok = %v, want %v", tt.name, ok, !tt.ignored)
			continue
		}
		if g, w := mustJSON(got), mustJSON(tt.want); ok && g != w {
			t.Errorf("%s: got %s, want %s", tt.name, g, w)
		}
	}

	// A Linear delivery outside the replay window is refused.
	stale := `{"action":"update","type":"Issue","url":"https://linear.app/issue/ENG-1/x","webhookTimestamp":` + ts + `}`
	if _, _, err := ParseWebhook(KindLinear, headers(nil), []byte(stale), now.Add(10*time.Minute)); !errors.Is(err, ErrWebhookAuth) {
		t.Errorf("stale linear delivery: err = %v, want ErrWebhookAuth", err)
	}
	if _, _, err := ParseWebhook(KindJira, headers(nil), []byte(`not json`), now); !errors.Is(err, ErrWebhookPayload) {
		t.Errorf("garbage payload: err = %v, want ErrWebhookPayload", err)
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// Each tracker's Comment call reaches its documented endpoint and reads back
// the comment id.
func TestClientComment(t *testing.T) {
	tests := []struct {
		tracker    Tracker
		externalID string
		wantMethod string
		wantPath   string
		wantField  string // the request body field carrying the text
		reply      string
		wantID     string
	}{
		{Tracker{Kind: KindGitHub, Target: "acme/web"}, "42", http.MethodPost, "/repos/acme/web/issues/42/comments", "body", `{"id":7}`, "7"},
		{Tracker{Kind: KindGitLab, Target: "acme/web"}, "7", http.MethodPost, "/api/v4/projects/acme%2Fweb/issues/7/notes", "body", `{"id":99}`, "99"},
		{Tracker{Kind: KindJira, Target: "SEC"}, "SEC-12", http.MethodPost, "/rest/api/2/issue/SEC-12/comment", "body", `{"id":"10001"}`, "10001"},
		{Tracker{Kind: KindAzureDevOps, Target: "Fabrikam"}, "131489", http.MethodPost, "/Fabrikam/_apis/wit/workItems/131489/comments", "text", `{"id":3}`, "3"},
		{Tracker{Kind: KindServiceNow, Target: "incident"}, "abc", http.MethodPatch, "/api/now/table/incident/abc", "work_notes", `{"result":{}}`, ""},
		{Tracker{Kind: KindLinear, Target: "ENG"}, "ENG-123", http.MethodPost, "/graphql", "", `{"data":{"commentCreate":{"success":true,"comment":{"id":"c-9"}}}}`, "c-9"},
	}
	for _, tt := range tests {
		var method, path string
		var body map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			method, path = r.Method, r.URL.EscapedPath()
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &body)
			_, _ = w.Write([]byte(tt.reply))
		}))
		tr := tt.tracker
		tr.BaseURL = srv.URL
		c, err := NewClient(tr, "tok", srv.Client())
		if err != nil {
			t.Fatal(err)
		}
		id, err := c.Comment(context.Background(), tt.externalID, "Patched")
		srv.Close()
		if err != nil {
			t.Errorf("%s: %v", tt.tracker.Kind, err)
			continue
		}
		text := body[tt.wantField]
		if tt.wantField == "" { // GraphQL: the text is a variable
			text = body["variables"].(map[string]any)["body"]
		}
		if method != tt.wantMethod || path != tt.wantPath || text != "Patched" || id != tt.wantID {
			t.Errorf("%s: %s %s text=%v id=%q; want %s %s, id %q", tt.tracker.Kind, method, path, text, id, tt.wantMethod, tt.wantPath, tt.wantID)
		}
	}
}

// A template is checked on save, and one that still fails on a real finding
// files the built-in ticket rather than none.
func TestIssueTemplates(t *testing.T) {
	for _, src := range []string{"{{.Nope}}", "{{", `{{range $i := .CVEs}}{{end}}{{template "x"}}`, strings.Repeat("x", maxTemplate+1)} {
		if err := checkTemplates(Tracker{BodyTemplate: src}); err == nil {
			t.Errorf("template %.30q accepted", src)
		}
	}
	s := &Service{publicURL: "https://xila.example"}
	f := finding.Finding{ID: "f-1", Title: "Prototype pollution", Severity: "high", Scanner: "trivy", CVE: []string{"CVE-1", "CVE-2"}}
	got := s.issueFor(context.Background(), Tracker{
		TitleTemplate: "[{{.Severity}}]\n  {{.Title}} ({{join .CVEs \", \"}})",
		BodyTemplate:  "{{.Default}}Link: {{.XilaURL}}",
	}, f)
	if got.Title != "[high] Prototype pollution (CVE-1, CVE-2)" {
		t.Errorf("title = %q", got.Title)
	}
	if !strings.HasPrefix(got.Body, BuildIssue(f, nil, s.publicURL).Body) || !strings.HasSuffix(got.Body, "Link: https://xila.example/findings/f-1") {
		t.Errorf("body = %q", got.Body)
	}
	// Grows past the render cap on this finding: the built-in body is filed.
	huge := finding.Finding{ID: "f-2", Title: "t", Severity: "low", Description: strings.Repeat("d", maxRendered)}
	if got := s.issueFor(context.Background(), Tracker{BodyTemplate: "{{.Description}}{{.Description}}"}, huge); got.Body != BuildIssue(huge, nil, s.publicURL).Body {
		t.Errorf("an oversized render was not replaced by the built-in body")
	}
}
