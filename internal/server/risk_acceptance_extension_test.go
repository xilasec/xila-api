package server

import (
	"net/http"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/config"
	"github.com/xilasec/xila-api/internal/pgtest"
)

// extensionFixture is a project with an owner, a second owner and an editor,
// and an approved acceptance of one finding expiring in 10 days.
type extensionFixture struct {
	app                   *fiber.App
	owner, second, editor string
	base                  string // the acceptance's URL
	fid                   string
	expires               time.Time
}

func newExtensionFixture(t *testing.T, fourEyes bool) extensionFixture {
	t.Helper()
	app := newTestAppOn(t, pgtest.Pool(t), func(c *config.Config) { c.RiskAcceptanceRequiresApproval = fourEyes })
	rbacUser(t, app, "founder@xila.io")
	fx := extensionFixture{app: app, owner: rbacUser(t, app, "lead@xila.io"), second: rbacUser(t, app, "second@xila.io"),
		editor: rbacUser(t, app, "editor@xila.io")}
	_, org := req(t, app, http.MethodPost, "/api/v1/orgs", fx.owner, `{"slug":"acme","name":"Acme"}`)
	_, team := req(t, app, http.MethodPost, "/api/v1/orgs/"+org["id"].(string)+"/teams", fx.owner, `{"slug":"core","name":"Core"}`)
	_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+team["id"].(string)+"/projects", fx.owner, `{"slug":"web","name":"web"}`)
	pid := p["id"].(string)
	for email, role := range map[string]string{"second@xila.io": "owner", "editor@xila.io": "editor"} {
		req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/members", fx.owner, `{"email":"`+email+`","role":"`+role+`"}`)
	}
	req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/scans?scanner=trivy", fx.owner, smokeTrivyReport)
	fx.fid = projectFindingIDs(t, app, fx.owner, pid)[0]
	fx.expires = time.Now().Add(10 * 24 * time.Hour).UTC().Truncate(time.Second)
	_, created := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/risk-acceptances", fx.editor,
		`{"title":"WAF covers it","justification":"virtual patch","expires_at":"`+fx.expires.Format(time.RFC3339)+`","finding_ids":["`+fx.fid+`"]}`)
	aid := created["risk_acceptance"].(map[string]any)["id"].(string)
	fx.base = "/api/v1/projects/" + pid + "/risk-acceptances/" + aid
	if resp, body := req(t, app, http.MethodPost, fx.base+"/approve", fx.owner, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("approve = %d %v", resp.StatusCode, body)
	}
	return fx
}

func (fx extensionFixture) extend(t *testing.T, token string, to time.Time, reason string) (*http.Response, map[string]any) {
	t.Helper()
	return req(t, fx.app, http.MethodPost, fx.base+"/extend", token, `{"expires_at":"`+to.Format(time.RFC3339)+`","reason":"`+reason+`"}`)
}

func (fx extensionFixture) acceptance(t *testing.T, token string) (map[string]any, []any) {
	t.Helper()
	_, out := req(t, fx.app, http.MethodGet, fx.base, token, "")
	exts, _ := out["extensions"].([]any)
	return out["risk_acceptance"].(map[string]any), exts
}

func expiry(t *testing.T, ra map[string]any) time.Time {
	t.Helper()
	at, err := time.Parse(time.RFC3339, ra["expires_at"].(string))
	if err != nil {
		t.Fatal(err)
	}
	return at.UTC()
}

// M13 follow-up (#2): an approved acceptance is extended, never revoked and
// re-requested (which would reopen its findings in between).
func TestRiskAcceptanceExtension(t *testing.T) {
	fx := newExtensionFixture(t, false)
	later := fx.expires.Add(30 * 24 * time.Hour)

	// An approved acceptance's expiry no longer changes by editing it.
	if resp, _ := req(t, fx.app, http.MethodPatch, fx.base, fx.owner, `{"expires_at":"`+later.Format(time.RFC3339)+`"}`); resp.StatusCode != http.StatusConflict {
		t.Errorf("PATCH on an approved acceptance = %d, want 409", resp.StatusCode)
	}
	if resp, _ := fx.extend(t, fx.editor, later, ""); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("extension without a reason = %d, want 400", resp.StatusCode)
	}
	if resp, _ := fx.extend(t, fx.editor, fx.expires.Add(-time.Hour), "earlier"); resp.StatusCode != http.StatusConflict {
		t.Errorf("an extension to an earlier date = %d, want 409", resp.StatusCode)
	}

	// The editor's extension waits; the acceptance stays active on its expiry.
	resp, out := fx.extend(t, fx.editor, later, "vendor fix slipped to next quarter")
	if resp.StatusCode != http.StatusAccepted || out["extension"].(map[string]any)["state"] != "pending" {
		t.Fatalf("editor's extension = %d %v, want 202 pending", resp.StatusCode, out)
	}
	ra, _ := fx.acceptance(t, fx.owner)
	if ra["state"] != "approved" || !expiry(t, ra).Equal(fx.expires) || ra["pending_extension"] == nil || ra["can_decide_extension"] != true {
		t.Fatalf("acceptance with a pending extension = %v", ra)
	}
	if resp, _ := fx.extend(t, fx.editor, later.Add(time.Hour), "again"); resp.StatusCode != http.StatusConflict {
		t.Errorf("a second pending extension = %d, want 409", resp.StatusCode)
	}
	if _, f := req(t, fx.app, http.MethodGet, "/api/v1/findings/"+fx.fid, fx.owner, ""); f["status"] != "risk_accepted" {
		t.Errorf("finding while the extension waits = %v, want still risk_accepted", f["status"])
	}
	// It is in the owner's approval queue.
	_, q := req(t, fx.app, http.MethodGet, "/api/v1/risk-acceptances?actionable=true", fx.second, "")
	if items := q["risk_acceptances"].([]any); len(items) != 1 {
		t.Errorf("actionable queue = %d items, want the acceptance with the pending extension", len(items))
	}
	// An editor can't decide it; an owner can.
	ext := ra["pending_extension"].(map[string]any)["id"].(string)
	if resp, _ := req(t, fx.app, http.MethodPost, fx.base+"/extensions/"+ext+"/approve", fx.editor, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("editor approving an extension = %d, want 403", resp.StatusCode)
	}
	if resp, body := req(t, fx.app, http.MethodPost, fx.base+"/extensions/"+ext+"/approve", fx.owner, `{"note":"ok"}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("owner approving = %d %v", resp.StatusCode, body)
	}
	ra, exts := fx.acceptance(t, fx.owner)
	if !expiry(t, ra).Equal(later) || ra["pending_extension"] != nil || len(exts) != 1 || exts[0].(map[string]any)["state"] != "approved" {
		t.Fatalf("after approval = expiry %v, pending %v, history %v", ra["expires_at"], ra["pending_extension"], exts)
	}

	// An owner's own extension applies at once.
	further := later.Add(30 * 24 * time.Hour)
	if resp, out := fx.extend(t, fx.owner, further, "still waiting on the vendor"); resp.StatusCode != http.StatusOK ||
		!expiry(t, out["risk_acceptance"].(map[string]any)).Equal(further) {
		t.Fatalf("owner's extension = %d %v, want applied", resp.StatusCode, out)
	}

	// Ending the acceptance withdraws a pending extension.
	fx.extend(t, fx.editor, further.Add(time.Hour), "one more")
	req(t, fx.app, http.MethodPost, fx.base+"/revoke", fx.owner, "")
	_, exts = fx.acceptance(t, fx.owner)
	if last := exts[len(exts)-1].(map[string]any); last["state"] != "withdrawn" {
		t.Errorf("pending extension after revoke = %v, want withdrawn", last["state"])
	}
}

// With four-eyes, an owner's extension waits for another owner, who can't be
// the one who asked.
func TestRiskAcceptanceExtensionFourEyes(t *testing.T) {
	fx := newExtensionFixture(t, true)
	later := fx.expires.Add(30 * 24 * time.Hour)
	resp, out := fx.extend(t, fx.owner, later, "vendor fix slipped")
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("owner's extension under four-eyes = %d %v, want 202", resp.StatusCode, out)
	}
	ext := out["extension"].(map[string]any)["id"].(string)
	if resp, _ := req(t, fx.app, http.MethodPost, fx.base+"/extensions/"+ext+"/approve", fx.owner, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("approving one's own extension = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, fx.app, http.MethodPost, fx.base+"/extensions/"+ext+"/reject", fx.second, `{"note":"fix it instead"}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("second owner rejecting = %d", resp.StatusCode)
	}
	if ra, _ := fx.acceptance(t, fx.owner); !expiry(t, ra).Equal(fx.expires) {
		t.Errorf("expiry after a rejected extension = %v, want unchanged %v", ra["expires_at"], fx.expires)
	}
}
