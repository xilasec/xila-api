package issuetracker

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// serviceNowClient speaks the ServiceNow Table API:
// https://developer.servicenow.com/dev.do#!/reference/api/latest/rest/c_TableAPI
// BaseURL is the instance root (e.g. https://your-instance.service-now.com);
// target is the table name (default "incident", see Service.Normalize).
// Records are identified by their sys_id. There is no open/closed flag: a
// table-specific state value (done/reopen, numeric ServiceNow state codes as
// strings, e.g. incident's "6" Resolved / "1" New) is compared and written
// directly on the "state" field, the same approach the Table API examples
// use for every table-specific choice list.
type serviceNowClient struct {
	api
	table  string
	done   string
	reopen string
}

// serviceNowAuth sends HTTP Basic auth (user/password) when a user is given,
// else the token as a Bearer OAuth access token — the Table API's two
// documented authentication modes:
// https://developer.servicenow.com/dev.do#!/reference/api/latest/rest/c_TableAPI (Authentication)
func serviceNowAuth(user, token string) func(*http.Request) {
	if user == "" {
		return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }
	}
	enc := base64.StdEncoding.EncodeToString([]byte(user + ":" + token))
	return func(r *http.Request) { r.Header.Set("Authorization", "Basic "+enc) }
}

func (c *serviceNowClient) tablePath(suffix string) string {
	return "/api/now/table/" + url.PathEscape(c.table) + suffix
}

// snResult is the Table API's uniform envelope: every response wraps its
// payload in "result" (an object for a single record, an array for a list).
type snResult struct {
	Result struct {
		SysID string `json:"sys_id"`
		State string `json:"state"`
	} `json:"result"`
}

func (c *serviceNowClient) Create(ctx context.Context, is Issue) (Ref, error) {
	body := map[string]any{"short_description": truncateRunes(is.Title, 160), "description": is.Body}
	if len(is.Labels) > 0 {
		// Most tables have no native tag field; folding labels into the work
		// notes keeps them visible without requiring a custom field to exist.
		body["work_notes"] = "Labels: " + strings.Join(is.Labels, ", ")
	}
	var out snResult
	if err := c.do(ctx, http.MethodPost, c.tablePath(""), body, &out); err != nil {
		return Ref{}, err
	}
	if out.Result.SysID == "" {
		return Ref{}, fmt.Errorf("servicenow: create returned no sys_id")
	}
	return Ref{ExternalID: out.Result.SysID, URL: c.recordURL(out.Result.SysID)}, nil
}

// recordURL builds the standard ServiceNow record view link
// (<instance>/<table>.do?sys_id=<id>), the form every table opens to.
func (c *serviceNowClient) recordURL(sysID string) string {
	return c.base + "/" + url.PathEscape(c.table) + ".do?sys_id=" + url.QueryEscape(sysID)
}

func (c *serviceNowClient) State(ctx context.Context, sysID string) (State, error) {
	var out snResult
	if err := c.do(ctx, http.MethodGet, c.tablePath("/"+url.PathEscape(sysID))+"?sysparm_fields=state", nil, &out); err != nil {
		return "", err
	}
	if out.Result.State == c.done {
		return StateClosed, nil
	}
	return StateOpen, nil
}

func (c *serviceNowClient) setState(ctx context.Context, sysID, state string) error {
	return c.do(ctx, http.MethodPatch, c.tablePath("/"+url.PathEscape(sysID)), map[string]string{"state": state}, nil)
}

func (c *serviceNowClient) Close(ctx context.Context, sysID string) error {
	return c.setState(ctx, sysID, c.done)
}

func (c *serviceNowClient) Reopen(ctx context.Context, sysID string) error {
	return c.setState(ctx, sysID, c.reopen)
}

// Check lists one record from the table — the cheapest call that proves the
// table exists and the credentials can read it.
func (c *serviceNowClient) Check(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, c.tablePath("")+"?sysparm_limit=1&sysparm_fields=sys_id", nil, nil)
}

// truncateRunes keeps s within n runes, matching maxTitle's "…" convention.
func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
