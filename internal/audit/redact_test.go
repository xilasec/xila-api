package audit

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestRedactBody(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string // JSON
	}{
		{"login", `{"email":"a@x.io","password":"hunter22"}`, `{"email":"a@x.io","password":"[REDACTED]"}`},
		{"password change", `{"current_password":"old","new_password":"new"}`,
			`{"current_password":"[REDACTED]","new_password":"[REDACTED]"}`},
		{"mfa", `{"mfa_token":"eyJ.x.y","code":"123456"}`, `{"mfa_token":"[REDACTED]","code":"[REDACTED]"}`},
		{"recovery code", `{"recovery_code":"abcd-efgh"}`, `{"recovery_code":"[REDACTED]"}`},
		{"password reset", `{"token":"rst","password":"newpass1"}`, `{"token":"[REDACTED]","password":"[REDACTED]"}`},
		{"oidc provider", `{"name":"Okta","client_id":"cid","client_secret":"shh","issuer":"https://okta"}`,
			`{"name":"Okta","client_id":"cid","client_secret":"[REDACTED]","issuer":"https://okta"}`},
		{"saml sp key", `{"sp_key":"-----BEGIN","sp_cert":"-----BEGIN","idp_metadata_url":"https://idp/md"}`,
			`{"sp_key":"[REDACTED]","sp_cert":"[REDACTED]","idp_metadata_url":"https://idp/md"}`},
		{"webhook channel", `{"name":"ops","type":"slack","url":"https://hooks.slack.com/T/B/secret","events":["*"]}`,
			`{"name":"ops","type":"slack","url":"[REDACTED]","events":["*"]}`},
		{"tracker token", `{"kind":"jira","base_url":"https://jira","token":"t0k","key":"SEC"}`,
			`{"kind":"jira","base_url":"https://jira","token":"[REDACTED]","key":"[REDACTED]"}`},
		{"connector api key", `{"api_key":"k","X-Api-Key":"k2"}`, `{"api_key":"[REDACTED]","X-Api-Key":"[REDACTED]"}`},
		{"nested and arrays", `{"config":{"bind_password":"p","host":"ldap"},"items":[{"secret":"s","n":1}]}`,
			`{"config":{"bind_password":"[REDACTED]","host":"ldap"},"items":[{"secret":"[REDACTED]","n":1}]}`},
		{"metadata about secrets is kept", `{"has_token":true,"has_client_secret":false,"password_changed_at":"2026-01-01"}`,
			`{"has_token":true,"has_client_secret":false,"password_changed_at":"2026-01-01"}`},
		{"ordinary fields untouched", `{"status":"risk_accepted","reason":"vendor fix due","severity":"high"}`,
			`{"status":"risk_accepted","reason":"vendor fix due","severity":"high"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RedactBody([]byte(tc.body), "application/json")
			var want any
			if err := json.Unmarshal([]byte(tc.want), &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("RedactBody(%s)\n got %v\nwant %v", tc.body, got, want)
			}
		})
	}
}

// A body that isn't JSON, or is too big, is described, never copied: a raw
// report or form post could hold anything.
func TestRedactBodyNeverCopiesOpaqueBodies(t *testing.T) {
	form := "SAMLResponse=PHNhbWw%3D&RelayState=x"
	got, _ := RedactBody([]byte(form), "application/x-www-form-urlencoded").(map[string]any)
	if got["bytes"] != len(form) || got["content_type"] != "application/x-www-form-urlencoded" {
		t.Errorf("form body = %v, want only its type and size", got)
	}
	big := `{"password":"p","pad":"` + strings.Repeat("a", maxBodyBytes) + `"}`
	if out, _ := json.Marshal(RedactBody([]byte(big), "application/json")); strings.Contains(string(out), `"p"`) || strings.Contains(string(out), "aaaa") {
		t.Errorf("oversized body kept content: %.80s", out)
	}
	if RedactBody(nil, "") != nil {
		t.Error("empty body should record nothing")
	}
}

// Handler-supplied before/after state goes through the same key policy.
func TestRedactAnyStructs(t *testing.T) {
	type tracker struct {
		BaseURL string `json:"base_url"`
		Token   string `json:"token"`
	}
	got := redactAny(tracker{BaseURL: "https://jira", Token: "secret-token"})
	want := map[string]any{"base_url": "https://jira", "token": Redacted}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("redactAny = %v, want %v", got, want)
	}
}

func TestDescribe(t *testing.T) {
	split := func(s string) []string { return apiSegments("/api/v1" + s) }
	cases := []struct {
		method, tmpl, path string
		action, rtype, rid string
	}{
		{"POST", "/teams/:teamID/projects", "/teams/t1/projects", "teams.projects.create", "projects", ""},
		{"PATCH", "/projects/:projectID", "/projects/p1", "projects.update", "projects", "p1"},
		{"DELETE", "/projects/:projectID/members/:userID", "/projects/p1/members/u1", "projects.members.delete", "members", "u1"},
		{"POST", "/users/:userID/deactivate", "/users/u1/deactivate", "users.deactivate", "users", "u1"},
		{"PUT", "/projects/:projectID/sla", "/projects/p1/sla", "projects.sla.update", "projects", "p1"},
		{"POST", "/users", "/users", "users.create", "users", ""},
		{"POST", "/retention/run", "/retention/run", "retention.run", "retention", ""},
		{"POST", "/me/password", "/me/password", "me.password", "me", ""},
		{"POST", "/findings/bulk", "/findings/bulk", "findings.bulk", "findings", ""},
	}
	for _, tc := range cases {
		a, rt, id := Describe(tc.method, split(tc.tmpl), split(tc.path))
		if a != tc.action || rt != tc.rtype || id != tc.rid {
			t.Errorf("%s %s = (%q, %q, %q), want (%q, %q, %q)", tc.method, tc.tmpl, a, rt, id, tc.action, tc.rtype, tc.rid)
		}
	}
}
