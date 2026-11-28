package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPseudonymizer(t *testing.T) {
	var doc any
	if err := json.Unmarshal([]byte(`{
		"id": "9f1c2a4e-0000-4000-8000-000000000001",
		"assignee_email": "Dana@Acme.io",
		"exception_reason": "confirmed with dana@acme.io and bob@acme.io",
		"events": [
			{"kind": "status", "actor_name": "dana@acme.io"},
			{"kind": "status", "actor_name": "system"},
			{"kind": "severity", "actor": "triage-rule:mute lows"}
		],
		"comments": [{"author": "Bob Smith", "body": "ok"}],
		"project": {"name": "shop"}
	}`), &doc); err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(newPseudonymizer().value(doc))
	got := string(out)
	if strings.Contains(got, "@acme.io") || strings.Contains(got, "Bob Smith") {
		t.Fatalf("personal data left in %s", got)
	}
	for _, want := range []string{
		`"assignee_email":"person-1"`, // case-insensitive: Dana@ and dana@ are one person
		`"author":"person-2"`,
		`"actor_name":"person-1"`,
		`"actor_name":"system"`,
		`"actor":"triage-rule:mute lows"`,
		`confirmed with person-1 and person-3`,
		`"id":"9f1c2a4e-0000-4000-8000-000000000001"`,
		`"name":"shop"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("want %s in %s", want, got)
		}
	}
}
