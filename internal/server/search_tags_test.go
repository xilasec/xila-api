package server

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"testing"
)

const searchTrivyReport = `{"Results":[
  {"Target":"pom.xml","Class":"lang-pkgs","Type":"pom","Vulnerabilities":[
    {"VulnerabilityID":"CVE-2021-44228","PkgName":"org.apache.logging.log4j:log4j-core","InstalledVersion":"2.14.1","FixedVersion":"2.15.0","Severity":"CRITICAL","Title":"Remote code execution in Log4j JNDI lookups","Description":"Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints."},
    {"VulnerabilityID":"CVE-2022-22965","PkgName":"org.springframework:spring-beans","InstalledVersion":"5.3.17","FixedVersion":"5.3.18","Severity":"CRITICAL","Title":"Spring4Shell data binding RCE","Description":"A Spring MVC application on JDK 9+ may be vulnerable to remote code execution via data binding."}]},
  {"Target":"package-lock.json","Class":"lang-pkgs","Type":"npm","Vulnerabilities":[
    {"VulnerabilityID":"CVE-2021-23337","PkgName":"lodash","InstalledVersion":"4.17.20","FixedVersion":"4.17.21","Severity":"HIGH","Title":"Command injection in lodash template","Description":"Lodash versions prior to 4.17.21 are vulnerable to Command Injection via the template function."}]}
]}`

func findingIDs(t *testing.T, body map[string]any) []string {
	t.Helper()
	fs, _ := body["findings"].([]any)
	out := []string{}
	for _, f := range fs {
		out = append(out, f.(map[string]any)["rule_id"].(string))
	}
	return out
}

// Full-text search finds findings by what people type — a CVE id, a package,
// a word from the description — and tags label findings, filter them, show
// up in history, and stay within what the caller may see.
func TestFindingSearchAndTags(t *testing.T) {
	app := newTestApp(t)
	rbacUser(t, app, "founder@xila.io")
	lead := rbacUser(t, app, "lead@xila.io")
	outsider := rbacUser(t, app, "outsider@xila.io")
	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", lead, `{"slug":"acme","name":"Acme"}`)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgBody["id"].(string)+"/teams", lead, `{"slug":"core","name":"Core"}`)
	_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+teamBody["id"].(string)+"/projects", lead, `{"slug":"web","name":"web"}`)
	projectID := p["id"].(string)
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+projectID+"/scans?scanner=trivy", lead, searchTrivyReport); resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload = %d", resp.StatusCode)
	}
	search := func(q string) []string {
		t.Helper()
		resp, body := req(t, app, http.MethodGet, "/api/v1/findings?q="+url.QueryEscape(q), lead, "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("search %q = %d %v", q, resp.StatusCode, body)
		}
		return findingIDs(t, body)
	}
	for q, want := range map[string][]string{
		"CVE-2021-44228":           {"CVE-2021-44228"},
		"lodash":                   {"CVE-2021-23337"},
		"spring4shell":             {"CVE-2022-22965"},
		"jndi ldap":                {"CVE-2021-44228"},                   // words from the description, any order
		`"via data binding"`:       {"CVE-2022-22965"},                   // a phrase
		"remote -spring":           {"CVE-2021-44228"},                   // exclusion
		"lodash or log4j-core":     {"CVE-2021-44228", "CVE-2021-23337"}, // either
		"nothing-matches-this-xyz": {},
	} {
		got := search(q)
		slices.Sort(got)
		w := slices.Clone(want)
		slices.Sort(w)
		if !slices.Equal(got, w) {
			t.Errorf("search %q = %v, want %v", q, got, w)
		}
	}

	// Tag one finding, then filter by tag.
	_, list := req(t, app, http.MethodGet, "/api/v1/findings?q=log4j", lead, "")
	log4j := list["findings"].([]any)[0].(map[string]any)["id"].(string)
	resp, f := req(t, app, http.MethodPut, "/api/v1/findings/"+log4j+"/tags", lead, `{"tags":[" PCI ","internet-facing","pci"]}`)
	if resp.StatusCode != http.StatusOK || fmt.Sprint(f["tags"]) != "[internet-facing pci]" {
		t.Fatalf("set tags = %d %v, want normalized [internet-facing pci]", resp.StatusCode, f["tags"])
	}
	if resp, _ := req(t, app, http.MethodPut, "/api/v1/findings/"+log4j+"/tags", lead, `{"tags":["no spaces allowed"]}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid tag = %d, want 400", resp.StatusCode)
	}
	if _, body := req(t, app, http.MethodGet, "/api/v1/findings?tag=pci", lead, ""); !slices.Equal(findingIDs(t, body), []string{"CVE-2021-44228"}) {
		t.Errorf("tag=pci = %v", findingIDs(t, body))
	}
	// Tags are searchable too, and several tags must all match.
	if got := search("internet-facing"); !slices.Equal(got, []string{"CVE-2021-44228"}) {
		t.Errorf("search by tag = %v", got)
	}
	if _, body := req(t, app, http.MethodGet, "/api/v1/findings?tag=pci,sprint-9", lead, ""); len(findingIDs(t, body)) != 0 {
		t.Errorf("tag=pci,sprint-9 matched %v; every tag must match", findingIDs(t, body))
	}

	// Bulk: tag everything critical, untag pci — one request, by filter.
	resp, out := req(t, app, http.MethodPost, "/api/v1/findings/bulk", lead,
		`{"filter":{"severity":"critical"},"add_tags":["sprint-9"],"remove_tags":["pci"]}`)
	if resp.StatusCode != http.StatusOK || len(out["updated"].([]any)) != 2 {
		t.Fatalf("bulk tags = %d %v", resp.StatusCode, out)
	}
	if _, body := req(t, app, http.MethodGet, "/api/v1/findings?tag=sprint-9", lead, ""); len(findingIDs(t, body)) != 2 {
		t.Errorf("after bulk, tag=sprint-9 = %v, want both criticals", findingIDs(t, body))
	}
	_, f = req(t, app, http.MethodGet, "/api/v1/findings/"+log4j, lead, "")
	if fmt.Sprint(f["tags"]) != "[internet-facing sprint-9]" {
		t.Errorf("log4j tags after bulk = %v", f["tags"])
	}

	// The change is in the finding's history, attributed.
	_, hist := req(t, app, http.MethodGet, "/api/v1/findings/"+log4j+"/history", lead, "")
	var sawTags bool
	for _, e := range hist["events"].([]any) {
		ev := e.(map[string]any)
		if ev["kind"] == "tags" && ev["from"] == "internet-facing, pci" && ev["to"] == "internet-facing, sprint-9" && ev["actor_name"] == "lead@xila.io" {
			sawTags = true
		}
	}
	if !sawTags {
		t.Errorf("history lacks the attributed tag change: %v", hist["events"])
	}

	// The tag list counts open findings, and only within the caller's projects.
	_, tags := req(t, app, http.MethodGet, "/api/v1/findings/tags", lead, "")
	if fmt.Sprint(tags["tags"]) != "[map[count:2 tag:sprint-9] map[count:1 tag:internet-facing]]" {
		t.Errorf("tags = %v", tags["tags"])
	}
	if _, tags := req(t, app, http.MethodGet, "/api/v1/findings/tags", outsider, ""); len(tags["tags"].([]any)) != 0 {
		t.Errorf("an outsider sees tags from a project they can't open: %v", tags["tags"])
	}
	if _, body := req(t, app, http.MethodGet, "/api/v1/findings?q=log4j", outsider, ""); len(findingIDs(t, body)) != 0 {
		t.Errorf("an outsider's search returned %v", findingIDs(t, body))
	}
	if resp, body := req(t, app, http.MethodPut, "/api/v1/findings/"+log4j+"/tags", outsider, `{"tags":["x"]}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("outsider tagging = %d %v, want 403", resp.StatusCode, body)
	}
	if _, f := req(t, app, http.MethodGet, "/api/v1/findings/"+log4j, lead, ""); fmt.Sprint(f["tags"]) != "[internet-facing sprint-9]" {
		t.Errorf("an outsider changed the tags: %v", f["tags"])
	}
}
