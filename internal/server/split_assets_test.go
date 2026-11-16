package server

import (
	"net/http"
	"os"
	"testing"

	"github.com/xilasec/xila-api/internal/pgtest"
)

// A multi-host Nessus scan uploaded with split_assets files each finding under
// its machine's host asset; a rescan reuses the assets; asset_id and
// split_assets together are refused.
func TestSplitAssetsPerHost(t *testing.T) {
	app := newTestAppOn(t, pgtest.Pool(t))
	admin := rbacUser(t, app, "admin@xila.io")
	_, o := req(t, app, http.MethodPost, "/api/v1/orgs", admin, `{"slug":"infra","name":"Infra"}`)
	_, tm := req(t, app, http.MethodPost, "/api/v1/orgs/"+o["id"].(string)+"/teams", admin, `{"slug":"ops","name":"Ops"}`)
	_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+tm["id"].(string)+"/projects", admin, `{"slug":"net","name":"net"}`)
	pid := p["id"].(string)
	// nessus_tenable.csv: 9 findings on two EC2 hosts (7 + 2).
	report, err := os.ReadFile("../scanner/testdata/nessus_tenable.csv")
	if err != nil {
		t.Fatal(err)
	}
	upload := func() {
		t.Helper()
		if resp, body := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/scans?scanner=nessus&split_assets=true&force=true", admin, string(report)); resp.StatusCode != http.StatusCreated {
			t.Fatalf("upload = %d %v", resp.StatusCode, body)
		}
	}
	upload()
	_, assets := req(t, app, http.MethodGet, "/api/v1/projects/"+pid+"/assets", admin, "")
	list, _ := assets["assets"].([]any)
	names := map[string]string{}
	for _, a := range list {
		m := a.(map[string]any)
		if m["type"] != "host" {
			t.Errorf("asset %v, want type host", m)
		}
		names[m["id"].(string)] = m["name"].(string)
	}
	if len(names) != 2 {
		t.Fatalf("host assets = %v, want the 2 scanned machines", names)
	}
	_, fl := req(t, app, http.MethodGet, "/api/v1/projects/"+pid+"/findings?limit=100", admin, "")
	perHost := map[string]int{}
	for _, f := range fl["findings"].([]any) {
		id, _ := f.(map[string]any)["asset_id"].(string)
		perHost[names[id]]++
	}
	if perHost["ip-127-0-0-1.us-west-2.compute.internal"] != 7 || perHost["ip-192-168-1-110.us-west-2.compute.internal"] != 2 {
		t.Errorf("findings per host = %v, want 7 and 2", perHost)
	}

	// A rescan reuses the same assets.
	upload()
	_, again := req(t, app, http.MethodGet, "/api/v1/projects/"+pid+"/assets", admin, "")
	if n := len(again["assets"].([]any)); n != 2 {
		t.Errorf("assets after a rescan = %d, want 2", n)
	}
	assetID := ""
	for id := range names {
		assetID = id
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/scans?scanner=nessus&split_assets=true&asset_id="+assetID, admin, string(report)); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("split_assets with asset_id = %d, want 400", resp.StatusCode)
	}
}
