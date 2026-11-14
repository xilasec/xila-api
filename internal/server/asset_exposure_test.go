package server

import (
	"net/http"
	"os"
	"slices"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// assetFindings returns the asset's findings keyed by rule id.
func assetFindings(t *testing.T, app *fiber.App, token, assetID string) map[string]map[string]any {
	t.Helper()
	resp, body := req(t, app, http.MethodGet, "/api/v1/assets/"+assetID+"/findings", token, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("asset findings = %d %v", resp.StatusCode, body)
	}
	out := map[string]map[string]any{}
	items, _ := body["findings"].([]any)
	for _, it := range items {
		f := it.(map[string]any)
		out[f["rule_id"].(string)] = f
	}
	return out
}

// Exposure end to end: a real Prowler report with a public bucket infers
// internet on the scanned asset and on the asset registered for the bucket;
// the findings carry it and their priority rises 1.25×. A manual assessment
// wins over inference, isolated discounts, and clearing it never discounts.
func TestAssetExposure(t *testing.T) {
	app := newTestApp(t)
	lead := rbacUser(t, app, "lead@xila.io")
	viewer := rbacUser(t, app, "viewer@xila.io")

	_, org := req(t, app, http.MethodPost, "/api/v1/orgs", lead, `{"slug":"acme","name":"Acme"}`)
	_, team := req(t, app, http.MethodPost, "/api/v1/orgs/"+org["id"].(string)+"/teams", lead, `{"slug":"cloud","name":"Cloud"}`)
	_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+team["id"].(string)+"/projects", lead, `{"slug":"aws","name":"aws"}`)
	pid := p["id"].(string)
	req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/members", lead, `{"email":"viewer@xila.io","role":"viewer"}`)

	_, account := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/assets", lead,
		`{"type":"cloud_resource","name":"aws account","identifier":"REDACTED_ACCOUNT_ID"}`)
	_, bucket := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/assets", lead,
		`{"type":"cloud_resource","name":"exposed bucket","identifier":"arn:aws:s3:::agentic-lab-exposed-bucket-53a94e59"}`)
	accountID, bucketID := account["id"].(string), bucket["id"].(string)
	if account["exposure"] != nil || account["exposure_source"] != nil {
		t.Fatalf("a new asset's exposure = %v/%v, want unknown", account["exposure"], account["exposure_source"])
	}

	report, err := os.ReadFile("../asset/testdata/prowler_v3_public_bucket.json")
	if err != nil {
		t.Fatal(err)
	}
	upload := func() {
		t.Helper()
		if resp, body := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/scans?scanner=prowler&asset_id="+accountID,
			lead, string(report)); resp.StatusCode != http.StatusCreated {
			t.Fatalf("upload prowler = %d %v", resp.StatusCode, body)
		}
	}
	upload()

	_, acc := req(t, app, http.MethodGet, "/api/v1/assets/"+accountID, viewer, "")
	if acc["exposure"] != "internet" || acc["exposure_source"] != "inferred" || acc["exposure_reason"] == "" {
		t.Errorf("scanned account after a public-bucket finding = %v/%v %q, want internet/inferred with a reason",
			acc["exposure"], acc["exposure_source"], acc["exposure_reason"])
	}
	_, bkt := req(t, app, http.MethodGet, "/api/v1/assets/"+bucketID, viewer, "")
	if bkt["exposure"] != "internet" || bkt["exposure_reason"] !=
		"prowler s3_bucket_public_access failed on arn:aws:s3:::agentic-lab-exposed-bucket-53a94e59: the resource is publicly exposed" {
		t.Errorf("the bucket's own asset = %v %q", bkt["exposure"], bkt["exposure_reason"])
	}

	// Prowler's critical public-bucket finding: 15 × 1.25; the medium EBS one 3 × 1.25.
	fs := assetFindings(t, app, viewer, accountID)
	public, ebs := fs["s3_bucket_public_access"], fs["ec2_ebs_default_encryption"]
	if public == nil || ebs == nil {
		t.Fatalf("findings on the account = %v", fs)
	}
	if public["asset_exposure"] != "internet" || public["priority"] != 18.75 || ebs["priority"] != 3.75 {
		t.Errorf("internet-facing priorities = %v (%v), %v; want 18.75 and 3.75",
			public["priority"], public["asset_exposure"], ebs["priority"])
	}

	// Viewers read exposure; only editors set it.
	if resp, _ := req(t, app, http.MethodPut, "/api/v1/assets/"+accountID+"/exposure", viewer, `{"exposure":"isolated"}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer setting exposure = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPut, "/api/v1/assets/"+accountID+"/exposure", lead, `{"exposure":"dmz"}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown exposure value = %d, want 400", resp.StatusCode)
	}

	// A manual assessment wins — and a re-scan's evidence doesn't overwrite it.
	resp, set := req(t, app, http.MethodPut, "/api/v1/assets/"+accountID+"/exposure", lead,
		`{"exposure":"isolated","reason":"sandbox account, no IGW"}`)
	if resp.StatusCode != http.StatusOK || set["exposure"] != "isolated" || set["exposure_source"] != "manual" ||
		set["exposure_reason"] != "sandbox account, no IGW" {
		t.Fatalf("manual exposure = %d %v", resp.StatusCode, set)
	}
	upload()
	fs = assetFindings(t, app, viewer, accountID)
	if p := fs["s3_bucket_public_access"]; p["asset_exposure"] != "isolated" || p["priority"] != 11.25 { // 15 × 0.75
		t.Errorf("isolated after a re-scan = %v %v, want isolated 11.25 (manual wins)", p["asset_exposure"], p["priority"])
	}

	// Clearing goes back to unknown, which never discounts: the base weight.
	_, cleared := req(t, app, http.MethodPut, "/api/v1/assets/"+accountID+"/exposure", lead, `{"exposure":""}`)
	if cleared["exposure"] != nil || cleared["exposure_source"] != nil || cleared["exposure_reason"] != "" {
		t.Errorf("cleared exposure = %v", cleared)
	}
	fs = assetFindings(t, app, viewer, accountID)
	if p := fs["s3_bucket_public_access"]; p["asset_exposure"] != nil || p["priority"] != 15.0 {
		t.Errorf("unknown exposure = %v %v, want nil 15", p["asset_exposure"], p["priority"])
	}
	// …and open to inference again.
	upload()
	if _, acc := req(t, app, http.MethodGet, "/api/v1/assets/"+accountID, viewer, ""); acc["exposure"] != "internet" {
		t.Errorf("re-inferred exposure = %v, want internet", acc["exposure"])
	}
}

// Relations and blast radius across projects, with RBAC: a base image in a
// platform project, an app image built from it in another project, deployed as
// a workload in a third; an image in a project the developer can't see is built
// from the same base and must never surface to them.
func TestAssetBlastRadius(t *testing.T) {
	app := newTestApp(t)
	lead := rbacUser(t, app, "lead@xila.io")
	dev := rbacUser(t, app, "dev@xila.io")

	_, org := req(t, app, http.MethodPost, "/api/v1/orgs", lead, `{"slug":"acme","name":"Acme"}`)
	_, team := req(t, app, http.MethodPost, "/api/v1/orgs/"+org["id"].(string)+"/teams", lead, `{"slug":"eng","name":"Eng"}`)
	project := func(slug string, devRole string) string {
		t.Helper()
		_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+team["id"].(string)+"/projects", lead, `{"slug":"`+slug+`","name":"`+slug+`"}`)
		if devRole != "" {
			req(t, app, http.MethodPost, "/api/v1/projects/"+p["id"].(string)+"/members", lead, `{"email":"dev@xila.io","role":"`+devRole+`"}`)
		}
		return p["id"].(string)
	}
	assetIn := func(pid, typ, name string) string {
		t.Helper()
		resp, a := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/assets", lead,
			`{"type":"`+typ+`","name":"`+name+`","identifier":"`+name+`"}`)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create asset %s = %d %v", name, resp.StatusCode, a)
		}
		// Each image ships the same vulnerable package (CVE-2020-1 in pkgA).
		req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/scans?scanner=trivy&asset_id="+a["id"].(string), lead, smokeTrivyReport)
		return a["id"].(string)
	}
	base := assetIn(project("platform", "viewer"), "container_image", "debian:12")
	appImg := assetIn(project("shop", "editor"), "container_image", "shop:1.4")
	workload := assetIn(project("shop-deploy", "viewer"), "kubernetes", "prod/shop")
	hidden := assetIn(project("secret", ""), "container_image", "secret:2.0")

	relate := func(token, path, from, to, kind string) (*http.Response, map[string]any) {
		t.Helper()
		return req(t, app, http.MethodPost, "/api/v1/assets/"+path+"/relations", token,
			`{"from_asset_id":"`+from+`","to_asset_id":"`+to+`","kind":"`+kind+`"}`)
	}
	// The developer edits shop: it can record that shop is built from the base
	// it can see, and is deployed as the workload it can see.
	if resp, b := relate(dev, appImg, appImg, base, "built_from"); resp.StatusCode != http.StatusCreated {
		t.Fatalf("built_from = %d %v", resp.StatusCode, b)
	}
	if resp, b := relate(dev, appImg, appImg, workload, "deployed_as"); resp.StatusCode != http.StatusCreated {
		t.Fatalf("deployed_as = %d %v", resp.StatusCode, b)
	}
	if resp, _ := relate(dev, appImg, appImg, base, "built_from"); resp.StatusCode != http.StatusConflict {
		t.Errorf("duplicate relation = %d, want 409", resp.StatusCode)
	}
	if resp, _ := relate(dev, appImg, appImg, appImg, "built_from"); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("self relation = %d, want 400", resp.StatusCode)
	}
	if resp, _ := relate(dev, appImg, base, workload, "built_from"); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("relation not touching the path asset = %d, want 400", resp.StatusCode)
	}
	// Viewer on the base's project: no edits from that side.
	if resp, _ := relate(dev, base, appImg, base, "built_from"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer relating from the base = %d, want 403", resp.StatusCode)
	}
	// An asset in a project the developer can't see is indistinguishable from a missing one.
	if resp, _ := relate(dev, appImg, appImg, hidden, "depends_on"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("relating to an invisible asset = %d, want 404", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/assets/"+hidden, dev, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("reading an invisible asset = %d, want 403", resp.StatusCode)
	}
	// The lead sees everything and links the hidden image to the same base.
	if resp, b := relate(lead, hidden, hidden, base, "built_from"); resp.StatusCode != http.StatusCreated {
		t.Fatalf("lead built_from = %d %v", resp.StatusCode, b)
	}

	// Relations list: the developer sees its two edges, never the hidden one.
	_, rels := req(t, app, http.MethodGet, "/api/v1/assets/"+base+"/relations", dev, "")
	if items, _ := rels["relations"].([]any); len(items) != 1 {
		t.Errorf("dev's relations of the base = %v, want only shop's built_from", rels["relations"])
	}
	_, rels = req(t, app, http.MethodGet, "/api/v1/assets/"+base+"/relations", lead, "")
	if items, _ := rels["relations"].([]any); len(items) != 2 {
		t.Errorf("lead's relations of the base = %v, want shop's and secret's", rels["relations"])
	}

	type hit struct {
		depth  float64
		via    string
		shared float64
	}
	blast := func(token string) map[string]hit {
		t.Helper()
		resp, body := req(t, app, http.MethodGet, "/api/v1/assets/"+base+"/blast-radius", token, "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("blast radius = %d %v", resp.StatusCode, body)
		}
		out := map[string]hit{}
		for _, it := range body["affected"].([]any) {
			e := it.(map[string]any)
			a := e["asset"].(map[string]any)
			out[a["id"].(string)] = hit{e["depth"].(float64), e["via"].(string), e["shared_count"].(float64)}
			for _, f := range e["shared_findings"].([]any) {
				if cves := f.(map[string]any)["cve"].([]any); !slices.Contains(cves, any("CVE-2020-1")) {
					t.Errorf("shared finding without the base's CVE: %v", f)
				}
			}
		}
		return out
	}
	// The 3-asset chain: base ← shop (built_from, depth 1) → prod/shop
	// (deployed_as, depth 2), each with the one CVE finding it shares (the
	// secret finding on each image has no CVE or package, so it is not inherited).
	got := blast(dev)
	want := map[string]hit{appImg: {1, "built_from", 1}, workload: {2, "deployed_as", 1}}
	if len(got) != len(want) || got[appImg] != want[appImg] || got[workload] != want[workload] {
		t.Errorf("dev's blast radius = %+v, want %+v (and never the hidden image)", got, want)
	}
	if got := blast(lead); len(got) != 3 || got[hidden] != (hit{1, "built_from", 1}) {
		t.Errorf("lead's blast radius = %+v, want the hidden image too", got)
	}
	// Nothing is built from the workload: an empty list, not null.
	if _, body := req(t, app, http.MethodGet, "/api/v1/assets/"+workload+"/blast-radius", dev, ""); body["affected"] == nil {
		t.Errorf("empty blast radius = %v, want []", body)
	}

	// Removing the build edge shrinks the radius to nothing.
	_, rels = req(t, app, http.MethodGet, "/api/v1/assets/"+appImg+"/relations", dev, "")
	var builtFrom string
	for _, it := range rels["relations"].([]any) {
		if r := it.(map[string]any); r["kind"] == "built_from" {
			builtFrom = r["id"].(string)
		}
	}
	if resp, _ := req(t, app, http.MethodDelete, "/api/v1/assets/"+workload+"/relations/"+builtFrom, lead, ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("deleting through an asset the edge doesn't touch = %d, want 404", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodDelete, "/api/v1/assets/"+appImg+"/relations/"+builtFrom, dev, ""); resp.StatusCode != http.StatusNoContent {
		t.Errorf("delete relation = %d, want 204", resp.StatusCode)
	}
	if got := blast(dev); len(got) != 0 {
		t.Errorf("blast radius after unlinking = %+v, want empty", got)
	}
}
