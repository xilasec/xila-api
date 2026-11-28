package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/config"
)

// evidenceSBOM is formatted on purpose (indentation, key order): the original
// must come back byte for byte, not re-serialized.
const evidenceSBOM = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {"component": {"bom-ref": "app", "type": "application", "name": "shop", "version": "3.1.0"}},
  "components": [
    {"bom-ref": "pkg:npm/lodash@4.17.21", "type": "library", "name": "lodash", "version": "4.17.21",
     "purl": "pkg:npm/lodash@4.17.21", "licenses": [{"license": {"id": "MIT"}}],
     "copyright": "Copyright OpenJS Foundation and other contributors",
     "externalReferences": [{"type": "website", "url": "https://lodash.com/"}]},
    {"bom-ref": "pkg:npm/left-pad@1.3.0", "type": "library", "name": "left-pad", "version": "1.3.0",
     "purl": "pkg:npm/left-pad@1.3.0"}
  ]
}
`

func evidenceProject(t *testing.T, app *fiber.App) (token, pid string) {
	t.Helper()
	token = rbacUser(t, app, "evidence@xila.io")
	_, org := req(t, app, http.MethodPost, "/api/v1/orgs", token, `{"slug":"acme","name":"Acme"}`)
	_, team := req(t, app, http.MethodPost, "/api/v1/orgs/"+org["id"].(string)+"/teams", token, `{"slug":"core","name":"Core"}`)
	_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+team["id"].(string)+"/projects", token, `{"slug":"shop","name":"shop"}`)
	return token, p["id"].(string)
}

// M14 follow-up (#3, #4): the SBOM as uploaded is evidence: kept byte for
// byte with its digest; components carry the copyright and homepage the
// document states, the notices file lists them with what their licenses
// require, and the license API carries those terms.
func TestSBOMEvidence(t *testing.T) {
	app := newTestApp(t)
	token, pid := evidenceProject(t, app)
	resp, up := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/sboms", token, evidenceSBOM)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload = %d %v", resp.StatusCode, up)
	}
	sum := sha256.Sum256([]byte(evidenceSBOM))
	if up["original_sha256"] != hex.EncodeToString(sum[:]) || up["original_size"] != float64(len(evidenceSBOM)) ||
		up["original_stored"] != true || up["original_media_type"] != "application/vnd.cyclonedx+json" {
		t.Fatalf("uploaded snapshot = %v", up)
	}
	sid := up["id"].(string)

	resp, body := rawGet(t, app, "/api/v1/sboms/"+sid+"/original", token)
	if resp.StatusCode != http.StatusOK || string(body) != evidenceSBOM {
		t.Fatalf("original = %d, identical %v", resp.StatusCode, string(body) == evidenceSBOM)
	}
	if got, want := resp.Header.Get("Repr-Digest"), "sha-256=:"+base64.StdEncoding.EncodeToString(sum[:])+":"; got != want {
		t.Errorf("Repr-Digest = %q, want %q", got, want)
	}
	if ct, cd := resp.Header.Get("Content-Type"), resp.Header.Get("Content-Disposition"); ct != "application/vnd.cyclonedx+json" || !strings.Contains(cd, `filename="shop-3.1.0.cdx.json"`) {
		t.Errorf("headers = %q / %q", ct, cd)
	}
	// Another tenant can't read it.
	if resp, _ := rawGet(t, app, "/api/v1/sboms/"+sid+"/original", rbacUser(t, app, "outsider@xila.io")); resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusNotFound {
		t.Errorf("outsider = %d, want 403/404", resp.StatusCode)
	}

	_, comps := req(t, app, http.MethodGet, "/api/v1/sboms/"+sid+"/components", token, "")
	var lodash map[string]any
	for _, c := range comps["components"].([]any) {
		if c.(map[string]any)["name"] == "lodash" {
			lodash = c.(map[string]any)
		}
	}
	if lodash["copyright"] != "Copyright OpenJS Foundation and other contributors" || lodash["homepage"] != "https://lodash.com/" {
		t.Errorf("lodash = copyright %v, homepage %v", lodash["copyright"], lodash["homepage"])
	}

	resp, notices := rawGet(t, app, "/api/v1/projects/"+pid+"/notices", token)
	for _, want := range []string{
		"## lodash 4.17.21", "- License: MIT", "- Copyright: Copyright OpenJS Foundation and other contributors",
		"- Homepage: <https://lodash.com/>", "## left-pad 1.3.0\n\n- Package: `pkg:npm/left-pad@1.3.0`\n- License: not stated",
		"- MIT: include-copyright",
	} {
		if !strings.Contains(string(notices), want) {
			t.Errorf("notices (%d) lack %q:\n%s", resp.StatusCode, want, notices)
		}
	}

	_, mit := req(t, app, http.MethodGet, "/api/v1/licenses/MIT", token, "")
	terms, _ := mit["terms"].(map[string]any)
	if conds, _ := terms["conditions"].([]any); len(conds) != 1 || conds[0] != "include-copyright" {
		t.Errorf("MIT terms = %v", mit["terms"])
	}
}

// With SBOM_KEEP_ORIGINAL=false the digest is still recorded, the bytes aren't.
func TestSBOMOriginalNotKept(t *testing.T) {
	app := newTestApp(t, func(c *config.Config) { c.SBOMKeepOriginal = false })
	token, pid := evidenceProject(t, app)
	_, up := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/sboms", token, evidenceSBOM)
	if up["original_stored"] != false || up["original_sha256"] == "" {
		t.Fatalf("snapshot = %v, want a digest but no stored original", up)
	}
	if resp, body := rawGet(t, app, "/api/v1/sboms/"+up["id"].(string)+"/original", token); resp.StatusCode != http.StatusNotFound {
		t.Errorf("original not kept = %d %s, want 404", resp.StatusCode, body)
	}
}
