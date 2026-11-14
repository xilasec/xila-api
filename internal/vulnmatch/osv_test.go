package vulnmatch

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

// mockOSV serves the two endpoints we use: batch detection + advisory detail.
func mockOSV(t *testing.T, detailHits *int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Queries []struct {
				Package struct {
					Purl string `json:"purl"`
				} `json:"package"`
			} `json:"queries"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		// Results are positional: log4j is affected, everything else is clean.
		results := make([]map[string]any, len(req.Queries))
		for i, q := range req.Queries {
			if strings.Contains(q.Package.Purl, "log4j") {
				results[i] = map[string]any{"vulns": []map[string]string{{"id": "GHSA-jfh8"}}}
			} else {
				results[i] = map[string]any{}
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	})
	mux.HandleFunc("/v1/vulns/GHSA-jfh8", func(w http.ResponseWriter, _ *http.Request) {
		*detailHits++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":                "GHSA-jfh8",
			"aliases":           []string{"CVE-2021-44228"},
			"summary":           "Log4Shell RCE",
			"details":           "remote code execution",
			"database_specific": map[string]string{"severity": "CRITICAL"},
			"affected": []map[string]any{{
				"ranges": []map[string]any{{
					"events": []map[string]string{{"introduced": "0"}, {"fixed": "2.15.0"}},
				}},
			}},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestOSVSourceQuery(t *testing.T) {
	hits := 0
	srv := mockOSV(t, &hits)
	src := NewOSVSource(srv.URL)

	// Two components share the same advisory; a third is clean.
	purls := []string{
		"pkg:maven/log4j-core@2.14.1",
		"pkg:maven/log4j-api@2.14.1",
		"pkg:npm/lodash@4.17.21",
	}
	got, err := src.Query(context.Background(), purls)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("affected purls = %d, want 2 (both log4j, not lodash)", len(got))
	}
	if _, clean := got["pkg:npm/lodash@4.17.21"]; clean {
		t.Error("lodash should have no advisories")
	}

	v := got["pkg:maven/log4j-core@2.14.1"][0]
	if v.ID != "GHSA-jfh8" || v.Severity != domain.SeverityCritical {
		t.Errorf("vuln = %+v, want the critical GHSA", v)
	}
	if len(v.CVEs) != 1 || v.CVEs[0] != "CVE-2021-44228" || v.Fixed != "2.15.0" {
		t.Errorf("vuln = %+v, want CVE-2021-44228 fixed in 2.15.0", v)
	}
	// The advisory is fetched once and reused across components (call-count control).
	if hits != 1 {
		t.Errorf("advisory detail fetched %d times, want 1 (cached across components)", hits)
	}
}
