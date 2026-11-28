package connector

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

const (
	defenderRec1 = `{"id":"r1","deviceId":"d1","deviceName":"host1","osPlatform":"Windows10",
		"softwareVendor":"adobe","softwareName":"reader","softwareVersion":"21.1",
		"cveId":"CVE-2021-1111","vulnerabilitySeverityLevel":"High","exploitabilityLevel":"ExploitIsInKit",
		"recommendedSecurityUpdate":"Adobe patch APSB21-1111","securityUpdateAvailable":true}`
	// No cveId: installed-software inventory row, not a vulnerability — skipped.
	defenderRec2 = `{"id":"r2","deviceId":"d1","deviceName":"host1","softwareVendor":"microsoft","softwareName":"edge","softwareVersion":"90.0","cveId":null}`
	defenderRec3 = `{"id":"r3","deviceId":"d2","deviceName":"host2","softwareVendor":"openssl","softwareName":"openssl","softwareVersion":"1.1.1",
		"cveId":"CVE-2021-2222","vulnerabilitySeverityLevel":"Critical","cvssScore":9.1}`
)

func fakeDefender(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/oauth2/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			if r.Form.Get("client_id") != "defender-client" || r.Form.Get("client_secret") != "defender-secret" ||
				r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("resource") != "https://api.security.microsoft.com" {
				http.Error(w, `{"error":"invalid_client","error_description":"bad credentials"}`, http.StatusUnauthorized)
				return
			}
			fmt.Fprint(w, `{"access_token":"defender-access-token","token_type":"Bearer","expires_in":3600}`)
		case r.URL.Path == "/api/machines/SoftwareVulnerabilitiesByMachine":
			if r.Header.Get("Authorization") != "Bearer defender-access-token" {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, `{"error":{"code":"Unauthorized"}}`)
				return
			}
			switch {
			case r.URL.Query().Get("pageSize") == "1":
				fmt.Fprintf(w, `{"value":[%s]}`, defenderRec1)
			case r.URL.Query().Get("$skiptoken") == "p2":
				fmt.Fprintf(w, `{"value":[%s]}`, defenderRec3)
			default:
				fmt.Fprintf(w, `{"value":[%s,%s],"@odata.nextLink":"%s/api/machines/SoftwareVulnerabilitiesByMachine?pageSize=2&$skiptoken=p2"}`,
					defenderRec1, defenderRec2, srv.URL)
			}
		case r.URL.Path == "/api/machines":
			fmt.Fprint(w, `{"value":[{"id":"d1","exposureLevel":"High"},{"id":"d2","exposureLevel":"Medium"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newDefender(base string) *microsoftDefender {
	return &microsoftDefender{base: base, authURL: base + "/oauth2/token", clientID: "defender-client",
		clientSecret: "defender-secret", hc: http.DefaultClient, pageSize: 2}
}

func TestDefenderFetch(t *testing.T) {
	srv := fakeDefender(t)
	fs, err := newDefender(srv.URL).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("findings = %d, want 2 (the no-CVE row is skipped)", len(fs))
	}

	f1 := fs[0]
	if f1.RuleID != "CVE-2021-1111" || f1.Severity != domain.SeverityHigh || f1.PackageName != "reader" ||
		f1.PackageVersion != "21.1" || f1.FilePath != "host1" || len(f1.CVE) != 1 || f1.CVE[0] != "CVE-2021-1111" {
		t.Errorf("f1 = %+v", f1)
	}
	if f1.Metadata["exposure_level"] != "High" {
		t.Errorf("f1 exposure_level = %v, want High", f1.Metadata["exposure_level"])
	}
	if !strings.Contains(f1.Description, "Adobe patch APSB21-1111") {
		t.Errorf("f1 description = %q", f1.Description)
	}

	f2 := fs[1]
	if f2.Severity != domain.SeverityCritical || f2.Metadata["exposure_level"] != "Medium" {
		t.Errorf("f2 = %+v", f2)
	}

	if name, err := newDefender(srv.URL).Check(context.Background()); err != nil || name == "" {
		t.Errorf("check = %q, %v", name, err)
	}
}

func TestDefenderBadCredentials(t *testing.T) {
	srv := fakeDefender(t)
	bad := newDefender(srv.URL)
	bad.clientSecret = "wrong"
	if _, err := bad.Fetch(context.Background()); !errors.As(err, new(RemoteError)) || !strings.Contains(err.Error(), "401") {
		t.Fatalf("bad client secret err = %v, want a 401 RemoteError", err)
	}
}

func TestDefenderRateLimitOnTokenEndpoint(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	_, err := newDefender(srv.URL).Fetch(context.Background())
	var rerr RemoteError
	if !errors.As(err, &rerr) || !strings.Contains(err.Error(), "429") {
		t.Fatalf("err = %v, want a RemoteError mentioning 429", err)
	}
	if attempts != maxRateLimitRetries+1 {
		t.Fatalf("attempts = %d, want %d", attempts, maxRateLimitRetries+1)
	}
}

func TestDefenderFetchRefusesPartial(t *testing.T) {
	// The software-vulnerabilities page succeeds but the exposure (machines)
	// lookup fails: that's enrichment only, so Fetch still succeeds, just
	// without exposure_level — it never fails the whole pull.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/token":
			fmt.Fprint(w, `{"access_token":"defender-access-token"}`)
		case "/api/machines/SoftwareVulnerabilitiesByMachine":
			fmt.Fprintf(w, `{"value":[%s]}`, defenderRec1)
		case "/api/machines":
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()
	fs, err := newDefender(srv.URL).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("findings = %d, want 1", len(fs))
	}
	if _, ok := fs[0].Metadata["exposure_level"]; ok {
		t.Error("exposure_level set despite a failed machines lookup")
	}
}

func TestParseDefenderCredentials(t *testing.T) {
	if _, err := parseDefenderCredentials(`{"client_id":"a","client_secret":"b"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := parseDefenderCredentials(`{"client_id":"a"}`); !errors.As(err, new(ValidationError)) {
		t.Errorf("missing client_secret err = %v, want ValidationError", err)
	}
}
