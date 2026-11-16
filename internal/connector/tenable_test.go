package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/domain"
)

const tenableExportUUID = "1d896500-2f92-467c-aa4d-6fe8d007b127"

// tenableChunk0/1 are shaped like the real chunk-download example in
// Tenable's "Download vulnerabilities chunk" reference.
var tenableChunk0 = `[
	{"asset": {"hostname": "sharepoint2016", "fqdn": "sharepoint2016.target.example.com", "ipv4": "203.0.113.71"},
	 "plugin": {"id": 156641, "name": "Security Updates for Microsoft SharePoint Server 2016",
	            "synopsis": "The host is missing security updates.", "description": "Missing patches.",
	            "solution": "Install KB5002113.", "cvss3_base_score": 8.8, "cvss_base_score": 9,
	            "risk_factor": "high", "cve": ["CVE-2022-21837", "CVE-2022-21840"]},
	 "port": {"port": 445, "protocol": "TCP", "service": "cifs"},
	 "severity": "high", "state": "OPEN", "finding_id": "02716af9-1adb-4057-b4d5-dcb0c36b290c",
	 "severity_modification_type": "NONE"}
]`
var tenableChunk1 = `[
	{"asset": {"hostname": "db01", "ipv4": "203.0.113.72"},
	 "plugin": {"id": 99001, "name": "Outdated TLS configuration", "synopsis": "Weak TLS in use.",
	            "description": "The server supports TLS 1.0.", "solution": "Disable TLS 1.0.",
	            "cvss_base_score": 5.3, "risk_factor": "medium", "cve": []},
	 "port": {"port": 443, "protocol": "TCP", "service": "https"},
	 "severity": "medium", "state": "OPEN", "finding_id": "aa11bb22-cc33-dd44-ee55-ff6677889900",
	 "severity_modification_type": "ACCEPTED"}
]`

func fakeTenable(t *testing.T, statusSequence []string, chunks map[int]string) *httptest.Server {
	t.Helper()
	statusCall := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-ApiKeys") != "accessKey=tio-access;secretKey=tio-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"statusCode":401,"error":"Unauthorized","message":"Invalid credentials."}`)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/networks":
			fmt.Fprint(w, `{"networks":[{"name":"Default"}]}`)
		case r.Method == http.MethodPost && r.URL.Path == "/vulns/export":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			filters, _ := body["filters"].(map[string]any)
			if filters == nil || fmt.Sprint(filters["state"]) != "[OPEN REOPENED]" {
				http.Error(w, "bad filters", http.StatusBadRequest)
				return
			}
			fmt.Fprintf(w, `{"export_uuid":"%s"}`, tenableExportUUID)
		case r.Method == http.MethodGet && r.URL.Path == "/vulns/export/"+tenableExportUUID+"/status":
			status := statusSequence[min(statusCall, len(statusSequence)-1)]
			statusCall++
			fmt.Fprintf(w, `{"uuid":"%s","status":"%s","chunks_available":[0,1],"total_chunks":2}`, tenableExportUUID, status)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/vulns/export/"+tenableExportUUID+"/chunks/"):
			id := strings.TrimPrefix(r.URL.Path, "/vulns/export/"+tenableExportUUID+"/chunks/")
			n := 0
			fmt.Sscanf(id, "%d", &n)
			w.Header().Set("Content-Type", "application/octet-stream")
			fmt.Fprint(w, chunks[n])
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTenable(base string) *tenable {
	return &tenable{base: base, accessKey: "tio-access", secretKey: "tio-secret", hc: http.DefaultClient, pollInterval: time.Millisecond}
}

func TestTenableFetch(t *testing.T) {
	srv := fakeTenable(t, []string{"QUEUED", "PROCESSING", "FINISHED"}, map[int]string{0: tenableChunk0, 1: tenableChunk1})
	fs, err := newTenable(srv.URL).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("findings = %d, want 2", len(fs))
	}

	sharepoint := fs[0]
	if sharepoint.RuleID != "156641" || sharepoint.Severity != domain.SeverityHigh || len(sharepoint.CVE) != 2 ||
		sharepoint.CVE[0] != "CVE-2022-21837" || sharepoint.FilePath != "sharepoint2016:445/tcp" ||
		sharepoint.CVSS == nil || *sharepoint.CVSS != 8.8 {
		t.Errorf("sharepoint = %+v", sharepoint)
	}
	if !strings.Contains(sharepoint.Description, "Solution: Install KB5002113.") {
		t.Errorf("sharepoint description = %q", sharepoint.Description)
	}
	if _, ok := sharepoint.Metadata["remote_triage"]; ok {
		t.Error("unmodified severity produced a remote verdict")
	}

	tls := fs[1]
	if tls.Metadata["remote_triage"] != string(domain.FindingRiskAccepted) {
		t.Errorf("accepted-risk metadata = %v", tls.Metadata)
	}
	if len(tls.CVE) != 0 {
		t.Errorf("tls cve = %v, want none", tls.CVE)
	}

	if name, err := newTenable(srv.URL).Check(context.Background()); err != nil {
		t.Errorf("check err = %v", err)
	} else if name == "" {
		t.Error("check returned an empty name")
	}
}

func TestTenableExportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/vulns/export":
			fmt.Fprintf(w, `{"export_uuid":"%s"}`, tenableExportUUID)
		case strings.HasSuffix(r.URL.Path, "/status"):
			fmt.Fprintf(w, `{"uuid":"%s","status":"ERROR","reason":"An unexpected error occurred."}`, tenableExportUUID)
		}
	}))
	defer srv.Close()
	tn := newTenable(srv.URL)
	tn.pollInterval = time.Millisecond
	_, err := tn.Fetch(context.Background())
	var rerr RemoteError
	if !errors.As(err, &rerr) || !strings.Contains(err.Error(), "error") {
		t.Fatalf("err = %v, want a RemoteError mentioning the export error", err)
	}
}

func TestTenableRateLimit(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	_, err := newTenable(srv.URL).Fetch(context.Background())
	var rerr RemoteError
	if !errors.As(err, &rerr) || !strings.Contains(err.Error(), "429") {
		t.Fatalf("err = %v, want a RemoteError mentioning 429", err)
	}
	if attempts != maxRateLimitRetries+1 {
		t.Fatalf("attempts = %d, want %d", attempts, maxRateLimitRetries+1)
	}
}

func TestTenableAuthFailure(t *testing.T) {
	srv := fakeTenable(t, []string{"FINISHED"}, map[int]string{0: tenableChunk0, 1: tenableChunk1})
	bad := newTenable(srv.URL)
	bad.secretKey = "wrong"
	if _, err := bad.Fetch(context.Background()); !errors.As(err, new(RemoteError)) || !strings.Contains(err.Error(), "401") {
		t.Fatalf("bad secret key err = %v, want a 401 RemoteError", err)
	}
}

func TestParseTenableCredentials(t *testing.T) {
	if _, err := parseTenableCredentials(`{"access_key":"a","secret_key":"b"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := parseTenableCredentials(`{"access_key":"a"}`); !errors.As(err, new(ValidationError)) {
		t.Errorf("missing secret_key err = %v, want ValidationError", err)
	}
}
