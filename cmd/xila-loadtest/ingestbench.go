package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand/v2" // nosemgrep: go.lang.security.audit.crypto.math_random.math-random-used -- seeded on purpose: reproducible load-test reports, never secrets
	"net/http"
	"time"
)

// runIngestBench uploads synthetic Trivy-format reports to a running api
// server's real scan.Service — the HTTP upload endpoint, same as CI/the
// xila CLI use in production — and measures end-to-end ingest throughput.
// Async mode (INGEST_ASYNC=true on the server) is detected from the 202
// response and timed to completion by polling GET /scans/{id}.
func runIngestBench(args []string) error {
	fs := flag.NewFlagSet("ingest-bench", flag.ExitOnError)
	baseURL := fs.String("base-url", "", "running api server base URL (required)")
	email := fs.String("email", "loadtest-admin@xila.local", "admin email (from seed)")
	password := fs.String("password", "loadtest-password-CHANGE-ME-123", "admin password (from seed)")
	project := fs.String("project", "", "project id to upload scans to (required)")
	scans := fs.Int("scans", 10, "number of scans to upload")
	findingsPerScan := fs.Int("findings-per-scan", 1000, "vulnerabilities per scan report")
	branch := fs.String("branch", "loadtest-ingest", "branch to upload to (isolated from the seeded backlog)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *baseURL == "" || *project == "" {
		return fmt.Errorf("--base-url and --project are required")
	}

	token, err := login(*baseURL, *email, *password)
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}

	client := &http.Client{Timeout: 120 * time.Second}
	url := fmt.Sprintf("%s/api/v1/projects/%s/scans?scanner=trivy&branch=%s", *baseURL, *project, *branch)

	totalFindings := 0
	lat := make([]time.Duration, 0, *scans)
	overallStart := time.Now()
	for i := range *scans {
		report := trivyReport(*findingsPerScan, i)
		start := time.Now()
		req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(report))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("upload scan %d: %w", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusAccepted {
			return fmt.Errorf("upload scan %d: status %d: %s", i, resp.StatusCode, body)
		}
		var sc struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		}
		if err := json.Unmarshal(body, &sc); err != nil {
			return fmt.Errorf("upload scan %d: decode response: %w", i, err)
		}
		async := resp.StatusCode == http.StatusAccepted
		if async {
			if err := pollScanDone(client, *baseURL, token, sc.ID); err != nil {
				return fmt.Errorf("scan %d (%s): %w", i, sc.ID, err)
			}
		}
		lat = append(lat, time.Since(start))
		totalFindings += *findingsPerScan
	}
	elapsed := time.Since(overallStart)

	p50, p95, p99, max := percentiles(lat)
	fmt.Printf("uploaded %d scans, %d findings total, in %s\n", *scans, totalFindings, elapsed.Round(time.Millisecond))
	fmt.Printf("throughput: %.0f findings/sec (wall clock)\n", float64(totalFindings)/elapsed.Seconds())
	fmt.Printf("per-scan latency: p50=%.0fms p95=%.0fms p99=%.0fms max=%.0fms\n", p50, p95, p99, max)
	return nil
}

func pollScanDone(client *http.Client, baseURL, token, scanID string) error {
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest(http.MethodGet, baseURL+"/api/v1/scans/"+scanID, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var sc struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		}
		if err := json.Unmarshal(body, &sc); err != nil {
			return fmt.Errorf("decode scan status: %w", err)
		}
		switch sc.Status {
		case "completed":
			return nil
		case "failed":
			return fmt.Errorf("scan failed: %s", sc.Error)
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for scan to finish")
}

// trivyReport builds a synthetic `trivy --format json` report with n
// vulnerabilities, overlapping CVE+package identities with the seeded
// dataset's pool so the upload exercises real cross-tool dedup, not an
// all-new, all-unique backlog.
func trivyReport(n, seed int) []byte {
	rnd := rand.New(rand.NewPCG(uint64(seed), 0xC0FFEE))
	type vuln struct {
		VulnerabilityID  string `json:"VulnerabilityID"`
		PkgName          string `json:"PkgName"`
		InstalledVersion string `json:"InstalledVersion"`
		FixedVersion     string `json:"FixedVersion"`
		Severity         string `json:"Severity"`
	}
	sevs := []string{"LOW", "MEDIUM", "HIGH", "CRITICAL"}
	vulns := make([]vuln, n)
	for i := range n {
		pkgIdx := rnd.IntN(max(n/4, 50))
		vulns[i] = vuln{
			VulnerabilityID:  fmt.Sprintf("CVE-%04d-%06d", 2015+pkgIdx%10, pkgIdx),
			PkgName:          fmt.Sprintf("pkg-%07d", pkgIdx),
			InstalledVersion: "1.0.0",
			FixedVersion:     "1.0.1",
			Severity:         sevs[rnd.IntN(len(sevs))],
		}
	}
	report := struct {
		Results []struct {
			Target          string `json:"Target"`
			Class           string `json:"Class"`
			Type            string `json:"Type"`
			Vulnerabilities []vuln `json:"Vulnerabilities"`
		} `json:"Results"`
	}{}
	report.Results = []struct {
		Target          string `json:"Target"`
		Class           string `json:"Class"`
		Type            string `json:"Type"`
		Vulnerabilities []vuln `json:"Vulnerabilities"`
	}{{Target: "go.mod", Class: "lang-pkgs", Type: "gomod", Vulnerabilities: vulns}}
	out, _ := json.Marshal(report)
	return out
}
