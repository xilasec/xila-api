package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand/v2" // nosemgrep: go.lang.security.audit.crypto.math_random.math-random-used -- seeded on purpose: reproducible load-test reports, never secrets
	"net/http"
	"strconv"
	"strings"
	"time"
)

// runIngestBench uploads synthetic Trivy-format reports to a running api
// server's real scan.Service (the HTTP upload endpoint, same as CI and the xila
// CLI use in production) and measures end-to-end ingest throughput.
// --concurrency runs that many uploaders at once, spread over --projects, which
// is what many repositories uploading together looks like. Async mode
// (INGEST_ASYNC=true on the server) is detected from the 202 response and timed
// to completion by polling GET /scans/{id}; a 429 is retried after Retry-After
// and counted.
func runIngestBench(args []string) error {
	fs := flag.NewFlagSet("ingest-bench", flag.ExitOnError)
	baseURL := fs.String("base-url", "", "running api server base URL (required)")
	email := fs.String("email", "loadtest-admin@xila.local", "admin email (from seed)")
	password := fs.String("password", "loadtest-password-CHANGE-ME-123", "admin password (from seed)")
	project := fs.String("project", "", "project id to upload scans to (this or --projects is required)")
	projects := fs.String("projects", "", "comma-separated project ids; uploader i uses project i mod len")
	concurrency := fs.Int("concurrency", 1, "uploaders running at once, each uploading --scans scans")
	scans := fs.Int("scans", 10, "scans per uploader")
	findingsPerScan := fs.Int("findings-per-scan", 1000, "vulnerabilities per scan report")
	branch := fs.String("branch", "loadtest-ingest", "branch prefix to upload to (isolated from the seeded backlog)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	targets := splitIDs(*projects)
	if len(targets) == 0 && *project != "" {
		targets = []string{*project}
	}
	if *baseURL == "" || len(targets) == 0 {
		return fmt.Errorf("--base-url and --project (or --projects) are required")
	}
	if *concurrency < 1 {
		return fmt.Errorf("--concurrency must be at least 1")
	}

	token, err := login(*baseURL, *email, *password)
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}
	client := &http.Client{Timeout: 10 * time.Minute}

	type result struct {
		lat     []time.Duration
		retries int
		err     error
	}
	results := make(chan result, *concurrency)
	overallStart := time.Now()
	for u := range *concurrency {
		go func() {
			br := *branch
			if *concurrency > 1 {
				br = fmt.Sprintf("%s-%d", *branch, u)
			}
			url := fmt.Sprintf("%s/api/v1/projects/%s/scans?scanner=trivy&branch=%s", *baseURL, targets[u%len(targets)], br)
			var r result
			for i := range *scans {
				start := time.Now()
				n, err := uploadOnce(client, url, token, *baseURL, trivyReport(*findingsPerScan, u*100000+i))
				r.retries += n
				if err != nil {
					r.err = fmt.Errorf("uploader %d, scan %d: %w", u, i, err)
					break
				}
				r.lat = append(r.lat, time.Since(start))
			}
			results <- r
		}()
	}
	var lat []time.Duration
	retries := 0
	var errs []error
	for range *concurrency {
		r := <-results
		lat = append(lat, r.lat...)
		retries += r.retries
		if r.err != nil {
			errs = append(errs, r.err)
		}
	}
	elapsed := time.Since(overallStart)
	if len(lat) == 0 {
		return fmt.Errorf("no scan completed: %v", errs)
	}

	totalFindings := len(lat) * *findingsPerScan
	p50, p95, p99, max := percentiles(lat)
	fmt.Printf("uploaded %d scans (%d uploaders x %d), %d findings total, in %s\n",
		len(lat), *concurrency, *scans, totalFindings, elapsed.Round(time.Millisecond))
	fmt.Printf("throughput: %.0f findings/sec (wall clock, all uploaders)\n", float64(totalFindings)/elapsed.Seconds())
	fmt.Printf("per-scan latency: p50=%.0fms p95=%.0fms p99=%.0fms max=%.0fms\n", p50, p95, p99, max)
	fmt.Printf("429 retries: %d\n", retries)
	if len(errs) > 0 {
		return fmt.Errorf("%d uploader(s) failed, first: %w", len(errs), errs[0])
	}
	return nil
}

// uploadOnce uploads one report, retrying 429 after Retry-After, and waits for
// an async scan to finish. It returns how many times it was told to retry.
func uploadOnce(client *http.Client, url, token, baseURL string, report []byte) (int, error) {
	for retries := 0; ; retries++ {
		req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(report))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			return retries, err
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests && retries < 100 {
			wait := 5 * time.Second
			if secs, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && secs > 0 {
				wait = time.Duration(secs) * time.Second
			}
			time.Sleep(wait)
			continue
		}
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusAccepted {
			return retries, fmt.Errorf("status %d: %s", resp.StatusCode, body)
		}
		var sc struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &sc); err != nil {
			return retries, fmt.Errorf("decode response: %w", err)
		}
		if resp.StatusCode == http.StatusAccepted {
			if err := pollScanDone(client, baseURL, token, sc.ID); err != nil {
				return retries, fmt.Errorf("scan %s: %w", sc.ID, err)
			}
		}
		return retries, nil
	}
}

func splitIDs(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func pollScanDone(client *http.Client, baseURL, token, scanID string) error {
	deadline := time.Now().Add(15 * time.Minute) // a burst can queue a while
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
