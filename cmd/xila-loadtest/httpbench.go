package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"
)

type endpointCase struct {
	name string
	path string
}

func runHTTPBench(args []string) error {
	fs := flag.NewFlagSet("http-bench", flag.ExitOnError)
	baseURL := fs.String("base-url", "", "running api server base URL, e.g. http://127.0.0.1:18099 (required)")
	email := fs.String("email", "loadtest-admin@xila.local", "admin email (from seed)")
	password := fs.String("password", "loadtest-password-CHANGE-ME-123", "admin password (from seed)")
	project := fs.String("project", "", "a big project id to scope project-scoped endpoints to (required)")
	requests := fs.Int("requests", 50, "measured requests per endpoint (after warmup)")
	warmup := fs.Int("warmup", 5, "warmup requests per endpoint, excluded from percentiles")
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

	cases := []endpointCase{
		{"findings-default", fmt.Sprintf("/api/v1/projects/%s/findings", *project)},
		{"findings-priority-open", fmt.Sprintf("/api/v1/projects/%s/findings?status=open&sort=priority", *project)},
		{"findings-severity-scanner", fmt.Sprintf("/api/v1/projects/%s/findings?severity=critical&scanner=trivy", *project)},
		{"findings-search", fmt.Sprintf("/api/v1/projects/%s/findings?q=pkg-0001234", *project)},
		{"findings-portfolio-all", "/api/v1/findings?limit=100"},
		{"project-summary", fmt.Sprintf("/api/v1/projects/%s/summary", *project)},
		{"portfolio", "/api/v1/portfolio"},
		{"components-project", fmt.Sprintf("/api/v1/projects/%s/components", *project)},
		{"components-search", "/api/v1/components?q=pkg-0001234"},
	}

	fmt.Printf("%-28s %8s %8s %8s %8s %8s\n", "endpoint", "p50(ms)", "p95(ms)", "p99(ms)", "max(ms)", "n")
	for _, c := range cases {
		lat, err := measure(*baseURL, c.path, token, *warmup, *requests)
		if err != nil {
			return fmt.Errorf("%s: %w", c.name, err)
		}
		p50, p95, p99, max := percentiles(lat)
		fmt.Printf("%-28s %8.1f %8.1f %8.1f %8.1f %8d\n", c.name, p50, p95, p99, max, len(lat))
	}
	return nil
}

func login(baseURL, email, password string) (string, error) {
	body, _ := json.Marshal(map[string]string{"email": email, "password": password})
	resp, err := http.Post(baseURL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d: %s", resp.StatusCode, data)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", err
	}
	if out.Token == "" {
		return "", fmt.Errorf("empty token in response")
	}
	return out.Token, nil
}

// measure issues warmup requests (uncounted, so the first real query plan /
// connection setup doesn't skew the percentiles) then `n` measured ones,
// returning each latency in order.
func measure(baseURL, path, token string, warmup, n int) ([]time.Duration, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	get := func() (time.Duration, error) {
		req, err := http.NewRequest(http.MethodGet, baseURL+path, nil)
		if err != nil {
			return 0, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		elapsed := time.Since(start)
		if resp.StatusCode != http.StatusOK {
			return 0, fmt.Errorf("GET %s: status %d", path, resp.StatusCode)
		}
		return elapsed, nil
	}
	for range warmup {
		if _, err := get(); err != nil {
			return nil, err
		}
	}
	lat := make([]time.Duration, 0, n)
	for range n {
		d, err := get()
		if err != nil {
			return nil, err
		}
		lat = append(lat, d)
	}
	return lat, nil
}

func percentiles(lat []time.Duration) (p50, p95, p99, max float64) {
	if len(lat) == 0 {
		return 0, 0, 0, 0
	}
	sorted := append([]time.Duration(nil), lat...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	pick := func(p float64) float64 {
		idx := int(p * float64(len(sorted)-1))
		return float64(sorted[idx]) / float64(time.Millisecond)
	}
	return pick(0.50), pick(0.95), pick(0.99), float64(sorted[len(sorted)-1]) / float64(time.Millisecond)
}
