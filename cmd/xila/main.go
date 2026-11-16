// Command xila is a tiny CI client for the Xila API: upload a scanner report and
// enforce the security gate (non-zero exit fails the build). Stdlib only.
//
//	xila upload --project <id> --scanner trivy --branch "$BRANCH" --gate report.json
//	xila gate   --project <id> --max-critical 0 --block-kev
//
// Connection comes from --url/--token or XILA_URL/XILA_TOKEN. Without a token,
// the CI platform's OIDC identity token is exchanged for a short-lived session
// (--oidc-token / XILA_OIDC_TOKEN, GitLab's XILA_ID_TOKEN, or GitHub Actions'
// ACTIONS_ID_TOKEN_REQUEST_* with audience XILA_OIDC_AUDIENCE).
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"time"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// version is set at release build time (-ldflags "-X main.version=v1.2.3").
var version = "dev"

const usage = `xila — CI client for the Xila security platform

Usage:
  xila upload --project <id> --scanner <name> [--branch <b> | --release <r>] [flags] <file|->
  xila gate   --project <id> [--branch <b> | --release <r>] [policy flags]
  xila mcp    (stdio MCP server for AI clients; proxies to the server's MCP_ENABLED endpoint)
  xila version

Findings are tracked per branch / release: upload with --branch so a PR's scan
never closes or changes main's findings. upload --gate gates the branch it uploaded;
gate without --branch evaluates the project's default branch.

Global flags (or env): --url (XILA_URL, default http://localhost:8080), --token (XILA_TOKEN),
  --oidc-token (XILA_OIDC_TOKEN)

Without a token, xila authenticates with the CI platform's OIDC identity token
(workload identity federation; an admin binds it to a Xila service account):
an explicit --oidc-token, GitLab's XILA_ID_TOKEN (id_tokens:), or GitHub
Actions' own (needs permissions: id-token: write; audience XILA_OIDC_AUDIENCE).

upload --comment posts the result to the pull request (GitHub Actions: needs
GITHUB_TOKEN + pull-requests:write). The comment is edited in place on each push,
so a PR carries one Xila comment, not a wall of them.

--check (upload or gate) creates/updates a GitHub check run with the gate
verdict and inline annotations for findings the scan introduced (GitHub
Actions: needs GITHUB_TOKEN + checks:write). Matched by name + head commit, so
each push updates the same check instead of adding another.

Exit codes: 0 ok / gate passed · 1 gate failed · 2 usage or transport error
`

func run(args []string, out, errw io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(errw, usage)
		return 2
	}
	switch args[0] {
	case "upload":
		return cmdUpload(args[1:], out, errw)
	case "gate":
		return cmdGate(args[1:], out, errw)
	case "mcp":
		return cmdMCP(args[1:], os.Stdin, out, errw)
	case "version", "--version":
		fmt.Fprintln(out, version)
		return 0
	case "-h", "--help", "help":
		fmt.Fprint(out, usage)
		return 0
	default:
		fmt.Fprintf(errw, "unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

// client talks to the Xila API with an API token, retrying overload and
// connection failures for up to retryFor (retry.go).
type client struct {
	base, token string
	hc          *http.Client
	retryFor    time.Duration
	log         io.Writer // retry notices
	sleep       func(time.Duration)
	now         func() time.Time
	rnd         func(int64) int64
}

func newClient(url, token string, retryFor time.Duration, log io.Writer) *client {
	return &client{base: url, token: token, hc: &http.Client{Timeout: 60 * time.Second},
		retryFor: retryFor, log: log, sleep: time.Sleep, now: time.Now, rnd: defaultRand}
}

// do sends a request (retrying per retry.go) and returns the status + body.
func (c *client) do(method, path, query string, body []byte) (int, []byte, error) {
	return c.send(func() (*http.Request, error) {
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequest(method, c.base+path+query, rd)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		return req, nil
	})
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// globalFlags registers --url/--token/--oidc-token on a flag set with env fallbacks.
func globalFlags(fs *flag.FlagSet) (url, token, oidcToken *string) {
	url = fs.String("url", env("XILA_URL", "http://localhost:8080"), "Xila base URL")
	token = fs.String("token", os.Getenv("XILA_TOKEN"), "API token (xila_…)")
	oidcToken = fs.String("oidc-token", os.Getenv("XILA_OIDC_TOKEN"), "CI OIDC identity token to exchange when no API token is set")
	return url, token, oidcToken
}

func cmdUpload(args []string, out, errw io.Writer) int {
	fs := flag.NewFlagSet("upload", flag.ContinueOnError)
	fs.SetOutput(errw)
	url, token, oidcToken := globalFlags(fs)
	project := fs.String("project", "", "project id (required)")
	scanner := fs.String("scanner", "", "scanner name, e.g. trivy (required)")
	format := fs.String("format", "", "override format, e.g. sarif")
	branch := fs.String("branch", "", "source branch (findings are tracked per branch)")
	release := fs.String("release", "", "instead of --branch: the release this scan is of")
	commit := fs.String("commit", "", "source commit")
	artifact := fs.String("artifact", "", "artifact name")
	engagement := fs.String("engagement", "", "engagement id: file the scan as one of its tests")
	force := fs.Bool("force", false, "process in full even if this report's content hash matches the previous scan (bypasses skip-unchanged)")
	gate := fs.Bool("gate", false, "run the gate after upload; non-zero exit on failure")
	newOnly := fs.Bool("new", false, "with --gate: evaluate only newly-introduced findings")
	baseline := fs.String("baseline", "", "with --gate: compare against this baseline branch for new-only (overrides the stored policy's baseline_branch)")
	wait := fs.Bool("wait", false, "wait for background processing to finish (implied by --gate)")
	comment := fs.Bool("comment", false, "post the result as a pull-request comment (GitHub Actions)")
	check := fs.Bool("check", false, "create/update a GitHub check run with inline annotations (GitHub Actions; needs permissions: checks: write)")
	timeout := fs.Duration("timeout", 10*time.Minute, "max time to wait for processing")
	retryFor := retryFlag(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *project == "" || *scanner == "" {
		fmt.Fprintln(errw, "error: --project and --scanner are required")
		return 2
	}
	data, err := readInput(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(errw, "error: %v\n", err)
		return 2
	}

	if *branch != "" && *release != "" {
		fmt.Fprintln(errw, "error: give --branch or --release, not both")
		return 2
	}
	q := neturl.Values{"scanner": {*scanner}}
	for k, v := range map[string]string{"format": *format, "branch": *branch, "release": *release, "commit": *commit, "artifact": *artifact, "engagement_id": *engagement} {
		if v != "" {
			q.Set(k, v)
		}
	}
	if *force {
		q.Set("force", "true")
	}
	bearer, err := resolveToken(*url, *token, *oidcToken, out)
	if err != nil {
		fmt.Fprintf(errw, "error: %v\n", err)
		return 2
	}
	c := newClient(*url, bearer, *retryFor, errw)
	status, body, err := c.do(http.MethodPost, "/api/v1/projects/"+*project+"/scans", "?"+q.Encode(), data)
	if err != nil {
		fmt.Fprintf(errw, "error: upload failed: %v\n", err)
		return 2
	}
	if status < 200 || status >= 300 {
		fmt.Fprintf(errw, "error: upload returned %d: %s\n", status, apiError(body))
		return 2
	}
	var sr struct {
		ID        string `json:"id"`
		Status    string `json:"status"`
		VersionID string `json:"version_id"`
	}
	_ = json.Unmarshal(body, &sr)
	fmt.Fprintf(out, "uploaded %s scan to project %s (scan %s)\n", *scanner, *project, sr.ID)

	// Async servers return 202 with a "processing" scan; wait for it to finish
	// before gating (the gate needs the processed backlog).
	if (*gate || *wait) && sr.Status == "processing" && sr.ID != "" {
		if code := waitForScan(c, sr.ID, *timeout, out, errw); code != 0 {
			return code
		}
	}

	var result *gateResult
	code := 0
	if *gate {
		// Gate the exact branch/release this scan landed on, not the default one.
		result, code = evaluateGate(c, *project, versionQuery("", "", sr.VersionID, *baseline), gateBody(nil, *newOnly), out, errw)
	}

	// The comment and check run are side effects, never a reason to fail a
	// build: if GitHub is down or the token can't write, the security verdict
	// still stands.
	if *comment {
		if err := postPRComment(c, *url, *project, sr.ID, result, out); err != nil {
			fmt.Fprintf(errw, "warning: could not post PR comment: %v\n", err)
		}
	}
	if *check {
		if err := postCheckRun(c, *url, *project, sr.ID, result, out); err != nil {
			fmt.Fprintf(errw, "warning: could not post check run: %v\n", err)
		}
	}
	return code
}

// postPRComment renders the scan result into the pull request. Silently does
// nothing outside a PR context — a push to main has no PR to comment on, and that
// is normal, not an error.
func postPRComment(c *client, baseURL, project, scanID string, gate *gateResult, out io.Writer) error {
	gh, pr, ok := ghFromEnv()
	if !ok {
		return nil
	}
	findings, total, err := c.newFindings(project, scanID)
	if err != nil {
		return err
	}
	url, err := gh.UpsertComment(pr, renderComment(baseURL, project, gate, findings, total))
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "posted PR comment: %s\n", url)
	return nil
}

// postCheckRun creates/updates a GitHub check run (conclusion from the gate
// result, summary = the same content as the PR comment, plus inline
// annotations for findings this scan introduced that have a file+line).
// Silently does nothing outside a GitHub Actions context. scanID may be empty
// (a bare `gate --check`, with no specific scan) — then there are no findings
// to list or annotate, only the verdict.
func postCheckRun(c *client, baseURL, project, scanID string, gate *gateResult, out io.Writer) error {
	gh, headSHA, ok := ghCheckEnv()
	if !ok {
		return nil
	}
	var findings []prFinding
	var total int
	if scanID != "" {
		var err error
		findings, total, err = c.newFindings(project, scanID)
		if err != nil {
			return err
		}
	}
	summary := renderComment(baseURL, project, gate, findings, total)
	annotations := buildAnnotations(findings)
	if capped := countLocatable(findings) - len(annotations); capped > 0 {
		summary += fmt.Sprintf("\n<sub>⚠️ %d additional findings have a file location but were not annotated (capped at %d annotations).</sub>\n", capped, maxAnnotations)
	}
	url, err := gh.UpsertCheckRun(headSHA, checkRunName, checkConclusion(gate), summary, annotations)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "posted check run: %s\n", url)
	return nil
}

// waitForScan polls a scan until it's completed or failed. Returns 0 on
// completion, non-zero on failure/timeout.
func waitForScan(c *client, scanID string, timeout time.Duration, out, errw io.Writer) int {
	fmt.Fprint(out, "waiting for processing…")
	deadline := time.Now().Add(timeout)
	for {
		status, body, err := c.do(http.MethodGet, "/api/v1/scans/"+scanID, "", nil)
		if err != nil || status != http.StatusOK {
			fmt.Fprintf(errw, "\nerror: scan lookup failed (%d): %v\n", status, err)
			return 2
		}
		var s struct{ Status, Error string }
		_ = json.Unmarshal(body, &s)
		switch s.Status {
		case "completed":
			fmt.Fprintln(out, " done")
			return 0
		case "failed":
			fmt.Fprintf(errw, "\nerror: scan processing failed: %s\n", s.Error)
			return 2
		}
		if time.Now().After(deadline) {
			fmt.Fprintln(errw, "\nerror: timed out waiting for scan to process")
			return 2
		}
		fmt.Fprint(out, ".")
		time.Sleep(time.Second)
	}
}

func cmdGate(args []string, out, errw io.Writer) int {
	fs := flag.NewFlagSet("gate", flag.ContinueOnError)
	fs.SetOutput(errw)
	url, token, oidcToken := globalFlags(fs)
	project := fs.String("project", "", "project id (required)")
	maxCritical := fs.Int("max-critical", -1, "fail if open criticals exceed this")
	maxHigh := fs.Int("max-high", -1, "fail if open highs exceed this")
	maxMedium := fs.Int("max-medium", -1, "fail if open mediums exceed this")
	maxLow := fs.Int("max-low", -1, "fail if open lows exceed this")
	maxInfo := fs.Int("max-info", -1, "fail if open info findings exceed this")
	blockKEV := fs.Bool("block-kev", false, "fail on any open CISA-KEV finding")
	maxEPSS := fs.Float64("max-epss", -1, "fail if any open finding EPSS ≥ this")
	blockLicense := fs.Bool("block-license", false, "fail on any open license violation")
	blockSLA := fs.Bool("block-sla-breach", false, "fail on any open finding past its remediation SLA")
	newOnly := fs.Bool("new", false, "evaluate only newly-introduced findings (ignore pre-existing debt)")
	baseline := fs.String("baseline", "", "compare against this baseline branch: a finding is new only if it isn't already open there (overrides the stored policy's baseline_branch)")
	maxRiskScore := fs.Float64("max-risk-score", -1, "fail if the gated version's weighted risk score exceeds this")
	branch := fs.String("branch", "", "gate this branch instead of the project's default (must have been uploaded)")
	release := fs.String("release", "", "gate this release instead of the project's default")
	check := fs.Bool("check", false, "create/update a GitHub check run with the gate verdict (GitHub Actions; needs permissions: checks: write)")
	retryFor := retryFlag(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *project == "" {
		fmt.Fprintln(errw, "error: --project is required")
		return 2
	}
	if *branch != "" && *release != "" {
		fmt.Fprintln(errw, "error: give --branch or --release, not both")
		return 2
	}

	// Build an inline policy only from the flags that were set.
	var policy map[string]any
	set := func(k string, v any) {
		if policy == nil {
			policy = map[string]any{}
		}
		policy[k] = v
	}
	if *maxCritical >= 0 {
		set("max_critical", *maxCritical)
	}
	if *maxHigh >= 0 {
		set("max_high", *maxHigh)
	}
	for k, v := range map[string]int{"max_medium": *maxMedium, "max_low": *maxLow, "max_info": *maxInfo} {
		if v >= 0 {
			set(k, v)
		}
	}
	if *blockKEV {
		set("block_kev", true)
	}
	if *maxEPSS >= 0 {
		set("max_epss", *maxEPSS)
	}
	if *blockLicense {
		set("block_license", true)
	}
	if *blockSLA {
		set("block_sla_breach", true)
	}
	if *maxRiskScore >= 0 {
		set("max_risk_score", *maxRiskScore)
	}

	bearer, err := resolveToken(*url, *token, *oidcToken, out)
	if err != nil {
		fmt.Fprintf(errw, "error: %v\n", err)
		return 2
	}
	c := newClient(*url, bearer, *retryFor, errw)
	result, code := evaluateGate(c, *project, versionQuery(*branch, *release, "", *baseline), gateBody(policy, *newOnly), out, errw)
	if *check {
		if err := postCheckRun(c, *url, *project, "", result, out); err != nil {
			fmt.Fprintf(errw, "warning: could not post check run: %v\n", err)
		}
	}
	return code
}

// gateBody builds the gate request JSON: an optional inline policy override plus
// an optional new-only flag. Returns nil when there's nothing to send.
func gateBody(policy map[string]any, newOnly bool) []byte {
	req := map[string]any{}
	if policy != nil {
		req["policy"] = policy
	}
	if newOnly {
		req["new_only"] = true
	}
	if len(req) == 0 {
		return nil
	}
	b, _ := json.Marshal(req)
	return b
}

// versionQuery selects which project version a gate evaluates: by branch or
// release name, or by id (what an upload returns), plus an optional baseline
// branch to compare "new" against. All empty = the default version, no baseline.
func versionQuery(branch, release, versionID, baseline string) string {
	q := neturl.Values{}
	for k, v := range map[string]string{"branch": branch, "release": release, "version_id": versionID, "baseline": baseline} {
		if v != "" {
			q.Set(k, v)
		}
	}
	if len(q) == 0 {
		return ""
	}
	return "?" + q.Encode()
}

type gateResult struct {
	Passed     bool   `json:"passed"`
	Scope      string `json:"scope"`
	NewOnly    bool   `json:"new_only"`
	Baseline   string `json:"baseline"`
	Violations []struct {
		Rule    string `json:"rule"`
		Message string `json:"message"`
	} `json:"violations"`
	Stats struct {
		OpenCritical int     `json:"open_critical"`
		OpenHigh     int     `json:"open_high"`
		OpenKEV      int     `json:"open_kev"`
		OpenLicense  int     `json:"open_license"`
		MaxEPSS      float64 `json:"max_epss"`
		RiskScore    float64 `json:"risk_score"`
	} `json:"stats"`
}

// evaluateGate runs the gate and returns the process exit code (0 pass / 1 fail
// / 2 error). reqBody is an optional JSON body (inline policy and/or new_only).
func evaluateGate(c *client, project, query string, reqBody []byte, out, errw io.Writer) (*gateResult, int) {
	status, body, err := c.do(http.MethodPost, "/api/v1/projects/"+project+"/gate", query, reqBody)
	if err != nil {
		fmt.Fprintf(errw, "error: gate request failed: %v\n", err)
		return nil, 2
	}
	if status != http.StatusOK && status != http.StatusUnprocessableEntity {
		fmt.Fprintf(errw, "error: gate returned %d: %s\n", status, apiError(body))
		return nil, 2
	}
	var r gateResult
	if err := json.Unmarshal(body, &r); err != nil {
		fmt.Fprintf(errw, "error: bad gate response: %v\n", err)
		return nil, 2
	}
	scope := r.Scope
	if r.NewOnly {
		scope += ", new-only"
		if r.Baseline != "" {
			scope += " vs " + r.Baseline
		}
	}
	fmt.Fprintf(out, "backlog: %d critical · %d high · %d KEV · %d license · max EPSS %.3f · risk %.1f\n",
		r.Stats.OpenCritical, r.Stats.OpenHigh, r.Stats.OpenKEV, r.Stats.OpenLicense, r.Stats.MaxEPSS, r.Stats.RiskScore)
	if r.Passed {
		fmt.Fprintf(out, "✔ gate PASSED (policy: %s)\n", scope)
		return &r, 0
	}
	fmt.Fprintf(out, "✗ gate FAILED (policy: %s)\n", scope)
	for _, v := range r.Violations {
		fmt.Fprintf(out, "  - %s\n", v.Message)
	}
	return &r, 1
}

// readInput reads a report from a file path, or from stdin when path is "" or "-".
func readInput(path string) ([]byte, error) {
	if path == "" || path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

// apiError pulls the {"error": …} message out of a response body, or returns raw.
func apiError(body []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		return e.Error
	}
	return string(body)
}
