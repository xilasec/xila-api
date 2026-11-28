package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"regexp"
	"strconv"
	"time"
)

// commentMarker identifies the comment we own. GitHub gives us no other way to
// find it again, and finding it again is the whole point: a security bot that
// posts a fresh comment on every push is a security bot people mute.
const commentMarker = "<!-- xila-report -->"

// ghClient is a minimal GitHub REST client — stdlib only, no SDK. The CLI is
// installed by `go install` in CI, so every dependency is a cost paid on every
// build.
type ghClient struct {
	token string
	repo  string // owner/name
	api   string
	hc    *http.Client
}

// ghFromEnv builds a client from the environment GitHub Actions provides.
// Returns nil when we're not in a pull-request context — there is nothing to
// comment on, and that is not an error.
func ghFromEnv() (*ghClient, int, bool) {
	token := os.Getenv("GITHUB_TOKEN")
	repo := os.Getenv("GITHUB_REPOSITORY")
	if token == "" || repo == "" {
		return nil, 0, false
	}
	pr, ok := prNumber()
	if !ok {
		return nil, 0, false
	}
	api := env("GITHUB_API_URL", "https://api.github.com")
	return &ghClient{token: token, repo: repo, api: api,
		hc: &http.Client{Timeout: 30 * time.Second}}, pr, true
}

// prNumber finds the pull request we're running against. Actions exposes it in
// the event payload; for pull_request_target and re-runs the ref is the fallback.
func prNumber() (int, bool) {
	if path := os.Getenv("GITHUB_EVENT_PATH"); path != "" {
		if data, err := os.ReadFile(path); err == nil { //nolint:gosec // G304: the GitHub Actions event file the runner names //nolint:gosec // G304: the GitHub Actions event file the runner names
			var event struct {
				PullRequest struct {
					Number int `json:"number"`
				} `json:"pull_request"`
				Number int `json:"number"`
			}
			if json.Unmarshal(data, &event) == nil {
				if n := event.PullRequest.Number; n > 0 {
					return n, true
				}
				if event.Number > 0 {
					return event.Number, true
				}
			}
		}
	}
	// refs/pull/123/merge
	if m := regexp.MustCompile(`refs/pull/(\d+)/`).FindStringSubmatch(os.Getenv("GITHUB_REF")); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			return n, true
		}
	}
	return 0, false
}

// ghCheckEnv builds a client plus the commit a check run attaches to. Unlike
// ghFromEnv (comments), this works for both pull_request and push events — a
// check run belongs to a commit, not a PR. Returns ok=false outside any
// GitHub Actions context (e.g. a local run), which is a silent no-op, not an
// error.
func ghCheckEnv() (*ghClient, string, bool) {
	token := os.Getenv("GITHUB_TOKEN")
	repo := os.Getenv("GITHUB_REPOSITORY")
	if token == "" || repo == "" {
		return nil, "", false
	}
	sha := prHeadSHA()
	if sha == "" {
		sha = os.Getenv("GITHUB_SHA")
	}
	if sha == "" {
		return nil, "", false
	}
	api := env("GITHUB_API_URL", "https://api.github.com")
	return &ghClient{token: token, repo: repo, api: api,
		hc: &http.Client{Timeout: 30 * time.Second}}, sha, true
}

// prHeadSHA reads the pull request's real head commit from the event payload.
// On a pull_request event GITHUB_SHA is the ephemeral test-merge commit; a
// check run must point at the branch's actual commit or it never shows up on
// the PR. Returns "" outside a pull_request event (ghCheckEnv falls back to
// GITHUB_SHA, which is the right commit for a push).
func prHeadSHA() string {
	path := os.Getenv("GITHUB_EVENT_PATH")
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path) //nolint:gosec // G304: the GitHub Actions event file the runner names
	if err != nil {
		return ""
	}
	var event struct {
		PullRequest struct {
			Head struct {
				SHA string `json:"sha"`
			} `json:"head"`
		} `json:"pull_request"`
	}
	if json.Unmarshal(data, &event) != nil {
		return ""
	}
	return event.PullRequest.Head.SHA
}

func (g *ghClient) do(method, path string, body any) ([]byte, error) {
	var buf io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		buf = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, g.api+path, buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := g.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("github %s %s: %s: %s", method, path, resp.Status, apiError(b))
	}
	return b, nil
}

// UpsertComment edits our existing comment on the PR, or creates one if there
// isn't one yet. Editing in place means a PR carries exactly one Xila comment
// whose content always reflects the current state of the branch — rather than a
// wall of stale verdicts from every push.
func (g *ghClient) UpsertComment(pr int, markdown string) (string, error) {
	body := markdown + "\n" + commentMarker

	id, err := g.findComment(pr)
	if err != nil {
		return "", err
	}
	if id > 0 {
		out, err := g.do(http.MethodPatch,
			fmt.Sprintf("/repos/%s/issues/comments/%d", g.repo, id),
			map[string]string{"body": body})
		if err != nil {
			return "", err
		}
		return commentURL(out), nil
	}
	out, err := g.do(http.MethodPost,
		fmt.Sprintf("/repos/%s/issues/%d/comments", g.repo, pr),
		map[string]string{"body": body})
	if err != nil {
		return "", err
	}
	return commentURL(out), nil
}

// findComment looks for the comment carrying our marker. Returns 0 when absent.
func (g *ghClient) findComment(pr int) (int, error) {
	for page := 1; page <= 10; page++ { // bounded: a PR with 1000 comments isn't ours to fix
		out, err := g.do(http.MethodGet,
			fmt.Sprintf("/repos/%s/issues/%d/comments?per_page=100&page=%d", g.repo, pr, page), nil)
		if err != nil {
			return 0, err
		}
		var comments []struct {
			ID   int    `json:"id"`
			Body string `json:"body"`
		}
		if err := json.Unmarshal(out, &comments); err != nil {
			return 0, err
		}
		for _, c := range comments {
			if bytes.Contains([]byte(c.Body), []byte(commentMarker)) {
				return c.ID, nil
			}
		}
		if len(comments) < 100 {
			return 0, nil
		}
	}
	return 0, nil
}

func commentURL(body []byte) string {
	var c struct {
		HTMLURL string `json:"html_url"`
	}
	_ = json.Unmarshal(body, &c)
	return c.HTMLURL
}

// UpsertCheckRun creates (or updates, matched by name + head SHA) a completed
// GitHub check run. The Checks API appends annotations on each update rather
// than replacing them, so annotations beyond the first batch are posted with
// further PATCH calls that carry only their own batch.
func (g *ghClient) UpsertCheckRun(headSHA, name, conclusion, summary string, annotations []checkAnnotation) (string, error) {
	id, htmlURL, err := g.findCheckRun(headSHA, name)
	if err != nil {
		return "", err
	}
	first, rest := batchAnnotations(annotations)
	output := map[string]any{"title": name, "summary": summary}
	if len(first) > 0 {
		output["annotations"] = first
	}
	body := map[string]any{
		"name": name, "head_sha": headSHA,
		"status": "completed", "conclusion": conclusion,
		"output": output,
	}
	var out []byte
	if id > 0 {
		out, err = g.do(http.MethodPatch, fmt.Sprintf("/repos/%s/check-runs/%d", g.repo, id), body)
	} else {
		out, err = g.do(http.MethodPost, fmt.Sprintf("/repos/%s/check-runs", g.repo), body)
	}
	if err != nil {
		return "", err
	}
	var cr struct {
		ID      int    `json:"id"`
		HTMLURL string `json:"html_url"`
	}
	_ = json.Unmarshal(out, &cr)
	if cr.ID > 0 {
		id = cr.ID
	}
	if cr.HTMLURL != "" {
		htmlURL = cr.HTMLURL
	}

	for _, batch := range rest {
		if _, err := g.do(http.MethodPatch, fmt.Sprintf("/repos/%s/check-runs/%d", g.repo, id),
			map[string]any{"output": map[string]any{"title": name, "summary": summary, "annotations": batch}}); err != nil {
			return htmlURL, err
		}
	}
	return htmlURL, nil
}

// findCheckRun looks up an existing check run with this name on this commit,
// so a re-run (retried job, re-push of the same commit) updates it instead of
// creating a duplicate. Returns 0 when absent.
func (g *ghClient) findCheckRun(headSHA, name string) (int, string, error) {
	out, err := g.do(http.MethodGet,
		fmt.Sprintf("/repos/%s/commits/%s/check-runs?check_name=%s", g.repo, headSHA, neturl.QueryEscape(name)), nil)
	if err != nil {
		return 0, "", err
	}
	var resp struct {
		CheckRuns []struct {
			ID      int    `json:"id"`
			HTMLURL string `json:"html_url"`
		} `json:"check_runs"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return 0, "", err
	}
	if len(resp.CheckRuns) > 0 {
		return resp.CheckRuns[0].ID, resp.CheckRuns[0].HTMLURL, nil
	}
	return 0, "", nil
}
