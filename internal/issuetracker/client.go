package issuetracker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Issue is what Xila files in a tracker.
type Issue struct {
	Title  string
	Body   string
	Labels []string
}

// Ref identifies a created issue: the tracker's id for it (Jira key, GitHub
// number, GitLab iid) and a browser URL.
type Ref struct {
	ExternalID string
	URL        string
}

// Client is one tracker's API. Implementations are stateless beyond their
// config and safe for concurrent use.
type Client interface {
	// Create files a new issue.
	Create(ctx context.Context, is Issue) (Ref, error)
	// State reports whether the issue is open or closed.
	State(ctx context.Context, externalID string) (State, error)
	// Close resolves the issue.
	Close(ctx context.Context, externalID string) error
	// Reopen reopens a closed issue.
	Reopen(ctx context.Context, externalID string) error
	// Check verifies the credentials and target with a cheap read.
	Check(ctx context.Context) error
}

// NewClient builds the client for a tracker with its decrypted token.
func NewClient(t Tracker, token string, hc *http.Client) (Client, error) {
	base := strings.TrimRight(t.BaseURL, "/")
	switch t.Kind {
	case KindJira:
		return &jiraClient{base: base, hc: hc, auth: jiraAuth(t.JiraEmail, token),
			project: t.Target, issueType: t.IssueType, done: t.DoneTransition, reopen: t.ReopenTransition}, nil
	case KindGitHub:
		return &githubClient{base: base, hc: hc, auth: githubAuth(token), repo: t.Target}, nil
	case KindGitLab:
		return &gitlabClient{base: base + "/api/v4", hc: hc, auth: gitlabAuth(token), project: t.Target}, nil
	case KindAzureDevOps:
		return &azureClient{base: base, hc: hc, auth: azureAuth(token),
			project: t.Target, workType: t.IssueType, done: t.DoneTransition, reopen: t.ReopenTransition}, nil
	case KindLinear:
		return &linearClient{base: base, hc: hc, auth: linearAuth(token),
			team: t.Target, done: t.DoneTransition, reopen: t.ReopenTransition}, nil
	case KindServiceNow:
		return &serviceNowClient{base: base, hc: hc, auth: serviceNowAuth(t.AuthUser, token),
			table: t.Target, done: t.DoneTransition, reopen: t.ReopenTransition}, nil
	}
	return nil, fmt.Errorf("unsupported tracker kind %q", t.Kind)
}

// api is the shared JSON-over-HTTP plumbing.
type api struct {
	base string
	hc   *http.Client
	auth func(*http.Request)
}

// do sends a JSON request (body may be nil) and decodes a JSON response into
// out (may be nil). Non-2xx responses become errors carrying a snippet of the
// tracker's message — never the request, which holds the credential.
func (a api) do(ctx context.Context, method, path string, body, out any) error {
	return a.doCT(ctx, method, path, "application/json", body, out)
}

// doCT is do with an explicit request Content-Type: Azure DevOps work item
// writes require "application/json-patch+json" rather than plain JSON.
func (a api) doCT(ctx context.Context, method, path, contentType string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", contentType)
	}
	a.auth(req)
	resp, err := a.hc.Do(req)
	if err != nil {
		return RemoteError{msg: method + " " + path + ": request failed", detail: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		msg := method + " " + path + ": " + resp.Status
		// Surfaced to instance admins (RemoteError.detail) so a rate-limited
		// tracker can be told apart from one that's actually misconfigured.
		if resp.StatusCode == http.StatusTooManyRequests {
			if ra := strings.TrimSpace(resp.Header.Get("Retry-After")); ra != "" {
				msg += " (Retry-After: " + ra + "s)"
			}
		}
		return RemoteError{msg: msg, detail: strings.TrimSpace(string(snippet))}
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out); err != nil {
		return RemoteError{msg: method + " " + path + ": invalid response", detail: err.Error()}
	}
	return nil
}

// RemoteError is a failed tracker call. Detail holds what the tracker (or the
// network) said; it is shown to instance admins only — anyone else who can
// point a tracker at a URL would otherwise get a probe that reads internal
// services' responses. It never contains the request (which holds the token).
type RemoteError struct{ msg, detail string }

func (e RemoteError) Error() string {
	if e.detail == "" {
		return e.msg
	}
	return e.msg + ": " + e.detail
}

// Public is the message without the remote's own words.
func (e RemoteError) Public() string { return e.msg }
