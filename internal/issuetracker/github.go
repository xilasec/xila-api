package issuetracker

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// githubClient speaks the GitHub REST API (github.com or Enterprise Server,
// whose base URL is https://host/api/v3). Target is "owner/repo"; issues are
// identified by their number.
type githubClient struct {
	api
	repo string
}

func githubAuth(token string) func(*http.Request) {
	return func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Accept", "application/vnd.github+json")
		r.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	}
}

func (c *githubClient) repoPath() string {
	owner, name, _ := strings.Cut(c.repo, "/")
	return "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name)
}

func (c *githubClient) Create(ctx context.Context, is Issue) (Ref, error) {
	body := map[string]any{"title": is.Title, "body": is.Body}
	if len(is.Labels) > 0 {
		body["labels"] = is.Labels
	}
	var out struct {
		Number  int    `json:"number"`
		HTMLURL string `json:"html_url"`
	}
	if err := c.do(ctx, http.MethodPost, c.repoPath()+"/issues", body, &out); err != nil {
		return Ref{}, err
	}
	if out.Number == 0 {
		return Ref{}, fmt.Errorf("github: create returned no issue number")
	}
	return Ref{ExternalID: strconv.Itoa(out.Number), URL: out.HTMLURL}, nil
}

func (c *githubClient) issuePath(number string) string {
	return c.repoPath() + "/issues/" + url.PathEscape(number)
}

func (c *githubClient) State(ctx context.Context, number string) (State, error) {
	var out struct {
		State string `json:"state"`
	}
	if err := c.do(ctx, http.MethodGet, c.issuePath(number), nil, &out); err != nil {
		return "", err
	}
	if out.State == "closed" {
		return StateClosed, nil
	}
	return StateOpen, nil
}

func (c *githubClient) Close(ctx context.Context, number string) error {
	return c.do(ctx, http.MethodPatch, c.issuePath(number),
		map[string]string{"state": "closed", "state_reason": "completed"}, nil)
}

func (c *githubClient) Reopen(ctx context.Context, number string) error {
	return c.do(ctx, http.MethodPatch, c.issuePath(number), map[string]string{"state": "open"}, nil)
}

// AddComment posts an issue comment:
// https://docs.github.com/en/rest/issues/comments#create-an-issue-comment
func (c *githubClient) AddComment(ctx context.Context, number, body string) error {
	return c.do(ctx, http.MethodPost, c.issuePath(number)+"/comments", map[string]string{"body": body}, nil)
}

func (c *githubClient) Check(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, c.repoPath(), nil, nil)
}
