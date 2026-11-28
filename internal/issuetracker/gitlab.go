package issuetracker

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// gitlabClient speaks the GitLab v4 API (gitlab.com or self-managed). Target is
// the numeric project id or its full path ("group/sub/repo", URL-encoded as one
// path segment); issues are identified by their project-scoped iid.
type gitlabClient struct {
	api
	project string
}

func gitlabAuth(token string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("PRIVATE-TOKEN", token) }
}

func (c *gitlabClient) projectPath() string {
	return "/projects/" + url.PathEscape(c.project)
}

func (c *gitlabClient) Create(ctx context.Context, is Issue) (Ref, error) {
	body := map[string]any{"title": is.Title, "description": is.Body}
	if len(is.Labels) > 0 {
		body["labels"] = strings.Join(is.Labels, ",")
	}
	var out struct {
		IID    int    `json:"iid"`
		WebURL string `json:"web_url"`
	}
	if err := c.do(ctx, http.MethodPost, c.projectPath()+"/issues", body, &out); err != nil {
		return Ref{}, err
	}
	if out.IID == 0 {
		return Ref{}, errors.New("gitlab: create returned no issue iid")
	}
	return Ref{ExternalID: strconv.Itoa(out.IID), URL: out.WebURL}, nil
}

func (c *gitlabClient) issuePath(iid string) string {
	return c.projectPath() + "/issues/" + url.PathEscape(iid)
}

func (c *gitlabClient) State(ctx context.Context, iid string) (State, error) {
	var out struct {
		State string `json:"state"` // "opened" | "closed"
	}
	if err := c.do(ctx, http.MethodGet, c.issuePath(iid), nil, &out); err != nil {
		return "", err
	}
	if out.State == "closed" {
		return StateClosed, nil
	}
	return StateOpen, nil
}

func (c *gitlabClient) Close(ctx context.Context, iid string) error {
	return c.do(ctx, http.MethodPut, c.issuePath(iid), map[string]string{"state_event": "close"}, nil)
}

func (c *gitlabClient) Reopen(ctx context.Context, iid string) error {
	return c.do(ctx, http.MethodPut, c.issuePath(iid), map[string]string{"state_event": "reopen"}, nil)
}

func (c *gitlabClient) Check(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, c.projectPath(), nil, nil)
}
