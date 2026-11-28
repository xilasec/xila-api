package issuetracker

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// jiraClient speaks Jira REST v2 (Cloud, Server and Data Center). Target is the
// project key; issues are identified by their key (e.g. SEC-12). Jira has no
// open/closed flag: an issue is closed when its status is in the "done"
// category, and closing/reopening are workflow transitions matched by name.
type jiraClient struct {
	api
	project   string
	issueType string
	done      string
	reopen    string
}

// jiraAuth uses basic email:token (Jira Cloud API tokens) when an email is
// given, else a Bearer personal access token (Server / Data Center).
func jiraAuth(email, token string) func(*http.Request) {
	if email != "" {
		v := "Basic " + base64.StdEncoding.EncodeToString([]byte(email+":"+token))
		return func(r *http.Request) { r.Header.Set("Authorization", v) }
	}
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }
}

func (c *jiraClient) Create(ctx context.Context, is Issue) (Ref, error) {
	fields := map[string]any{
		"project":     map[string]string{"key": c.project},
		"summary":     is.Title,
		"description": is.Body,
		"issuetype":   map[string]string{"name": c.issueType},
	}
	if len(is.Labels) > 0 {
		fields["labels"] = is.Labels
	}
	var out struct {
		Key string `json:"key"`
	}
	if err := c.do(ctx, http.MethodPost, "/rest/api/2/issue", map[string]any{"fields": fields}, &out); err != nil {
		return Ref{}, err
	}
	if out.Key == "" {
		return Ref{}, errors.New("jira: create returned no issue key")
	}
	return Ref{ExternalID: out.Key, URL: c.base + "/browse/" + out.Key}, nil
}

func (c *jiraClient) State(ctx context.Context, key string) (State, error) {
	var out struct {
		Fields struct {
			Status struct {
				StatusCategory struct {
					Key string `json:"key"`
				} `json:"statusCategory"`
			} `json:"status"`
		} `json:"fields"`
	}
	if err := c.do(ctx, http.MethodGet, "/rest/api/2/issue/"+url.PathEscape(key)+"?fields=status", nil, &out); err != nil {
		return "", err
	}
	if out.Fields.Status.StatusCategory.Key == "done" {
		return StateClosed, nil
	}
	return StateOpen, nil
}

func (c *jiraClient) Close(ctx context.Context, key string) error {
	return c.transition(ctx, key, c.done)
}

func (c *jiraClient) Reopen(ctx context.Context, key string) error {
	return c.transition(ctx, key, c.reopen)
}

// transition applies the issue's available transition whose name — or target
// status name — matches (case-insensitively).
func (c *jiraClient) transition(ctx context.Context, key, name string) error {
	path := "/rest/api/2/issue/" + url.PathEscape(key) + "/transitions"
	var out struct {
		Transitions []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			To   struct {
				Name string `json:"name"`
			} `json:"to"`
		} `json:"transitions"`
	}
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return err
	}
	for _, t := range out.Transitions {
		if strings.EqualFold(t.Name, name) || strings.EqualFold(t.To.Name, name) {
			return c.do(ctx, http.MethodPost, path, map[string]any{"transition": map[string]string{"id": t.ID}}, nil)
		}
	}
	return fmt.Errorf("jira: issue %s has no transition named %q", key, name)
}

func (c *jiraClient) Check(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/rest/api/2/project/"+url.PathEscape(c.project), nil, nil)
}

// Comment: https://developer.atlassian.com/cloud/jira/platform/rest/v2/api-group-issue-comments/#api-rest-api-2-issue-issueidorkey-comment-post
func (c *jiraClient) Comment(ctx context.Context, key, body string) (string, error) {
	var out struct {
		ID string `json:"id"`
	}
	if err := c.do(ctx, http.MethodPost, "/rest/api/2/issue/"+url.PathEscape(key)+"/comment", map[string]string{"body": body}, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}
