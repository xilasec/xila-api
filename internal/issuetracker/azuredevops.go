package issuetracker

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// azureClient speaks the Azure DevOps (Services or Server/TFS) work item
// tracking REST API, api-version 7.1:
// https://learn.microsoft.com/en-us/rest/api/azure/devops/wit/work-items/create?view=azure-devops-rest-7.1
// https://learn.microsoft.com/en-us/rest/api/azure/devops/wit/work-items/update?view=azure-devops-rest-7.1
// BaseURL is the organization (cloud, e.g. https://dev.azure.com/fabrikam) or
// collection (on-prem Server, e.g. https://tfs.acme.local/DefaultCollection)
// URL; target is the project name. Work items are identified by their
// numeric id. There is no open/closed flag: a work item is closed when its
// System.State field equals done (case-insensitively); close/reopen write
// that field directly — unlike Jira there is no named transition to look up.
type azureClient struct {
	api
	project  string
	workType string
	done     string
	reopen   string
}

// azureAuth sends the PAT as the password of HTTP Basic auth with an empty
// username, the scheme Azure DevOps documents for personal access tokens:
// https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate
func azureAuth(token string) func(*http.Request) {
	enc := base64.StdEncoding.EncodeToString([]byte(":" + token))
	return func(r *http.Request) { r.Header.Set("Authorization", "Basic "+enc) }
}

func (c *azureClient) workItemPath(suffix string) string {
	return "/" + url.PathEscape(c.project) + "/_apis/wit/workitems" + suffix + "?api-version=7.1"
}

// azurePatchOp is one operation of the "application/json-patch+json" body
// every work item write uses. Azure DevOps' own examples use "add" even to
// change a field that already has a value.
type azurePatchOp struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value string `json:"value"`
}

func (c *azureClient) Create(ctx context.Context, is Issue) (Ref, error) {
	ops := []azurePatchOp{
		{Op: "add", Path: "/fields/System.Title", Value: is.Title},
		{Op: "add", Path: "/fields/System.Description", Value: is.Body},
	}
	if len(is.Labels) > 0 {
		// Azure Boards has no label list; System.Tags is its semicolon-separated
		// free-text equivalent.
		ops = append(ops, azurePatchOp{Op: "add", Path: "/fields/System.Tags", Value: strings.Join(is.Labels, "; ")})
	}
	var out struct {
		ID    int `json:"id"`
		Links struct {
			HTML struct {
				Href string `json:"href"`
			} `json:"html"`
		} `json:"_links"`
	}
	path := c.workItemPath("/$" + url.PathEscape(c.workType))
	if err := c.doCT(ctx, http.MethodPost, path, "application/json-patch+json", ops, &out); err != nil {
		return Ref{}, err
	}
	if out.ID == 0 {
		return Ref{}, errors.New("azure-devops: create returned no work item id")
	}
	return Ref{ExternalID: strconv.Itoa(out.ID), URL: out.Links.HTML.Href}, nil
}

func (c *azureClient) State(ctx context.Context, id string) (State, error) {
	var out struct {
		Fields struct {
			State string `json:"System.State"`
		} `json:"fields"`
	}
	if err := c.do(ctx, http.MethodGet, c.workItemPath("/"+url.PathEscape(id)), nil, &out); err != nil {
		return "", err
	}
	if strings.EqualFold(out.Fields.State, c.done) {
		return StateClosed, nil
	}
	return StateOpen, nil
}

func (c *azureClient) setState(ctx context.Context, id, state string) error {
	ops := []azurePatchOp{{Op: "add", Path: "/fields/System.State", Value: state}}
	return c.doCT(ctx, http.MethodPatch, c.workItemPath("/"+url.PathEscape(id)), "application/json-patch+json", ops, nil)
}

func (c *azureClient) Close(ctx context.Context, id string) error { return c.setState(ctx, id, c.done) }
func (c *azureClient) Reopen(ctx context.Context, id string) error {
	return c.setState(ctx, id, c.reopen)
}

// Check reads the project itself (Core API), cheaper than listing work items
// and still proves both the organization URL and the PAT are good:
// https://learn.microsoft.com/en-us/rest/api/azure/devops/core/projects/get?view=azure-devops-rest-7.1
func (c *azureClient) Check(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/_apis/projects/"+url.PathEscape(c.project)+"?api-version=7.1", nil, nil)
}
