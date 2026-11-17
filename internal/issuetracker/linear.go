package issuetracker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// linearClient speaks the Linear GraphQL API, a single POST endpoint:
// https://linear.app/developers/graphql
// Target is the team id (or key); issues are identified by Linear's
// human-readable identifier (e.g. "ENG-123"), which the `issue` query and
// `issueUpdate` mutation accept in place of the internal UUID. Linear has no
// open/closed flag: every workflow state carries a `type` (triage, backlog,
// unstarted, started, completed, canceled); done/reopen select a state of
// that *type*, not a name (state names are per-team and renamable):
// https://github.com/linear/linear-solutions/blob/main/integration_guides/scenarios/01-create-issue-with-labels/using-graphql.ts
type linearClient struct {
	api
	team   string
	done   string // workflow state type that counts as closed, e.g. "completed"
	reopen string // workflow state type a reopen moves back to, e.g. "unstarted"
}

// linearAuth sends a personal API key as-is in the Authorization header
// (no "Bearer" prefix — that prefix is for OAuth2 access tokens instead):
// https://linear.app/developers/graphql#authentication
func linearAuth(token string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Authorization", token) }
}

type graphQLRequest struct {
	Query     string `json:"query"`
	Variables any    `json:"variables,omitempty"`
}

type graphQLError struct {
	Message string `json:"message"`
}

// graphQL posts one query/mutation to /graphql and decodes its data into
// out. A GraphQL-level failure (returned with HTTP 200) is surfaced the same
// way a transport error is: https://linear.app/developers/graphql#error-handling
func (c *linearClient) graphQL(ctx context.Context, query string, vars, out any) error {
	var resp struct {
		Data   json.RawMessage `json:"data"`
		Errors []graphQLError  `json:"errors"`
	}
	if err := c.do(ctx, http.MethodPost, "/graphql", graphQLRequest{Query: query, Variables: vars}, &resp); err != nil {
		return err
	}
	if len(resp.Errors) > 0 {
		msgs := make([]string, len(resp.Errors))
		for i, e := range resp.Errors {
			msgs[i] = e.Message
		}
		return RemoteError{msg: "linear: graphql error", detail: strings.Join(msgs, "; ")}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(resp.Data, out)
}

// linearCreateMutation follows the official issueCreate example:
// https://linear.app/developers/graphql#creating--editing-issues
const linearCreateMutation = `mutation($input: IssueCreateInput!) {
  issueCreate(input: $input) {
    success
    issue { identifier url }
  }
}`

func (c *linearClient) Create(ctx context.Context, is Issue) (Ref, error) {
	var out struct {
		IssueCreate struct {
			Success bool `json:"success"`
			Issue   struct {
				Identifier string `json:"identifier"`
				URL        string `json:"url"`
			} `json:"issue"`
		} `json:"issueCreate"`
	}
	vars := map[string]any{"input": map[string]any{"teamId": c.team, "title": is.Title, "description": is.Body}}
	if err := c.graphQL(ctx, linearCreateMutation, vars, &out); err != nil {
		return Ref{}, err
	}
	if !out.IssueCreate.Success || out.IssueCreate.Issue.Identifier == "" {
		return Ref{}, fmt.Errorf("linear: create returned no issue")
	}
	return Ref{ExternalID: out.IssueCreate.Issue.Identifier, URL: out.IssueCreate.Issue.URL}, nil
}

const linearStateQuery = `query($id: String!) { issue(id: $id) { state { type } } }`

func (c *linearClient) State(ctx context.Context, identifier string) (State, error) {
	var out struct {
		Issue struct {
			State struct {
				Type string `json:"type"`
			} `json:"state"`
		} `json:"issue"`
	}
	if err := c.graphQL(ctx, linearStateQuery, map[string]any{"id": identifier}, &out); err != nil {
		return "", err
	}
	if isLinearClosedType(out.Issue.State.Type) {
		return StateClosed, nil
	}
	return StateOpen, nil
}

func isLinearClosedType(t string) bool { return t == "completed" || t == "canceled" }

// linearWorkflowStatesQuery matches the official find-workflow-state example
// (filtering by state *type* rather than name, since teams can rename
// states): the linear-solutions integration guide cited above. $teamId is
// typed ID! there, unlike the plain id arguments above — Linear's own
// comment: "Use ID! type (not String!) for the teamId variable when
// filtering by team.id."
const linearWorkflowStatesQuery = `query($teamId: ID!) {
  workflowStates(filter: { team: { id: { eq: $teamId } } }) { nodes { id type } }
}`

// stateID resolves a workflow-state type (e.g. "completed") to one concrete
// state id in the team, since issueUpdate takes a state id, not a type.
func (c *linearClient) stateID(ctx context.Context, wantType string) (string, error) {
	var out struct {
		WorkflowStates struct {
			Nodes []struct {
				ID   string `json:"id"`
				Type string `json:"type"`
			} `json:"nodes"`
		} `json:"workflowStates"`
	}
	if err := c.graphQL(ctx, linearWorkflowStatesQuery, map[string]any{"teamId": c.team}, &out); err != nil {
		return "", err
	}
	for _, n := range out.WorkflowStates.Nodes {
		if n.Type == wantType {
			return n.ID, nil
		}
	}
	return "", fmt.Errorf("linear: team %s has no workflow state of type %q", c.team, wantType)
}

const linearUpdateMutation = `mutation($id: String!, $input: IssueUpdateInput!) {
  issueUpdate(id: $id, input: $input) { success }
}`

func (c *linearClient) setState(ctx context.Context, identifier, wantType string) error {
	id, err := c.stateID(ctx, wantType)
	if err != nil {
		return err
	}
	var out struct {
		IssueUpdate struct {
			Success bool `json:"success"`
		} `json:"issueUpdate"`
	}
	vars := map[string]any{"id": identifier, "input": map[string]any{"stateId": id}}
	return c.graphQL(ctx, linearUpdateMutation, vars, &out)
}

func (c *linearClient) Close(ctx context.Context, identifier string) error {
	return c.setState(ctx, identifier, c.done)
}

func (c *linearClient) Reopen(ctx context.Context, identifier string) error {
	return c.setState(ctx, identifier, c.reopen)
}

// Check reads the team itself, the cheapest call that proves both the team
// id and the API key are good: https://linear.app/developers/graphql#getting-started
const linearCheckQuery = `query($teamId: String!) { team(id: $teamId) { id } }`

func (c *linearClient) Check(ctx context.Context) error {
	var out struct {
		Team struct {
			ID string `json:"id"`
		} `json:"team"`
	}
	return c.graphQL(ctx, linearCheckQuery, map[string]any{"teamId": c.team}, &out)
}
