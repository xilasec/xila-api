package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"

	"github.com/xilasec/xila-api/internal/auth"
)

// writeTimeout bounds one synchronous insert: the user's request is waiting.
const writeTimeout = 5 * time.Second

// store is what the recorder needs from the Repository.
type store interface {
	Insert(ctx context.Context, e Entry) error
	ScopeOf(ctx context.Context, projectID, teamID string) (team, org string, err error)
}

// resourceProjects resolves a project-owned resource (finding, scan, …) to its
// project (membership.Repository).
type resourceProjects interface {
	ProjectOfResource(ctx context.Context, resource, id string) (string, bool, error)
}

// Recorder writes entries for HTTP requests.
type Recorder struct {
	store     store
	resources resourceProjects
	secret    string // JWT secret: names the user an SSO login or MFA challenge is for
	failures  metric.Int64Counter
	routes    func() []fiber.Route // the app's route table (Attach); nil = not attached
}

// Attach gives the recorder the app's route table, so a request refused by a
// middleware before any route matched (authorization, a switched-off
// feature) is still described by the route it was for.
func (r *Recorder) Attach(app *fiber.App) {
	r.routes = sync.OnceValue(func() []fiber.Route { return app.GetRoutes(true) })
}

// template returns the segments of the route a refused request was for: the
// route with this method whose segments match, preferring the one with the
// most static segments (/remediation/sweep over /remediation/:actionID).
func (r *Recorder) template(method string, segs []string) []string {
	if r.routes == nil {
		return nil
	}
	var best []string
	bestStatic := -1
	for _, rt := range r.routes() {
		if rt.Method != method {
			continue
		}
		t := apiSegments(rt.Path)
		if len(t) != len(segs) {
			continue
		}
		static, ok := 0, true
		for i, s := range t {
			if strings.HasPrefix(s, ":") || strings.HasPrefix(s, "*") {
				continue
			}
			if !strings.EqualFold(s, segs[i]) {
				ok = false
				break
			}
			static++
		}
		if ok && static > bestStatic {
			best, bestStatic = t, static
		}
	}
	return best
}

// NewRecorder constructs a recorder. secret is the JWT signing secret.
func NewRecorder(s store, resources resourceProjects, secret string) *Recorder {
	failures, err := otel.Meter("github.com/xilasec/xila-api/internal/audit").Int64Counter("xila.audit.write_failures",
		metric.WithDescription("Audit log entries that could not be written"))
	if err != nil {
		slog.Error("audit: failure counter", "error", err)
	}
	return &Recorder{store: s, resources: resources, secret: secret, failures: failures}
}

type changesKey struct{}

// SetChanges records a handler's before / after state for the request's audit
// entry, in place of the redacted request body. Both are redacted with the
// same key policy.
func SetChanges(c *fiber.Ctx, before, after any) {
	c.Locals(changesKey{}, map[string]any{"before": redactAny(before), "after": redactAny(after)})
}

// ViaUserValue is the fasthttp user value an in-process caller (the MCP
// server) sets on a sub-request to name itself — "mcp:<tool>" — recorded as
// changes.via. A user value, not a header: a client can't set it.
const ViaUserValue = "xila.audit.via"

// Envelope reports whether path is a request envelope that isn't recorded
// itself because each action inside it is: an MCP call's tools run as API
// sub-requests, each audited (changes.via = "mcp:<tool>"); recording the
// envelope too would log every read-only tool call as a change.
func Envelope(path string) bool {
	return path == "/api/v1/mcp"
}

func mutating(method string) bool {
	switch method {
	case fiber.MethodPost, fiber.MethodPut, fiber.MethodPatch, fiber.MethodDelete:
		return true
	}
	return false
}

// Middleware records every mutating request on the authenticated API. It
// runs after authentication and before authorization, so a refused attempt
// is recorded too (as a failure).
func (r *Recorder) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) (err error) {
		if !mutating(c.Method()) || Envelope(c.Path()) {
			return c.Next()
		}
		path := strings.Clone(c.Path())
		e := Entry{
			Method:    c.Method(),
			Path:      path,
			ClientIP:  strings.Clone(c.IP()),
			RequestID: requestID(c),
		}
		setActor(&e, auth.CurrentActor(c))
		body := RedactBody(c.Body(), strings.Clone(c.Get(fiber.HeaderContentType)))
		r.scope(c.UserContext(), &e, apiSegments(path), body)

		defer func() {
			p := recover()
			status := statusOf(c, err)
			if p != nil {
				status = fiber.StatusInternalServerError
			}
			e.Status = status
			e.Outcome = outcomeOf(status)
			r.describe(c, &e)
			ch, ok := c.Locals(changesKey{}).(map[string]any)
			if !ok {
				ch = map[string]any{}
				if body != nil {
					ch["request"] = body
				}
			}
			if via, ok := c.Context().UserValue(ViaUserValue).(string); ok && via != "" {
				ch["via"] = via
			}
			if len(ch) > 0 {
				e.Changes = mustJSON(ch)
			}
			r.write(c, e)
			if p != nil {
				panic(p)
			}
		}()
		return c.Next()
	}
}

func requestID(c *fiber.Ctx) string {
	id, _ := c.Locals(requestid.ConfigDefault.ContextKey).(string)
	return id
}

func setActor(e *Entry, a auth.Actor) {
	switch {
	case a.UserID == "":
		e.ActorKind = ActorAnonymous
		return
	case a.IsServiceAccount:
		e.ActorKind = ActorServiceAccount
	case a.IsToken:
		e.ActorKind = ActorAPIToken
	default:
		e.ActorKind = ActorUser
	}
	e.ActorUserID = new(a.UserID)
	if a.TokenID != "" {
		e.ActorTokenID = new(a.TokenID)
	}
}

// apiSegments returns a path's segments after /api/v1.
func apiSegments(path string) []string {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	for i, s := range segs {
		if s == "v1" {
			return segs[i+1:]
		}
	}
	return segs
}

func isUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}

// scope fills project / team / org from the request path, resolving a
// project-owned resource (/findings/{id}, /scans/{id}, …) to its project. It
// runs before the handler: after a DELETE there is nothing left to resolve.
// A path without one falls back to a project_id in the JSON body (a
// project-scoped API token or channel). A lookup failure only leaves the
// scope empty.
func (r *Recorder) scope(ctx context.Context, e *Entry, segs []string, body any) {
	var projectID, teamID, orgID string
	if len(segs) < 2 || !isUUID(segs[1]) {
		if m, ok := body.(map[string]any); ok {
			if id, _ := m["project_id"].(string); isUUID(id) {
				segs = []string{"projects", id}
			}
		}
	}
	if len(segs) < 2 || !isUUID(segs[1]) {
		return
	}
	switch segs[0] {
	case "projects":
		projectID = segs[1]
	case "teams":
		teamID = segs[1]
	case "orgs":
		orgID = segs[1]
	default:
		if r.resources != nil {
			p, ok, err := r.resources.ProjectOfResource(ctx, segs[0], segs[1])
			if err != nil {
				slog.WarnContext(ctx, "audit: resolve resource project", "error", err)
			}
			if ok {
				projectID = p
			}
		}
	}
	if projectID != "" || teamID != "" {
		team, org, err := r.store.ScopeOf(ctx, projectID, teamID)
		if err != nil {
			slog.WarnContext(ctx, "audit: resolve scope", "error", err)
		}
		if team != "" {
			teamID = team
		}
		if org != "" {
			orgID = org
		}
	}
	e.ProjectID, e.TeamID, e.OrgID = optional(projectID), optional(teamID), optional(orgID)
}

// describe names the action and resource from the matched route template, e.g.
// DELETE /projects/:projectID/members/:userID → "projects.members.delete" on
// resource members/<userID>. A create names the new resource by the id in its
// response, and a created project / team / org becomes the entry's scope.
func (r *Recorder) describe(c *fiber.Ctx, e *Entry) {
	segs := apiSegments(e.Path)
	tmpl := segs
	// The matched route's template — unless a middleware answered before any
	// route matched (then c.Route() is the middleware's, whose path is a prefix).
	if rt := c.Route(); rt != nil && rt.Method != "USE" && len(apiSegments(rt.Path)) == len(segs) {
		tmpl = apiSegments(rt.Path)
	} else if t := r.template(e.Method, segs); t != nil {
		tmpl = t
	}
	e.Action, e.ResourceType, e.ResourceID = Describe(e.Method, tmpl, segs)
	if e.ResourceID == "" && e.Method == fiber.MethodPost && e.Outcome == OutcomeSuccess {
		if id := responseID(c); id != "" {
			e.ResourceID = id
			switch e.ResourceType {
			case "projects":
				e.ProjectID = optional(id)
			case "teams":
				e.TeamID = optional(id)
			case "orgs":
				e.OrgID = optional(id)
			}
		}
	}
}

// Describe derives (action, resource type, resource id) from a route
// template's segments and the concrete path's. Param segments (":x") name the
// resource before them; the static segments, dotted, name the action, and a
// verb from the method ends it — unless the route ends in a non-collection
// word, which is the action itself (POST /users/:id/deactivate →
// "users.deactivate").
func Describe(method string, tmpl, segs []string) (action, resourceType, resourceID string) {
	var statics []string
	cur := ""
	for i, s := range tmpl {
		if strings.HasPrefix(s, ":") || strings.HasPrefix(s, "*") {
			resourceType = cur
			if i < len(segs) {
				resourceID = segs[i]
			}
			continue
		}
		cur = s
		statics = append(statics, s)
	}
	if len(statics) == 0 {
		return strings.ToLower(method), "", ""
	}
	last := statics[len(statics)-1]
	endsStatic := len(tmpl) > 0 && tmpl[len(tmpl)-1] == last
	switch {
	case endsStatic && resourceType == "":
		// No id in the path: a collection create, or an instance-wide action.
		resourceType = statics[0]
		if strings.HasSuffix(last, "s") {
			resourceType = last
		}
	case endsStatic && strings.HasSuffix(last, "s") && method == fiber.MethodPost:
		// POST /projects/:id/members: a new member of that project.
		resourceType, resourceID = last, ""
	}
	verb := map[string]string{
		fiber.MethodPost: "create", fiber.MethodPut: "update", fiber.MethodPatch: "update", fiber.MethodDelete: "delete",
	}[method]
	name := strings.Join(statics, ".")
	if endsStatic && method == fiber.MethodPost && !strings.HasSuffix(last, "s") {
		return name, resourceType, resourceID
	}
	return name + "." + verb, resourceType, resourceID
}

// responseID reads the "id" of a JSON response (the resource a POST created).
func responseID(c *fiber.Ctx) string {
	if !strings.HasPrefix(string(c.Response().Header.ContentType()), fiber.MIMEApplicationJSON) {
		return ""
	}
	var out struct {
		ID any `json:"id"`
	}
	if json.Unmarshal(c.Response().Body(), &out) != nil {
		return ""
	}
	if s, ok := out.ID.(string); ok {
		return s
	}
	return ""
}

// statusOf is the status the client will see: an error isn't rendered yet
// when this runs (the app-level logger renders it), so derive it.
func statusOf(c *fiber.Ctx, err error) int {
	if err == nil {
		return c.Response().StatusCode()
	}
	if fe, ok := err.(*fiber.Error); ok {
		return fe.Code
	}
	return fiber.StatusInternalServerError
}

func outcomeOf(status int) string {
	if status >= 400 {
		return OutcomeFailure
	}
	return OutcomeSuccess
}

// write inserts e without ever failing the request: a lost entry is logged
// and counted instead.
func (r *Recorder) write(c *fiber.Ctx, e Entry) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(c.UserContext()), writeTimeout)
	defer cancel()
	if err := r.store.Insert(ctx, e); err != nil {
		slog.ErrorContext(ctx, "audit: entry not written", "error", err, "action", e.Action, "path", e.Path)
		if r.failures != nil {
			r.failures.Add(ctx, 1)
		}
	}
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return new(s)
}
