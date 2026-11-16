package scim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/audit"
	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/httpx"
)

// Schema URNs (RFC 7643/7644).
const (
	schemaUser       = "urn:ietf:params:scim:schemas:core:2.0:User"
	schemaGroup      = "urn:ietf:params:scim:schemas:core:2.0:Group"
	schemaList       = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	schemaError      = "urn:ietf:params:scim:api:messages:2.0:Error"
	schemaPatch      = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	schemaSPConfig   = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	schemaResType    = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	schemaSchema     = "urn:ietf:params:scim:schemas:core:2.0:Schema"
	contentType      = "application/scim+json"
	maxPage          = 200
	tokenKey         = "scimToken"
	auditResourceTag = "scim"
)

// auditWriter records SCIM's own audit entries (audit.Repository).
type auditWriter interface {
	Insert(ctx context.Context, e audit.Entry) error
}

// Handler serves the SCIM endpoints (/scim/v2, outside the session-authenticated
// API) and the admin's token management (/scim-tokens, on the secured API).
type Handler struct {
	store *Store
	audit auditWriter
}

// NewHandler constructs a Handler; audit may be nil.
func NewHandler(store *Store, audit auditWriter) *Handler {
	return &Handler{store: store, audit: audit}
}

// RegisterAdmin mounts token management on the secured API (instance admin,
// enforced by authz).
func (h *Handler) RegisterAdmin(r fiber.Router) {
	r.Get("/scim-tokens", h.listTokens)
	r.Post("/scim-tokens", h.createToken)
	r.Delete("/scim-tokens/:tokenID", h.revokeToken)
}

// RegisterSCIM mounts the SCIM protocol endpoints under r (…/scim/v2). They
// authenticate with a SCIM token only.
func (h *Handler) RegisterSCIM(r fiber.Router) {
	// The token check sits on each route, not on a group, so no catch-all
	// /scim/v2 route exists.
	a := h.authenticate
	r.Get("/scim/v2/ServiceProviderConfig", a, h.serviceProviderConfig)
	r.Get("/scim/v2/ResourceTypes", a, h.resourceTypes)
	r.Get("/scim/v2/Schemas", a, h.schemas)
	r.Get("/scim/v2/Users", a, h.listUsers)
	r.Post("/scim/v2/Users", a, h.createUser)
	r.Get("/scim/v2/Users/:id", a, h.getUser)
	r.Put("/scim/v2/Users/:id", a, h.replaceUser)
	r.Patch("/scim/v2/Users/:id", a, h.patchUser)
	r.Delete("/scim/v2/Users/:id", a, h.deleteUser)
	r.Get("/scim/v2/Groups", a, h.listGroups)
	r.Post("/scim/v2/Groups", a, h.createGroup)
	r.Get("/scim/v2/Groups/:id", a, h.getGroup)
	r.Put("/scim/v2/Groups/:id", a, h.replaceGroup)
	r.Patch("/scim/v2/Groups/:id", a, h.patchGroup)
	r.Delete("/scim/v2/Groups/:id", a, h.deleteGroup)
}

// --- token management (admin) ---

type createTokenRequest struct {
	Name  string `json:"name"`
	OrgID string `json:"org_id"`
}

func (h *Handler) listTokens(c *fiber.Ctx) error {
	ts, err := h.store.ListTokens(c.UserContext())
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"tokens": ts})
}

func (h *Handler) createToken(c *fiber.Ctx) error {
	if a := auth.CurrentActor(c); a.IsToken {
		return fiber.NewError(fiber.StatusForbidden, "API tokens can't create SCIM tokens; sign in")
	}
	var body createTokenRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" || body.OrgID == "" {
		return fiber.NewError(fiber.StatusBadRequest, "name and org_id are required")
	}
	t, secret, err := h.store.CreateToken(c.UserContext(), body.Name, body.OrgID, auth.UserID(c))
	if errors.Is(err, ErrNotFound) {
		return fiber.NewError(fiber.StatusBadRequest, "organization not found")
	}
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"token": t, "secret": secret})
}

func (h *Handler) revokeToken(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "tokenID")
	if err != nil {
		return err
	}
	if err := h.store.RevokeToken(c.UserContext(), id); errors.Is(err, ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "token not found")
	} else if err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// --- protocol plumbing ---

// scimError writes an RFC 7644 §3.12 error.
func scimError(c *fiber.Ctx, status int, scimType, detail string) error {
	body := fiber.Map{"schemas": []string{schemaError}, "status": strconv.Itoa(status), "detail": detail}
	if scimType != "" {
		body["scimType"] = scimType
	}
	c.Set(fiber.HeaderContentType, contentType)
	return c.Status(status).JSON(body)
}

// fail maps a store error onto a SCIM error.
func fail(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, ErrNotFound):
		return scimError(c, fiber.StatusNotFound, "", "resource not found")
	case errors.Is(err, ErrUniqueness):
		return scimError(c, fiber.StatusConflict, "uniqueness", "a resource with that userName, displayName or externalId already exists")
	case errors.Is(err, ErrProtected):
		return scimError(c, fiber.StatusForbidden, "mutability", err.Error())
	case errors.Is(err, errInvalid):
		return scimError(c, fiber.StatusBadRequest, "invalidValue", err.Error())
	}
	slog.ErrorContext(c.UserContext(), "scim request failed", "path", c.Path(), "error", err)
	return scimError(c, fiber.StatusInternalServerError, "", "internal error")
}

func send(c *fiber.Ctx, status int, v any) error {
	c.Set(fiber.HeaderContentType, contentType)
	return c.Status(status).JSON(v)
}

func (h *Handler) authenticate(c *fiber.Ctx) error {
	raw, ok := strings.CutPrefix(c.Get(fiber.HeaderAuthorization), "Bearer ")
	if !ok {
		err := scimError(c, fiber.StatusUnauthorized, "", "a SCIM bearer token is required")
		h.record(c, Token{})
		return err
	}
	t, err := h.store.Authenticate(c.UserContext(), strings.TrimSpace(raw))
	if errors.Is(err, ErrUnauthorized) {
		err := scimError(c, fiber.StatusUnauthorized, "", err.Error())
		h.record(c, Token{})
		return err
	}
	if err != nil {
		return fail(c, err)
	}
	c.Locals(tokenKey, t)
	err = c.Next()
	h.record(c, t)
	return err
}

func token(c *fiber.Ctx) Token {
	t, _ := c.Locals(tokenKey).(Token)
	return t
}

// record writes one audit entry per SCIM change: who (the token), what, and
// the outcome. The body isn't stored: it carries only directory attributes.
// A refused token (t.ID == "") is recorded as an anonymous failure, reads
// included: someone is probing the provisioning endpoint.
func (h *Handler) record(c *fiber.Ctx, t Token) {
	if h.audit == nil || (t.ID != "" && c.Method() == fiber.MethodGet) {
		return
	}
	segs := strings.Split(strings.Trim(c.Path(), "/"), "/")
	resource, id := "", ""
	for i, s := range segs {
		if s == "Users" || s == "Groups" {
			resource = strings.ToLower(strings.TrimSuffix(s, "s"))
			if i+1 < len(segs) {
				id = segs[i+1]
			}
		}
	}
	verb := map[string]string{fiber.MethodPost: "create", fiber.MethodPut: "replace", fiber.MethodPatch: "update", fiber.MethodDelete: "delete"}[c.Method()]
	status := c.Response().StatusCode()
	outcome := "success"
	if status >= 400 {
		outcome = "failure"
	}
	if verb == "" {
		verb = "read"
	}
	e := audit.Entry{
		ActorKind: auditResourceTag, ActorEmail: "scim:" + t.Name,
		Action: "scim." + resource + "s." + verb, ResourceType: resource, ResourceID: id,
		Method: c.Method(), Path: c.Path(), ClientIP: c.IP(), Status: status, Outcome: outcome,
		RequestID: c.GetRespHeader(fiber.HeaderXRequestID),
	}
	if t.ID == "" {
		e.ActorKind, e.ActorEmail, e.Action = "anonymous", "", "scim.auth"
	} else {
		org := t.OrgID
		e.OrgID = &org
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(c.UserContext()), 5*time.Second)
	defer cancel()
	if err := h.audit.Insert(ctx, e); err != nil {
		slog.WarnContext(ctx, "scim audit entry failed", "error", err)
	}
}

// page reads startIndex (1-based) and count.
func page(c *fiber.Ctx) (offset, limit, start int) {
	start = c.QueryInt("startIndex", 1)
	if start < 1 {
		start = 1
	}
	limit = c.QueryInt("count", 100)
	if limit < 0 {
		limit = 0
	}
	if limit > maxPage {
		limit = maxPage
	}
	return start - 1, limit, start
}

var filterRE = regexp.MustCompile(`^\s*([A-Za-z.]+)\s+(?i:eq)\s+"((?:[^"\\]|\\.)*)"\s*$`)

// parseFilter reads `attr eq "value"`, the only filter IdPs send for
// provisioning; attrs maps the accepted attribute names (case-insensitive)
// to their canonical form.
func parseFilter(raw string, attrs map[string]string) (attr, value string, ok bool) {
	if strings.TrimSpace(raw) == "" {
		return "", "", true
	}
	m := filterRE.FindStringSubmatch(raw)
	if m == nil {
		return "", "", false
	}
	a, known := attrs[strings.ToLower(m[1])]
	if !known {
		return "", "", false
	}
	v, err := strconv.Unquote(`"` + m[2] + `"`)
	if err != nil {
		return "", "", false
	}
	return a, v, true
}

func location(c *fiber.Ctx, kind, id string) string {
	return c.BaseURL() + strings.TrimSuffix(c.Path()[:strings.Index(c.Path(), "/scim/v2")], "/") + "/scim/v2/" + kind + "/" + id
}

func meta(c *fiber.Ctx, kind, id string, created, modified time.Time) fiber.Map {
	return fiber.Map{
		"resourceType": strings.TrimSuffix(kind, "s"), "created": created.UTC().Format(time.RFC3339),
		"lastModified": modified.UTC().Format(time.RFC3339), "location": location(c, kind, id),
	}
}

// --- users ---

func userJSON(c *fiber.Ctx, u User) fiber.Map {
	groups := make([]fiber.Map, 0, len(u.Groups))
	for _, g := range u.Groups {
		groups = append(groups, fiber.Map{"value": g.ID, "display": g.Display, "$ref": location(c, "Groups", g.ID)})
	}
	m := fiber.Map{
		"schemas": []string{schemaUser}, "id": u.ID, "userName": u.Email, "displayName": u.Email,
		"emails": []fiber.Map{{"value": u.Email, "primary": true, "type": "work"}},
		"active": u.Active, "groups": groups, "meta": meta(c, "Users", u.ID, u.CreatedAt, u.UpdatedAt),
	}
	if u.ExternalID != nil {
		m["externalId"] = *u.ExternalID
	}
	return m
}

var userFilterAttrs = map[string]string{"username": "userName", "externalid": "externalId", "emails.value": "userName", "emails": "userName"}

func (h *Handler) listUsers(c *fiber.Ctx) error {
	attr, value, ok := parseFilter(c.Query("filter"), userFilterAttrs)
	if !ok {
		return scimError(c, fiber.StatusBadRequest, "invalidFilter", `only 'userName eq "…"' and 'externalId eq "…"' filters are supported`)
	}
	offset, limit, start := page(c)
	us, total, err := h.store.ListUsers(c.UserContext(), token(c).OrgID, UserFilter{Attr: attr, Value: value}, offset, limit)
	if err != nil {
		return fail(c, err)
	}
	res := make([]fiber.Map, len(us))
	for i, u := range us {
		res[i] = userJSON(c, u)
	}
	return send(c, fiber.StatusOK, fiber.Map{"schemas": []string{schemaList}, "totalResults": total,
		"startIndex": start, "itemsPerPage": len(res), "Resources": res})
}

func (h *Handler) getUser(c *fiber.Ctx) error {
	u, err := h.store.GetUser(c.UserContext(), token(c).OrgID, c.Params("id"))
	if err != nil {
		return fail(c, err)
	}
	return send(c, fiber.StatusOK, userJSON(c, u))
}

// userBody is the part of a SCIM User Xila keeps. Names and other profile
// attributes are accepted and ignored: Xila knows a person by email.
type userBody struct {
	UserName   string           `json:"userName"`
	ExternalID *string          `json:"externalId"`
	Active     *json.RawMessage `json:"active"`
	Emails     []struct {
		Value   string `json:"value"`
		Primary bool   `json:"primary"`
	} `json:"emails"`
}

// email is the userName, else the primary (or first) email.
func (b userBody) email() string {
	if strings.TrimSpace(b.UserName) != "" {
		return b.UserName
	}
	for _, e := range b.Emails {
		if e.Primary {
			return e.Value
		}
	}
	if len(b.Emails) > 0 {
		return b.Emails[0].Value
	}
	return ""
}

// boolValue reads a SCIM boolean, which some IdPs (Azure AD / Entra) send as
// the string "True" / "False".
func boolValue(raw json.RawMessage) (bool, error) {
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		return b, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if v, err := strconv.ParseBool(strings.ToLower(strings.TrimSpace(s))); err == nil {
			return v, nil
		}
	}
	return false, fmt.Errorf("%w: active must be a boolean", errInvalid)
}

func (h *Handler) createUser(c *fiber.Ctx) error {
	var b userBody
	if err := json.Unmarshal(c.Body(), &b); err != nil {
		return scimError(c, fiber.StatusBadRequest, "invalidSyntax", "the body is not a SCIM User")
	}
	email := strings.TrimSpace(b.email())
	if !strings.Contains(email, "@") {
		return scimError(c, fiber.StatusBadRequest, "invalidValue", "userName must be the user's email address")
	}
	active := true
	if b.Active != nil {
		v, err := boolValue(*b.Active)
		if err != nil {
			return fail(c, err)
		}
		active = v
	}
	ext := ""
	if b.ExternalID != nil {
		ext = *b.ExternalID
	}
	u, err := h.store.CreateUser(c.UserContext(), token(c).OrgID, email, ext, active)
	if err != nil {
		return fail(c, err)
	}
	return send(c, fiber.StatusCreated, userJSON(c, u))
}

func (h *Handler) replaceUser(c *fiber.Ctx) error {
	var b userBody
	if err := json.Unmarshal(c.Body(), &b); err != nil {
		return scimError(c, fiber.StatusBadRequest, "invalidSyntax", "the body is not a SCIM User")
	}
	org, id := token(c).OrgID, c.Params("id")
	email := b.email()
	ext := ""
	if b.ExternalID != nil {
		ext = *b.ExternalID
	}
	if err := h.store.UpdateUser(c.UserContext(), org, id, &email, &ext); err != nil {
		return fail(c, err)
	}
	active := true
	if b.Active != nil {
		v, err := boolValue(*b.Active)
		if err != nil {
			return fail(c, err)
		}
		active = v
	}
	if err := h.store.SetActive(c.UserContext(), org, id, active); err != nil {
		return fail(c, err)
	}
	return h.respondUser(c, org, id)
}

// respondUser answers with the user, or 204 when the change took them out of
// this org (a deactivated multi-org user).
func (h *Handler) respondUser(c *fiber.Ctx, org, id string) error {
	u, err := h.store.GetUser(c.UserContext(), org, id)
	if errors.Is(err, ErrNotFound) {
		return c.SendStatus(fiber.StatusNoContent)
	}
	if err != nil {
		return fail(c, err)
	}
	return send(c, fiber.StatusOK, userJSON(c, u))
}

type patchOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value"`
}

type patchBody struct {
	Schemas    []string  `json:"schemas"`
	Operations []patchOp `json:"Operations"`
}

func readPatch(c *fiber.Ctx) (patchBody, error) {
	var p patchBody
	if err := json.Unmarshal(c.Body(), &p); err != nil || len(p.Operations) == 0 {
		return p, fmt.Errorf("%w: the body is not a SCIM PatchOp", errInvalid)
	}
	for i := range p.Operations {
		p.Operations[i].Op = strings.ToLower(p.Operations[i].Op)
		switch p.Operations[i].Op {
		case "add", "replace", "remove":
		default:
			return p, fmt.Errorf("%w: unknown op %q", errInvalid, p.Operations[i].Op)
		}
	}
	return p, nil
}

func (h *Handler) patchUser(c *fiber.Ctx) error {
	p, err := readPatch(c)
	if err != nil {
		return fail(c, err)
	}
	org, id := token(c).OrgID, c.Params("id")
	ctx := c.UserContext()
	if _, err := h.store.GetUser(ctx, org, id); err != nil {
		return fail(c, err)
	}
	var active *bool
	var email, ext *string
	set := func(path string, raw json.RawMessage) error {
		switch strings.ToLower(path) {
		case "active":
			v, err := boolValue(raw)
			if err != nil {
				return err
			}
			active = &v
		case "username", "emails", `emails[type eq "work"].value`, "emails[primary eq true].value":
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				var list []struct {
					Value string `json:"value"`
				}
				if json.Unmarshal(raw, &list) != nil || len(list) == 0 {
					return fmt.Errorf("%w: %s must be a string", errInvalid, path)
				}
				s = list[0].Value
			}
			email = &s
		case "externalid":
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				return fmt.Errorf("%w: externalId must be a string", errInvalid)
			}
			ext = &s
		}
		return nil // names and other profile attributes: accepted, not kept
	}
	for _, op := range p.Operations {
		if op.Op == "remove" {
			if strings.EqualFold(op.Path, "externalId") {
				empty := ""
				ext = &empty
			}
			continue
		}
		if op.Path != "" {
			if err := set(op.Path, op.Value); err != nil {
				return fail(c, err)
			}
			continue
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(op.Value, &fields); err != nil {
			return fail(c, fmt.Errorf("%w: a path-less operation needs an object value", errInvalid))
		}
		for k, v := range fields {
			if err := set(k, v); err != nil {
				return fail(c, err)
			}
		}
	}
	if email != nil || ext != nil {
		if err := h.store.UpdateUser(ctx, org, id, email, ext); err != nil {
			return fail(c, err)
		}
	}
	if active != nil {
		if err := h.store.SetActive(ctx, org, id, *active); err != nil {
			return fail(c, err)
		}
	}
	return h.respondUser(c, org, id)
}

func (h *Handler) deleteUser(c *fiber.Ctx) error {
	if err := h.store.Remove(c.UserContext(), token(c).OrgID, c.Params("id")); err != nil {
		return fail(c, err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// --- groups ---

func groupJSON(c *fiber.Ctx, g Group, withMembers bool) fiber.Map {
	m := fiber.Map{"schemas": []string{schemaGroup}, "id": g.ID, "displayName": g.Name,
		"meta": meta(c, "Groups", g.ID, g.CreatedAt, g.UpdatedAt)}
	if withMembers {
		members := make([]fiber.Map, 0, len(g.Members))
		for _, u := range g.Members {
			members = append(members, fiber.Map{"value": u.ID, "display": u.Display, "$ref": location(c, "Users", u.ID)})
		}
		m["members"] = members
	}
	if g.ExternalID != nil {
		m["externalId"] = *g.ExternalID
	}
	return m
}

var groupFilterAttrs = map[string]string{"displayname": "displayName", "externalid": "externalId"}

func (h *Handler) listGroups(c *fiber.Ctx) error {
	attr, value, ok := parseFilter(c.Query("filter"), groupFilterAttrs)
	if !ok {
		return scimError(c, fiber.StatusBadRequest, "invalidFilter", `only 'displayName eq "…"' and 'externalId eq "…"' filters are supported`)
	}
	withMembers := !strings.Contains(strings.ToLower(c.Query("excludedAttributes")), "members")
	offset, limit, start := page(c)
	gs, total, err := h.store.ListGroups(c.UserContext(), token(c).OrgID, GroupFilter{Attr: attr, Value: value}, offset, limit, withMembers)
	if err != nil {
		return fail(c, err)
	}
	res := make([]fiber.Map, len(gs))
	for i, g := range gs {
		res[i] = groupJSON(c, g, withMembers)
	}
	return send(c, fiber.StatusOK, fiber.Map{"schemas": []string{schemaList}, "totalResults": total,
		"startIndex": start, "itemsPerPage": len(res), "Resources": res})
}

func (h *Handler) getGroup(c *fiber.Ctx) error {
	g, err := h.store.GetGroup(c.UserContext(), token(c).OrgID, c.Params("id"))
	if err != nil {
		return fail(c, err)
	}
	return send(c, fiber.StatusOK, groupJSON(c, g, true))
}

type memberRef struct {
	Value string `json:"value"`
}

type groupBody struct {
	DisplayName string      `json:"displayName"`
	ExternalID  *string     `json:"externalId"`
	Members     []memberRef `json:"members"`
}

func memberIDs(ms []memberRef) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		if v := strings.TrimSpace(m.Value); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func (h *Handler) createGroup(c *fiber.Ctx) error {
	var b groupBody
	if err := json.Unmarshal(c.Body(), &b); err != nil || strings.TrimSpace(b.DisplayName) == "" {
		return scimError(c, fiber.StatusBadRequest, "invalidValue", "displayName is required")
	}
	ext := ""
	if b.ExternalID != nil {
		ext = *b.ExternalID
	}
	g, err := h.store.CreateGroup(c.UserContext(), token(c).OrgID, strings.TrimSpace(b.DisplayName), ext, memberIDs(b.Members))
	if err != nil {
		return fail(c, err)
	}
	return send(c, fiber.StatusCreated, groupJSON(c, g, true))
}

func (h *Handler) replaceGroup(c *fiber.Ctx) error {
	var b groupBody
	if err := json.Unmarshal(c.Body(), &b); err != nil {
		return scimError(c, fiber.StatusBadRequest, "invalidSyntax", "the body is not a SCIM Group")
	}
	org, id, ctx := token(c).OrgID, c.Params("id"), c.UserContext()
	name := strings.TrimSpace(b.DisplayName)
	ext := ""
	if b.ExternalID != nil {
		ext = *b.ExternalID
	}
	if err := h.store.UpdateGroup(ctx, org, id, &name, &ext); err != nil {
		return fail(c, err)
	}
	if err := h.store.SetMembers(ctx, org, id, memberIDs(b.Members)); err != nil {
		return fail(c, err)
	}
	return h.getGroup(c)
}

// memberPathRE matches `members[value eq "id"]`, how IdPs remove one member.
var memberPathRE = regexp.MustCompile(`^(?i:members)\[\s*(?i:value)\s+(?i:eq)\s+"([^"]+)"\s*\]$`)

func (h *Handler) patchGroup(c *fiber.Ctx) error {
	p, err := readPatch(c)
	if err != nil {
		return fail(c, err)
	}
	org, id, ctx := token(c).OrgID, c.Params("id"), c.UserContext()
	if _, err := h.store.GetGroup(ctx, org, id); err != nil {
		return fail(c, err)
	}
	members := func(raw json.RawMessage) ([]string, error) {
		var ms []memberRef
		if err := json.Unmarshal(raw, &ms); err != nil {
			var one memberRef
			if json.Unmarshal(raw, &one) != nil {
				return nil, fmt.Errorf("%w: members must be a list of {\"value\": id}", errInvalid)
			}
			ms = []memberRef{one}
		}
		return memberIDs(ms), nil
	}
	for _, op := range p.Operations {
		path := strings.TrimSpace(op.Path)
		var err error
		switch {
		case memberPathRE.MatchString(path) && op.Op == "remove":
			err = h.store.RemoveMembers(ctx, org, id, []string{memberPathRE.FindStringSubmatch(path)[1]})
		case strings.EqualFold(path, "members"):
			var ids []string
			if op.Op != "remove" || len(op.Value) > 0 {
				if ids, err = members(op.Value); err != nil {
					return fail(c, err)
				}
			}
			switch {
			case op.Op == "add":
				err = h.store.AddMembers(ctx, org, id, ids)
			case op.Op == "replace":
				err = h.store.SetMembers(ctx, org, id, ids)
			case len(op.Value) == 0: // remove every member
				err = h.store.SetMembers(ctx, org, id, nil)
			default:
				err = h.store.RemoveMembers(ctx, org, id, ids)
			}
		case strings.EqualFold(path, "displayName"):
			var name string
			if json.Unmarshal(op.Value, &name) != nil {
				return fail(c, fmt.Errorf("%w: displayName must be a string", errInvalid))
			}
			err = h.store.UpdateGroup(ctx, org, id, &name, nil)
		case strings.EqualFold(path, "externalId"):
			ext := ""
			if op.Op != "remove" && json.Unmarshal(op.Value, &ext) != nil {
				return fail(c, fmt.Errorf("%w: externalId must be a string", errInvalid))
			}
			err = h.store.UpdateGroup(ctx, org, id, nil, &ext)
		case path == "":
			var b groupBody
			if json.Unmarshal(op.Value, &b) != nil {
				return fail(c, fmt.Errorf("%w: a path-less operation needs an object value", errInvalid))
			}
			var name *string
			if strings.TrimSpace(b.DisplayName) != "" {
				n := strings.TrimSpace(b.DisplayName)
				name = &n
			}
			if err = h.store.UpdateGroup(ctx, org, id, name, b.ExternalID); err == nil && b.Members != nil {
				if op.Op == "add" {
					err = h.store.AddMembers(ctx, org, id, memberIDs(b.Members))
				} else {
					err = h.store.SetMembers(ctx, org, id, memberIDs(b.Members))
				}
			}
		default:
			return fail(c, fmt.Errorf("%w: unsupported path %q", errInvalid, path))
		}
		if err != nil {
			return fail(c, err)
		}
	}
	if strings.Contains(strings.ToLower(c.Query("excludedAttributes")), "members") {
		return c.SendStatus(fiber.StatusNoContent)
	}
	return h.getGroup(c)
}

func (h *Handler) deleteGroup(c *fiber.Ctx) error {
	if err := h.store.DeleteGroup(c.UserContext(), token(c).OrgID, c.Params("id")); err != nil {
		return fail(c, err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// --- discovery ---

func (h *Handler) serviceProviderConfig(c *fiber.Ctx) error {
	return send(c, fiber.StatusOK, fiber.Map{
		"schemas":        []string{schemaSPConfig},
		"patch":          fiber.Map{"supported": true},
		"bulk":           fiber.Map{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":         fiber.Map{"supported": true, "maxResults": maxPage},
		"changePassword": fiber.Map{"supported": false},
		"sort":           fiber.Map{"supported": false},
		"etag":           fiber.Map{"supported": false},
		"authenticationSchemes": []fiber.Map{{
			"type": "oauthbearertoken", "name": "Bearer token", "primary": true,
			"description": "A SCIM token created by a Xila admin (Admin, SCIM).",
		}},
	})
}

func (h *Handler) resourceTypes(c *fiber.Ctx) error {
	types := []fiber.Map{
		{"schemas": []string{schemaResType}, "id": "User", "name": "User", "endpoint": "/Users", "schema": schemaUser},
		{"schemas": []string{schemaResType}, "id": "Group", "name": "Group", "endpoint": "/Groups", "schema": schemaGroup},
	}
	return send(c, fiber.StatusOK, fiber.Map{"schemas": []string{schemaList}, "totalResults": len(types),
		"startIndex": 1, "itemsPerPage": len(types), "Resources": types})
}

func attr(name, typ string, required bool, extra fiber.Map) fiber.Map {
	m := fiber.Map{"name": name, "type": typ, "multiValued": false, "required": required,
		"caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func (h *Handler) schemas(c *fiber.Ctx) error {
	user := fiber.Map{"schemas": []string{schemaSchema}, "id": schemaUser, "name": "User", "attributes": []fiber.Map{
		attr("userName", "string", true, fiber.Map{"uniqueness": "server", "description": "The user's email address."}),
		attr("externalId", "string", false, nil),
		attr("active", "boolean", false, nil),
		attr("emails", "complex", false, fiber.Map{"multiValued": true}),
		attr("groups", "complex", false, fiber.Map{"multiValued": true, "mutability": "readOnly"}),
	}}
	group := fiber.Map{"schemas": []string{schemaSchema}, "id": schemaGroup, "name": "Group", "attributes": []fiber.Map{
		attr("displayName", "string", true, fiber.Map{"uniqueness": "server"}),
		attr("externalId", "string", false, nil),
		attr("members", "complex", false, fiber.Map{"multiValued": true}),
	}}
	return send(c, fiber.StatusOK, fiber.Map{"schemas": []string{schemaList}, "totalResults": 2,
		"startIndex": 1, "itemsPerPage": 2, "Resources": []fiber.Map{user, group}})
}
