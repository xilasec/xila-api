// Package badge serves README badges: shields-style SVGs of a project's open
// findings, gate verdict and SLA posture. They are public — a README is read
// by people who aren't signed in — but only to whoever holds the project's
// badge token, so a project id alone reveals nothing.
package badge

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/gate"
	"github.com/xilasec/xila-api/internal/httpx"
	"github.com/xilasec/xila-api/internal/portfolio"
)

// tokenPrefix marks a badge token (never an API credential).
const tokenPrefix = "xb_"

// Kinds of badge.
const (
	KindFindings = "findings"
	KindGate     = "gate"
	KindSLA      = "sla"
)

// Repository stores each project's badge token hash.
type Repository struct{ db *pgxpool.Pool }

// NewRepository constructs the repository.
func NewRepository(db *pgxpool.Pool) *Repository { return &Repository{db: db} }

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Rotate issues a new token for the project, replacing any previous one, and
// returns it — the only time it is ever visible.
func (r *Repository) Rotate(ctx context.Context, projectID, actor string) (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("badge token: %w", err)
	}
	token := tokenPrefix + base64.RawURLEncoding.EncodeToString(buf)
	_, err := r.db.Exec(ctx, `INSERT INTO project_badge_tokens (project_id, token_hash, created_by, created_at)
		VALUES ($1, $2, NULLIF($3, '')::uuid, now())
		ON CONFLICT (project_id) DO UPDATE SET token_hash = EXCLUDED.token_hash,
			created_by = EXCLUDED.created_by, created_at = now()`, projectID, hashToken(token), actor)
	if err != nil {
		return "", fmt.Errorf("store badge token: %w", err)
	}
	return token, nil
}

// Revoke deletes the project's token; its badges stop resolving.
func (r *Repository) Revoke(ctx context.Context, projectID string) error {
	_, err := r.db.Exec(ctx, `DELETE FROM project_badge_tokens WHERE project_id = $1`, projectID)
	return err
}

// Issued reports when the project's current token was issued (nil: none).
func (r *Repository) Issued(ctx context.Context, projectID string) (*time.Time, error) {
	var at time.Time
	err := r.db.QueryRow(ctx, `SELECT created_at FROM project_badge_tokens WHERE project_id = $1`, projectID).Scan(&at)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &at, nil
}

// ProjectFor resolves a token to its project ("" when unknown or revoked).
func (r *Repository) ProjectFor(ctx context.Context, token string) (string, error) {
	if !strings.HasPrefix(token, tokenPrefix) || len(token) > 100 {
		return "", nil
	}
	var pid string
	err := r.db.QueryRow(ctx, `SELECT project_id FROM project_badge_tokens WHERE token_hash = $1`, hashToken(token)).Scan(&pid)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return pid, err
}

// Data sources (the domain repositories).
type (
	overviewSource interface {
		Overview(ctx context.Context, pids []string) (portfolio.Overview, error)
	}
	gatePolicies interface {
		Effective(ctx context.Context, projectID string) (gate.Policy, string, error)
	}
	gateStats interface {
		ComputeGateStats(ctx context.Context, projectID, versionID string, newOnly bool, baselineVersionID string) (finding.GateStats, error)
	}
)

// Handler serves the badge-token management routes (authenticated, owner
// writes) and the public badge SVGs.
type Handler struct {
	repo      *Repository
	overview  overviewSource
	policies  gatePolicies
	stats     gateStats
	publicURL string
}

// NewHandler constructs the handler.
func NewHandler(repo *Repository, overview overviewSource, policies gatePolicies, stats gateStats) *Handler {
	return &Handler{repo: repo, overview: overview, policies: policies, stats: stats}
}

// WithPublicURL sets the origin badge links are built on (PUBLIC_URL); without
// it they use the request's own origin, which behind a proxy may be internal.
func (h *Handler) WithPublicURL(u string) *Handler {
	h.publicURL = strings.TrimRight(u, "/")
	return h
}

// Register mounts the token routes on the authenticated router. authz: GET
// needs project viewer, POST/DELETE project owner (a token publishes data).
func (h *Handler) Register(r fiber.Router) {
	r.Get("/projects/:projectID/badge-token", h.status)
	r.Post("/projects/:projectID/badge-token", h.rotate)
	r.Delete("/projects/:projectID/badge-token", h.revoke)
}

// RegisterPublic mounts the badge SVGs, outside authentication.
func (h *Handler) RegisterPublic(r fiber.Router) {
	r.Get("/badges/:token/:file", h.svg)
}

func (h *Handler) status(c *fiber.Ctx) error {
	pid, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	at, err := h.repo.Issued(c.UserContext(), pid)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"enabled": at != nil, "issued_at": at})
}

func (h *Handler) rotate(c *fiber.Ctx) error {
	pid, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	token, err := h.repo.Rotate(c.UserContext(), pid, auth.UserID(c))
	if err != nil {
		return err
	}
	origin := h.publicURL
	if origin == "" {
		origin = c.BaseURL()
	}
	base := origin + "/api/v1/badges/" + token + "/"
	md := map[string]string{}
	urls := map[string]string{}
	for _, k := range []string{KindFindings, KindGate, KindSLA} {
		urls[k] = base + k + ".svg"
		md[k] = fmt.Sprintf("![Xila %s](%s)", k, urls[k])
	}
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"token": token, "urls": urls, "markdown": md})
}

func (h *Handler) revoke(c *fiber.Ctx) error {
	pid, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	if err := h.repo.Revoke(c.UserContext(), pid); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// svg handles GET /badges/{token}/{kind}.svg. An unknown token and an unknown
// kind look the same — a neutral "unknown" badge with 404 — so the endpoint
// can't be used to probe which tokens exist.
func (h *Handler) svg(c *fiber.Ctx) error {
	c.Set(fiber.HeaderContentType, "image/svg+xml; charset=utf-8")
	c.Set(fiber.HeaderCacheControl, "max-age=300")
	c.Set(fiber.HeaderContentSecurityPolicy, "default-src 'none'; style-src 'unsafe-inline'")
	c.Set(fiber.HeaderXContentTypeOptions, "nosniff")

	kind, ok := strings.CutSuffix(c.Params("file"), ".svg")
	label := map[string]string{KindFindings: "vulnerabilities", KindGate: "security gate", KindSLA: "remediation SLA"}[kind]
	pid := ""
	if ok && label != "" {
		var err error
		if pid, err = h.repo.ProjectFor(c.UserContext(), c.Params("token")); err != nil {
			return err
		}
	}
	if pid == "" {
		return c.Status(fiber.StatusNotFound).SendString(Render(Badge{Label: "xila", Message: "unknown", Color: ColorGrey}))
	}
	b, err := h.badge(c.UserContext(), pid, kind)
	if err != nil {
		return err
	}
	b.Label = label
	return c.SendString(Render(b))
}

// badge computes one badge's message and colour from the live numbers — the
// same ones the project page shows (default version, duplicates collapsed).
func (h *Handler) badge(ctx context.Context, pid, kind string) (Badge, error) {
	switch kind {
	case KindGate:
		policy, _, err := h.policies.Effective(ctx, pid)
		if err != nil {
			return Badge{}, err
		}
		stats, err := h.stats.ComputeGateStats(ctx, pid, "", policy.NewOnly, "")
		if err != nil {
			return Badge{}, err
		}
		// The public badge doesn't check declared scan expectations (that needs
		// an ingesthealth query); require_expected_scans only affects CI's gate.
		if gate.Evaluate(policy, stats, nil).Passed {
			return Badge{Message: "passing", Color: ColorGreen}, nil
		}
		return Badge{Message: "failing", Color: ColorRed}, nil
	}
	ov, err := h.overview.Overview(ctx, []string{pid})
	if err != nil {
		return Badge{}, err
	}
	if kind == KindSLA {
		return slaBadge(ov.SLA), nil
	}
	return findingsBadge(ov.OpenBySeverity), nil
}

// findingsBadge summarises the open backlog by its two worst non-empty
// severities ("2 critical · 5 high"), coloured by the worst.
func findingsBadge(open map[domain.Severity]int) Badge {
	var parts []string
	color := ""
	for _, s := range []domain.Severity{domain.SeverityCritical, domain.SeverityHigh, domain.SeverityMedium, domain.SeverityLow} {
		if n := open[s]; n > 0 && len(parts) < 2 {
			parts = append(parts, fmt.Sprintf("%d %s", n, s))
			if color == "" {
				color = severityColor[s]
			}
		}
	}
	if len(parts) == 0 {
		return Badge{Message: "none", Color: ColorGreen}
	}
	return Badge{Message: strings.Join(parts, " · "), Color: color}
}

// slaBadge shows breaches first (what needs attention), else the on-time share.
func slaBadge(s finding.SLAStats) Badge {
	switch {
	case s.Breached > 0:
		return Badge{Message: fmt.Sprintf("%d breached", s.Breached), Color: ColorRed}
	case s.Compliance == nil:
		return Badge{Message: "on track", Color: ColorGreen}
	}
	pct := *s.Compliance * 100
	color := ColorGreen
	switch {
	case pct < 80:
		color = ColorOrange
	case pct < 95:
		color = ColorYellow
	}
	return Badge{Message: fmt.Sprintf("%.0f%% on time", pct), Color: color}
}
