package compliance

import (
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/audit"
	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/httpx"
)

// Handler exposes frameworks and per-project compliance posture.
type Handler struct {
	repo *Repository
}

// NewHandler constructs a compliance Handler.
func NewHandler(repo *Repository) *Handler {
	return &Handler{repo: repo}
}

// Register mounts compliance routes.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/frameworks", h.ListFrameworks)
	r.Get("/projects/:projectID/compliance", h.Evaluate)
	r.Get("/projects/:projectID/compliance/:framework", h.EvaluateOne)
	r.Put("/projects/:projectID/compliance/:framework/attestations/:code", h.Attest)
	r.Delete("/projects/:projectID/compliance/:framework/attestations/:code", h.RemoveAttestation)
}

// ListFrameworks handles GET /frameworks.
func (h *Handler) ListFrameworks(c *fiber.Ctx) error {
	frameworks, err := h.repo.ListFrameworks(c.UserContext())
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"frameworks": frameworks})
}

// Evaluate handles GET /projects/{id}/compliance — posture across all
// frameworks (or one via ?framework=key).
func (h *Handler) Evaluate(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}

	if key := c.Query("framework"); key != "" {
		return h.evaluateOne(c, projectID, key)
	}

	frameworks, err := h.repo.ListFrameworks(c.UserContext())
	if err != nil {
		return err
	}
	keys := make([]string, len(frameworks))
	for i, fw := range frameworks {
		keys[i] = fw.Key
	}
	results, err := h.repo.EvaluateAll(c.UserContext(), projectID, keys)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"compliance": results})
}

// EvaluateOne handles GET /projects/{id}/compliance/{framework}.
func (h *Handler) EvaluateOne(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	return h.evaluateOne(c, projectID, c.Params("framework"))
}

func (h *Handler) evaluateOne(c *fiber.Ctx, projectID, key string) error {
	res, err := h.repo.Evaluate(c.UserContext(), projectID, key)
	if errors.Is(err, ErrFrameworkNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "framework not found")
	}
	if err != nil {
		return err
	}
	return c.JSON(res)
}

// Attestation note / URL limits.
const (
	maxNote = 4000
	maxURL  = 2048
)

type attestRequest struct {
	Note        string     `json:"note"`
	EvidenceURL string     `json:"evidence_url"`
	ExpiresAt   *time.Time `json:"expires_at"`
}

// Attest handles PUT /projects/{id}/compliance/{framework}/attestations/{code}:
// record how the project meets a manual control (project editor).
func (h *Handler) Attest(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	code, err := url.PathUnescape(c.Params("code"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid control code")
	}
	var in attestRequest
	if err := httpx.Parse(c, &in); err != nil {
		return err
	}
	in.Note, in.EvidenceURL = strings.TrimSpace(in.Note), strings.TrimSpace(in.EvidenceURL)
	switch {
	case in.Note == "":
		return fiber.NewError(fiber.StatusBadRequest, "note is required: say how the control is met")
	case len(in.Note) > maxNote:
		return fiber.NewError(fiber.StatusBadRequest, "note is too long")
	case in.EvidenceURL != "" && !validEvidenceURL(in.EvidenceURL):
		return fiber.NewError(fiber.StatusBadRequest, "evidence_url must be an absolute http(s) URL")
	case in.ExpiresAt != nil && !in.ExpiresAt.After(time.Now()):
		return fiber.NewError(fiber.StatusBadRequest, "expires_at must be in the future")
	}
	key := c.Params("framework")
	before, err := h.repo.GetAttestation(c.UserContext(), projectID, key, code)
	if err != nil && !errors.Is(err, ErrNoAttestation) {
		return attestError(err)
	}
	a, err := h.repo.Attest(c.UserContext(), projectID, key, code, auth.UserID(c),
		AttestationInput{Note: in.Note, EvidenceURL: in.EvidenceURL, ExpiresAt: in.ExpiresAt})
	if err != nil {
		return attestError(err)
	}
	if before.Note != "" {
		audit.SetChanges(c, before, a)
	} else {
		audit.SetChanges(c, nil, a)
	}
	return c.JSON(a)
}

// RemoveAttestation handles DELETE …/attestations/{code} (project editor).
func (h *Handler) RemoveAttestation(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	code, err := url.PathUnescape(c.Params("code"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid control code")
	}
	key := c.Params("framework")
	before, err := h.repo.GetAttestation(c.UserContext(), projectID, key, code)
	if err != nil {
		return attestError(err)
	}
	if err := h.repo.RemoveAttestation(c.UserContext(), projectID, key, code); err != nil {
		return attestError(err)
	}
	audit.SetChanges(c, before, nil)
	return c.SendStatus(fiber.StatusNoContent)
}

func attestError(err error) error {
	switch {
	case errors.Is(err, ErrFrameworkNotFound):
		return fiber.NewError(fiber.StatusNotFound, "framework not found")
	case errors.Is(err, ErrControlNotFound):
		return fiber.NewError(fiber.StatusNotFound, "control not found")
	case errors.Is(err, ErrNoAttestation):
		return fiber.NewError(fiber.StatusNotFound, "control has no attestation")
	case errors.Is(err, ErrNotManual):
		return fiber.NewError(fiber.StatusConflict, "only manual controls are attested; this control is measured from findings")
	}
	return err
}

func validEvidenceURL(s string) bool {
	if len(s) > maxURL {
		return false
	}
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil
}
