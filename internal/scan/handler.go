package scan

import (
	"bytes"
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/xilasec/xila-api/internal/httpx"
)

// Handler exposes scan ingestion and listing over HTTP.
type Handler struct {
	repo   *Repository
	ingest *Service
	async  bool          // enqueue uploads for background processing instead of blocking
	queue  *QueueMonitor // optional: queue depth for /ingest/queue + backpressure
}

// NewHandler constructs a scan Handler. When async is true, uploads are queued
// and return 202 Accepted; a worker pool processes them off the request path.
// queue may be nil (no queue reporting, no backpressure).
func NewHandler(repo *Repository, ingest *Service, async bool, queue *QueueMonitor) *Handler {
	return &Handler{repo: repo, ingest: ingest, async: async, queue: queue}
}

// Register mounts scan routes.
func (h *Handler) Register(r fiber.Router) {
	r.Post("/projects/:projectID/scans", h.Ingest)
	r.Get("/projects/:projectID/scans", h.List)
	r.Get("/scans/:scanID", h.Get)
	r.Get("/ingest/queue", h.Queue)
}

// Queue handles GET /ingest/queue — how far behind ingestion is (admin).
func (h *Handler) Queue(c *fiber.Ctx) error {
	if h.queue == nil {
		return c.JSON(fiber.Map{"async": false})
	}
	s := h.queue.Snapshot()
	return c.JSON(fiber.Map{
		"async":               h.async,
		"pending":             s.Pending,
		"processing":          s.Processing,
		"failed":              s.Failed,
		"oldest_wait_seconds": s.OldestWaitSeconds,
		"saturated":           h.queue.Saturated(),
	})
}

// Ingest handles POST /projects/{id}/scans.
//
// The request body is the raw scanner output (e.g. `trivy --format json`).
// Metadata is passed as query parameters:
//
//	POST /projects/{id}/scans?scanner=trivy&branch=main&commit=abc123
//	POST /projects/{id}/scans?scanner=trivy&release=v1.4.0
//	Content-Type: application/json
//	<raw trivy report>
func (h *Handler) Ingest(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	scannerName := strings.TrimSpace(c.Query("scanner"))
	if scannerName == "" {
		return fiber.NewError(fiber.StatusBadRequest, "scanner query parameter is required")
	}
	if len(c.Body()) == 0 {
		return fiber.NewError(fiber.StatusBadRequest, "request body (raw scan output) is required")
	}
	if c.Query("branch") != "" && c.Query("release") != "" {
		return fiber.NewError(fiber.StatusBadRequest, "give branch or release, not both")
	}

	req := IngestRequest{
		ProjectID:    projectID,
		AssetID:      c.Query("asset_id"),
		Scanner:      scannerName,
		Format:       c.Query("format"),
		CommitSHA:    c.Query("commit"),
		Branch:       strings.TrimSpace(c.Query("branch")),
		Release:      strings.TrimSpace(c.Query("release")),
		EngagementID: c.Query("engagement_id"),
		CloseMissing: c.QueryBool("close_missing", true),
		Force:        c.QueryBool("force", false),
	}
	if req.EngagementID != "" {
		if uuid.Validate(req.EngagementID) != nil {
			return fiber.NewError(fiber.StatusBadRequest, ErrUnknownEngagement.Error())
		}
	}

	// Shed load rather than accept work we cannot get to: a queued-but-unprocessed
	// scan looks ingested to the client, so its gate verdict would be based on a
	// backlog we never updated. Better to tell CI to come back.
	if h.async && h.queue != nil && h.queue.Saturated() {
		c.Set(fiber.HeaderRetryAfter, "30")
		return fiber.NewError(fiber.StatusTooManyRequests, "ingest queue is saturated; retry shortly")
	}

	// Async: persist the payload + a scan row and return 202 immediately; a worker
	// runs the pipeline. Sync: process inline and return 201 with the finished scan.
	var sc Scan
	if h.async {
		sc, err = h.ingest.Enqueue(c.UserContext(), req, append([]byte(nil), c.Body()...))
	} else {
		sc, err = h.ingest.Ingest(c.UserContext(), req, bytes.NewReader(c.Body()))
	}
	switch {
	case errors.Is(err, ErrProjectNotFound):
		return fiber.NewError(fiber.StatusNotFound, "project not found")
	case errors.Is(err, ErrUnknownEngagement):
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	case errors.Is(err, ErrCollection):
		return fiber.NewError(fiber.StatusConflict, err.Error())
	case errors.Is(err, ErrUnknownScanner):
		return fiber.NewError(fiber.StatusBadRequest, "unknown scanner: "+scannerName)
	case err != nil:
		// A parse failure is a bad request from the caller's perspective.
		return fiber.NewError(fiber.StatusUnprocessableEntity, err.Error())
	}
	if h.async {
		return c.Status(fiber.StatusAccepted).JSON(sc)
	}
	return c.Status(fiber.StatusCreated).JSON(sc)
}

// List handles GET /projects/{id}/scans.
func (h *Handler) List(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	scans, err := h.repo.List(c.UserContext(), projectID, c.QueryBool("archived"))
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"scans": scans})
}

// Get handles GET /scans/{id}.
func (h *Handler) Get(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "scanID")
	if err != nil {
		return err
	}
	sc, err := h.repo.Get(c.UserContext(), id)
	if errors.Is(err, ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "scan not found")
	}
	if err != nil {
		return err
	}
	return c.JSON(sc)
}
