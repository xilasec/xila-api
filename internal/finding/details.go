package finding

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/httpx"
)

// ManualScanner is the scanner name of findings a person reported by hand
// (internal/engagement). Only their write-up is editable: a scanner's text
// belongs to the scanner and its next report would overwrite an edit.
const ManualScanner = "manual"

// Write-up edit errors.
var (
	ErrNotManual  = errors.New("only a manually reported finding's write-up can be edited")
	ErrEmptyTitle = errors.New("title cannot be empty")
)

// Details is a manual finding's editable write-up. Nil fields are unchanged.
type Details struct {
	Title            *string   `json:"title"`
	Description      *string   `json:"description"`
	StepsToReproduce *string   `json:"steps_to_reproduce"`
	Impact           *string   `json:"impact"`
	Mitigation       *string   `json:"mitigation"`
	References       *[]string `json:"references"`
}

// metadata returns the metadata keys d sets ("" removes a key).
func (d Details) metadata() map[string]string {
	m := map[string]string{}
	for k, v := range map[string]*string{"steps_to_reproduce": d.StepsToReproduce, "impact": d.Impact, "mitigation": d.Mitigation} {
		if v != nil {
			m[k] = strings.TrimSpace(*v)
		}
	}
	if d.References != nil {
		var refs []string
		for _, r := range *d.References {
			if r = strings.TrimSpace(r); r != "" {
				refs = append(refs, r)
			}
		}
		m["references"] = strings.Join(refs, "\n")
	}
	return m
}

// UpdateDetails rewrites a manual finding's write-up, attributed to actor.
func (r *Repository) UpdateDetails(ctx context.Context, id string, d Details, actor string) (Finding, error) {
	if d.Title != nil {
		t := strings.TrimSpace(*d.Title)
		if t == "" {
			return Finding{}, ErrEmptyTitle
		}
		d.Title = &t
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return Finding{}, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	if err := withActor(ctx, tx, actor, "edited write-up"); err != nil {
		return Finding{}, err
	}
	var scanner string
	if err := tx.QueryRow(ctx, `SELECT scanner FROM findings WHERE id = $1 FOR UPDATE`, id).Scan(&scanner); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Finding{}, ErrNotFound
		}
		return Finding{}, fmt.Errorf("lock finding: %w", err)
	}
	if scanner != ManualScanner {
		return Finding{}, ErrNotManual
	}
	// Empty strings drop their metadata key, so a cleared section disappears.
	set, drop := map[string]string{}, []string{}
	for k, v := range d.metadata() {
		if v == "" {
			drop = append(drop, k)
		} else {
			set[k] = v
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE findings SET title = COALESCE($2, title), description = COALESCE($3, description),
			metadata = (COALESCE(metadata, '{}'::jsonb) - $5::text[]) || $4::jsonb, updated_at = now()
		WHERE id = $1`, id, d.Title, d.Description, set, drop); err != nil {
		return Finding{}, fmt.Errorf("update details: %w", err)
	}
	out, err := readFindings(ctx, tx, []string{id})
	if err != nil {
		return Finding{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Finding{}, fmt.Errorf("commit: %w", err)
	}
	return out[0], nil
}

// UpdateDetails handles PATCH /findings/{id}/details (project editor).
func (h *Handler) UpdateDetails(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "findingID")
	if err != nil {
		return err
	}
	if done, err := h.precondition(c, id); done || err != nil {
		return err
	}
	var d Details
	if err := httpx.Parse(c, &d); err != nil {
		return err
	}
	out, err := h.repo.UpdateDetails(c.UserContext(), id, d, auth.UserID(c))
	switch {
	case errors.Is(err, ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "finding not found")
	case errors.Is(err, ErrNotManual):
		return fiber.NewError(fiber.StatusConflict, err.Error())
	case errors.Is(err, ErrEmptyTitle):
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	case err != nil:
		return err
	}
	return c.JSON(out)
}
