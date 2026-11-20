package vex

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xilasec/xila-api/internal/domain"
)

// access answers per-project authorization questions (membership.Repository).
type access interface {
	RoleOnProject(ctx context.Context, userID, projectID string) (domain.TeamRole, bool, error)
}

// DocumentService authorizes and orchestrates stored VEX document management.
// A project/versions-scope document needs editor on its project; a
// vulnerability-scope document (it reads and documents every project's data)
// is admin-only to create, edit, delete or publish. isAdmin is supplied by the
// caller, already DB-checked this request by internal/authz.Middleware.
type DocumentService struct {
	repo   *DocumentRepository
	access access
	prefix string
}

// NewDocumentService wires the document service. prefix is VEX_DOCUMENT_PREFIX
// ("" defaults to "XILA").
func NewDocumentService(repo *DocumentRepository, access access, prefix string) *DocumentService {
	if prefix == "" {
		prefix = "XILA"
	}
	return &DocumentService{repo: repo, access: access, prefix: prefix}
}

func (s *DocumentService) authorize(ctx context.Context, userID string, isAdmin bool, d Document, min domain.TeamRole) error {
	if isAdmin {
		return nil
	}
	if d.ScopeKind == ScopeVulnerability {
		return ErrDocForbidden
	}
	role, ok, err := s.access.RoleOnProject(ctx, userID, d.ProjectID)
	if err != nil {
		return err
	}
	if !ok || !role.AtLeast(min) {
		return ErrDocForbidden
	}
	return nil
}

// List returns the documents visible to the caller: every document for an
// admin, else project/versions-scope documents on their visible projects
// (pids), never a vulnerability-scope one.
func (s *DocumentService) List(ctx context.Context, isAdmin bool, pids []string, limit, offset int) ([]Document, error) {
	return s.repo.List(ctx, Filter{AllAccess: isAdmin, ProjectIDs: pids, Limit: limit, Offset: offset})
}

// Get returns one document the caller may at least view.
func (s *DocumentService) Get(ctx context.Context, userID string, isAdmin bool, id string) (Document, error) {
	d, err := s.repo.Get(ctx, id)
	if err != nil {
		return Document{}, err
	}
	if err := s.authorize(ctx, userID, isAdmin, d, domain.TeamViewer); err != nil {
		return Document{}, err
	}
	return d, nil
}

// Create validates and stores a new document.
func (s *DocumentService) Create(ctx context.Context, userID string, isAdmin bool, d Document, actor *string) (Document, error) {
	if err := d.Validate(); err != nil {
		return Document{}, fmt.Errorf("invalid document: %w", err)
	}
	if err := s.authorize(ctx, userID, isAdmin, d, domain.TeamEditor); err != nil {
		return Document{}, err
	}
	return s.repo.Create(ctx, d, s.prefix, actor)
}

// Update validates and replaces a document's editable fields, authorizing
// against both its current project (can the caller edit it today) and its
// new one (can the caller edit where they're moving it / the new scope).
func (s *DocumentService) Update(ctx context.Context, userID string, isAdmin bool, d Document) (Document, error) {
	existing, err := s.repo.Get(ctx, d.ID)
	if err != nil {
		return Document{}, err
	}
	if err := s.authorize(ctx, userID, isAdmin, existing, domain.TeamEditor); err != nil {
		return Document{}, err
	}
	if err := d.Validate(); err != nil {
		return Document{}, fmt.Errorf("invalid document: %w", err)
	}
	if err := s.authorize(ctx, userID, isAdmin, d, domain.TeamEditor); err != nil {
		return Document{}, err
	}
	return s.repo.Update(ctx, d)
}

// Delete removes a document.
func (s *DocumentService) Delete(ctx context.Context, userID string, isAdmin bool, id string) error {
	d, err := s.repo.Get(ctx, id)
	if err != nil {
		return err
	}
	if err := s.authorize(ctx, userID, isAdmin, d, domain.TeamEditor); err != nil {
		return err
	}
	return s.repo.Delete(ctx, id)
}

// Publish (re-)renders the document and reports whether a new revision was
// appended (false = nothing changed since the last publish).
func (s *DocumentService) Publish(ctx context.Context, userID string, isAdmin bool, id string) (Document, bool, error) {
	d, err := s.repo.Get(ctx, id)
	if err != nil {
		return Document{}, false, err
	}
	if err := s.authorize(ctx, userID, isAdmin, d, domain.TeamEditor); err != nil {
		return Document{}, false, err
	}
	return s.repo.Publish(ctx, id)
}

// ListRevisions returns a document's revision history metadata.
func (s *DocumentService) ListRevisions(ctx context.Context, userID string, isAdmin bool, id string) ([]DocRevisionMeta, error) {
	d, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, userID, isAdmin, d, domain.TeamViewer); err != nil {
		return nil, err
	}
	return d.Revisions, nil
}

// RevisionContent returns one revision's frozen content, with the owning
// document (for the download filename/content type).
func (s *DocumentService) RevisionContent(ctx context.Context, userID string, isAdmin bool, id string, number int) (json.RawMessage, Document, error) {
	d, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, Document{}, err
	}
	if err := s.authorize(ctx, userID, isAdmin, d, domain.TeamViewer); err != nil {
		return nil, Document{}, err
	}
	content, err := s.repo.RevisionContent(ctx, id, number)
	return content, d, err
}
