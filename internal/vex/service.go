package vex

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
)

// vexResponseDomain converts stored response strings (already filtered to
// known values by the importer) to domain.VexResponse, dropping anything
// that somehow doesn't validate rather than guessing.
func vexResponseDomain(ss []string) []domain.VexResponse {
	var out []domain.VexResponse
	for _, s := range ss {
		r := domain.VexResponse(s)
		if r.Valid() {
			out = append(out, r)
		}
	}
	return out
}

// maxVexBytes caps how much of an upload we buffer.
const maxVexBytes = 16 << 20

// vexActor is recorded as the actor on findings this engine triages, so a human
// reading the audit trail can see the decision came from a VEX document and not
// from a person.
const vexActor = "vex"

// statementStore reads a project's statements (Repository satisfies it).
type statementStore interface {
	Upsert(ctx context.Context, s Statement) (Statement, error)
	ListByProject(ctx context.Context, projectID string) ([]Statement, error)
}

// findingStore is the subset of the finding repository the engine needs — the
// same shape auto-triage uses.
type findingStore interface {
	ListForTriage(ctx context.Context, projectID string) ([]finding.Finding, error)
	ListForTriageScan(ctx context.Context, projectID, scanID string) ([]finding.Finding, error)
	SetStatus(ctx context.Context, id string, t finding.Triage) (finding.Finding, error)
}

// projectChecker verifies a project exists before an upload.
type projectChecker interface {
	Exists(ctx context.Context, id string) (bool, error)
}

// ErrProjectNotFound is returned when uploading against a missing project.
var ErrProjectNotFound = ErrNoProject

// Service ingests VEX documents and applies their verdicts to findings.
type Service struct {
	statements statementStore
	findings   findingStore
	projects   projectChecker
}

// NewService wires the VEX dependencies.
func NewService(statements statementStore, findings findingStore, projects projectChecker) *Service {
	return &Service{statements: statements, findings: findings, projects: projects}
}

// Name identifies this pass in the ingest pipeline.
func (s *Service) Name() string { return "vex" }

// Ingest parses an uploaded VEX document (OpenVEX or CycloneDX), stores its
// statements against the project, and immediately applies them to the existing
// backlog — the point of uploading an analysis is that it takes effect now, not
// on the next scan.
func (s *Service) Ingest(ctx context.Context, projectID string, raw io.Reader) ([]Statement, int, error) {
	data, err := io.ReadAll(io.LimitReader(raw, maxVexBytes))
	if err != nil {
		return nil, 0, fmt.Errorf("read vex: %w", err)
	}
	parsed, err := Parse(data)
	if err != nil {
		return nil, 0, err
	}

	exists, err := s.projects.Exists(ctx, projectID)
	if err != nil {
		return nil, 0, err
	}
	if !exists {
		return nil, 0, ErrProjectNotFound
	}

	stored := make([]Statement, 0, len(parsed))
	for _, st := range parsed {
		st.ProjectID = projectID
		out, err := s.statements.Upsert(ctx, st)
		if err != nil {
			return nil, 0, err
		}
		stored = append(stored, out)
	}

	applied, err := s.ApplyToProject(ctx, projectID)
	if err != nil {
		return stored, 0, err
	}
	return stored, applied, nil
}

// ApplyToScan applies the project's statements to the findings one scan reported.
// It satisfies the ingest pipeline's applier seam, so an analysis made once keeps
// holding: the scanner will keep reporting the CVE on every scan, and we keep
// answering "we already looked at that".
func (s *Service) ApplyToScan(ctx context.Context, projectID, scanID string) (int, error) {
	return s.apply(ctx, projectID, func(ctx context.Context) ([]finding.Finding, error) {
		return s.findings.ListForTriageScan(ctx, projectID, scanID)
	})
}

// ApplyToProject applies the statements to a project's whole active backlog —
// what a fresh upload does.
func (s *Service) ApplyToProject(ctx context.Context, projectID string) (int, error) {
	return s.apply(ctx, projectID, func(ctx context.Context) ([]finding.Finding, error) {
		return s.findings.ListForTriage(ctx, projectID)
	})
}

func (s *Service) apply(ctx context.Context, projectID string, load func(context.Context) ([]finding.Finding, error)) (int, error) {
	stmts, err := s.statements.ListByProject(ctx, projectID)
	if err != nil {
		return 0, err
	}
	if len(stmts) == 0 {
		return 0, nil
	}
	findings, err := load(ctx)
	if err != nil {
		return 0, err
	}

	changed := 0
	for _, f := range findings {
		st, ok := match(stmts, f)
		if !ok {
			continue
		}
		target, ok := targetStatus(st.Status)
		if !ok || f.Status == target {
			continue // under_investigation, or already where the statement wants it
		}
		if _, err := s.findings.SetStatus(ctx, f.ID, finding.Triage{
			Status:           target,
			Reason:           reason(st),
			Actor:            vexActor,
			VexJustification: domain.VexJustification(CycloneJustification(st.Justification)),
			VexResponse:      vexResponseDomain(st.Response),
		}); err != nil {
			return changed, err
		}
		changed++
	}
	return changed, nil
}

// targetStatus maps a VEX verdict onto a finding lifecycle state.
//
// not_affected/fixed become false_positive rather than remediated: remediated is
// reserved for "the scanner stopped reporting it", and would be reopened the
// moment the next scan reported the package again. A triage state is sticky,
// which is exactly the property a durable analysis needs.
func targetStatus(s Status) (domain.FindingStatus, bool) {
	switch s {
	case StatusNotAffected, StatusFixed:
		return domain.FindingFalsePositive, true
	case StatusAffected:
		return domain.FindingConfirmed, true
	}
	return "", false
}

// match finds the statement that applies to a finding, preferring one that names
// the exact product over a project-wide statement about the vulnerability.
func match(stmts []Statement, f finding.Finding) (Statement, bool) {
	var wildcard Statement
	var haveWildcard bool
	for _, st := range stmts {
		if !namesVuln(st.VulnID, f) {
			continue
		}
		if st.Product == "" {
			wildcard, haveWildcard = st, true
			continue
		}
		if namesProduct(st.Product, f) {
			return st, true // an exact product match always wins
		}
	}
	return wildcard, haveWildcard
}

// namesVuln matches the statement's advisory id against the finding's CVEs and
// its rule id (OSV findings carry a GHSA there).
func namesVuln(vulnID string, f finding.Finding) bool {
	if vulnID == "" {
		return false
	}
	if strings.EqualFold(vulnID, f.RuleID) {
		return true
	}
	for _, cve := range f.CVE {
		if strings.EqualFold(vulnID, cve) {
			return true
		}
	}
	return false
}

// namesProduct matches a VEX product identifier — a PURL, or a bare package name
// — against the finding's package.
func namesProduct(product string, f finding.Finding) bool {
	if f.Purl != "" && strings.EqualFold(product, f.Purl) {
		return true
	}
	if f.PackageName != "" && strings.EqualFold(product, f.PackageName) {
		return true
	}
	// A PURL that carries a version matches the package it names, e.g.
	// pkg:npm/lodash@4.17.21 against package lodash @ 4.17.21.
	if f.PackageName != "" && strings.HasPrefix(product, "pkg:") {
		name, version, _ := strings.Cut(strings.TrimPrefix(product, "pkg:"), "@")
		if idx := strings.LastIndex(name, "/"); idx >= 0 {
			name = name[idx+1:]
		}
		if strings.EqualFold(name, f.PackageName) {
			return version == "" || f.PackageVersion == "" || strings.EqualFold(version, f.PackageVersion)
		}
	}
	return false
}

// reason is the human-readable rationale recorded on the finding.
func reason(st Statement) string {
	parts := []string{"VEX: " + string(st.Status)}
	if st.Justification != "" {
		parts = append(parts, st.Justification)
	}
	if st.Detail != "" {
		parts = append(parts, st.Detail)
	}
	return strings.Join(parts, " — ")
}
