// Package cra runs EU Cyber Resilience Act Article 14 reporting: the product
// declaration, the cases opened for actively exploited vulnerabilities and
// their 24 h / 72 h / 14 d clocks. The Annex I posture is the eu-cra
// compliance framework; its evidence report (internal/evidence) adds the
// Article 14 section read through Article14.
package cra

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// FrameworkKey is the CRA framework (migration 000060).
const FrameworkKey = "eu-cra"

// Repository stores products and cases.
type Repository struct{ db *pgxpool.Pool }

// NewRepository constructs the repository.
func NewRepository(db *pgxpool.Pool) *Repository { return &Repository{db: db} }

// Article14 reads a project's product declaration and its reporting cases,
// each stage's deadline compliance derived at at.
func (r *Repository) Article14(ctx context.Context, projectID string, at time.Time) (Product, []Case, error) {
	p, err := r.Product(ctx, projectID)
	if err != nil {
		return Product{}, nil, err
	}
	cases, err := r.List(ctx, CaseFilter{ProjectID: projectID})
	if err != nil {
		return Product{}, nil, err
	}
	for i := range cases {
		cases[i].derive(at)
	}
	return p, cases, nil
}
