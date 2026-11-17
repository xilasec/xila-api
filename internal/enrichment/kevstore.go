package enrichment

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// KEVRepository stores each KEV catalog's last successful download, so a
// catalog that fails keeps asserting what it last listed.
type KEVRepository struct{ db *pgxpool.Pool }

// NewKEVRepository constructs the repository.
func NewKEVRepository(db *pgxpool.Pool) *KEVRepository { return &KEVRepository{db: db} }

// KEVCatalogStatus is one catalog's sync state.
type KEVCatalogStatus struct {
	Source    string     `json:"source"`
	Entries   int        `json:"entries"`
	SyncedAt  *time.Time `json:"synced_at"`
	LastError string     `json:"last_error"`
	FailedAt  *time.Time `json:"failed_at"`
}

// Replace swaps one catalog's ids for list, in one transaction.
func (r *KEVRepository) Replace(ctx context.Context, source string, list KEVList) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	if _, err := tx.Exec(ctx, `DELETE FROM kev_catalog_entries WHERE source = $1`, source); err != nil {
		return fmt.Errorf("clear %s: %w", source, err)
	}
	rows := make([][]any, len(list.IDs))
	for i, id := range list.IDs {
		rows[i] = []any{source, id, list.Ransomware[id]}
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"kev_catalog_entries"}, []string{"source", "vuln_id", "ransomware"},
		pgx.CopyFromRows(rows)); err != nil {
		return fmt.Errorf("store %s: %w", source, err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO kev_catalogs (source, entries, synced_at, last_error, failed_at)
		VALUES ($1, $2, now(), '', NULL)
		ON CONFLICT (source) DO UPDATE SET entries = $2, synced_at = now(), last_error = '', failed_at = NULL`,
		source, len(list.IDs)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Failed records a failed download; the catalog's previous ids stay.
func (r *KEVRepository) Failed(ctx context.Context, source string, cause error) error {
	_, err := r.db.Exec(ctx, `INSERT INTO kev_catalogs (source, last_error, failed_at) VALUES ($1, $2, now())
		ON CONFLICT (source) DO UPDATE SET last_error = $2, failed_at = now()`, source, cause.Error())
	return err
}

// KEVAssertions is what the configured catalogs assert: the catalogs listing
// each vulnerability id, and the ids any of them marks as used in ransomware
// campaigns.
type KEVAssertions struct {
	Sources    map[string][]string
	Ransomware map[string]bool
}

// Assertions maps every stored vulnerability id to the catalogs asserting it,
// restricted to sources (the configured catalogs: one dropped from
// KEV_SOURCES stops asserting).
func (r *KEVRepository) Assertions(ctx context.Context, sources []string) (KEVAssertions, error) {
	out := KEVAssertions{Sources: map[string][]string{}, Ransomware: map[string]bool{}}
	rows, err := r.db.Query(ctx, `SELECT vuln_id, array_agg(source ORDER BY source), bool_or(ransomware)
		FROM kev_catalog_entries WHERE source = ANY($1) GROUP BY vuln_id`, sources)
	if err != nil {
		return out, fmt.Errorf("kev assertions: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var src []string
		var ransomware bool
		if err := rows.Scan(&id, &src, &ransomware); err != nil {
			return out, err
		}
		out.Sources[id] = src
		if ransomware {
			out.Ransomware[id] = true
		}
	}
	return out, rows.Err()
}

// Status lists each catalog's sync state.
func (r *KEVRepository) Status(ctx context.Context) ([]KEVCatalogStatus, error) {
	rows, err := r.db.Query(ctx, `SELECT source, entries, synced_at, last_error, failed_at FROM kev_catalogs ORDER BY source`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []KEVCatalogStatus{}
	for rows.Next() {
		var s KEVCatalogStatus
		if err := rows.Scan(&s.Source, &s.Entries, &s.SyncedAt, &s.LastError, &s.FailedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
