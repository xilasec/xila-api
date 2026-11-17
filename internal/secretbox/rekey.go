package secretbox

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SealedColumn describes one column sealed with the INTEGRATION_SECRET_KEY
// ring: its table, primary key column, the sealed bytea column, and the SQL
// expression that reproduces the row's AAD exactly as the owning package
// computes it (a project id, a user id, a channel id, a provider id plus a
// column suffix, or a fixed constant). Table/PKColumn/Column/AADExpr are
// server-authored constants, never user input — safe to interpolate into SQL.
type SealedColumn struct {
	Table, PKColumn, Column, AADExpr string
}

// Registry lists every column sealed with the shared INTEGRATION_SECRET_KEY
// ring, so Rekey and Status can walk them generically. A new sealed column
// must be added here (see CLAUDE.md "Secrets at rest"); a bytea column named
// like one of these (*_enc, sealed_*, *_sealed) that is missing from the
// registry fails TestSealedColumnsRegistered (internal/server).
//
// `signing_secret` (notification_channels) predates that naming convention
// and is sealed anyway — a reminder that the drift test only catches future
// columns that follow it; anything named differently still needs adding here
// by hand.
var Registry = []SealedColumn{
	{Table: "issue_trackers", PKColumn: "id", Column: "token_enc", AADExpr: "project_id::text"},
	{Table: "connectors", PKColumn: "id", Column: "token_enc", AADExpr: "project_id::text"},
	{Table: "notification_channels", PKColumn: "id", Column: "signing_secret", AADExpr: "id::text"},
	{Table: "notification_channels", PKColumn: "id", Column: "url_enc", AADExpr: "id::text"},
	{Table: "users", PKColumn: "id", Column: "mfa_secret_enc", AADExpr: "'mfa:' || id::text"},
	{Table: "saml_sp_keys", PKColumn: "id", Column: "key_enc", AADExpr: "'saml-sp-key'"},
	{Table: "sso_providers", PKColumn: "id", Column: "client_secret_enc", AADExpr: "'sso-provider:' || id::text || ':client_secret'"},
	{Table: "sso_providers", PKColumn: "id", Column: "sp_key_enc", AADExpr: "'sso-provider:' || id::text || ':sp_key'"},
}

// ColumnStatus tallies one registry entry's rows by which key opened them.
type ColumnStatus struct {
	Table      string `json:"table"`
	Column     string `json:"column"`
	Total      int    `json:"total"`
	Primary    int    `json:"primary"`
	Previous   int    `json:"previous"`
	Unreadable int    `json:"unreadable"`
}

// rekeyBatch bounds how many rows one scan iteration reads, so a large table
// is paged rather than loaded whole.
const rekeyBatch = 500

// Status scans every registered column read-only and tallies how many rows
// open with the primary key, a previous key, or no configured key at all —
// what GET /admin/secrets/status reports. previous reaching zero for every
// column means INTEGRATION_SECRET_KEY_PREVIOUS can be dropped.
func Status(ctx context.Context, db *pgxpool.Pool, ring *Keyring) ([]ColumnStatus, error) {
	return scanRegistry(ctx, db, ring, false)
}

// Rekey re-seals, under the ring's primary key, every row a previous key
// opened. A row already sealed with the primary is left untouched (the
// UPDATE compares the stored ciphertext, so it only ever rewrites a row this
// call actually changed, and loses a race to a concurrent rekey or a fresh
// Seal cleanly). A row no configured key can open is counted as unreadable
// and logged by table and id only, never its value, and left as is.
func Rekey(ctx context.Context, db *pgxpool.Pool, ring *Keyring) ([]ColumnStatus, error) {
	return scanRegistry(ctx, db, ring, true)
}

func scanRegistry(ctx context.Context, db *pgxpool.Pool, ring *Keyring, reseal bool) ([]ColumnStatus, error) {
	out := make([]ColumnStatus, 0, len(Registry))
	for _, col := range Registry {
		st, err := scanColumn(ctx, db, ring, col, reseal)
		if err != nil {
			return out, err
		}
		out = append(out, st)
	}
	return out, nil
}

type sealedRow struct {
	pk, aad string
	sealed  []byte
}

func scanColumn(ctx context.Context, db *pgxpool.Pool, ring *Keyring, col SealedColumn, reseal bool) (ColumnStatus, error) {
	st := ColumnStatus{Table: col.Table, Column: col.Column}
	// Keyset-paginated by the PK's text form: stable under concurrent UPDATEs
	// to the sealed column (the PK itself never changes), and works whether
	// the PK is a UUID or (saml_sp_keys) a smallint.
	selectSQL := fmt.Sprintf(
		`SELECT %[1]s::text, %[2]s, %[3]s FROM %[4]s WHERE %[3]s IS NOT NULL AND %[1]s::text > $1 ORDER BY %[1]s::text LIMIT $2`,
		col.PKColumn, col.AADExpr, col.Column, col.Table)
	updateSQL := fmt.Sprintf(
		`UPDATE %[1]s SET %[2]s = $3 WHERE %[3]s::text = $1 AND %[2]s = $2`,
		col.Table, col.Column, col.PKColumn)

	after := ""
	for {
		batch, err := fetchSealedBatch(ctx, db, selectSQL, after)
		if err != nil {
			return st, fmt.Errorf("secretbox: scan %s.%s: %w", col.Table, col.Column, err)
		}
		if len(batch) == 0 {
			break
		}
		for _, r := range batch {
			st.Total++
			plain, tier, err := ring.OpenTier(r.sealed, r.aad)
			switch {
			case err != nil:
				st.Unreadable++
				slog.Warn("secretbox: row cannot be opened with any configured key", "table", col.Table, "column", col.Column, "id", r.pk)
			case tier == tierPrimary:
				st.Primary++
			default: // tierPrevious
				st.Previous++
				if reseal {
					newSealed, err := ring.Seal(plain, r.aad)
					if err != nil {
						return st, fmt.Errorf("secretbox: reseal %s.%s: %w", col.Table, col.Column, err)
					}
					if _, err := db.Exec(ctx, updateSQL, r.pk, r.sealed, newSealed); err != nil {
						return st, fmt.Errorf("secretbox: reseal %s.%s: %w", col.Table, col.Column, err)
					}
				}
			}
			after = r.pk
		}
		if len(batch) < rekeyBatch {
			break
		}
	}
	return st, nil
}

func fetchSealedBatch(ctx context.Context, db *pgxpool.Pool, selectSQL, after string) ([]sealedRow, error) {
	rows, err := db.Query(ctx, selectSQL, after, rekeyBatch)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var batch []sealedRow
	for rows.Next() {
		var r sealedRow
		if err := rows.Scan(&r.pk, &r.aad, &r.sealed); err != nil {
			return nil, err
		}
		batch = append(batch, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return batch, nil
}
