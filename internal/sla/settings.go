package sla

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// MinFactor / MaxFactor bound a criticality factor (mirrors the sla_settings
// CHECK constraints).
const (
	MinFactor float64 = 0.1
	MaxFactor float64 = 10
)

// Factors scale a policy's windows per project business criticality.
type Factors struct {
	Critical float64 `json:"critical"`
	High     float64 `json:"high"`
	Medium   float64 `json:"medium"`
	Low      float64 `json:"low"`
}

// Validate checks every factor is within MinFactor..MaxFactor.
func (f Factors) Validate() error {
	for name, v := range map[string]float64{"critical": f.Critical, "high": f.High, "medium": f.Medium, "low": f.Low} {
		if v < MinFactor || v > MaxFactor {
			return fmt.Errorf("factors.%s must be between %g and %g", name, MinFactor, MaxFactor)
		}
	}
	return nil
}

// Settings are the instance-wide SLA options. With ScaleByCriticality on, a
// finding's window is round(policy days × the factor for its project's
// business criticality), at least 1 day — the same policy then gives a
// critical system less time than a low-importance one.
type Settings struct {
	ScaleByCriticality bool       `json:"scale_by_criticality"`
	Factors            Factors    `json:"factors"`
	UpdatedAt          *time.Time `json:"updated_at,omitempty"`
}

// Matrix is the window each (project criticality, severity) gets under the
// instance's effective policy with the current settings — what an admin needs
// to see before trusting the switch. Computed by the same SQL function the
// findings use (sla_scaled_days), so it can't disagree with them.
type Matrix map[string]Days

const settingsColumns = `scale_by_criticality, critical_factor::float8, high_factor::float8,
	medium_factor::float8, low_factor::float8, updated_at`

func scanSettings(row pgx.Row) (Settings, error) {
	var s Settings
	err := row.Scan(&s.ScaleByCriticality, &s.Factors.Critical, &s.Factors.High,
		&s.Factors.Medium, &s.Factors.Low, &s.UpdatedAt)
	return s, err
}

// Settings returns the instance-wide SLA settings.
func (r *Repository) Settings(ctx context.Context) (Settings, error) {
	s, err := scanSettings(r.db.QueryRow(ctx, `SELECT `+settingsColumns+` FROM sla_settings`))
	if err != nil {
		return Settings{}, fmt.Errorf("get sla settings: %w", err)
	}
	return s, nil
}

// PutSettings stores the settings and re-applies every finding's window in the
// same transaction, so turning scaling on (or changing a factor) moves the
// existing backlog's deadlines too, not just new findings'.
func (r *Repository) PutSettings(ctx context.Context, s Settings) (Settings, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return Settings{}, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	out, err := scanSettings(tx.QueryRow(ctx, `
		INSERT INTO sla_settings (id, scale_by_criticality, critical_factor, high_factor, medium_factor, low_factor, updated_at)
		VALUES (true, $1, $2, $3, $4, $5, now())
		ON CONFLICT (id) DO UPDATE SET
			scale_by_criticality = EXCLUDED.scale_by_criticality,
			critical_factor = EXCLUDED.critical_factor, high_factor = EXCLUDED.high_factor,
			medium_factor = EXCLUDED.medium_factor, low_factor = EXCLUDED.low_factor,
			updated_at = now()
		RETURNING `+settingsColumns,
		s.ScaleByCriticality, s.Factors.Critical, s.Factors.High, s.Factors.Medium, s.Factors.Low))
	if err != nil {
		return Settings{}, fmt.Errorf("put sla settings: %w", err)
	}
	if err := reapply(ctx, tx, Global); err != nil {
		return Settings{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Settings{}, fmt.Errorf("commit: %w", err)
	}
	return out, nil
}

// Matrix returns the windows of the instance's effective policy (global, else
// built-in) for each project criticality under the current settings.
func (r *Repository) Matrix(ctx context.Context) (Matrix, error) {
	rows, err := r.db.Query(ctx, `
		SELECT c.crit,
		       sla_scaled_days(p.critical_days, c.crit), sla_scaled_days(p.high_days, c.crit),
		       sla_scaled_days(p.medium_days, c.crit), sla_scaled_days(p.low_days, c.crit),
		       sla_scaled_days(p.info_days, c.crit),
		       sla_scaled_days(p.kev_days, c.crit), sla_scaled_days(p.exploited_days, c.crit)
		FROM sla_policy_for(NULL) p
		CROSS JOIN unnest(ARRAY['critical', 'high', 'medium', 'low']) AS c(crit)`)
	if err != nil {
		return nil, fmt.Errorf("sla matrix: %w", err)
	}
	defer rows.Close()
	m := Matrix{}
	for rows.Next() {
		var crit string
		var d Days
		if err := rows.Scan(&crit, &d.Critical, &d.High, &d.Medium, &d.Low, &d.Info, &d.KEV, &d.Exploited); err != nil {
			return nil, fmt.Errorf("scan sla matrix: %w", err)
		}
		m[crit] = d
	}
	return m, rows.Err()
}
