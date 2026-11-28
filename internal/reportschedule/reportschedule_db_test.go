package reportschedule_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/reportschedule"
)

func seedUser(t *testing.T, pool *pgxpool.Pool, email string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO users (email, password_hash) VALUES ($1, 'x') RETURNING id`, email).Scan(&id); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

func seedReportProject(t *testing.T, pool *pgxpool.Pool, slug string) string {
	t.Helper()
	var teamID, projectID string
	ctx := context.Background()
	if err := pool.QueryRow(ctx, `WITH o AS (INSERT INTO organizations (slug, name) VALUES ('o-'||$1, $1) RETURNING id)
		INSERT INTO teams (org_id, slug, name) SELECT id, $1, $1 FROM o RETURNING id`, "team-"+slug).Scan(&teamID); err != nil {
		t.Fatalf("seed team: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO projects (team_id, slug, name) VALUES ($1,$2,$2) RETURNING id`,
		teamID, slug).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	return projectID
}

func TestRepositoryCRUD(t *testing.T) {
	pool := pgtest.Pool(t)
	owner := seedUser(t, pool, "owner@x.io")
	pid := seedReportProject(t, pool, "proj-sched")
	repo := reportschedule.NewRepository(pool)
	ctx := context.Background()

	sch, err := repo.Create(ctx, reportschedule.Schedule{
		OwnerID: owner, Name: "Weekly project report", Kind: reportschedule.KindProject, ProjectID: &pid,
		Cadence: reportschedule.CadenceWeekly, Hour: 8, Weekday: new(1),
		RecipientEmails: []string{"a@x.io"}, Enabled: true,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if sch.OwnerEmail != "owner@x.io" || sch.ProjectName != "proj-sched" {
		t.Fatalf("joined fields missing: %+v", sch)
	}

	got, err := repo.Get(ctx, sch.ID)
	if err != nil || got.Name != sch.Name {
		t.Fatalf("get: %v %+v", err, got)
	}

	list, err := repo.ListByOwner(ctx, owner)
	if err != nil || len(list) != 1 {
		t.Fatalf("list by owner: %v %d", err, len(list))
	}

	enabled, err := repo.ListEnabled(ctx)
	if err != nil || len(enabled) != 1 {
		t.Fatalf("list enabled: %v %d", err, len(enabled))
	}

	sch.Name = "Renamed"
	sch.Enabled = false
	if _, err := repo.Update(ctx, sch); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _ = repo.Get(ctx, sch.ID)
	if got.Name != "Renamed" || got.Enabled {
		t.Fatalf("update not applied: %+v", got)
	}

	if err := repo.RecordRun(ctx, sch.ID, "success", "", 2); err != nil {
		t.Fatalf("record run: %v", err)
	}
	runs, err := repo.ListRuns(ctx, sch.ID, 10)
	if err != nil || len(runs) != 1 || runs[0].Recipients != 2 {
		t.Fatalf("list runs: %v %+v", err, runs)
	}
	got, _ = repo.Get(ctx, sch.ID)
	if got.LastRunStatus != "success" || got.LastRunAt == nil {
		t.Fatalf("last run not recorded: %+v", got)
	}

	if err := repo.Delete(ctx, sch.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := repo.Get(ctx, sch.ID); err != reportschedule.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
