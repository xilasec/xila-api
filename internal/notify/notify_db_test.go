package notify_test

import (
	"context"
	"testing"

	"github.com/xilasec/xila-api/internal/notify"
	"github.com/xilasec/xila-api/internal/pgtest"
)

func TestChannelCRUDAndEventMatching(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := notify.NewRepository(pool)
	ctx := context.Background()

	all, err := repo.Create(ctx, notify.Channel{
		Name: "all", Type: "slack", URL: "https://hooks.slack/x", Enabled: true,
	})
	if err != nil {
		t.Fatalf("create all: %v", err)
	}
	if len(all.Events) != 1 || all.Events[0] != "*" { // defaults to "*"
		t.Errorf("default events = %v, want [*]", all.Events)
	}

	if _, err := repo.Create(ctx, notify.Channel{
		Name: "accepts", Type: "webhook", URL: "https://hook", Events: []string{notify.EventRiskAcceptanceApproved}, Enabled: true,
	}); err != nil {
		t.Fatalf("create accepts: %v", err)
	}
	if _, err := repo.Create(ctx, notify.Channel{
		Name: "disabled", Type: "webhook", URL: "https://hook", Events: []string{"*"}, Enabled: false,
	}); err != nil {
		t.Fatalf("create disabled: %v", err)
	}

	// A risk-accepted event reaches the '*' channel and the specific one, not the disabled one.
	forEvent, err := repo.ListForEvent(ctx, notify.EventRiskAcceptanceApproved, "", "")
	if err != nil {
		t.Fatalf("list for event: %v", err)
	}
	if len(forEvent) != 2 {
		t.Errorf("channels for risk_accepted = %d, want 2", len(forEvent))
	}

	// An unrelated event only reaches the '*' channel.
	forOther, _ := repo.ListForEvent(ctx, notify.EventExceptionExpired, "", "")
	if len(forOther) != 1 {
		t.Errorf("channels for expired = %d, want 1", len(forOther))
	}

	if list, _ := repo.List(ctx); len(list) != 3 {
		t.Errorf("list = %d, want 3", len(list))
	}
	if err := repo.Delete(ctx, all.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := repo.Delete(ctx, all.ID); err != notify.ErrNotFound {
		t.Errorf("second delete = %v, want ErrNotFound", err)
	}
}

func TestProjectScopedRoutingAndDeliveryLog(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := notify.NewRepository(pool)
	ctx := context.Background()

	var teamID, projA, projB string
	pool.QueryRow(ctx, `WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-nt','o') RETURNING id) INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id`).Scan(&teamID)
	pool.QueryRow(ctx, `INSERT INTO projects (team_id,slug,name) VALUES ($1,'a','a') RETURNING id`, teamID).Scan(&projA)
	pool.QueryRow(ctx, `INSERT INTO projects (team_id,slug,name) VALUES ($1,'b','b') RETURNING id`, teamID).Scan(&projB)

	if _, err := repo.Create(ctx, notify.Channel{Name: "global", Type: "webhook", URL: "https://g", Events: []string{"*"}, Enabled: true}); err != nil {
		t.Fatalf("create global: %v", err)
	}
	scoped, err := repo.Create(ctx, notify.Channel{Name: "team-a", Type: "slack", URL: "https://a", Events: []string{"*"}, ProjectID: &projA, Enabled: true})
	if err != nil {
		t.Fatalf("create scoped: %v", err)
	}
	if scoped.ProjectID == nil || *scoped.ProjectID != projA {
		t.Errorf("scoped project = %v, want %s", scoped.ProjectID, projA)
	}

	// Project A event -> global + team-a. Project B event -> global only. No project -> global only.
	if chs, _ := repo.ListForEvent(ctx, notify.EventCriticalFinding, projA, ""); len(chs) != 2 {
		t.Errorf("projA channels = %d, want 2", len(chs))
	}
	if chs, _ := repo.ListForEvent(ctx, notify.EventCriticalFinding, projB, ""); len(chs) != 1 {
		t.Errorf("projB channels = %d, want 1 (global only)", len(chs))
	}
	if chs, _ := repo.ListForEvent(ctx, notify.EventPolicyViolation, "", ""); len(chs) != 1 {
		t.Errorf("no-project channels = %d, want 1 (global only)", len(chs))
	}

	// Delivery log round-trips.
	status := 200
	if err := repo.LogDelivery(ctx, notify.Delivery{
		ChannelID: &scoped.ID, ChannelName: "team-a", EventType: notify.EventTest, Delivered: true, StatusCode: &status, Attempts: 1,
	}); err != nil {
		t.Fatalf("log delivery: %v", err)
	}
	deliveries, err := repo.ListDeliveries(ctx, 10)
	if err != nil {
		t.Fatalf("list deliveries: %v", err)
	}
	if len(deliveries) != 1 || !deliveries[0].Delivered || deliveries[0].ChannelName != "team-a" {
		t.Errorf("deliveries = %+v", deliveries)
	}
}
