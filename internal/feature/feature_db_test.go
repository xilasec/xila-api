package feature_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/feature"
	"github.com/xilasec/xila-api/internal/pgtest"
)

// Everything defaults to on; a switch takes effect at once on the replica
// that made it and on every other replica once its cache expires; unknown and
// unavailable features can't be switched on.
func TestStoreSwitches(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	now := time.Now()
	a := feature.NewStore(pool, feature.MCP)
	b := feature.NewStore(pool, feature.MCP)
	b.SetClock(func() time.Time { return now })

	states, err := a.List(ctx)
	if err != nil || len(states) != len(feature.Defs) {
		t.Fatalf("List = %d, %v", len(states), err)
	}
	for _, st := range states {
		wantOn := st.Key != feature.MCP
		if st.Enabled != wantOn || st.Available != wantOn || st.UpdatedAt != nil {
			t.Errorf("default %s = %+v", st.Key, st)
		}
		if st.OwnerOnly != (st.Key == feature.MFA) {
			t.Errorf("%s owner_only = %v", st.Key, st.OwnerOnly)
		}
	}
	if !b.Enabled(ctx, feature.CRA) { // b caches "on" now
		t.Fatal("cra off by default")
	}

	st, err := a.Set(ctx, feature.CRA, false, "")
	if err != nil || st.Enabled || st.UpdatedAt == nil {
		t.Fatalf("Set off = %+v, %v", st, err)
	}
	if a.Enabled(ctx, feature.CRA) {
		t.Error("the replica that switched cra off still sees it on")
	}
	if !b.Enabled(ctx, feature.CRA) {
		t.Error("another replica dropped its cache before CacheTTL")
	}
	now = now.Add(feature.CacheTTL)
	if b.Enabled(ctx, feature.CRA) {
		t.Error("another replica still sees cra on after CacheTTL")
	}
	if !a.Enabled(ctx, feature.Remediation) {
		t.Error("switching cra off touched remediation")
	}

	if _, err := a.Set(ctx, feature.MCP, true, ""); !errors.Is(err, feature.ErrUnavailable) {
		t.Errorf("turning on an unconfigured feature = %v, want ErrUnavailable", err)
	}
	if a.Enabled(ctx, feature.MCP) {
		t.Error("an unconfigured feature reads as on")
	}
	if _, err := a.Set(ctx, feature.MCP, false, ""); err != nil {
		t.Errorf("switching an unconfigured feature off = %v", err)
	}
	if _, err := a.Set(ctx, "nope", false, ""); !errors.Is(err, feature.ErrUnknown) {
		t.Errorf("unknown key = %v, want ErrUnknown", err)
	}
	if !a.Enabled(ctx, "nope") {
		t.Error("an unknown key must read as on, never silently off")
	}
}
