package user_test

import (
	"context"
	"errors"
	"testing"

	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/user"
)

// TestOwnerCannotBeDemoted is the whole point of having an owner. Before this,
// every admin could demote every other admin — including whoever set the instance
// up — so one careless or compromised admin account could lock everyone else out.
func TestOwnerCannotBeDemoted(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := user.NewRepository(pool)
	ctx := context.Background()

	// The first user to register bootstraps as admin AND owner.
	owner, err := repo.Create(ctx, "founder@x.io", "hash")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !owner.IsAdmin || !owner.IsOwner {
		t.Fatalf("the first user must bootstrap as admin+owner, got admin=%v owner=%v",
			owner.IsAdmin, owner.IsOwner)
	}

	// Everyone after is a plain user.
	second, err := repo.Create(ctx, "second@x.io", "hash")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if second.IsAdmin || second.IsOwner {
		t.Errorf("the second user must not be admin or owner, got %+v", second)
	}

	// Another admin — even a legitimate one — cannot take the owner's admin away.
	if _, err := repo.SetAdmin(ctx, owner.ID, false); !errors.Is(err, user.ErrOwnerProtected) {
		t.Errorf("demoting the owner = %v, want ErrOwnerProtected", err)
	}
	got, _ := repo.GetByID(ctx, owner.ID)
	if !got.IsAdmin || !got.IsOwner {
		t.Error("the owner lost their status despite the guard")
	}

	// A normal admin is still demotable — this protects the owner, not admins.
	promoted, err := repo.SetAdmin(ctx, second.ID, true)
	if err != nil || !promoted.IsAdmin {
		t.Fatalf("promote: %v", err)
	}
	if demoted, err := repo.SetAdmin(ctx, second.ID, false); err != nil || demoted.IsAdmin {
		t.Errorf("a regular admin must still be demotable: %v", err)
	}
}

// TestOwnershipTransfer: ownership moves only by the owner handing it over, and
// there is never a moment with zero or two owners.
func TestOwnershipTransfer(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := user.NewRepository(pool)
	ctx := context.Background()

	owner, _ := repo.Create(ctx, "founder@x.io", "hash")
	successor, _ := repo.Create(ctx, "successor@x.io", "hash")
	bystander, _ := repo.Create(ctx, "bystander@x.io", "hash")

	// A non-owner cannot give away something they don't have — even as an admin.
	if _, err := repo.SetAdmin(ctx, bystander.ID, true); err != nil {
		t.Fatalf("promote: %v", err)
	}
	if _, err := repo.TransferOwnership(ctx, bystander.ID, bystander.ID); !errors.Is(err, user.ErrNotOwner) {
		t.Errorf("an admin transferring ownership to themselves = %v, want ErrNotOwner", err)
	}
	if _, err := repo.TransferOwnership(ctx, bystander.ID, successor.ID); !errors.Is(err, user.ErrNotOwner) {
		t.Errorf("a non-owner transferring ownership = %v, want ErrNotOwner", err)
	}

	// The owner hands it over. The successor becomes owner and admin at once.
	newOwner, err := repo.TransferOwnership(ctx, owner.ID, successor.ID)
	if err != nil {
		t.Fatalf("transfer: %v", err)
	}
	if !newOwner.IsOwner || !newOwner.IsAdmin {
		t.Errorf("the new owner = %+v, want owner+admin", newOwner)
	}

	// The old owner keeps admin (they were one) but is no longer protected.
	old, _ := repo.GetByID(ctx, owner.ID)
	if old.IsOwner {
		t.Error("the previous owner is still marked owner — there are now two")
	}
	if !old.IsAdmin {
		t.Error("the previous owner should remain an admin; transferring is not a demotion")
	}
	if _, err := repo.SetAdmin(ctx, old.ID, false); err != nil {
		t.Errorf("the previous owner should now be demotable like any admin: %v", err)
	}

	// And the new owner is protected in turn.
	if _, err := repo.SetAdmin(ctx, successor.ID, false); !errors.Is(err, user.ErrOwnerProtected) {
		t.Errorf("the new owner must be protected, got %v", err)
	}

	// Exactly one owner, always.
	var owners int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE is_owner`).Scan(&owners); err != nil {
		t.Fatal(err)
	}
	if owners != 1 {
		t.Errorf("%d owners; there must be exactly one", owners)
	}
}

// The database refuses a second owner even if code tries — the invariant is in the
// schema, not in whoever remembered to check.
func TestSingleOwnerIsEnforcedByTheDatabase(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := user.NewRepository(pool)
	ctx := context.Background()

	_, _ = repo.Create(ctx, "founder@x.io", "hash")
	second, _ := repo.Create(ctx, "second@x.io", "hash")

	_, err := pool.Exec(ctx, `UPDATE users SET is_admin = true, is_owner = true WHERE id = $1`, second.ID)
	if err == nil {
		t.Fatal("the database allowed a second owner; the unique index is not doing its job")
	}

	// And an owner who isn't an admin is impossible by construction — that's what
	// makes "there is always at least one admin" a schema invariant.
	if _, err := pool.Exec(ctx, `UPDATE users SET is_admin = false WHERE is_owner`); err == nil {
		t.Error("the database allowed a non-admin owner")
	}
}
