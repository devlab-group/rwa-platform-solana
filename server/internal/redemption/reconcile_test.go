package redemption

import (
	"context"
	"testing"

	"github.com/rwa-platform/server/internal/dal/memory"
	"github.com/rwa-platform/server/internal/dal/models"
)

// TestReconcileRebuildsReadModelFromEvents mirrors
// TestReconcileRebuildsReadModelFromEvents but drives Reconcile with a
// base58 program ID address (not an EVM common.Address-derived hex string),
// proving the free function works with the addressing shape the
// decoder actually uses.
func TestReconcileRebuildsReadModelFromEvents(t *testing.T) {
	programID := "REdempT10n1111111111111111111111111111111"
	events := memory.NewChainEventRepository()
	repo := memory.NewRedemptionRequestRepository()
	ctx := context.Background()

	mustCreate := func(name, id string, block uint64, extra map[string]any) {
		e := ev(name, id, block, 0, extra)
		e.Address = programID
		e.ChainID = 900001
		if err := events.Create(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	mustCreate("RedemptionRequested", "1", 10, map[string]any{
		"beneficiary": "BeneFiciary11111111111111111111111111111", "rwaAmount": "1000", "quoteAmount": "950", "createdAt": "1000",
	})
	mustCreate("RedemptionFunded", "1", 11, map[string]any{"funder": "Funder1111111111111111111111111111111111", "quoteAmount": "950"})

	if err := Reconcile(ctx, events, 900001, programID, 1209600, repo); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	r, err := repo.Get(ctx, "1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if r.Status != models.RedemptionFunded {
		t.Errorf("Status = %s, want Funded", r.Status)
	}
	if r.Beneficiary != "BeneFiciary11111111111111111111111111111" {
		t.Errorf("Beneficiary = %q, unexpected", r.Beneficiary)
	}
	// createdAt arrives as a decimal string (not a numeric type) from the
	// decoder; confirms BuildStates' toInt64 parses it rather than
	// silently defaulting to 0 (which would make TimeoutAt == redemptionTimeout).
	if r.TimeoutAt != 1000+1209600 {
		t.Errorf("TimeoutAt = %d, want %d (createdAt string \"1000\" must be parsed, not defaulted to 0)", r.TimeoutAt, 1000+1209600)
	}
}

// TestReconcileIsReversible confirms Reconcile re-derives from
// scratch on every call, same as (*Service).Reconcile: a rolled-back event
// must un-derive the state it produced, not leave it stuck.
func TestReconcileIsReversible(t *testing.T) {
	programID := "REdempT10n1111111111111111111111111111111"
	events := memory.NewChainEventRepository()
	repo := memory.NewRedemptionRequestRepository()
	ctx := context.Background()

	e := ev("RedemptionRequested", "1", 10, 0, map[string]any{
		"beneficiary": "BeneFiciary11111111111111111111111111111", "rwaAmount": "1000", "quoteAmount": "950", "createdAt": "1000",
	})
	e.Address = programID
	e.ChainID = 900001
	if err := events.Create(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := Reconcile(ctx, events, 900001, programID, 1209600, repo); err != nil {
		t.Fatalf("Reconcile (first): %v", err)
	}
	if _, err := repo.Get(ctx, "1"); err != nil {
		t.Fatalf("precondition Get: %v", err)
	}

	if _, err := events.DeleteFromBlock(ctx, 900001, programID, 10); err != nil {
		t.Fatal(err)
	}
	if err := Reconcile(ctx, events, 900001, programID, 1209600, repo); err != nil {
		t.Fatalf("Reconcile (after rollback): %v", err)
	}
	if _, err := repo.Get(ctx, "1"); err == nil {
		t.Fatal("expected request 1 to be pruned after its only backing event was rolled back")
	}
}

// TestReconcileCreatedAtBoundaryValues pins Reconcile's toInt64
// boundary behavior for createdAt (a decimal string from the decoder).
// Both a non-numeric string and a string that overflows int64 fail-safe to 0:
// projector.go's toInt64 maps any strconv.ParseInt error to 0 rather than
// returning ParseInt's clamped math.MaxInt64 magnitude, so createdAt can never
// wrap TimeoutAt (createdAt+redemptionTimeout) negative from a malformed or
// adversarial value. createdAt=0 is treated as long-expired, consistent with
// compliance's toInt64.
func TestReconcileCreatedAtBoundaryValues(t *testing.T) {
	programID := "REdempT10n1111111111111111111111111111111"
	ctx := context.Background()

	t.Run("non-numeric string", func(t *testing.T) {
		events := memory.NewChainEventRepository()
		repo := memory.NewRedemptionRequestRepository()
		e := ev("RedemptionRequested", "nn1", 10, 0, map[string]any{
			"beneficiary": "BeneFiciary11111111111111111111111111111", "rwaAmount": "1000", "quoteAmount": "950", "createdAt": "not-a-number",
		})
		e.Address = programID
		e.ChainID = 900001
		if err := events.Create(ctx, e); err != nil {
			t.Fatal(err)
		}
		if err := Reconcile(ctx, events, 900001, programID, 1209600, repo); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		r, err := repo.Get(ctx, "nn1")
		if err != nil {
			t.Fatal(err)
		}
		if r.CreatedAt != 0 {
			t.Errorf("CreatedAt = %d, want 0 for a non-numeric createdAt", r.CreatedAt)
		}
		if r.TimeoutAt != 1209600 {
			t.Errorf("TimeoutAt = %d, want %d (0 + redemptionTimeout)", r.TimeoutAt, 1209600)
		}
	})

	t.Run("overflows int64", func(t *testing.T) {
		events := memory.NewChainEventRepository()
		repo := memory.NewRedemptionRequestRepository()
		e := ev("RedemptionRequested", "ovf1", 10, 0, map[string]any{
			"beneficiary": "BeneFiciary11111111111111111111111111111", "rwaAmount": "1000", "quoteAmount": "950", "createdAt": "99999999999999999999999999999999",
		})
		e.Address = programID
		e.ChainID = 900001
		if err := events.Create(ctx, e); err != nil {
			t.Fatal(err)
		}
		if err := Reconcile(ctx, events, 900001, programID, 1209600, repo); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		r, err := repo.Get(ctx, "ovf1")
		if err != nil {
			t.Fatal(err)
		}
		if r.CreatedAt != 0 {
			t.Errorf("CreatedAt = %d, want 0 (an int64 overflow must fail-safe to 0, not ParseInt's clamped math.MaxInt64)", r.CreatedAt)
		}
		if r.TimeoutAt != 1209600 {
			t.Errorf("TimeoutAt = %d, want %d (0 + redemptionTimeout, no signed-overflow wrap)", r.TimeoutAt, 1209600)
		}
	})
}
