package compliance

import (
	"context"
	"testing"

	"github.com/rwa-platform/server/internal/dal/memory"
	"github.com/rwa-platform/server/internal/dal/models"
)

func statusChangedEvent(programID, account string, newStatus uint, newValidUntil string) *models.ChainEvent {
	return &models.ChainEvent{
		ChainID: 900001, Address: programID, Name: "StatusChanged", TxHash: "sig1", LogIndex: 0, BlockNumber: 10,
		Data: map[string]any{
			"account": account, "previousStatus": uint(0), "newStatus": newStatus,
			"previousValidUntil": "0", "newValidUntil": newValidUntil, "authority": "SomeAuthority111111111111111111111111111111",
		},
	}
}

// TestReconcileAppliesRealTypesCorrectly verifies Reconcile
// correctly folds StatusChanged events using the exact Go types the Solana
// decoder produces (newStatus: uint, newValidUntil: decimal string),
// round-tripping through both Allowed (1) and Blocked (2) to pin the full
// 0=Unknown/1=Allowed/2=Blocked ordering against the Rust
// ComplianceStatus enum.
func TestReconcileAppliesRealTypesCorrectly(t *testing.T) {
	programID := "CompLiance111111111111111111111111111111111"
	account := "InvestoR111111111111111111111111111111111111"
	events := memory.NewChainEventRepository()
	investors := memory.NewInvestorRepository()
	ctx := context.Background()

	if err := events.Create(ctx, statusChangedEvent(programID, account, 1, "2000000000")); err != nil {
		t.Fatal(err)
	}
	if err := Reconcile(ctx, events, 900001, programID, investors); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	inv, err := investors.Get(ctx, account)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Status != models.ComplianceAllowed {
		t.Errorf("Status = %s, want Allowed", inv.Status)
	}
	if inv.ValidUntil != 2000000000 {
		t.Errorf("ValidUntil = %d, want 2000000000", inv.ValidUntil)
	}

	if err := events.Create(ctx, &models.ChainEvent{
		ChainID: 900001, Address: programID, Name: "StatusChanged", TxHash: "sig2", LogIndex: 0, BlockNumber: 11,
		Data: statusChangedEvent(programID, account, 2, "0").Data,
	}); err != nil {
		t.Fatal(err)
	}
	if err := Reconcile(ctx, events, 900001, programID, investors); err != nil {
		t.Fatal(err)
	}
	inv, err = investors.Get(ctx, account)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Status != models.ComplianceBlocked {
		t.Errorf("Status = %s, want Blocked", inv.Status)
	}
	if inv.ValidUntil != 0 {
		t.Errorf("ValidUntil = %d, want 0", inv.ValidUntil)
	}
}

// TestReconcileIsReversible mirrors redemption's
// TestReconcileIsReversible: a rolled-back StatusChanged event
// (indexer reorg deleting the chain_events row outright) must reset the
// investor to the no-event default (Unknown/ValidUntil=0), not leave the
// previously-projected status stuck.
func TestReconcileIsReversible(t *testing.T) {
	programID := "CompLiance111111111111111111111111111111111"
	account := "InvestoR111111111111111111111111111111111111"
	events := memory.NewChainEventRepository()
	investors := memory.NewInvestorRepository()
	ctx := context.Background()

	if err := events.Create(ctx, statusChangedEvent(programID, account, 1, "2000000000")); err != nil {
		t.Fatal(err)
	}
	if err := Reconcile(ctx, events, 900001, programID, investors); err != nil {
		t.Fatalf("Reconcile (first): %v", err)
	}
	inv, err := investors.Get(ctx, account)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Status != models.ComplianceAllowed {
		t.Fatalf("precondition: Status = %s, want Allowed", inv.Status)
	}

	if _, err := events.DeleteFromBlock(ctx, 900001, programID, 10); err != nil {
		t.Fatal(err)
	}
	if err := Reconcile(ctx, events, 900001, programID, investors); err != nil {
		t.Fatalf("Reconcile (after rollback): %v", err)
	}
	inv, err = investors.Get(ctx, account)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Status != models.ComplianceUnknown {
		t.Errorf("Status = %s, want Unknown after the only backing event was rolled back", inv.Status)
	}
	if inv.ValidUntil != 0 {
		t.Errorf("ValidUntil = %d, want 0 after rollback", inv.ValidUntil)
	}
}

// TestReconcileToInt64BoundaryValues pins Reconcile's behavior
// for a newValidUntil string strconv.ParseInt cannot represent:
// adaptStatusEvents only rewrites the field into an int64 when
// ParseInt succeeds (reconcile.go); on ANY parse failure — a
// non-numeric string OR one that overflows int64 — it leaves the raw string
// in place, and this package's toInt64 (projector.go) has no `case string`
// at all (unlike internal/redemption's — see
// TestReconcileCreatedAtBoundaryValues for the contrast), so both
// failure modes fall through to its default case and resolve ValidUntil to
// 0 uniformly. This IS the intended fail-safe: an investor whose
// ValidUntil could not be parsed ends up looking already-expired
// (ValidUntil=0), never accidentally granted a long-lived allowance. Pinning
// current behavior, not changing it (test-only task).
func TestReconcileToInt64BoundaryValues(t *testing.T) {
	programID := "CompLiance111111111111111111111111111111111"
	ctx := context.Background()

	t.Run("non-numeric string", func(t *testing.T) {
		account := "InvestoRNonNum1111111111111111111111111111"
		events := memory.NewChainEventRepository()
		investors := memory.NewInvestorRepository()
		if err := events.Create(ctx, statusChangedEvent(programID, account, 1, "not-a-number")); err != nil {
			t.Fatal(err)
		}
		if err := Reconcile(ctx, events, 900001, programID, investors); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		inv, err := investors.Get(ctx, account)
		if err != nil {
			t.Fatal(err)
		}
		if inv.ValidUntil != 0 {
			t.Errorf("ValidUntil = %d, want 0 for a non-numeric newValidUntil", inv.ValidUntil)
		}
	})

	t.Run("overflows int64", func(t *testing.T) {
		account := "InvestoROverflow111111111111111111111111111"
		events := memory.NewChainEventRepository()
		investors := memory.NewInvestorRepository()
		if err := events.Create(ctx, statusChangedEvent(programID, account, 1, "99999999999999999999999999999999")); err != nil {
			t.Fatal(err)
		}
		if err := Reconcile(ctx, events, 900001, programID, investors); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		inv, err := investors.Get(ctx, account)
		if err != nil {
			t.Fatal(err)
		}
		if inv.ValidUntil != 0 {
			t.Errorf("ValidUntil = %d, want 0 for a newValidUntil that overflows int64", inv.ValidUntil)
		}
	})
}
