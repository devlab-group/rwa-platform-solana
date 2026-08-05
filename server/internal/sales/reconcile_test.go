package sales

import (
	"context"
	"testing"

	"github.com/rwa-platform/server/internal/dal/memory"
	"github.com/rwa-platform/server/internal/dal/models"
)

// TestReconcileBuildsPurchasesFromEvents drives Reconcile with a
// base58 Vault program ID and Solana-shaped Purchased event data (no
// "strategy" key, unlike EVM's), proving the free function and
// BuildPurchases handle the Solana event shape correctly.
func TestReconcileBuildsPurchasesFromEvents(t *testing.T) {
	programID := "VauLT1111111111111111111111111111111111111"
	events := memory.NewChainEventRepository()
	purchases := memory.NewPurchaseRepository()
	ctx := context.Background()

	if err := events.Create(ctx, &models.ChainEvent{
		ChainID: 900001, Address: programID, Name: "Purchased", TxHash: "sig1", LogIndex: 0, BlockNumber: 10,
		Data: map[string]any{
			"buyer": "Buyer111111111111111111111111111111111111", "recipient": "Recipient111111111111111111111111111111",
			"tokenAmount": "1000", "quoteAmount": "950",
		},
	}); err != nil {
		t.Fatal(err)
	}

	if err := Reconcile(ctx, events, 900001, programID, purchases); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	items, _, err := purchases.ListPage(ctx, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("len(items) = %d, want 1", len(items))
	}
	if items[0].Buyer != "Buyer111111111111111111111111111111111111" || items[0].TokenAmount != "1000" {
		t.Errorf("unexpected purchase: %+v", items[0])
	}
}

// TestReconcileIsReversible mirrors redemption's
// TestReconcileIsReversible: Reconcile re-derives from scratch on
// every call, same as (*Service).Reconcile, so a rolled-back event (indexer
// reorg deleting the chain_events row outright) must un-derive the purchase
// it produced, not leave it stuck in the read model.
func TestReconcileIsReversible(t *testing.T) {
	programID := "VauLT1111111111111111111111111111111111111"
	events := memory.NewChainEventRepository()
	purchases := memory.NewPurchaseRepository()
	ctx := context.Background()

	if err := events.Create(ctx, &models.ChainEvent{
		ChainID: 900001, Address: programID, Name: "Purchased", TxHash: "sig1", LogIndex: 0, BlockNumber: 10,
		Data: map[string]any{
			"buyer": "Buyer111111111111111111111111111111111111", "recipient": "Recipient111111111111111111111111111111",
			"tokenAmount": "1000", "quoteAmount": "950",
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := Reconcile(ctx, events, 900001, programID, purchases); err != nil {
		t.Fatalf("Reconcile (first): %v", err)
	}
	items, _, err := purchases.ListPage(ctx, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("precondition: len(items) = %d, want 1", len(items))
	}

	if _, err := events.DeleteFromBlock(ctx, 900001, programID, 10); err != nil {
		t.Fatal(err)
	}
	if err := Reconcile(ctx, events, 900001, programID, purchases); err != nil {
		t.Fatalf("Reconcile (after rollback): %v", err)
	}
	items, _, err = purchases.ListPage(ctx, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("expected the purchase to be pruned after its only backing event was rolled back, got %d items", len(items))
	}
}

// TestReconcileIgnoresEVMOnlyEventNames confirms querying EventNames
// (which includes the EVM-only TreasuryChanged/StrategyChanged) against a
// Solana address is a harmless no-op, not an error.
func TestReconcileIgnoresEVMOnlyEventNames(t *testing.T) {
	programID := "VauLT1111111111111111111111111111111111111"
	events := memory.NewChainEventRepository()
	purchases := memory.NewPurchaseRepository()
	ctx := context.Background()

	if err := Reconcile(ctx, events, 900001, programID, purchases); err != nil {
		t.Fatalf("Reconcile on an empty event set: %v", err)
	}
	items, _, err := purchases.ListPage(ctx, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Errorf("len(items) = %d, want 0", len(items))
	}
}
