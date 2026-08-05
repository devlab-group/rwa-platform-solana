package sales

import (
	"context"
	"testing"

	"github.com/rwa-platform/server/internal/dal/memory"
)

// TestServesPurchasesButNotInventory covers the wiring path
// (cmd/platform's buildApp): a Service built over a repository serves
// ListPurchases off it, but GetInventory always returns ErrNoChainClient
// (not a panic) since there is no chain client to read Vault/strategy state
// from directly.
func TestServesPurchasesButNotInventory(t *testing.T) {
	purchases := memory.NewPurchaseRepository()
	svc := New(purchases)
	ctx := context.Background()

	page, _, err := svc.ListPurchases(ctx, 100, "", 10)
	if err != nil {
		t.Fatalf("ListPurchases: %v", err)
	}
	if len(page) != 0 {
		t.Fatalf("ListPurchases len = %d, want 0", len(page))
	}

	if _, err := svc.GetInventory(ctx); err != ErrNoChainClient {
		t.Fatalf("GetInventory err = %v, want ErrNoChainClient", err)
	}
}
