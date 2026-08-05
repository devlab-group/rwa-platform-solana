package sales

import (
	"context"
	"fmt"
	"time"

	"github.com/rwa-platform/server/internal/dal/models"
	"github.com/rwa-platform/server/internal/dal/repository"
)

// EventNames are the Vault events the sales/security projectors decode:
// Purchased (the sales read model), TreasuryChanged and StrategyChanged
// (the governance-authority changes the project security projector folds
// — the Vault program never emits these two; see
// Reconcile's doc comment), and ProceedsWithdrawn (a treasury
// withdrawal, surfaced by the stack-transactions projector).
var EventNames = []string{"Purchased", "TreasuryChanged", "StrategyChanged", "ProceedsWithdrawn"}

// Reconcile rebuilds the purchases read model out of every persisted
// rwa-vault chain event for (chainID, vaultProgramID), doing a
// generation-swap rebuild: every surviving record is Upsert'd
// (create-or-replace by id, never deleted first) tagged with a fresh
// generation, so a reader mid-rebuild always sees either the previous
// generation's value for an id not yet reached, or the new generation's
// value for one already reached — never a gap. Only AFTER every record has
// been upserted are stale entries (ids that no longer appear at all, e.g.
// rolled back by a reorg) pruned by generation. It reuses the same
// BuildPurchases this package's frozen event-mapping contract already
// produces from indexed events (buyer/recipient/tokenAmount/quoteAmount).
// Querying EventNames also asks for TreasuryChanged/StrategyChanged, which
// the Vault program never emits (those authority changes are
// RoleChanged there — see the security projector) — those two queries just
// come back empty, no error.
//
// This is a free function rather than a (*Service) method for the same
// reason as redemption.Reconcile: it takes the repository directly.
func Reconcile(ctx context.Context, chainEvents repository.ChainEventRepository, chainID int64, vaultProgramID string, purchases repository.PurchaseRepository) error {
	var all []*models.ChainEvent
	for _, name := range EventNames {
		evs, err := chainEvents.ListByName(ctx, chainID, vaultProgramID, name)
		if err != nil {
			return fmt.Errorf("sales: list %s events: %w", name, err)
		}
		all = append(all, evs...)
	}

	gen := time.Now().UnixNano()
	for _, p := range BuildPurchases(all) {
		p.Generation = gen
		if err := purchases.Upsert(ctx, p); err != nil {
			return fmt.Errorf("sales: upsert purchase %s: %w", p.ID, err)
		}
	}
	if err := purchases.DeleteStaleGeneration(ctx, gen); err != nil {
		return fmt.Errorf("sales: prune stale purchases: %w", err)
	}
	return nil
}
