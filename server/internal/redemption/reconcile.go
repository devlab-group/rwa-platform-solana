package redemption

import (
	"context"
	"fmt"
	"time"

	"github.com/rwa-platform/server/internal/dal/models"
	"github.com/rwa-platform/server/internal/dal/repository"
)

// EventNames are the RedemptionEscrow events the projector understands, in
// the fixed order defined by IRedemptionEscrow.
var EventNames = []string{
	"RedemptionRequested", "RedemptionFunded", "RedemptionCompleted", "RedemptionRejected", "RedemptionCancelled",
}

// Reconcile rebuilds the redemption_requests read model out of every
// persisted rwa-redemption chain event for (chainID, escrowProgramID), doing
// a generation-swap rebuild: every derived state is Upsert'd under the
// current generation first (never deleted), and only once that is complete
// are ids that no longer have a derived state at all (e.g. rolled back by a
// reorg) pruned by generation — so a concurrent reader never observes an
// empty or partially-rebuilt read model. It reuses the same BuildStates this
// package's frozen event-mapping contract already produces from indexed
// events (RedemptionRequested/Funded/Completed/Rejected/Cancelled, with Data
// keys id, beneficiary, rwaAmount, quoteAmount, createdAt, funder,
// reasonCode).
//
// This is a free function rather than a (*Service) method because it takes
// the repository directly, the same shape as internal/compliance.Reconcile
// and project.ReconcileSecurity.
func Reconcile(ctx context.Context, chainEvents repository.ChainEventRepository, chainID int64, escrowProgramID string, redemptionTimeout int64, repo repository.RedemptionRequestRepository) error {
	var all []*models.ChainEvent
	for _, name := range EventNames {
		evs, err := chainEvents.ListByName(ctx, chainID, escrowProgramID, name)
		if err != nil {
			return fmt.Errorf("redemption: list %s events: %w", name, err)
		}
		all = append(all, evs...)
	}

	states := BuildStates(all, redemptionTimeout)
	gen := time.Now().UnixNano()

	for _, r := range states {
		r.Generation = gen
		if err := repo.Upsert(ctx, r); err != nil {
			return fmt.Errorf("redemption: upsert %s: %w", r.ID, err)
		}
	}
	if err := repo.DeleteStaleGeneration(ctx, gen); err != nil {
		return fmt.Errorf("redemption: prune stale read-model entries: %w", err)
	}
	return nil
}
