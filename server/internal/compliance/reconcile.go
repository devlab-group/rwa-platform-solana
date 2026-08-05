package compliance

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/rwa-platform/server/internal/dal/models"
	"github.com/rwa-platform/server/internal/dal/repository"
)

// Reconcile derives each account's Status/ValidUntil by full replay of the
// indexed rwa-compliance StatusChanged events, keyed by the registry
// program's base58 ID, and persists the result.
//
// The events are pre-adapted before replay: the decoder
// (internal/blockchain) writes StatusChanged.newStatus as Go `uint` — not
// one of toUint8's cases (uint8/int32/int/int64/uint64/float64, see
// projector.go) — and newValidUntil as a decimal Go `string`, which toInt64
// has no case for. Both would silently resolve to 0 otherwise. The
// uint/newStatus gap self-heals once a real Mongo round-trip has occurred
// (the driver decodes a stored int back as int32/int64) but the
// string/newValidUntil gap does NOT: a Go string round-trips through BSON
// as a string, never coerced to a number, so every investor's ValidUntil
// would silently stay 0 forever in production, not just under the
// in-memory test double. adaptStatusEvents fixes exactly those two fields
// into the shapes toUint8/toInt64 already handle.
//
// The rebuild is exact and reversible: states is rebuilt from ALL currently
// persisted StatusChanged events on every call (not incrementally), so an
// account whose only/last such event was orphaned by an indexer rollback
// simply won't appear in states anymore. Such accounts are reset here —
// Status/ValidUntil back to "no known status" — rather than left at
// whatever stale value a prior call upserted; otherwise a rolled-back
// compliance action would leave a wallet permanently (and incorrectly)
// Allowed or Blocked. OwnershipVerified is off-chain data the registry
// knows nothing about, so it is preserved from the existing record.
func Reconcile(ctx context.Context, chainEvents repository.ChainEventRepository, chainID int64, complianceProgramID string, investors repository.InvestorRepository) error {
	raw, err := chainEvents.ListByName(ctx, chainID, complianceProgramID, "StatusChanged")
	if err != nil {
		return fmt.Errorf("compliance: list StatusChanged events: %w", err)
	}
	states := BuildStatuses(adaptStatusEvents(raw))

	now := time.Now().UTC()
	for account, s := range states {
		existing, err := investors.Get(ctx, account)
		ownershipVerified := false
		createdAt := now
		if err == nil {
			ownershipVerified = existing.OwnershipVerified
			createdAt = existing.CreatedAt
		} else if !errors.Is(err, repository.ErrNotFound) {
			return fmt.Errorf("compliance: load investor %s: %w", account, err)
		}
		if err := investors.Upsert(ctx, &models.Investor{
			Address: account, Status: s.Status, ValidUntil: s.ValidUntil,
			OwnershipVerified: ownershipVerified, CreatedAt: createdAt, UpdatedAt: now,
		}); err != nil {
			return fmt.Errorf("compliance: upsert investor %s: %w", account, err)
		}
	}

	all, err := investors.List(ctx)
	if err != nil {
		return fmt.Errorf("compliance: list investors for reconcile: %w", err)
	}
	for _, inv := range all {
		if _, ok := states[inv.Address]; ok {
			continue // just upserted above from a surviving event
		}
		if inv.Status == models.ComplianceUnknown && inv.ValidUntil == 0 {
			continue // already at the no-event default; nothing to reset
		}
		inv.Status = models.ComplianceUnknown
		inv.ValidUntil = 0
		inv.UpdatedAt = now
		if err := investors.Upsert(ctx, inv); err != nil {
			return fmt.Errorf("compliance: reset investor %s with no surviving status event: %w", inv.Address, err)
		}
	}
	return nil
}

// adaptStatusEvents returns a copy of events (never mutating the
// caller's slice or Data maps) with newStatus coerced from Go uint to int32
// and newValidUntil coerced from decimal string to int64 — the shapes
// BuildStatuses' internal toUint8/toInt64 already handle. previousStatus/
// previousValidUntil are left alone: BuildStatuses never reads them.
func adaptStatusEvents(events []*models.ChainEvent) []*models.ChainEvent {
	out := make([]*models.ChainEvent, len(events))
	for i, e := range events {
		cp := *e
		data := make(map[string]any, len(e.Data))
		for k, v := range e.Data {
			data[k] = v
		}
		if v, ok := data["newStatus"].(uint); ok {
			data["newStatus"] = int32(v)
		}
		if v, ok := data["newValidUntil"].(string); ok {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				data["newValidUntil"] = n
			}
		}
		cp.Data = data
		out[i] = &cp
	}
	return out
}
