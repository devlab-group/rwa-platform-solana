package compliance

import (
	"sort"

	"github.com/rwa-platform/server/internal/dal/models"
)

// statusNames maps the on-chain uint8 OnChainStatus encoding to the domain
// string enum.
var statusNames = map[uint8]models.ComplianceStatus{
	0: models.ComplianceUnknown,
	1: models.ComplianceAllowed,
	2: models.ComplianceBlocked,
}

// BuildStatuses replays ComplianceRegistry StatusChanged events in
// (blockNumber, logIndex) order and derives each account's current
// on-chain status. Chain state is the only source of truth for Status/
// ValidUntil; it says nothing about OwnershipVerified,
// which Reconcile preserves from the existing investor record.
//
// Sort is stable with a TxHash tiebreak: BlockNumber is the slot and
// LogIndex resets per transaction, so two StatusChanged events from
// different transactions in the same slot can collide on (BlockNumber,
// LogIndex). True intra-slot cross-transaction ordering isn't recoverable
// from getSignaturesForAddress, so this picks a stable, documented total
// order (by TxHash) instead of leaving the "latest wins" outcome to
// sort.Slice's unspecified tie behavior, which could derive
// a different final status across runs from the same persisted events.
func BuildStatuses(events []*models.ChainEvent) map[string]struct {
	Status     models.ComplianceStatus
	ValidUntil int64
} {
	sorted := make([]*models.ChainEvent, len(events))
	copy(sorted, events)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].BlockNumber != sorted[j].BlockNumber {
			return sorted[i].BlockNumber < sorted[j].BlockNumber
		}
		if sorted[i].LogIndex != sorted[j].LogIndex {
			return sorted[i].LogIndex < sorted[j].LogIndex
		}
		return sorted[i].TxHash < sorted[j].TxHash
	})

	states := map[string]struct {
		Status     models.ComplianceStatus
		ValidUntil int64
	}{}
	for _, e := range sorted {
		if e.Name != "StatusChanged" {
			continue
		}
		account := toString(e.Data["account"])
		if account == "" {
			continue
		}
		status, ok := statusNames[toUint8(e.Data["newStatus"])]
		if !ok {
			status = models.ComplianceUnknown
		}
		states[account] = struct {
			Status     models.ComplianceStatus
			ValidUntil int64
		}{Status: status, ValidUntil: toInt64(e.Data["newValidUntil"])}
	}
	return states
}

func toString(v any) string {
	s, _ := v.(string)
	return s
}

// toUint8 and toInt64 accept every numeric shape a ChainEvent.Data value can
// actually arrive in: the original Go type (uint8/uint64/...) when it comes
// straight from the indexer within the same process, but int32 (small ints)
// or int64 (large/unsigned ints, via bson.Long) once it has round-tripped
// through MongoDB's Go driver, which decodes a stored BSON int32/int64 into
// exactly those two Go types regardless of the field's original width —
// never uint8, even for a value the indexer wrote as a Go uint8.
func toUint8(v any) uint8 {
	switch t := v.(type) {
	case uint8:
		return t
	case int32:
		return uint8(t)
	case int:
		return uint8(t)
	case int64:
		return uint8(t)
	case uint64:
		return uint8(t)
	case float64:
		return uint8(t)
	default:
		return 0
	}
}

func toInt64(v any) int64 {
	switch t := v.(type) {
	case uint64:
		return int64(t)
	case int64:
		return t
	case int32:
		return int64(t)
	case int:
		return int64(t)
	case float64:
		return int64(t)
	default:
		return 0
	}
}
