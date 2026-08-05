package redemption

import (
	"sort"
	"strconv"
	"time"

	"github.com/rwa-platform/server/internal/dal/models"
)

// BuildStates replays RedemptionEscrow chain events in (blockNumber,
// logIndex) order and derives the current models.RedemptionRequest for each
// id, following the FROZEN transition table in
// docs/spec/redemption-state-machine.md:
//
//	None -> Pending -> {Funded -> Completed | Rejected | Cancelled}
//
// This is the ONLY source of redemption status; it
// never reads server workflow tables. Events with an unrecognized id
// ordering (e.g. Funded before Requested, which cannot happen on a
// correctly indexed chain but could appear from a malformed test/fixture)
// are skipped rather than panicking.
// Sort is stable with a TxHash tiebreak: BlockNumber is the slot and
// LogIndex resets per transaction, so two events from different
// transactions in the same slot can collide on (BlockNumber, LogIndex).
// True intra-slot cross-transaction ordering isn't recoverable from
// getSignaturesForAddress, so this picks a stable, documented total order
// (by TxHash) rather than leaving state transitions to sort.Slice's
// unspecified tie behavior, which could derive a different final status
// across runs from the same persisted events.
func BuildStates(events []*models.ChainEvent, redemptionTimeout int64) map[string]*models.RedemptionRequest {
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

	states := map[string]*models.RedemptionRequest{}
	now := time.Now().UTC()

	for _, e := range sorted {
		id, _ := e.Data["id"].(string)
		if id == "" {
			continue
		}
		switch e.Name {
		case "RedemptionRequested":
			// Ignore a duplicate RedemptionRequested for an id already
			// seen earlier in sorted order. Impossible on a correctly indexed
			// chain (ids are unique on-chain), but unconditionally
			// overwriting would reset an already-Funded/Completed state back
			// to a fresh Pending on a later duplicate/spoofed event. A
			// genuine full rebuild is unaffected: Reconcile always starts
			// BuildStates from an empty states map, so the first sighting of
			// a real id still creates it normally.
			if _, ok := states[id]; ok {
				continue
			}
			createdAt := toInt64(e.Data["createdAt"])
			states[id] = &models.RedemptionRequest{
				ID:            id,
				Beneficiary:   toString(e.Data["beneficiary"]),
				RWAAmount:     toString(e.Data["rwaAmount"]),
				QuoteAmount:   toString(e.Data["quoteAmount"]),
				Status:        models.RedemptionPending,
				CreatedAt:     createdAt,
				TimeoutAt:     createdAt + redemptionTimeout,
				RequestTxHash: e.TxHash,
				UpdatedAt:     now,
			}
		case "RedemptionFunded":
			if r, ok := states[id]; ok && r.Status == models.RedemptionPending {
				r.Status = models.RedemptionFunded
				r.FundTxHash = e.TxHash
				r.FundedAtBlock = e.BlockNumber
				r.UpdatedAt = now
			}
		case "RedemptionCompleted":
			if r, ok := states[id]; ok && r.Status == models.RedemptionFunded {
				r.Status = models.RedemptionCompleted
				r.ClaimTxHash = e.TxHash
				r.UpdatedAt = now
			}
		case "RedemptionRejected":
			if r, ok := states[id]; ok && r.Status == models.RedemptionPending {
				r.Status = models.RedemptionRejected
				r.ReasonCode = toString(e.Data["reasonCode"])
				r.UpdatedAt = now
			}
		case "RedemptionCancelled":
			if r, ok := states[id]; ok && r.Status == models.RedemptionPending {
				r.Status = models.RedemptionCancelled
				r.UpdatedAt = now
			}
		}
	}
	return states
}

func toString(v any) string {
	s, _ := v.(string)
	return s
}

// toInt64 accepts every numeric shape a ChainEvent.Data value can arrive in
// (see internal/compliance/projector.go's toInt64 for why int32 is in this
// list: MongoDB's Go driver decodes any stored small int as int32, never
// the field's original Go width).
func toInt64(v any) int64 {
	switch t := v.(type) {
	case int64:
		return t
	case uint64:
		return int64(t)
	case int32:
		return int64(t)
	case int:
		return int64(t)
	case float64:
		return int64(t)
	case string:
		// Fail-safe to 0 on a malformed or out-of-range value rather than
		// discarding the error: ParseInt returns math.MaxInt64 on overflow,
		// which would make createdAt+timeout wrap negative (a redemption that
		// looks instantly timed out). A real on-chain u64 timestamp is always
		// well within int64, so 0 (treated as long-expired) is the safe floor.
		n, err := strconv.ParseInt(t, 10, 64)
		if err != nil {
			return 0
		}
		return n
	default:
		return 0
	}
}
