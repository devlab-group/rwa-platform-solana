// Package txindex projects indexed chain events into Transaction records for
// on-chain transactions the server did NOT itself submit.
//
// This server broadcasts exactly one kind of transaction — the compliance hot
// key's set_status call (see internal/compliance.StatusService). Every other
// on-chain action is encoded in the browser and broadcast from the connected
// wallet: buys, the whole redemption lifecycle, treasury withdrawals, role and
// price changes, pause/unpause, admin transfers, mint/burn. None of those ever
// produce a Transaction record on their own, so without this projector
// GET /transactions shows a single compliance row and nothing else, no matter
// how much activity the indexer has ingested.
//
// Like project.ReconcileSecurity and the other read-model reconcilers, this is
// a FULL REPLAY over whatever chain_events currently holds — not an
// append-only delta feed — which is what makes it rollback-safe: re-deriving
// from scratch every tick reflects both a new out-of-band action and the later
// disappearance of one. It is idempotent: each record's ID is a deterministic
// function of the signature (models.EventDerivedTxIDPrefix+txHash) and its
// SubmittedAt is pinned to the earliest event's IndexedAt (preserved once
// written), so repeated runs and stable keyset pagination both hold.
//
// Two deliberate differences from the EVM projector this replaces:
//
//   - No ReconciliationRequired freeze check. That flag guarded against
//     projecting while an EVM reorg's common ancestor was unresolved; the
//     Solana indexer never sets it (see internal/api/project.go), so a check
//     here would be dead code implying a safety property that isn't wired.
//   - Rolled-back records are DELETED rather than moved to a "reorged"
//     status. models.TxStatus has no such state — the server reads at a fixed
//     commitment, so its own transactions have a flat lifecycle — and adding
//     one would change the frozen api/openapi.yaml enum. Deleting matches what
//     these records are: a pure projection that must not outlive the events
//     backing it.
package txindex

import (
	"context"
	"fmt"
	"time"

	"github.com/rwa-platform/server/internal/dal/models"
	"github.com/rwa-platform/server/internal/dal/repository"
)

// txKinds maps each decoded event to a human-readable Transaction Kind, in
// PRIMARY-EVENT PRIORITY ORDER (earliest = highest priority). One transaction
// commonly emits several events — accepting an admin transfer emits
// AdminChanged alongside a RoleChanged, and bootstrap finalization emits both
// programs' Finalized in a single signature — so the record's Kind/From/To
// come from the highest-priority decoded event in that transaction.
//
// Value-bearing business actions rank above authority bookkeeping so a buy
// reads as "purchase" rather than whatever else its signature happened to
// carry. Names are the post-decode ChainEvent.Name, which is why the two
// colliding Finalized events appear under the disambiguated names
// blockchain.Decode assigns them (ComplianceFinalized / SupplyFinalized) —
// matching on "Finalized" here would silently never fire.
var txKinds = []struct{ event, kind string }{
	{"Purchased", "purchase"},
	{"ProceedsWithdrawn", "treasury_withdrawal"},
	{"Minted", "mint"},
	{"Burned", "burn"},
	{"RedemptionRequested", "redemption_requested"},
	{"RedemptionFunded", "redemption_funded"},
	// claim_redemption emits RedemptionCompleted (there is no distinct
	// "RedemptionClaimed" event) — it IS the claim, so it maps to that kind.
	{"RedemptionCompleted", "redemption_claimed"},
	{"RedemptionRejected", "redemption_rejected"},
	{"RedemptionCancelled", "redemption_cancelled"},
	{"RequestClosed", "redemption_request_closed"},
	{"StatusChanged", "compliance_status_changed"},
	{"PurchasePriceUpdated", "price_updated"},
	{"RedemptionPriceUpdated", "price_updated"},
	{"AuditorChanged", "auditor_changed"},
	{"PricerChanged", "pricer_changed"},
	{"PauseSet", "pause_set"},
	{"ComplianceFinalized", "compliance_finalized"},
	{"SupplyFinalized", "supply_finalized"},
	{"AdminProposed", "admin_transfer_scheduled"},
	{"AdminChanged", "admin_changed"},
	{"AdminTransferCancelled", "admin_transfer_cancelled"},
	{"RoleChanged", "role_changed"},
}

var (
	kindByEvent = map[string]string{}
	rankByEvent = map[string]int{}
)

func init() {
	for i, k := range txKinds {
		kindByEvent[k.event] = k.kind
		rankByEvent[k.event] = i
	}
}

// actorKeys are the event-data fields, in priority order, naming the account
// that signed the transaction. The first present, non-empty one wins.
//
// Order matters and is checked against the Anchor event definitions, not
// guessed:
//
//   - "by" is the explicit actor on every governance event, so it goes first.
//   - "buyer"/"funder"/"beneficiary" are the signer on Purchased /
//     RedemptionFunded / RedemptionRequested+RedemptionCancelled.
//   - "authority" outranks "account" because StatusChanged carries BOTH: the
//     authority signed it, while account is the wallet being acted upon.
//     Reversing these would attribute every compliance write to its subject.
//   - "newAdmin" is last-resort for AdminChanged, which carries no "by" —
//     accept_admin is called by the incoming admin, so it is the signer.
//     AdminProposed also has newAdmin but carries "by", which wins.
//
// Events with no actor field at all (Minted/Burned name the vault and the
// record, never the relayer; SupplyFinalized names only accounts) leave From
// empty rather than inventing an attribution. Those rows still list — they
// just won't match an `address` filter.
var actorKeys = []string{"by", "buyer", "funder", "beneficiary", "authority", "newAdmin", "account"}

// Reconcile replays every chain event for chainID into event-derived
// Transaction records. It:
//   - skips any signature a server-submitted record already owns, so the
//     compliance set_status call isn't listed twice;
//   - upserts one record per remaining signature that has at least one
//     non-removed decoded event, Status confirmed;
//   - deletes any previously-written event-derived record whose signature no
//     longer appears in the events (rolled back by the indexer).
//
// Safe to call repeatedly and before any deployment exists.
func Reconcile(ctx context.Context, txs repository.TransactionRepository, chainEvents repository.ChainEventRepository, chainID int64) error {
	events, err := chainEvents.ListAll(ctx, chainID)
	if err != nil {
		return fmt.Errorf("txindex: list all chain events: %w", err)
	}

	// Every existing record, read once. This is also the dedup source: it is
	// deliberately NOT a per-signature GetByTxHash, which takes chainID and
	// would miss a server-submitted record persisted under a different one.
	// Signatures are globally unique, so matching on the signature alone is
	// both correct and cheaper.
	existing, err := txs.List(ctx)
	if err != nil {
		return fmt.Errorf("txindex: list transactions: %w", err)
	}
	ownedByManager := map[string]bool{}
	derivedByHash := map[string]*models.Transaction{}
	for _, t := range existing {
		if models.IsEventDerived(t) {
			derivedByHash[t.TxHash] = t
			continue
		}
		if t.TxHash != "" {
			ownedByManager[t.TxHash] = true
		}
	}

	byTx := map[string][]*models.ChainEvent{}
	for _, e := range events {
		if e.Removed {
			continue
		}
		byTx[e.TxHash] = append(byTx[e.TxHash], e)
	}

	now := time.Now().UTC()
	live := map[string]bool{}

	for txHash, evs := range byTx {
		primary := pickPrimary(evs)
		if primary == nil {
			continue // only undecodable logs — nothing to attribute
		}
		live[txHash] = true
		if ownedByManager[txHash] {
			continue // a server-submitted record already lists this signature
		}

		prev := derivedByHash[txHash]
		rec := buildEventDerivedTx(chainID, txHash, evs, primary, prev, now)
		if prev == nil {
			if err := txs.Create(ctx, rec); err != nil {
				return fmt.Errorf("txindex: create event-derived tx %s: %w", txHash, err)
			}
		} else if err := txs.Update(ctx, rec); err != nil {
			return fmt.Errorf("txindex: update event-derived tx %s: %w", txHash, err)
		}
	}

	// Rollback pass: an event-derived record whose signature no longer appears
	// in chain_events had its events deleted out from under it. Drop it — see
	// the package doc comment on why this deletes rather than restatuses.
	for txHash, t := range derivedByHash {
		if live[txHash] {
			continue
		}
		if err := txs.Delete(ctx, t.ID); err != nil {
			return fmt.Errorf("txindex: delete rolled-back tx %s: %w", txHash, err)
		}
	}
	return nil
}

// pickPrimary returns the highest-priority decoded event among a transaction's
// events, or nil when none is decoded. Ties break by (slot, logIndex) so the
// choice is stable across replays regardless of storage order.
func pickPrimary(evs []*models.ChainEvent) *models.ChainEvent {
	var best *models.ChainEvent
	bestRank := 0
	for _, e := range evs {
		if e.Name == "" || e.Name == "unknown" {
			continue
		}
		r, ok := rankByEvent[e.Name]
		if !ok {
			// Decoded but unmapped — a program gained an event this map
			// hasn't been taught. Still eligible (it becomes Kind verbatim),
			// but ranked below everything known so it never outranks a
			// business action in the same transaction.
			r = len(txKinds)
		}
		if best == nil || r < bestRank || (r == bestRank && earlier(e, best)) {
			best, bestRank = e, r
		}
	}
	return best
}

// buildEventDerivedTx assembles the record from a transaction's events and its
// chosen primary. To is the primary's emitting program; From the signer decoded
// from it; Kind the mapped (or raw) event name. BlockNumber comes from the
// latest event and SubmittedAt from the earliest — pinned once written, so the
// SubmittedAt-ordered keyset pagination never reshuffles under replay.
func buildEventDerivedTx(chainID int64, txHash string, evs []*models.ChainEvent, primary *models.ChainEvent, prev *models.Transaction, now time.Time) *models.Transaction {
	earliest, latest := evs[0], evs[0]
	for _, e := range evs {
		if earlier(e, earliest) {
			earliest = e
		}
		if earlier(latest, e) {
			latest = e
		}
	}
	kind, ok := kindByEvent[primary.Name]
	if !ok {
		kind = primary.Name
	}
	submittedAt := earliest.IndexedAt
	if prev != nil && !prev.SubmittedAt.IsZero() {
		submittedAt = prev.SubmittedAt
	}
	return &models.Transaction{
		ID:          models.EventDerivedTxIDPrefix + txHash,
		ChainID:     chainID,
		TxHash:      txHash,
		Kind:        kind,
		From:        actorFrom(primary.Data),
		To:          primary.Address,
		Status:      models.TxConfirmed,
		BlockNumber: latest.BlockNumber,
		SubmittedAt: submittedAt,
		UpdatedAt:   now,
	}
}

// actorFrom returns the first present signer address among actorKeys, or ""
// when the event names none. Values are base58 pubkeys decoded by
// blockchain.Decode; they are passed through as-is rather than re-validated,
// since anything reaching here already round-tripped through that decoder.
func actorFrom(data map[string]any) string {
	for _, k := range actorKeys {
		if v, _ := data[k].(string); v != "" {
			return v
		}
	}
	return ""
}

// earlier reports whether a precedes b in (slot, logIndex) order.
func earlier(a, b *models.ChainEvent) bool {
	if a.BlockNumber != b.BlockNumber {
		return a.BlockNumber < b.BlockNumber
	}
	return a.LogIndex < b.LogIndex
}
