package models

import "time"

// TxStatus is the lifecycle state of a server-submitted transaction.
//
// The server broadcasts exactly one kind of transaction — the compliance hot
// key's set_status call (see internal/compliance.StatusService) — and it
// reads at a fixed commitment (normally "finalized"), so the lifecycle is
// flat. There is no fee-bumped replacement, no account-nonce sequence, and no
// rollback of an already-observed confirmation, so none of the EVM-style
// intermediate/recovery states (mined, replaced, reverted, reorged,
// broadcast-unknown, nonce-consumed-externally, needs-intervention) have a
// counterpart here.
type TxStatus string

const (
	// TxPending means the transaction was persisted and broadcast, but has
	// not yet been observed at the configured commitment.
	TxPending TxStatus = "pending"
	// TxConfirmed means the cluster reported the transaction at the
	// configured commitment. Because that commitment is fixed (normally
	// "finalized"), this is terminal — it is never walked back.
	TxConfirmed TxStatus = "confirmed"
	// TxFailed means the transaction did not take effect: submission itself
	// returned a definite error, or the cluster reported the transaction
	// with an execution error. Nothing happened on-chain, so a TxFailed
	// record's Idempotency-Key is retryable — the caller may submit the
	// same logical operation again (see
	// compliance.StatusService's retry policy).
	TxFailed TxStatus = "failed"
)

// AllTxStatuses is the single source-of-truth list of every TxStatus the
// server can persist and the API can therefore emit. The OpenAPI
// Transaction.status enum, the generated TS type, and the UI status maps must
// cover exactly this set — the transactions handler returns the raw status
// string, so any status missing from the enum/UI renders as an
// undefined/unknown badge. A contract test (TestAllTxStatusesMatchesConstants)
// asserts this slice stays in lockstep with the const block above, and
// TestAllTxStatusesMatchesOpenAPIEnum asserts it matches api/openapi.yaml's
// enum exactly.
var AllTxStatuses = []TxStatus{
	TxPending,
	TxConfirmed,
	TxFailed,
}

// EventDerivedTxIDPrefix marks a Transaction the server did NOT submit —
// one synthesized from indexed chain events by txindex.ReconcileTransactions
// so that wallet-broadcast actions (buys, the redemption lifecycle, treasury
// withdrawals, role/price/pause changes) appear in GET /transactions
// alongside the server's own compliance writes.
//
// The ID is a deterministic function of the signature, which is what makes
// the projector idempotent: replaying the same events re-derives the same
// _id and updates in place rather than accumulating duplicates.
const EventDerivedTxIDPrefix = "evt:"

// IsEventDerived reports whether tx was synthesized from chain events rather
// than submitted by this server. Used to keep the two populations apart: the
// projector only ever rewrites or removes its own records, so a
// server-submitted row (which carries lifecycle state the events cannot
// reconstruct, e.g. a pending broadcast or a definite submission failure) is
// never clobbered by a replay.
func IsEventDerived(tx *Transaction) bool {
	return tx != nil && len(tx.ID) > len(EventDerivedTxIDPrefix) &&
		tx.ID[:len(EventDerivedTxIDPrefix)] == EventDerivedTxIDPrefix
}

// Transaction is one chain transaction (collection: transactions) — either
// submitted by this server (see TxStatus) or synthesized from indexed events
// (see EventDerivedTxIDPrefix).
type Transaction struct {
	ID             string `json:"id" bson:"_id"`
	IdempotencyKey string `json:"idempotencyKey,omitempty" bson:"idempotencyKey,omitempty"`
	Kind           string `json:"kind" bson:"kind"`
	ChainID        int64  `json:"chainId" bson:"chainId"`
	// From is the fee payer / signing account (base58); To is the program
	// the instruction targets (base58).
	From string `json:"from" bson:"from"`
	To   string `json:"to" bson:"to"`
	// TxHash is the transaction signature (base58).
	TxHash string   `json:"txHash" bson:"txHash"`
	Status TxStatus `json:"status" bson:"status"`
	// BlockNumber is the slot the transaction was confirmed in; zero while
	// still pending.
	BlockNumber uint64    `json:"blockNumber,omitempty" bson:"blockNumber,omitempty"`
	SubmittedAt time.Time `json:"submittedAt" bson:"submittedAt"`
	UpdatedAt   time.Time `json:"updatedAt" bson:"updatedAt"`
}
