package txindex

import (
	"context"
	"testing"
	"time"

	"github.com/rwa-platform/server/internal/dal/memory"
	"github.com/rwa-platform/server/internal/dal/models"
)

const chainID int64 = 103

const (
	vaultProgram      = "2XnocgeBA5iT4mUEvuMCkbNPBscs9n7A2MdYL2zPBVjT"
	complianceProgram = "ECGfTwvG1JaAxJ11ub7HjgTB9KJFH4HSDUJR7reFeVVH"
	redemptionProgram = "32J24AMuuocveSVofvbqWS4HrspAKqsNp7xnrtWw1uFY"
	buyer             = "EBbtqhpUzonDFRJewDv7UFdwJj73ZuwZPcgRbAmfsPuj"
	subject           = "LhiYte7h75hKQw6K95k2BJBRyVj4zPpxYUfiJh49hb6"
)

type repos struct {
	txs    *memory.TransactionRepository
	events *memory.ChainEventRepository
}

func newRepos() repos {
	return repos{txs: memory.NewTransactionRepository(), events: memory.NewChainEventRepository()}
}

// addEvent stores one decoded event. slot/logIndex position it within the
// replay; data carries the actor fields actorFrom reads.
func (r repos) addEvent(t *testing.T, addr, txHash, name string, slot uint64, logIndex uint, data map[string]any) {
	t.Helper()
	if data == nil {
		data = map[string]any{}
	}
	err := r.events.Create(context.Background(), &models.ChainEvent{
		ChainID: chainID, Address: addr, TxHash: txHash, LogIndex: logIndex,
		BlockNumber: slot, Name: name, Data: data,
		IndexedAt: time.Unix(1_700_000_000+int64(slot), 0).UTC(),
	})
	if err != nil {
		t.Fatalf("seed event: %v", err)
	}
}

func (r repos) run(t *testing.T) {
	t.Helper()
	if err := Reconcile(context.Background(), r.txs, r.events, chainID); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
}

func (r repos) byHash(t *testing.T, txHash string) *models.Transaction {
	t.Helper()
	all, err := r.txs.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, tx := range all {
		if tx.TxHash == txHash {
			return tx
		}
	}
	return nil
}

func (r repos) count(t *testing.T) int {
	t.Helper()
	all, err := r.txs.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	return len(all)
}

// The regression this package exists for: the server submits only the
// compliance set_status call, so before this projector every wallet-broadcast
// action was invisible in GET /transactions no matter how much the indexer had
// ingested. This walks the exact sequence a real deployment produces.
func TestReconcileProjectsWalletBroadcastActions(t *testing.T) {
	r := newRepos()
	r.addEvent(t, vaultProgram, "sig-buy", "Purchased", 2715, 0, map[string]any{
		"buyer": buyer, "recipient": buyer, "tokenAmount": "100000000", "quoteAmount": "100000000",
	})
	r.addEvent(t, redemptionProgram, "sig-request", "RedemptionRequested", 2796, 0, map[string]any{
		"id": "1", "beneficiary": buyer, "rwaAmount": "5000000", "quoteAmount": "5000000",
	})
	r.addEvent(t, redemptionProgram, "sig-fund", "RedemptionFunded", 2865, 0, map[string]any{
		"id": "1", "funder": buyer, "quoteAmount": "5000000",
	})
	r.addEvent(t, redemptionProgram, "sig-claim", "RedemptionCompleted", 7093, 0, map[string]any{
		"id": "1", "beneficiary": buyer, "rwaAmount": "5000000", "quoteAmount": "5000000",
	})
	r.addEvent(t, vaultProgram, "sig-withdraw", "ProceedsWithdrawn", 7177, 0, map[string]any{
		"treasury": subject, "amount": "100000000", "by": buyer,
	})

	r.run(t)

	want := map[string]string{
		"sig-buy":      "purchase",
		"sig-request":  "redemption_requested",
		"sig-fund":     "redemption_funded",
		"sig-claim":    "redemption_claimed",
		"sig-withdraw": "treasury_withdrawal",
	}
	if got := r.count(t); got != len(want) {
		t.Fatalf("transaction count = %d, want %d", got, len(want))
	}
	for hash, kind := range want {
		tx := r.byHash(t, hash)
		if tx == nil {
			t.Fatalf("no transaction projected for %s", hash)
		}
		if tx.Kind != kind {
			t.Errorf("%s kind = %q, want %q", hash, tx.Kind, kind)
		}
		if tx.Status != models.TxConfirmed {
			t.Errorf("%s status = %q, want confirmed", hash, tx.Status)
		}
		if tx.From != buyer {
			t.Errorf("%s from = %q, want the signing wallet %q", hash, tx.From, buyer)
		}
		if !models.IsEventDerived(tx) {
			t.Errorf("%s id %q is not marked event-derived", hash, tx.ID)
		}
	}
}

// A second run must not duplicate or churn: the ID is derived from the
// signature and SubmittedAt is pinned once written, which is what keeps
// SubmittedAt-ordered keyset pagination stable across ticks.
func TestReconcileIsIdempotent(t *testing.T) {
	r := newRepos()
	r.addEvent(t, vaultProgram, "sig-buy", "Purchased", 2715, 0, map[string]any{"buyer": buyer})

	r.run(t)
	first := *r.byHash(t, "sig-buy")

	// A later event in the same transaction must not move SubmittedAt.
	r.addEvent(t, vaultProgram, "sig-buy", "RoleChanged", 2715, 1, map[string]any{"by": buyer})
	r.run(t)

	if got := r.count(t); got != 1 {
		t.Fatalf("transaction count after replay = %d, want 1", got)
	}
	again := r.byHash(t, "sig-buy")
	if !again.SubmittedAt.Equal(first.SubmittedAt) {
		t.Errorf("SubmittedAt moved on replay: %v -> %v", first.SubmittedAt, again.SubmittedAt)
	}
	if again.ID != first.ID {
		t.Errorf("ID changed on replay: %q -> %q", first.ID, again.ID)
	}
}

// The compliance set_status call emits StatusChanged, so its signature appears
// in BOTH populations. It must list once, from the server's own record — that
// one carries real lifecycle state (it can be pending, or failed) which the
// events cannot reconstruct.
func TestReconcileDoesNotDuplicateServerSubmittedTransactions(t *testing.T) {
	r := newRepos()
	if err := r.txs.Create(context.Background(), &models.Transaction{
		ID: "uuid-1", Kind: "compliance.setStatus", TxHash: "sig-status",
		From: buyer, To: complianceProgram, Status: models.TxPending,
		// Deliberately 0, matching what StatusService persists today while
		// events carry the configured chain id. Dedup must not depend on
		// these agreeing.
		ChainID:     0,
		SubmittedAt: time.Unix(1_700_000_000, 0).UTC(),
	}); err != nil {
		t.Fatalf("seed server tx: %v", err)
	}
	r.addEvent(t, complianceProgram, "sig-status", "StatusChanged", 2071, 0, map[string]any{
		"account": subject, "authority": buyer, "newStatus": uint(1),
	})

	r.run(t)

	if got := r.count(t); got != 1 {
		t.Fatalf("transaction count = %d, want 1 (no duplicate for the server's own signature)", got)
	}
	tx := r.byHash(t, "sig-status")
	if tx.ID != "uuid-1" || tx.Kind != "compliance.setStatus" {
		t.Errorf("server-submitted record was overwritten: id=%q kind=%q", tx.ID, tx.Kind)
	}
	if tx.Status != models.TxPending {
		t.Errorf("status = %q, want the server's own pending state preserved", tx.Status)
	}
}

// StatusChanged names both the acting authority and the wallet acted upon.
// Attributing it to the subject would make an `address` filter claim the
// investor sent the compliance write.
func TestActorPrefersAuthorityOverSubjectAccount(t *testing.T) {
	r := newRepos()
	r.addEvent(t, complianceProgram, "sig-status", "StatusChanged", 2071, 0, map[string]any{
		"account": subject, "authority": buyer,
	})

	r.run(t)

	if got := r.byHash(t, "sig-status").From; got != buyer {
		t.Errorf("from = %q, want the authority %q, not the subject account", got, buyer)
	}
}

// accept_admin emits AdminChanged, which carries no "by" — the incoming admin
// is the signer.
func TestActorFallsBackToNewAdminWhenNoByField(t *testing.T) {
	r := newRepos()
	r.addEvent(t, complianceProgram, "sig-accept", "AdminChanged", 3000, 0, map[string]any{
		"previous": subject, "newAdmin": buyer,
	})

	r.run(t)

	tx := r.byHash(t, "sig-accept")
	if tx.From != buyer {
		t.Errorf("from = %q, want the accepting admin %q", tx.From, buyer)
	}
	if tx.Kind != "admin_changed" {
		t.Errorf("kind = %q, want admin_changed", tx.Kind)
	}
}

// Minted names the vault and the record, never the relayer. Inventing an
// attribution would be worse than leaving it blank, but the row must still
// list.
func TestEventWithNoActorFieldStillProjects(t *testing.T) {
	r := newRepos()
	r.addEvent(t, "FtiSEvVU51FBuXuD5fBK1JDqeyAayJwuNSJx7vXGPQBT", "sig-mint", "Minted", 1991, 0,
		map[string]any{"vault": subject, "amount": "1000000000"})

	r.run(t)

	tx := r.byHash(t, "sig-mint")
	if tx == nil {
		t.Fatal("Minted produced no transaction")
	}
	if tx.From != "" {
		t.Errorf("from = %q, want empty (the event names no signer)", tx.From)
	}
	if tx.Kind != "mint" {
		t.Errorf("kind = %q, want mint", tx.Kind)
	}
}

// One signature, several events: the business action must win over the
// authority bookkeeping that rode along with it, whatever order they are
// stored in.
func TestPrimaryEventPrefersBusinessActionOverBookkeeping(t *testing.T) {
	r := newRepos()
	// RoleChanged first (lower slot position) to prove ranking, not order,
	// decides.
	r.addEvent(t, vaultProgram, "sig-multi", "RoleChanged", 4000, 0, map[string]any{"by": subject})
	r.addEvent(t, vaultProgram, "sig-multi", "Purchased", 4000, 1, map[string]any{"buyer": buyer})

	r.run(t)

	tx := r.byHash(t, "sig-multi")
	if tx.Kind != "purchase" {
		t.Errorf("kind = %q, want purchase (the business action outranks RoleChanged)", tx.Kind)
	}
	if tx.From != buyer {
		t.Errorf("from = %q, want the primary event's buyer %q", tx.From, buyer)
	}
}

// Bootstrap finalization emits both programs' Finalized under one signature.
// blockchain.Decode renames them apart; matching on the raw "Finalized" here
// would silently never fire, so this pins the disambiguated names.
func TestDisambiguatedFinalizedNamesAreMapped(t *testing.T) {
	for _, tc := range []struct{ name, kind string }{
		{"ComplianceFinalized", "compliance_finalized"},
		{"SupplyFinalized", "supply_finalized"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRepos()
			r.addEvent(t, complianceProgram, "sig-"+tc.name, tc.name, 1607, 0, map[string]any{"by": buyer})
			r.run(t)
			if got := r.byHash(t, "sig-"+tc.name).Kind; got != tc.kind {
				t.Errorf("kind = %q, want %q", got, tc.kind)
			}
		})
	}
}

// A program gaining an event this map hasn't been taught must still produce a
// row (Kind verbatim), and must never outrank a known business action.
func TestUnmappedEventProjectsVerbatimAndRanksLast(t *testing.T) {
	r := newRepos()
	r.addEvent(t, vaultProgram, "sig-new", "SomeFutureEvent", 5000, 0, map[string]any{"by": buyer})
	r.addEvent(t, vaultProgram, "sig-mixed", "SomeFutureEvent", 5001, 0, map[string]any{"by": subject})
	r.addEvent(t, vaultProgram, "sig-mixed", "Purchased", 5001, 1, map[string]any{"buyer": buyer})

	r.run(t)

	if got := r.byHash(t, "sig-new").Kind; got != "SomeFutureEvent" {
		t.Errorf("unmapped kind = %q, want the raw event name", got)
	}
	if got := r.byHash(t, "sig-mixed").Kind; got != "purchase" {
		t.Errorf("mixed kind = %q, want purchase (unmapped must rank last)", got)
	}
}

// Full-replay semantics: a record must not outlive the events backing it.
func TestRolledBackTransactionIsRemoved(t *testing.T) {
	r := newRepos()
	r.addEvent(t, vaultProgram, "sig-buy", "Purchased", 2715, 0, map[string]any{"buyer": buyer})
	r.addEvent(t, vaultProgram, "sig-later", "Purchased", 9000, 0, map[string]any{"buyer": buyer})
	r.run(t)
	if got := r.count(t); got != 2 {
		t.Fatalf("setup: count = %d, want 2", got)
	}

	// The indexer hard-deletes on rollback (DeleteFromBlock), which is what a
	// reindex or a rolled-back slot looks like to this projector.
	if _, err := r.events.DeleteFromBlock(context.Background(), chainID, vaultProgram, 9000); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	r.run(t)

	if r.byHash(t, "sig-later") != nil {
		t.Error("rolled-back transaction still listed")
	}
	if r.byHash(t, "sig-buy") == nil {
		t.Error("surviving transaction was removed too")
	}
}

// The rollback pass must only ever touch this projector's own records.
func TestRollbackPassNeverDeletesServerSubmittedRecords(t *testing.T) {
	r := newRepos()
	if err := r.txs.Create(context.Background(), &models.Transaction{
		ID: "uuid-1", Kind: "compliance.setStatus", TxHash: "sig-status",
		From: buyer, To: complianceProgram, Status: models.TxPending,
		SubmittedAt: time.Unix(1_700_000_000, 0).UTC(),
	}); err != nil {
		t.Fatalf("seed server tx: %v", err)
	}

	// No events at all — the server record was written before its
	// StatusChanged was ever indexed, which is the real ordering (the record
	// is persisted before broadcast).
	r.run(t)

	if r.byHash(t, "sig-status") == nil {
		t.Fatal("server-submitted record was deleted by the rollback pass")
	}
}

// A soft-removed event must not resurrect a record, and must not keep one
// alive. The Solana indexer only hard-deletes today, but ListAll's contract
// includes removed rows, so the projector filters them explicitly.
func TestSoftRemovedEventsAreIgnored(t *testing.T) {
	r := newRepos()
	if err := r.events.Create(context.Background(), &models.ChainEvent{
		ChainID: chainID, Address: vaultProgram, TxHash: "sig-gone", LogIndex: 0,
		BlockNumber: 2715, Name: "Purchased", Data: map[string]any{"buyer": buyer},
		Removed: true, IndexedAt: time.Unix(1_700_000_000, 0).UTC(),
	}); err != nil {
		t.Fatalf("seed removed event: %v", err)
	}

	r.run(t)

	if got := r.count(t); got != 0 {
		t.Fatalf("count = %d, want 0 (a removed event backs nothing)", got)
	}
}

// Events for another chain must not leak into this chain's projection.
func TestOtherChainEventsAreExcluded(t *testing.T) {
	r := newRepos()
	if err := r.events.Create(context.Background(), &models.ChainEvent{
		ChainID: chainID + 1, Address: vaultProgram, TxHash: "sig-other", LogIndex: 0,
		BlockNumber: 2715, Name: "Purchased", Data: map[string]any{"buyer": buyer},
		IndexedAt: time.Unix(1_700_000_000, 0).UTC(),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	r.run(t)

	if got := r.count(t); got != 0 {
		t.Fatalf("count = %d, want 0", got)
	}
}

// Running against a deployment that has never emitted anything must be a
// clean no-op — pollAndReconcile calls this every 5s from boot.
func TestReconcileOnEmptyStateIsNoOp(t *testing.T) {
	r := newRepos()
	r.run(t)
	if got := r.count(t); got != 0 {
		t.Fatalf("count = %d, want 0", got)
	}
}

// Every kind this projector can emit must be a stable, non-empty slug: the SPA
// renders Transaction.kind verbatim, so an empty or duplicated-by-accident
// mapping shows up as a blank cell.
func TestEveryMappedKindIsNonEmpty(t *testing.T) {
	for _, k := range txKinds {
		if k.event == "" || k.kind == "" {
			t.Errorf("empty mapping entry: %+v", k)
		}
	}
	if len(kindByEvent) != len(txKinds) {
		t.Errorf("duplicate event name in txKinds: %d unique of %d entries", len(kindByEvent), len(txKinds))
	}
}
