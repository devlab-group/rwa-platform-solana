package blockchain

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/rwa-platform/server/internal/dal/memory"
)

const testChainID int64 = 900

const vaultProgramID = "VauLtProgram11111111111111111111111111111"

// purchasedDisc is the real Vault IDL discriminator for Purchased.
var purchasedDisc = [8]byte{20, 112, 33, 232, 177, 248, 215, 233}

func purchasedPayload(tokenAmount, quoteAmount uint64) []byte {
	buyer, _ := pubkeyBytes(0x01)
	recipient, _ := pubkeyBytes(0x02)
	return buildPayload(purchasedDisc, buyer, recipient, leU64(tokenAmount), leU64(quoteAmount))
}

func newTestRepos() (*memory.IndexerCheckpointRepository, *memory.ChainEventRepository) {
	return memory.NewIndexerCheckpointRepository(), memory.NewChainEventRepository()
}

func newTestIndexer(src *fakeSource, checkpoints *memory.IndexerCheckpointRepository, events *memory.ChainEventRepository) *Indexer {
	programIDs := map[ProgramRole]string{RoleVault: vaultProgramID}
	return New(src, checkpoints, events, programIDs, testChainID, "finalized", 0)
}

func TestIndexerIngestsAndAdvancesCheckpoint(t *testing.T) {
	src := newFakeSource()
	src.SetSlot(10)
	src.AddTx(vaultProgramID, SigInfo{Signature: "sig1", Slot: 5}, framedLogLines(vaultProgramID,
		"Program log: instruction: buy",
		programDataLine(purchasedPayload(100, 50)),
	), nil)
	src.AddTx(vaultProgramID, SigInfo{Signature: "sig2", Slot: 6}, framedLogLines(vaultProgramID,
		programDataLine(purchasedPayload(200, 75)),
	), nil)

	checkpoints, events := newTestRepos()
	idx := newTestIndexer(src, checkpoints, events)

	if err := idx.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}

	cp, err := checkpoints.Get(context.Background(), testChainID, vaultProgramID)
	if err != nil {
		t.Fatalf("checkpoint not saved: %v", err)
	}
	if cp.LastBlock != 6 || cp.LastBlockHash != "sig2" {
		t.Errorf("checkpoint = (slot=%d, sig=%q), want (6, sig2)", cp.LastBlock, cp.LastBlockHash)
	}

	evs, err := events.ListByName(context.Background(), testChainID, vaultProgramID, "Purchased")
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 {
		t.Fatalf("expected 2 Purchased events, got %d", len(evs))
	}
	if evs[0].TxHash != "sig1" || evs[0].BlockNumber != 5 {
		t.Errorf("event0 = %+v", evs[0])
	}
	if evs[0].Data["tokenAmount"] != "100" {
		t.Errorf("event0 tokenAmount = %v, want 100", evs[0].Data["tokenAmount"])
	}
	if evs[1].TxHash != "sig2" || evs[1].Data["tokenAmount"] != "200" {
		t.Errorf("event1 = %+v", evs[1])
	}
}

// TestIndexerNewestToOldestReordering proves Poll processes an initial
// backlog in chronological (oldest-first) order even though the RPC serves
// pages newest-first, by checking LogIndex/ordering artifacts that would
// only line up correctly if sig1 (added first, hence oldest) was ingested
// before sig2.
func TestIndexerNewestToOldestReordering(t *testing.T) {
	src := newFakeSource()
	src.SetSlot(10)
	for i := 1; i <= 5; i++ {
		src.AddTx(vaultProgramID, SigInfo{Signature: fmt.Sprintf("sig%d", i), Slot: uint64(i)}, framedLogLines(vaultProgramID,
			programDataLine(purchasedPayload(uint64(i)*10, uint64(i))),
		), nil)
	}

	checkpoints, events := newTestRepos()
	idx := newTestIndexer(src, checkpoints, events)
	if err := idx.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}

	evs, err := events.ListByName(context.Background(), testChainID, vaultProgramID, "Purchased")
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 5 {
		t.Fatalf("expected 5 events, got %d", len(evs))
	}
	for i, e := range evs {
		wantSig := fmt.Sprintf("sig%d", i+1)
		if e.TxHash != wantSig {
			t.Errorf("event[%d].TxHash = %q, want %q (chronological order)", i, e.TxHash, wantSig)
		}
	}

	cp, err := checkpoints.Get(context.Background(), testChainID, vaultProgramID)
	if err != nil {
		t.Fatal(err)
	}
	if cp.LastBlockHash != "sig5" {
		t.Errorf("checkpoint sig = %q, want sig5 (newest processed)", cp.LastBlockHash)
	}
}

// TestIndexerIdempotentAcrossPolls proves a second Poll with no new chain
// activity does not duplicate events nor error.
func TestIndexerIdempotentAcrossPolls(t *testing.T) {
	src := newFakeSource()
	src.SetSlot(10)
	src.AddTx(vaultProgramID, SigInfo{Signature: "sig1", Slot: 5}, framedLogLines(vaultProgramID,
		programDataLine(purchasedPayload(100, 50)),
	), nil)

	checkpoints, events := newTestRepos()
	idx := newTestIndexer(src, checkpoints, events)

	if err := idx.Poll(context.Background()); err != nil {
		t.Fatalf("Poll #1: %v", err)
	}
	if err := idx.Poll(context.Background()); err != nil {
		t.Fatalf("Poll #2: %v", err)
	}

	evs, err := events.ListByName(context.Background(), testChainID, vaultProgramID, "Purchased")
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 {
		t.Fatalf("expected 1 event after 2 idempotent polls, got %d", len(evs))
	}
}

// TestIndexerSkipsFailedTransactions proves a signature reported with a
// non-nil Err is never fetched/decoded — its "logged" events (if any) must
// not be ingested.
func TestIndexerSkipsFailedTransactions(t *testing.T) {
	src := newFakeSource()
	src.SetSlot(10)
	src.AddTx(vaultProgramID, SigInfo{Signature: "sig-ok", Slot: 1}, framedLogLines(vaultProgramID,
		programDataLine(purchasedPayload(100, 50)),
	), nil)
	src.AddTx(vaultProgramID, SigInfo{Signature: "sig-failed", Slot: 2, Err: map[string]any{"InstructionError": []any{0, "Custom"}}}, framedLogLines(vaultProgramID,
		programDataLine(purchasedPayload(999, 999)),
	), nil)

	checkpoints, events := newTestRepos()
	idx := newTestIndexer(src, checkpoints, events)
	if err := idx.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}

	evs, err := events.ListByName(context.Background(), testChainID, vaultProgramID, "Purchased")
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 {
		t.Fatalf("expected 1 event (failed tx skipped), got %d", len(evs))
	}
	if evs[0].TxHash != "sig-ok" {
		t.Errorf("ingested event from %q, want sig-ok only", evs[0].TxHash)
	}

	// A failed signature is never GetTransaction-fetched/decoded, so it
	// never contributes an event — but it IS a signature this poll has
	// observed, so the checkpoint advances past it too: otherwise every
	// subsequent poll would re-list and re-skip the same
	// trailing failed signature forever, and stall entirely if the
	// program's newest activity were a run of failures.
	cp, err := checkpoints.Get(context.Background(), testChainID, vaultProgramID)
	if err != nil {
		t.Fatal(err)
	}
	if cp.LastBlockHash != "sig-failed" {
		t.Errorf("checkpoint sig = %q, want sig-failed (the newest signature observed this poll, even though it emitted no events)", cp.LastBlockHash)
	}

	// A subsequent poll must not re-list sig-failed (checkpoint moved past
	// it) and must not error or duplicate anything.
	if err := idx.Poll(context.Background()); err != nil {
		t.Fatalf("Poll #2: %v", err)
	}
	evs2, err := events.ListByName(context.Background(), testChainID, vaultProgramID, "Purchased")
	if err != nil {
		t.Fatal(err)
	}
	if len(evs2) != 1 {
		t.Errorf("after idempotent re-poll: expected 1 event, got %d", len(evs2))
	}
}

// TestIndexerAdvancesPastTrailingRunOfFailedTransactions is a
// regression guard: when a program's ENTIRE new activity since the last
// checkpoint is a run of failed transactions (no successful signature
// anywhere in the batch to fall back on), the checkpoint must still
// advance to the newest of them — otherwise indexing that program would
// stall indefinitely, re-fetching and re-skipping the same failed
// signatures on every tick.
func TestIndexerAdvancesPastTrailingRunOfFailedTransactions(t *testing.T) {
	src := newFakeSource()
	src.SetSlot(10)
	failErr := map[string]any{"InstructionError": []any{0, "Custom"}}
	src.AddTx(vaultProgramID, SigInfo{Signature: "sig-fail-1", Slot: 1, Err: failErr}, nil, nil)
	src.AddTx(vaultProgramID, SigInfo{Signature: "sig-fail-2", Slot: 2, Err: failErr}, nil, nil)
	src.AddTx(vaultProgramID, SigInfo{Signature: "sig-fail-3", Slot: 3, Err: failErr}, nil, nil)

	checkpoints, events := newTestRepos()
	idx := newTestIndexer(src, checkpoints, events)
	if err := idx.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}

	cp, err := checkpoints.Get(context.Background(), testChainID, vaultProgramID)
	if err != nil {
		t.Fatalf("checkpoint not saved: %v", err)
	}
	if cp.LastBlockHash != "sig-fail-3" {
		t.Errorf("checkpoint sig = %q, want sig-fail-3 (newest of the all-failed batch)", cp.LastBlockHash)
	}

	evs, err := events.ListAll(context.Background(), testChainID)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 0 {
		t.Errorf("expected no events from an all-failed batch, got %d", len(evs))
	}
}

// TestIndexerSkipsNonEventAndGarbageLogLines proves an ordinary
// "Program log:" line and a "Program data:" line with an unrecognized
// discriminator are both skipped without error, and don't produce spurious
// ChainEvents.
func TestIndexerSkipsNonEventAndGarbageLogLines(t *testing.T) {
	src := newFakeSource()
	src.SetSlot(10)
	garbage := base64.StdEncoding.EncodeToString([]byte{0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6})
	src.AddTx(vaultProgramID, SigInfo{Signature: "sig1", Slot: 1}, []string{
		"Program VauLtProgram11111111111111111111111111111 invoke [1]",
		"Program log: instruction: buy",
		"Program data: " + garbage,
		programDataLine(purchasedPayload(42, 7)),
		"Program VauLtProgram11111111111111111111111111111 success",
	}, nil)

	checkpoints, events := newTestRepos()
	idx := newTestIndexer(src, checkpoints, events)
	if err := idx.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}

	evs, err := events.ListByName(context.Background(), testChainID, vaultProgramID, "Purchased")
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evs))
	}
	// The Purchased data line is the 4th log line (index 3), but only 2 of
	// the 5 lines have the "Program data:" prefix (garbage at index 2,
	// Purchased at index 3) — LogIndex counts matched data-lines only, so
	// the real event should be LogIndex 1 (the garbage line consumed 0).
	if evs[0].LogIndex != 1 {
		t.Errorf("LogIndex = %d, want 1", evs[0].LogIndex)
	}
}

// TestIndexerPaginatesAcrossPageBoundary proves a backlog spanning more
// than one getSignaturesForAddress page (limit=1000) is fully ingested and
// still ends up in correct chronological order.
func TestIndexerPaginatesAcrossPageBoundary(t *testing.T) {
	src := newFakeSource()
	src.SetSlot(0)
	const total = 1250
	for i := 1; i <= total; i++ {
		src.AddTx(vaultProgramID, SigInfo{Signature: fmt.Sprintf("sig%04d", i), Slot: uint64(i)}, framedLogLines(vaultProgramID,
			programDataLine(purchasedPayload(uint64(i), 1)),
		), nil)
	}
	src.SetSlot(total)

	checkpoints, events := newTestRepos()
	idx := newTestIndexer(src, checkpoints, events)
	if err := idx.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}

	evs, err := events.ListByName(context.Background(), testChainID, vaultProgramID, "Purchased")
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != total {
		t.Fatalf("expected %d events, got %d", total, len(evs))
	}
	for i, e := range evs {
		want := fmt.Sprintf("sig%04d", i+1)
		if e.TxHash != want {
			t.Fatalf("event[%d].TxHash = %q, want %q", i, e.TxHash, want)
		}
	}

	cp, err := checkpoints.Get(context.Background(), testChainID, vaultProgramID)
	if err != nil {
		t.Fatal(err)
	}
	if cp.LastBlockHash != fmt.Sprintf("sig%04d", total) {
		t.Errorf("checkpoint sig = %q, want sig%04d", cp.LastBlockHash, total)
	}

	// A subsequent poll with no new activity must not duplicate anything.
	if err := idx.Poll(context.Background()); err != nil {
		t.Fatalf("Poll #2: %v", err)
	}
	evs2, err := events.ListByName(context.Background(), testChainID, vaultProgramID, "Purchased")
	if err != nil {
		t.Fatal(err)
	}
	if len(evs2) != total {
		t.Fatalf("after idempotent re-poll: expected %d events, got %d", total, len(evs2))
	}
}

// TestIndexerAddressIsProgramIDVerbatim proves ChainEvent.Address is the
// configured program ID exactly as given (never derived/lowercased),
// matching the frozen contract's addressing invariant.
func TestIndexerAddressIsProgramIDVerbatim(t *testing.T) {
	src := newFakeSource()
	src.SetSlot(1)
	src.AddTx(vaultProgramID, SigInfo{Signature: "sig1", Slot: 1}, framedLogLines(vaultProgramID,
		programDataLine(purchasedPayload(1, 1)),
	), nil)

	checkpoints, events := newTestRepos()
	idx := newTestIndexer(src, checkpoints, events)
	if err := idx.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}

	evs, err := events.ListAll(context.Background(), testChainID)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0].Address != vaultProgramID {
		t.Errorf("Address = %q, want %q verbatim", evs[0].Address, vaultProgramID)
	}
}
