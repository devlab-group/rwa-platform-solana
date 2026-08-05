package blockchain

import (
	"context"
	"fmt"
	"testing"

	"github.com/rwa-platform/server/internal/dal/models"
)

// TestIndexerShortPageAboveCheckpointFailsClosed pins the invariant that a
// page that comes back short (nothing older left on THIS RPC node) is not,
// by itself, proof the poll reached the checkpointed prefix —
// only that this particular node has nothing older than `before` to serve.
// A non-archival/load-balanced/freshly-resynced node can genuinely lack
// history a fully-synced node would have, in which case a short page can
// arrive well ABOVE the checkpoint slot. The old code treated any short
// page as "reached the prefix" and jumped the contiguous checkpoint to the
// tip, silently skipping every signature strictly between the checkpoint
// and the newest page it happened to see — the same permanent-loss shape
// already fixed once, via a different trigger.
//
// This seeds a checkpoint whose signature the fakeSource's history does NOT
// contain at all (simulating an RPC whose retained history for the program
// ends above the real checkpoint slot), then adds a handful of newer
// signatures. fetchNewSignatures can never observe anything at or below the
// checkpoint slot no matter how it pages, so it must fail closed: an error,
// and the checkpoint must not move.
func TestIndexerShortPageAboveCheckpointFailsClosed(t *testing.T) {
	src := newFakeSource()
	// Deliberately do NOT AddTx the checkpoint's own signature — the
	// fakeSource's history starts strictly above it, exactly as a
	// non-archival RPC's retained history would.
	for i := 101; i <= 105; i++ {
		src.AddTx(vaultProgramID, SigInfo{Signature: fmt.Sprintf("sig%05d", i), Slot: uint64(i)}, framedLogLines(vaultProgramID,
			programDataLine(purchasedPayload(uint64(i), 1)),
		), nil)
	}
	src.SetSlot(105)

	checkpoints, events := newTestRepos()
	// Seed a pre-existing contiguous checkpoint whose signature/slot are
	// nowhere in the fakeSource's history — simulating a checkpoint
	// established against a DIFFERENT, fully-synced RPC that this poll's
	// RPC endpoint can no longer serve.
	if err := checkpoints.Set(context.Background(), &models.IndexerCheckpoint{
		ChainID: testChainID, Address: vaultProgramID,
		LastBlock: 50, LastBlockHash: "sig00050",
	}); err != nil {
		t.Fatal(err)
	}

	idx := newTestIndexer(src, checkpoints, events)
	if err := idx.Poll(context.Background()); err == nil {
		t.Fatal("Poll: expected an error — this RPC can never prove it reached the checkpointed prefix")
	}

	// The checkpoint must be untouched: neither jumped to the tip nor
	// otherwise advanced.
	cp, err := checkpoints.Get(context.Background(), testChainID, vaultProgramID)
	if err != nil {
		t.Fatal(err)
	}
	if cp.LastBlock != 50 || cp.LastBlockHash != "sig00050" {
		t.Errorf("checkpoint = (slot=%d, sig=%q), want it unchanged at (50, sig00050) — must not advance without proof", cp.LastBlock, cp.LastBlockHash)
	}

	// Nothing must have been ingested either — the poll failed before any
	// of this batch could be trusted as gap-free.
	evs, err := events.ListByName(context.Background(), testChainID, vaultProgramID, "Purchased")
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 0 {
		t.Errorf("expected 0 events ingested from a failed-proof poll, got %d", len(evs))
	}
}

// TestIndexerDeepGapAfterExistingCheckpointOpensBackfillNotError proves the
// decode-skip behaviour does not turn the ordinary "backlog deeper than one poll's page
// cap" case into an error: when paging exhausts maxFetchPages on nothing
// but full pages (never a short/empty one), that is the normal
// deep-backlog signal, not an unclosable gap — pollProgram must open a
// backfill frontier exactly as before, not fail the poll.
func TestIndexerDeepGapAfterExistingCheckpointOpensBackfillNotError(t *testing.T) {
	src := newFakeSource()
	// The checkpoint's own signature IS present in this source's history
	// (unlike the fail-closed test above) — this RPC has full history, the
	// backlog above the checkpoint is just deeper than one poll can drain.
	src.AddTx(vaultProgramID, SigInfo{Signature: "sig-checkpoint", Slot: 1}, framedLogLines(vaultProgramID,
		programDataLine(purchasedPayload(1, 1)),
	), nil)
	const total = 10500
	for i := 1; i <= total; i++ {
		src.AddTx(vaultProgramID, SigInfo{Signature: fmt.Sprintf("sig%05d", i), Slot: uint64(i + 1)}, framedLogLines(vaultProgramID,
			programDataLine(purchasedPayload(uint64(i), 1)),
		), nil)
	}
	src.SetSlot(total + 1)

	checkpoints, events := newTestRepos()
	if err := checkpoints.Set(context.Background(), &models.IndexerCheckpoint{
		ChainID: testChainID, Address: vaultProgramID,
		LastBlock: 1, LastBlockHash: "sig-checkpoint",
	}); err != nil {
		t.Fatal(err)
	}

	idx := newTestIndexer(src, checkpoints, events)
	if err := idx.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: expected no error (deep backlog opens a backfill frontier), got: %v", err)
	}

	cp, err := checkpoints.Get(context.Background(), testChainID, vaultProgramID)
	if err != nil {
		t.Fatal(err)
	}
	if cp.LastBlockHash != "sig-checkpoint" {
		t.Errorf("contiguous checkpoint = %q, want unchanged at sig-checkpoint (gap still open)", cp.LastBlockHash)
	}
	if cp.BackfillCursor == "" {
		t.Error("expected a backfill frontier to have opened for the deep backlog")
	}
}
