package blockchain

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestPollProgramWritesHeartbeatOnEmptyPoll pins the invariant that a
// poll that finds NO new signatures at all (a healthy, idle program) must
// still persist a fresh LastSuccessfulPollAt heartbeat — the old code only
// ever wrote UpdatedAt, and only when the signature cursor itself advanced,
// so an idle-but-healthy program never refreshed anything and would
// eventually look wedged to readiness (cmd/platform's
// complianceReadinessCheck).
func TestPollProgramWritesHeartbeatOnEmptyPoll(t *testing.T) {
	src := newFakeSource()
	src.SetSlot(10) // no transactions added at all

	checkpoints, events := newTestRepos()
	idx := newTestIndexer(src, checkpoints, events)

	before := time.Now().UTC()
	if err := idx.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}

	cp, err := checkpoints.Get(context.Background(), testChainID, vaultProgramID)
	if err != nil {
		t.Fatalf("checkpoint row not created despite a successful (empty) poll: %v", err)
	}
	if cp.LastSuccessfulPollAt.Before(before) {
		t.Errorf("LastSuccessfulPollAt = %v, want a timestamp at/after %v (this poll)", cp.LastSuccessfulPollAt, before)
	}
	if cp.LastBlockHash != "" || cp.LastBlock != 0 {
		t.Errorf("an empty poll must not fabricate a signature cursor: LastBlock=%d LastBlockHash=%q", cp.LastBlock, cp.LastBlockHash)
	}

	// A second empty poll must refresh the heartbeat again (proves this
	// isn't a one-shot "checkpoint row didn't exist yet" artifact).
	time.Sleep(time.Millisecond)
	mid := time.Now().UTC()
	if err := idx.Poll(context.Background()); err != nil {
		t.Fatalf("Poll #2: %v", err)
	}
	cp2, err := checkpoints.Get(context.Background(), testChainID, vaultProgramID)
	if err != nil {
		t.Fatal(err)
	}
	if !cp2.LastSuccessfulPollAt.After(mid.Add(-time.Millisecond)) {
		t.Errorf("Poll #2 LastSuccessfulPollAt = %v, want it refreshed at/after %v", cp2.LastSuccessfulPollAt, mid)
	}
}

// TestPollProgramHeartbeatDuringBackfillPreservesFrontier proves the
// heartbeat write on a backfill poll (one that opens or continues a
// BackfillCursor frontier — see maxFetchPages' doc comment) does NOT clobber
// the cursor/backfill fields that same poll just set: recordSuccessfulPoll
// re-reads the checkpoint AFTER setBackfillFrontier has already written it,
// so the frontier must survive intact alongside a fresh heartbeat.
func TestPollProgramHeartbeatDuringBackfillPreservesFrontier(t *testing.T) {
	src := newFakeSource()
	const total = 10500 // deeper than one maxFetchPages*sigPageLimit window
	for i := 1; i <= total; i++ {
		src.AddTx(vaultProgramID, SigInfo{Signature: fmt.Sprintf("sig%05d", i), Slot: uint64(i)}, framedLogLines(vaultProgramID,
			programDataLine(purchasedPayload(uint64(i), 1)),
		), nil)
	}
	src.SetSlot(total)

	checkpoints, events := newTestRepos()
	idx := newTestIndexer(src, checkpoints, events)

	before := time.Now().UTC()
	if err := idx.Poll(context.Background()); err != nil {
		t.Fatalf("Poll #1: %v", err)
	}

	cp, err := checkpoints.Get(context.Background(), testChainID, vaultProgramID)
	if err != nil {
		t.Fatal(err)
	}
	if cp.BackfillCursor == "" {
		t.Fatal("expected a backfill frontier to have opened (backlog deeper than one page cap)")
	}
	if cp.LastSuccessfulPollAt.Before(before) {
		t.Errorf("LastSuccessfulPollAt = %v, want at/after %v even though this poll only advanced the backfill frontier, not the contiguous checkpoint", cp.LastSuccessfulPollAt, before)
	}
	// The frontier fields set by setBackfillFrontier this same poll must be
	// untouched by the subsequent heartbeat write.
	wantCursor := cp.BackfillCursor
	wantTargetHash := cp.BackfillTargetHash
	wantTargetSlot := cp.BackfillTargetSlot
	if wantCursor == "" || wantTargetHash == "" || wantTargetSlot == 0 {
		t.Fatalf("backfill frontier not fully populated: %+v", cp)
	}

	// Poll #2 closes the backfill; the heartbeat must still be present and
	// the contiguous checkpoint promoted — recordSuccessfulPoll must not
	// have clobbered closeBackfill's write either.
	if err := idx.Poll(context.Background()); err != nil {
		t.Fatalf("Poll #2: %v", err)
	}
	cp2, err := checkpoints.Get(context.Background(), testChainID, vaultProgramID)
	if err != nil {
		t.Fatal(err)
	}
	if cp2.BackfillCursor != "" {
		t.Errorf("BackfillCursor = %q after the gap closed, want cleared", cp2.BackfillCursor)
	}
	if cp2.LastBlockHash != wantTargetHash || cp2.LastBlock != wantTargetSlot {
		t.Errorf("contiguous checkpoint after close = (%d,%q), want (%d,%q)", cp2.LastBlock, cp2.LastBlockHash, wantTargetSlot, wantTargetHash)
	}
	if cp2.LastSuccessfulPollAt.IsZero() {
		t.Error("LastSuccessfulPollAt is zero after Poll #2, want it set")
	}
}

// TestPollProgramNoHeartbeatOnFailedPoll proves a poll that actually fails
// (a genuine RPC error, not "nothing new") must NOT write a fresh heartbeat
// — otherwise readiness could report healthy through a wedged/erroring
// indexer.
func TestPollProgramNoHeartbeatOnFailedPoll(t *testing.T) {
	src := newFakeSource()
	src.SetSlot(10)
	src.AddTx(vaultProgramID, SigInfo{Signature: "sig-bad", Slot: 1}, framedLogLines(vaultProgramID,
		programDataLine(purchasedPayload(1, 1)),
	), nil)
	wrapped := &erroringSource{fakeSource: src, errSigs: map[string]string{"sig-bad": "simulated RPC failure"}}

	checkpoints, events := newTestRepos()
	programIDs := map[ProgramRole]string{RoleVault: vaultProgramID}
	idx := New(wrapped, checkpoints, events, programIDs, testChainID, "finalized", 0)

	if err := idx.Poll(context.Background()); err == nil {
		t.Fatal("Poll: expected an error from the injected GetTransaction failure")
	}
	if _, err := checkpoints.Get(context.Background(), testChainID, vaultProgramID); err == nil {
		t.Error("checkpoint row exists after a failed poll (no signature was ever successfully observed) — heartbeat must not have been written")
	}
}

// TestPollProgramMidBatchAdvanceThenFailurePreservesHeartbeat pins the
// invariant that advanceProgramCheckpoint fires mid-poll every
// checkpointBatchSize signatures (see pollProgram), independent of whether
// the poll as a whole eventually succeeds. The old from-scratch
// IndexerCheckpoint write in advanceProgramCheckpoint (and
// setBackfillFrontier) zeroed LastSuccessfulPollAt on every such write —
// if a later signature in the SAME poll then failed (so the deferred
// recordSuccessfulPoll heartbeat write never runs, since err != nil), the
// checkpoint was left with a wiped heartbeat despite a prior, genuinely
// successful poll having recorded one — flapping readiness/the security
// watermark to not-ready for a perfectly healthy indexer.
func TestPollProgramMidBatchAdvanceThenFailurePreservesHeartbeat(t *testing.T) {
	src := newFakeSource()
	src.AddTx(vaultProgramID, SigInfo{Signature: "sig-warm", Slot: 1}, framedLogLines(vaultProgramID,
		programDataLine(purchasedPayload(1, 1)),
	), nil)
	src.SetSlot(1)

	checkpoints, events := newTestRepos()
	idx := newTestIndexer(src, checkpoints, events)

	// Poll #1: establishes a real checkpoint and a real heartbeat.
	before := time.Now().UTC()
	if err := idx.Poll(context.Background()); err != nil {
		t.Fatalf("Poll #1: %v", err)
	}
	warmCp, err := checkpoints.Get(context.Background(), testChainID, vaultProgramID)
	if err != nil {
		t.Fatal(err)
	}
	if warmCp.LastSuccessfulPollAt.Before(before) {
		t.Fatalf("Poll #1 did not record a heartbeat: %+v", warmCp)
	}
	heartbeat := warmCp.LastSuccessfulPollAt

	// Add more than one checkpointBatchSize worth of new signatures, with
	// one late signature (well past the first mid-batch advance at 100)
	// injected to fail GetTransaction — so pollProgram advances the
	// checkpoint mid-batch, then errors, and Poll #2 as a whole fails
	// (deferred recordSuccessfulPoll never runs).
	const total = 250
	const failAt = 150
	for i := 2; i <= total+1; i++ {
		src.AddTx(vaultProgramID, SigInfo{Signature: fmt.Sprintf("sig%05d", i), Slot: uint64(i)}, framedLogLines(vaultProgramID,
			programDataLine(purchasedPayload(uint64(i), 1)),
		), nil)
	}
	src.SetSlot(total + 1)
	failSig := fmt.Sprintf("sig%05d", failAt)
	wrapped := &erroringSource{fakeSource: src, errSigs: map[string]string{failSig: "simulated RPC failure"}}
	idx2 := New(wrapped, checkpoints, events, map[ProgramRole]string{RoleVault: vaultProgramID}, testChainID, "finalized", 0)

	if err := idx2.Poll(context.Background()); err == nil {
		t.Fatal("Poll #2: expected an error from the injected GetTransaction failure")
	}

	cp, err := checkpoints.Get(context.Background(), testChainID, vaultProgramID)
	if err != nil {
		t.Fatal(err)
	}
	// The mid-batch advance (past the first 100 of this poll's new
	// signatures) must have happened...
	wantSig := fmt.Sprintf("sig%05d", 1+checkpointBatchSize)
	if cp.LastBlockHash != wantSig {
		t.Fatalf("checkpoint = %q, want %q (mid-batch advance before the injected failure)", cp.LastBlockHash, wantSig)
	}
	// ...but the heartbeat recorded by Poll #1 must have survived it,
	// untouched — not zeroed, not silently dropped.
	if !cp.LastSuccessfulPollAt.Equal(heartbeat) {
		t.Errorf("LastSuccessfulPollAt = %v after a mid-batch advance + later failure, want it unchanged at %v (Poll #1's heartbeat)", cp.LastSuccessfulPollAt, heartbeat)
	}
}
