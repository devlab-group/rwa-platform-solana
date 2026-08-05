package blockchain

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// erroringSource wraps a *fakeSource and injects a GetTransaction failure
// for specific signatures, so a test can exercise "the RPC call for this one
// transaction fails" without the fakeSource itself needing to grow
// error-injection knobs every other test would also see.
type erroringSource struct {
	*fakeSource
	errSigs map[string]string
}

func (e *erroringSource) GetTransaction(ctx context.Context, sig, commitment string) (*Tx, error) {
	if msg, bad := e.errSigs[sig]; bad {
		return nil, fmt.Errorf("erroringSource: injected failure for %s: %s", sig, msg)
	}
	return e.fakeSource.GetTransaction(ctx, sig, commitment)
}

// TestIndexerDecodeErrorSkipsLineAndAdvancesCheckpoint proves a "Program
// data:" line whose 8-byte discriminator IS recognized but whose body is
// too short to hold the event's declared fields (a corrupt/malformed log,
// not an unrelated program's data line -- see TestDecodeTruncatedBodyErrors
// in decode_test.go) is skipped like any other non-matching line, NOT
// treated as a fatal Poll error: the old "fail loudly, stop the checkpoint"
// behavior let a single poisoned emission durably wedge the indexer, since
// the same poisoned signature would be re-fetched and re-abort every
// subsequent tick forever. Poll must now succeed, ingest the good
// signature's event, and advance the checkpoint past BOTH signatures.
func TestIndexerDecodeErrorSkipsLineAndAdvancesCheckpoint(t *testing.T) {
	src := newFakeSource()
	src.SetSlot(10)
	src.AddTx(vaultProgramID, SigInfo{Signature: "sig-good", Slot: 1}, framedLogLines(vaultProgramID,
		programDataLine(purchasedPayload(1, 1)),
	), nil)
	// Purchased's real discriminator, but a body far too short to hold
	// buyer/recipient/tokenAmount/quoteAmount.
	corrupt := buildPayload(purchasedDisc, []byte{1, 2, 3})
	src.AddTx(vaultProgramID, SigInfo{Signature: "sig-corrupt", Slot: 2}, framedLogLines(vaultProgramID,
		programDataLine(corrupt),
	), nil)

	checkpoints, events := newTestRepos()
	idx := newTestIndexer(src, checkpoints, events)

	if err := idx.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v, want the corrupt line skipped rather than a fatal error", err)
	}

	cp, err := checkpoints.Get(context.Background(), testChainID, vaultProgramID)
	if err != nil {
		t.Fatalf("checkpoint not saved: %v", err)
	}
	if cp.LastBlockHash != "sig-corrupt" {
		t.Errorf("checkpoint sig = %q, want sig-corrupt (the newest signature actually processed)", cp.LastBlockHash)
	}

	evs, err := events.ListByName(context.Background(), testChainID, vaultProgramID, "Purchased")
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0].TxHash != "sig-good" {
		t.Errorf("events = %+v, want exactly the sig-good Purchased event", evs)
	}

	// A second Poll must not re-process sig-corrupt (the checkpoint moved
	// past it) and must not error again.
	if err := idx.Poll(context.Background()); err != nil {
		t.Fatalf("Poll #2: %v", err)
	}
}

// TestIndexerForeignProgramDataLineNotIngested pins the invariant that a
// transaction that plainly references the real target
// program (so it surfaces under getSignaturesForAddress(target)) but whose
// ONLY "Program data:" line was actually emitted by a different, foreign
// program nested inside the same transaction (invoked via CPI, its own
// "Program <foreignID> invoke [2]" / "... success" framing) must NOT be
// ingested as a target-program event, even though the foreign line's
// discriminator+body are byte-for-byte a valid target event -- exactly what
// an attacker who deploys a trivial program to forge events would craft. A
// genuinely-emitted line from the real target program, elsewhere in the
// same log, IS still ingested.
func TestIndexerForeignProgramDataLineNotIngested(t *testing.T) {
	const foreignProgramID = "ForeignProgram111111111111111111111111111"

	forged := purchasedPayload(999999, 999999) // a valid Purchased body, but never actually run by vaultProgramID
	genuine := purchasedPayload(42, 7)

	src := newFakeSource()
	src.SetSlot(10)
	src.AddTx(vaultProgramID, SigInfo{Signature: "sig-attack", Slot: 1}, []string{
		// The outer instruction plainly references vaultProgramID (as a
		// plain account, not as the invoked program) -- this is why
		// getSignaturesForAddress(vaultProgramID) would return this tx --
		// but the top-level invocation is the FOREIGN program, and IT is
		// what actually emits the data line.
		"Program " + foreignProgramID + " invoke [1]",
		"Program log: pwned",
		programDataLine(forged),
		"Program " + foreignProgramID + " success",
	}, nil)
	// A second, honest transaction where vaultProgramID genuinely emits its
	// own event, to prove the fix doesn't just blanket-skip everything.
	src.AddTx(vaultProgramID, SigInfo{Signature: "sig-honest", Slot: 2}, framedLogLines(vaultProgramID,
		programDataLine(genuine),
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
		t.Fatalf("expected exactly 1 Purchased event (the genuine one), got %d: %+v", len(evs), evs)
	}
	if evs[0].TxHash != "sig-honest" || evs[0].Data["tokenAmount"] != "42" {
		t.Errorf("ingested event = %+v, want the genuine sig-honest Purchased(42, 7)", evs[0])
	}

	cp, err := checkpoints.Get(context.Background(), testChainID, vaultProgramID)
	if err != nil {
		t.Fatalf("checkpoint not saved: %v", err)
	}
	if cp.LastBlockHash != "sig-honest" {
		t.Errorf("checkpoint sig = %q, want sig-honest", cp.LastBlockHash)
	}
}

// TestIndexerGetTransactionErrorLeavesThatProgramsCheckpointUnadvanced
// covers a 2-program configuration where one program's GetTransaction call
// fails: Poll must return an error naming the failing program, and that
// program's own checkpoint must not advance. Compliance is scanned before
// Vault in the indexer's fixed programOrder (see indexer.go) and has no
// failures of its own, so its checkpoint DOES advance in the same Poll
// call -- proving the failure is scoped to the one program whose RPC call
// actually failed, not the whole poll cycle silently losing all progress.
func TestIndexerGetTransactionErrorLeavesThatProgramsCheckpointUnadvanced(t *testing.T) {
	const complianceProgramID = "CompLianceProgram111111111111111111111111"
	statusChangedDisc := [8]byte{146, 235, 222, 125, 145, 246, 34, 240}
	accountRaw, _ := pubkeyBytes(0x04)
	authorityRaw, _ := pubkeyBytes(0x05)
	statusPayload := buildPayload(statusChangedDisc, accountRaw, []byte{1}, []byte{2}, leU64(0), leU64(1800000000), authorityRaw)

	src := newFakeSource()
	src.SetSlot(10)
	src.AddTx(complianceProgramID, SigInfo{Signature: "compliance-sig1", Slot: 1}, framedLogLines(complianceProgramID,
		programDataLine(statusPayload),
	), nil)
	src.AddTx(vaultProgramID, SigInfo{Signature: "vault-sig1", Slot: 2}, framedLogLines(vaultProgramID,
		programDataLine(purchasedPayload(1, 1)),
	), nil)

	wrapped := &erroringSource{fakeSource: src, errSigs: map[string]string{"vault-sig1": "simulated RPC failure"}}

	checkpoints, events := newTestRepos()
	programIDs := map[ProgramRole]string{
		RoleCompliance: complianceProgramID,
		RoleVault:      vaultProgramID,
	}
	idx := New(wrapped, checkpoints, events, programIDs, testChainID, "finalized", 0)

	err := idx.Poll(context.Background())
	if err == nil {
		t.Fatal("Poll: expected an error from GetTransaction failing for the vault program")
	}
	if !strings.Contains(err.Error(), "vault") {
		t.Errorf("error = %v, want it to name the failing program (vault)", err)
	}

	if _, err := checkpoints.Get(context.Background(), testChainID, complianceProgramID); err != nil {
		t.Errorf("compliance checkpoint missing (compliance had no failure of its own): %v", err)
	}
	if _, err := checkpoints.Get(context.Background(), testChainID, vaultProgramID); err == nil {
		t.Error("vault checkpoint was saved despite GetTransaction failing")
	}
}

// TestIndexerLaterProgramStillPolledAfterEarlierProgramFails is a
// regression guard: the old Poll returned on the FIRST pollProgram error,
// which starves every later program in programOrder of its own scan.
// Compliance is scanned before vault; this test makes compliance fail and
// proves vault -- later in programOrder -- is still fully polled (ingested
// and checkpointed) in the same Poll call, with the returned error naming
// compliance.
func TestIndexerLaterProgramStillPolledAfterEarlierProgramFails(t *testing.T) {
	const complianceProgramID = "CompLianceProgram111111111111111111111111"

	src := newFakeSource()
	src.SetSlot(10)
	src.AddTx(complianceProgramID, SigInfo{Signature: "compliance-sig1", Slot: 1}, nil, nil)
	src.AddTx(vaultProgramID, SigInfo{Signature: "vault-sig1", Slot: 2}, framedLogLines(vaultProgramID,
		programDataLine(purchasedPayload(5, 5)),
	), nil)

	wrapped := &erroringSource{fakeSource: src, errSigs: map[string]string{"compliance-sig1": "simulated RPC failure"}}

	checkpoints, events := newTestRepos()
	programIDs := map[ProgramRole]string{
		RoleCompliance: complianceProgramID,
		RoleVault:      vaultProgramID,
	}
	idx := New(wrapped, checkpoints, events, programIDs, testChainID, "finalized", 0)

	err := idx.Poll(context.Background())
	if err == nil {
		t.Fatal("Poll: expected an error from GetTransaction failing for the compliance program")
	}
	if !strings.Contains(err.Error(), "compliance") {
		t.Errorf("error = %v, want it to name the failing program (compliance)", err)
	}

	evs, err := events.ListByName(context.Background(), testChainID, vaultProgramID, "Purchased")
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0].TxHash != "vault-sig1" {
		t.Errorf("vault events = %+v, want the vault-sig1 Purchased event (vault must still be polled despite compliance failing first)", evs)
	}
	if _, err := checkpoints.Get(context.Background(), testChainID, vaultProgramID); err != nil {
		t.Errorf("vault checkpoint missing (vault must still advance despite compliance's failure): %v", err)
	}
	if _, err := checkpoints.Get(context.Background(), testChainID, complianceProgramID); err == nil {
		t.Error("compliance checkpoint was saved despite GetTransaction failing")
	}
}

// TestIndexerCPIFramingIgnoresTextThatLooksLikeFraming pins the invariant
// that a program's own msg!() log text can render as e.g. "Program
// log: FAKE invoke [1]" or "Program log: something failed: x" -- text that
// starts with "Program " and contains " invoke [...]" or " failed: ",
// exactly like genuine CPI push/pop framing. The old plain-prefix-match
// parser mis-parsed these as real stack operations, which could either drop
// a genuine event (a spurious pop leaves the real program off the stack
// when its own data line next appears) or misattribute one (a spurious
// push shadows the real top of stack). The fixed, structural parser must
// ignore both decoy lines entirely: the genuine VAULT events on either side
// of them are still correctly attributed, and a genuine nested foreign
// CPI's own data line is still correctly rejected (never attributed to
// VAULT) -- i.e. no event is forged and none is lost.
func TestIndexerCPIFramingIgnoresTextThatLooksLikeFraming(t *testing.T) {
	const otherProgramID = "ForeignProgram111111111111111111111111111"

	src := newFakeSource()
	src.SetSlot(1)
	src.AddTx(vaultProgramID, SigInfo{Signature: "sig1", Slot: 1}, []string{
		"Program " + vaultProgramID + " invoke [1]",
		"Program log: instruction: buy",
		programDataLine(purchasedPayload(100, 50)),  // genuine VAULT event #1
		"Program log: FAKE invoke [1]",              // decoy push -- must be ignored
		"Program " + otherProgramID + " invoke [2]", // genuine nested CPI, real depth 2
		programDataLine(purchasedPayload(999, 999)), // OTHER's own line -- must NOT be attributed to VAULT
		"Program " + otherProgramID + " success",
		"Program log: something failed: x",         // decoy pop -- must be ignored
		programDataLine(purchasedPayload(200, 75)), // genuine VAULT event #2
		"Program " + vaultProgramID + " success",
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
	if len(evs) != 2 {
		t.Fatalf("expected exactly 2 genuine VAULT events, got %d: %+v", len(evs), evs)
	}
	if evs[0].Data["tokenAmount"] != "100" {
		t.Errorf("event0 tokenAmount = %v, want 100 (must not have been misattributed by the decoy push)", evs[0].Data["tokenAmount"])
	}
	if evs[1].Data["tokenAmount"] != "200" {
		t.Errorf("event1 tokenAmount = %v, want 200 (must not have been dropped by the decoy pop)", evs[1].Data["tokenAmount"])
	}
	for _, e := range evs {
		if e.Data["tokenAmount"] == "999" {
			t.Errorf("forged/foreign event ingested as a VAULT event: %+v", e)
		}
	}
}

// TestIndexerPartialBatchFailureLeavesIncrementalCheckpointProgress pins
// incremental checkpoint advancement: within a single pollProgram call
// spanning more than one checkpointBatchSize, a
// failure partway through (e.g. a transient GetTransaction error) must not
// discard the checkpoint progress already made on the earlier, fully
// ingested batch -- the old all-or-nothing design only ever advanced the
// checkpoint once, at the very end, so any mid-backlog failure lost 100% of
// this poll's progress and forced a full re-fetch/re-decode of everything
// already ingested on the next attempt.
func TestIndexerPartialBatchFailureLeavesIncrementalCheckpointProgress(t *testing.T) {
	src := newFakeSource()
	src.SetSlot(1)
	const total = 250
	const failAt = 150 // partway through the 2nd checkpoint batch (101-200)
	for i := 1; i <= total; i++ {
		src.AddTx(vaultProgramID, SigInfo{Signature: fmt.Sprintf("sig%04d", i), Slot: uint64(i)}, framedLogLines(vaultProgramID,
			programDataLine(purchasedPayload(uint64(i), 1)),
		), nil)
	}
	src.SetSlot(total)

	failSig := fmt.Sprintf("sig%04d", failAt)
	wrapped := &erroringSource{fakeSource: src, errSigs: map[string]string{failSig: "simulated RPC failure"}}

	checkpoints, events := newTestRepos()
	programIDs := map[ProgramRole]string{RoleVault: vaultProgramID}
	idx := New(wrapped, checkpoints, events, programIDs, testChainID, "finalized", 0)

	if err := idx.Poll(context.Background()); err == nil {
		t.Fatal("Poll: expected an error from the injected GetTransaction failure")
	}

	// The first checkpointBatchSize (100) signatures were fully ingested
	// before the failure, so the checkpoint must reflect that batch --
	// NOT be left unset (all-or-nothing) and NOT already include anything
	// past it (the failure happened before the 2nd batch's own boundary).
	cp, err := checkpoints.Get(context.Background(), testChainID, vaultProgramID)
	if err != nil {
		t.Fatalf("checkpoint not saved despite a full first batch being ingested: %v", err)
	}
	wantCheckpointSig := fmt.Sprintf("sig%04d", checkpointBatchSize)
	if cp.LastBlockHash != wantCheckpointSig {
		t.Errorf("checkpoint = %q, want %q (the newest signature in the last FULLY completed batch)", cp.LastBlockHash, wantCheckpointSig)
	}

	evs, err := events.ListByName(context.Background(), testChainID, vaultProgramID, "Purchased")
	if err != nil {
		t.Fatal(err)
	}
	// sig0001..sig0149 (everything strictly before the failing signature)
	// should have been ingested; sig0150 (the failure) and everything
	// after it in this poll must not have been.
	wantEvents := failAt - 1
	if len(evs) != wantEvents {
		t.Fatalf("ingested %d events before the failure, want %d", len(evs), wantEvents)
	}
	if evs[len(evs)-1].TxHash != fmt.Sprintf("sig%04d", failAt-1) {
		t.Errorf("last ingested event = %q, want sig%04d", evs[len(evs)-1].TxHash, failAt-1)
	}

	// A second Poll must not re-ingest the first 100 (checkpoint moved
	// past them, and ingestion is idempotent regardless), and should make
	// further progress once the injected failure is no longer in its way.
	idx2 := New(src, checkpoints, events, programIDs, testChainID, "finalized", 0)
	if err := idx2.Poll(context.Background()); err != nil {
		t.Fatalf("Poll #2: %v", err)
	}
	evs2, err := events.ListByName(context.Background(), testChainID, vaultProgramID, "Purchased")
	if err != nil {
		t.Fatal(err)
	}
	if len(evs2) != total {
		t.Fatalf("after recovery poll: expected all %d events ingested, got %d", total, len(evs2))
	}
}

// TestIndexerFetchCapsPagesPerPoll pins bounding a single fetch: a backlog
// deeper than maxFetchPages*sigPageLimit signatures must not be entirely
// paged into memory (and ingested) in one Poll call. One poll ingests only
// the newest maxFetchPages*sigPageLimit signatures — the TOP slice of the
// gap, because getSignaturesForAddress pages backward from the tip.
//
// Crucially: that first poll must NOT jump the
// contiguous checkpoint to the tip and abandon the un-paged bottom of the
// gap. Instead it freezes the contiguous prefix and records a backfill
// frontier; a later poll pages the rest of the gap in and only then promotes
// the checkpoint to the tip. The middle of a deep backlog is drained, never
// silently skipped.
func TestIndexerFetchCapsPagesPerPoll(t *testing.T) {
	src := newFakeSource()
	const total = 10500
	for i := 1; i <= total; i++ {
		src.AddTx(vaultProgramID, SigInfo{Signature: fmt.Sprintf("sig%05d", i), Slot: uint64(i)}, framedLogLines(vaultProgramID,
			programDataLine(purchasedPayload(uint64(i), 1)),
		), nil)
	}
	src.SetSlot(total)

	checkpoints, events := newTestRepos()
	idx := newTestIndexer(src, checkpoints, events)

	// Poll #1: ingests only the newest `capped` signatures (the top of the
	// gap) and opens a backfill frontier rather than skipping the rest.
	if err := idx.Poll(context.Background()); err != nil {
		t.Fatalf("Poll #1: %v", err)
	}

	evs, err := events.ListByName(context.Background(), testChainID, vaultProgramID, "Purchased")
	if err != nil {
		t.Fatal(err)
	}
	const capped = maxFetchPages * sigPageLimit
	if len(evs) != capped {
		t.Fatalf("poll #1: expected exactly %d events (fetch capped at %d pages of %d), got %d", capped, maxFetchPages, sigPageLimit, len(evs))
	}
	topOfGap := fmt.Sprintf("sig%05d", total-capped+1) // sig00501: oldest of the newest `capped`
	if evs[0].TxHash != topOfGap {
		t.Errorf("poll #1 oldest ingested = %q, want %q (the batch is the newest %d signatures)", evs[0].TxHash, topOfGap, capped)
	}
	tip := fmt.Sprintf("sig%05d", total)
	if evs[len(evs)-1].TxHash != tip {
		t.Errorf("poll #1 newest ingested = %q, want %q", evs[len(evs)-1].TxHash, tip)
	}

	// The contiguous checkpoint must NOT have jumped to the tip: on a first
	// sync there is no gap-free prefix yet, so LastBlockHash stays "". Instead
	// a backfill frontier is recorded — cursor at the top of the gap, target
	// at the high-water tip — so the next poll resumes downward.
	cp, err := checkpoints.Get(context.Background(), testChainID, vaultProgramID)
	if err != nil {
		t.Fatal(err)
	}
	if cp.LastBlockHash != "" {
		t.Errorf("poll #1 contiguous checkpoint = %q, want \"\" (gap still open, prefix must not jump to tip)", cp.LastBlockHash)
	}
	if cp.BackfillCursor != topOfGap {
		t.Errorf("poll #1 BackfillCursor = %q, want %q (resume paging below the ingested top slice)", cp.BackfillCursor, topOfGap)
	}
	if cp.BackfillTargetHash != tip {
		t.Errorf("poll #1 BackfillTargetHash = %q, want %q (high-water tip to promote once the gap closes)", cp.BackfillTargetHash, tip)
	}

	// Poll #2: pages in the remaining bottom of the gap (sig00001..sig00500),
	// closes it, and promotes the checkpoint to the tip.
	if err := idx.Poll(context.Background()); err != nil {
		t.Fatalf("Poll #2: %v", err)
	}

	evs2, err := events.ListByName(context.Background(), testChainID, vaultProgramID, "Purchased")
	if err != nil {
		t.Fatal(err)
	}
	if len(evs2) != total {
		t.Fatalf("poll #2: expected the WHOLE backlog drained (%d events, nothing skipped), got %d", total, len(evs2))
	}
	for i, e := range evs2 {
		want := fmt.Sprintf("sig%05d", i+1)
		if e.TxHash != want {
			t.Fatalf("drained event[%d].TxHash = %q, want %q (contiguous, no interior gap)", i, e.TxHash, want)
		}
	}

	cp2, err := checkpoints.Get(context.Background(), testChainID, vaultProgramID)
	if err != nil {
		t.Fatal(err)
	}
	if cp2.LastBlockHash != tip {
		t.Errorf("poll #2 contiguous checkpoint = %q, want %q (gap closed)", cp2.LastBlockHash, tip)
	}
	if cp2.BackfillCursor != "" {
		t.Errorf("poll #2 BackfillCursor = %q, want \"\" (frontier cleared once the gap closed)", cp2.BackfillCursor)
	}

	// Poll #3: fully drained, nothing new — must be a no-op (no dups, no error).
	if err := idx.Poll(context.Background()); err != nil {
		t.Fatalf("Poll #3: %v", err)
	}
	evs3, err := events.ListByName(context.Background(), testChainID, vaultProgramID, "Purchased")
	if err != nil {
		t.Fatal(err)
	}
	if len(evs3) != total {
		t.Errorf("poll #3 (idempotent): expected %d events, got %d", total, len(evs3))
	}
}

// TestIndexerBackfillDrainsAcrossThreePolls covers the backfill
// continuation branch: a backlog deeper than TWO page caps needs an
// intermediate backfill poll that neither opens nor closes the gap — it just
// advances the frontier downward while preserving the high-water target
// recorded when the gap first opened. The whole backlog must drain with no
// interior signature skipped, and the contiguous checkpoint must not move off
// the frozen prefix until the final poll reaches the bottom.
func TestIndexerBackfillDrainsAcrossThreePolls(t *testing.T) {
	src := newFakeSource()
	const capped = maxFetchPages * sigPageLimit
	const total = 2*capped + 300 // 20300: opens (poll 1), continues (poll 2), closes (poll 3)
	for i := 1; i <= total; i++ {
		src.AddTx(vaultProgramID, SigInfo{Signature: fmt.Sprintf("sig%05d", i), Slot: uint64(i)}, framedLogLines(vaultProgramID,
			programDataLine(purchasedPayload(uint64(i), 1)),
		), nil)
	}
	src.SetSlot(total)

	checkpoints, events := newTestRepos()
	idx := newTestIndexer(src, checkpoints, events)
	tip := fmt.Sprintf("sig%05d", total)

	// Poll #1 opens the gap; poll #2 is the intermediate continuation.
	for poll := 1; poll <= 2; poll++ {
		if err := idx.Poll(context.Background()); err != nil {
			t.Fatalf("Poll #%d: %v", poll, err)
		}
		cp, err := checkpoints.Get(context.Background(), testChainID, vaultProgramID)
		if err != nil {
			t.Fatal(err)
		}
		if cp.LastBlockHash != "" {
			t.Errorf("poll #%d contiguous checkpoint = %q, want \"\" (gap still open)", poll, cp.LastBlockHash)
		}
		if cp.BackfillCursor == "" {
			t.Errorf("poll #%d BackfillCursor cleared early, want frontier still set", poll)
		}
		if cp.BackfillTargetHash != tip {
			t.Errorf("poll #%d BackfillTargetHash = %q, want %q preserved from when the gap opened", poll, cp.BackfillTargetHash, tip)
		}
		wantIngested := poll * capped
		evs, err := events.ListByName(context.Background(), testChainID, vaultProgramID, "Purchased")
		if err != nil {
			t.Fatal(err)
		}
		if len(evs) != wantIngested {
			t.Errorf("poll #%d ingested %d events, want %d (one capped slice per poll)", poll, len(evs), wantIngested)
		}
	}

	// Poll #3 reaches the bottom, closes the gap, promotes the checkpoint.
	if err := idx.Poll(context.Background()); err != nil {
		t.Fatalf("Poll #3: %v", err)
	}
	evs, err := events.ListByName(context.Background(), testChainID, vaultProgramID, "Purchased")
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != total {
		t.Fatalf("expected the whole %d-signature backlog drained, got %d", total, len(evs))
	}
	for i, e := range evs {
		want := fmt.Sprintf("sig%05d", i+1)
		if e.TxHash != want {
			t.Fatalf("drained event[%d].TxHash = %q, want %q (no interior gap)", i, e.TxHash, want)
		}
	}
	cp, err := checkpoints.Get(context.Background(), testChainID, vaultProgramID)
	if err != nil {
		t.Fatal(err)
	}
	if cp.LastBlockHash != tip || cp.BackfillCursor != "" {
		t.Errorf("after drain: checkpoint=%q backfillCursor=%q, want (%q, \"\")", cp.LastBlockHash, cp.BackfillCursor, tip)
	}
}

// TestIndexerStartSlotFilterAppliesAcrossFirstSyncBackfill guards the
// interaction between the backfill frontier and the startSlot filter: when
// a program's FIRST sync backlog is deep enough to span
// multiple polls, the checkpoint row exists from poll #2 onward (it carries
// the frontier) even though no contiguous prefix has been established yet. The
// startSlot skip must therefore key off "no contiguous prefix yet"
// (LastBlockHash == "") rather than "no checkpoint row", or the later polls of
// a first-sync backfill — which reach the OLDEST, most likely pre-deployment
// signatures — would replay that pre-deployment history into the read model.
func TestIndexerStartSlotFilterAppliesAcrossFirstSyncBackfill(t *testing.T) {
	const capped = maxFetchPages * sigPageLimit
	const total = capped + 200 // 10200: two polls; the oldest 200 are paged on poll #2
	const startSlot = uint64(150)

	src := newFakeSource()
	for i := 1; i <= total; i++ {
		src.AddTx(vaultProgramID, SigInfo{Signature: fmt.Sprintf("sig%05d", i), Slot: uint64(i)}, framedLogLines(vaultProgramID,
			programDataLine(purchasedPayload(uint64(i), 1)),
		), nil)
	}
	src.SetSlot(total)

	checkpoints, events := newTestRepos()
	programIDs := map[ProgramRole]string{RoleVault: vaultProgramID}
	idx := New(src, checkpoints, events, programIDs, testChainID, "finalized", startSlot)

	// Poll #1 opens the frontier (writes the checkpoint row); poll #2 pages in
	// the oldest 200 signatures, of which slots 1..149 predate startSlot.
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
	// Only signatures at slot >= startSlot may be ingested: sig00150..sig10200.
	wantIngested := int(total) - int(startSlot) + 1
	if len(evs) != wantIngested {
		t.Fatalf("ingested %d events, want %d (pre-startSlot history skipped even on backfill polls)", len(evs), wantIngested)
	}
	for _, e := range evs {
		if e.BlockNumber < startSlot {
			t.Errorf("ingested pre-deployment event at slot %d (< startSlot %d) — startSlot filter stopped applying mid-backfill", e.BlockNumber, startSlot)
		}
	}
}

// TestIndexerFirstSyncSkipsSignaturesBeforeStartSlot pins the invariant
// that startSlot (accepted by New but previously never consulted)
// must be used to skip ingesting any signature older than the deployment's
// startSlot on a program's FIRST sync (no checkpoint yet) -- otherwise a
// deployment reusing a program ID (or one with genesis/test activity)
// would replay pre-deployment history into the read model. The skipped
// signature still counts as observed for checkpoint-advance purposes (same
// as a failed tx).
func TestIndexerFirstSyncSkipsSignaturesBeforeStartSlot(t *testing.T) {
	const startSlot = uint64(100)

	src := newFakeSource()
	src.SetSlot(200)
	src.AddTx(vaultProgramID, SigInfo{Signature: "sig-pre-deploy", Slot: 50}, framedLogLines(vaultProgramID,
		programDataLine(purchasedPayload(1, 1)),
	), nil)
	src.AddTx(vaultProgramID, SigInfo{Signature: "sig-post-deploy", Slot: 150}, framedLogLines(vaultProgramID,
		programDataLine(purchasedPayload(2, 2)),
	), nil)

	checkpoints, events := newTestRepos()
	programIDs := map[ProgramRole]string{RoleVault: vaultProgramID}
	idx := New(src, checkpoints, events, programIDs, testChainID, "finalized", startSlot)

	if err := idx.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}

	evs, err := events.ListByName(context.Background(), testChainID, vaultProgramID, "Purchased")
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0].TxHash != "sig-post-deploy" {
		t.Errorf("events = %+v, want exactly the sig-post-deploy event (pre-deploy history must be skipped)", evs)
	}

	// The pre-deploy signature is still "observed" -- the checkpoint must
	// advance past both signatures, not just the ingested one.
	cp, err := checkpoints.Get(context.Background(), testChainID, vaultProgramID)
	if err != nil {
		t.Fatal(err)
	}
	if cp.LastBlockHash != "sig-post-deploy" {
		t.Errorf("checkpoint = %q, want sig-post-deploy (the newest signature observed)", cp.LastBlockHash)
	}
}
