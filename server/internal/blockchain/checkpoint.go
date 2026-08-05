package blockchain

import (
	"context"
	"fmt"
	"time"

	"github.com/rwa-platform/server/internal/dal/models"
	"github.com/rwa-platform/server/internal/dal/repository"
)

// Each of the 5 emitting programs pages its own getSignaturesForAddress
// history independently (unlike the EVM indexer's single shared
// FilterLogs checkpoint), so it gets its own IndexerCheckpoint row: Address
// = the program's base58 program ID (verbatim, per the frozen addressing
// invariant), LastBlock = slot, LastBlockHash = the last successfully
// processed transaction signature.

// loadProgramCheckpoint returns the persisted checkpoint for one program's
// scan cursor (chainID, programID) and whether one existed yet.
func loadProgramCheckpoint(ctx context.Context, checkpoints repository.IndexerCheckpointRepository, chainID int64, programID string) (*models.IndexerCheckpoint, bool, error) {
	cp, err := checkpoints.Get(ctx, chainID, programID)
	if err == nil {
		return cp, true, nil
	}
	if err != repository.ErrNotFound {
		return nil, false, fmt.Errorf("blockchain: load checkpoint for %s: %w", programID, err)
	}
	return &models.IndexerCheckpoint{ChainID: chainID, Address: programID}, false, nil
}

// advanceProgramCheckpoint moves programID's contiguous cursor forward to
// (slot, signature) and clears any backfill frontier (the fields are written
// back as their zero values, i.e. dropped from the stored document). Poll calls
// this only on a contiguous forward scan — one that pages from the chain tip
// all the way down to the existing checkpoint in a single poll — so the
// resulting (slot, signature) is genuinely the newest of a gap-free prefix.
// A crash mid-backlog simply re-fetches (idempotently, via
// ChainEventRepository.Exists) the same backlog on the next Poll rather than
// silently skipping part of it.
//
// IndexerCheckpointRepository.Set is a full-document replace, not a partial
// update, so — like recordSuccessfulPoll — this re-reads whatever row is
// currently persisted and mutates only the fields this call owns, rather
// than building a fresh zero-valued document from scratch. The old
// from-scratch version zeroed LastSuccessfulPollAt on every advance,
// including the mid-batch advances pollProgram makes every
// checkpointBatchSize signatures: a poll that ingested a full batch and
// THEN failed on a later signature would leave the checkpoint's heartbeat
// wiped despite genuinely-successful earlier polls, flapping readiness/the
// security watermark to not-ready even though the indexer is healthy.
func advanceProgramCheckpoint(ctx context.Context, checkpoints repository.IndexerCheckpointRepository, chainID int64, programID string, slot uint64, signature string) error {
	cp, _, err := loadProgramCheckpoint(ctx, checkpoints, chainID, programID)
	if err != nil {
		return err
	}
	cp.LastBlock = slot
	cp.LastBlockHash = signature
	cp.BackfillCursor = ""
	cp.BackfillTargetHash = ""
	cp.BackfillTargetSlot = 0
	cp.UpdatedAt = time.Now().UTC()
	return checkpoints.Set(ctx, cp)
}

// setBackfillFrontier records progress on a backlog that is too deep to drain
// in one poll (see models.IndexerCheckpoint's backfill fields). The contiguous
// prefix (prefixSlot, prefixSig) is left exactly where it was — downstream
// projectors keep reading a gap-free, if stale, checkpoint — while cursor is
// the oldest signature ingested so far (the next poll's downward `before`) and
// (targetSlot, targetSig) is the high-water tip to promote once the gap
// finally closes. prefixSig is "" during a first sync that has not yet
// established any contiguous checkpoint.
//
// Like advanceProgramCheckpoint, this re-reads the existing row and mutates
// only the fields it owns rather than building a fresh document from
// scratch, so a poll that only opens/advances the backfill frontier does not
// wipe the poll-health heartbeat a prior successful poll already recorded.
func setBackfillFrontier(ctx context.Context, checkpoints repository.IndexerCheckpointRepository, chainID int64, programID string, prefixSlot uint64, prefixSig, cursor string, targetSlot uint64, targetSig string) error {
	cp, _, err := loadProgramCheckpoint(ctx, checkpoints, chainID, programID)
	if err != nil {
		return err
	}
	cp.LastBlock = prefixSlot
	cp.LastBlockHash = prefixSig
	cp.BackfillCursor = cursor
	cp.BackfillTargetHash = targetSig
	cp.BackfillTargetSlot = targetSlot
	cp.UpdatedAt = time.Now().UTC()
	return checkpoints.Set(ctx, cp)
}

// recordSuccessfulPoll persists the models.IndexerCheckpoint.
// LastSuccessfulPollAt heartbeat — see that field's doc comment. It
// must be called once at the end of EVERY successful pollProgram
// return, including a poll that ingested zero signatures or only advanced
// the backfill frontier.
//
// IndexerCheckpointRepository.Set is a full-document replace, not a partial
// update, so this re-reads whatever row is currently persisted — which, by
// the time pollProgram calls this (after any advanceProgramCheckpoint /
// setBackfillFrontier / closeBackfill call earlier in the same poll has
// already run) already reflects this poll's cursor/backfill state — and
// writes it back with only the heartbeat changed, so the cursor and backfill
// fields those calls just set are never clobbered. A program with literally
// no prior checkpoint row (its first-ever successful poll, which happened to
// ingest zero signatures) gets a fresh row containing only the heartbeat,
// which is exactly the desired "healthy but nothing to index yet" state.
func recordSuccessfulPoll(ctx context.Context, checkpoints repository.IndexerCheckpointRepository, chainID int64, programID string) error {
	cp, _, err := loadProgramCheckpoint(ctx, checkpoints, chainID, programID)
	if err != nil {
		return err
	}
	cp.LastSuccessfulPollAt = time.Now().UTC()
	return checkpoints.Set(ctx, cp)
}
