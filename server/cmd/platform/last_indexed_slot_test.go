package main

import (
	"context"
	"errors"
	"testing"

	"github.com/rwa-platform/server/internal/config"
	"github.com/rwa-platform/server/internal/dal/memory"
	"github.com/rwa-platform/server/internal/dal/models"
	"github.com/rwa-platform/server/internal/dal/repository"
)

func slotTestCfg() config.Config {
	return config.Config{
		ChainID:                 900001,
		ProgramCompliance:       "CompLiance111111111111111111111111111111111",
		ProgramVault:            "VauLT1111111111111111111111111111111111111",
		ProgramPricing:          "PriciNg111111111111111111111111111111111111",
		ProgramRedemption:       "REdempT10n1111111111111111111111111111111",
		ProgramSupplyController: "SuppLyCtR1111111111111111111111111111111111",
	}
}

// TestLastIndexedSlotPicksMinimumAcrossPrograms proves the
// most-behind program's checkpoint bounds the reported slot (buildApp's
// doc comment on LastIndexedBlock), not e.g. the first one iterated or the
// max.
func TestLastIndexedSlotPicksMinimumAcrossPrograms(t *testing.T) {
	cfg := slotTestCfg()
	repos := memory.New()
	ctx := context.Background()
	checkpoints := map[string]uint64{
		cfg.ProgramCompliance:       500,
		cfg.ProgramVault:            300, // most behind
		cfg.ProgramPricing:          700,
		cfg.ProgramRedemption:       600,
		cfg.ProgramSupplyController: 900,
	}
	for pid, slot := range checkpoints {
		if err := repos.IndexerCheckpoints.Set(ctx, &models.IndexerCheckpoint{
			ChainID: cfg.ChainID, Address: pid, LastBlock: slot,
		}); err != nil {
			t.Fatal(err)
		}
	}

	if got := lastIndexedSlot(cfg, repos); got != 300 {
		t.Errorf("lastIndexedSlot() = %d, want 300 (the most-behind program's checkpoint)", got)
	}
}

// TestLastIndexedSlotZeroWithNoCheckpoints: before any program has
// completed a poll, there is nothing to bound by, so it must report 0 rather
// than erroring or panicking.
func TestLastIndexedSlotZeroWithNoCheckpoints(t *testing.T) {
	cfg := slotTestCfg()
	repos := memory.New()
	if got := lastIndexedSlot(cfg, repos); got != 0 {
		t.Errorf("lastIndexedSlot() = %d, want 0 with no checkpoints at all", got)
	}
}

// TestLastIndexedSlotZeroWhenAnyProgramHasNoCheckpointYet is a
// regression test: a program with no checkpoint yet (e.g. it just
// started polling and hasn't completed a pass) must force the WHOLE result
// to 0, not be silently skipped — the old version only took the min across
// programs that DID have a row, reporting a height none of the
// deployment's configured programs have collectively reached (a real,
// misleadingly-fresh-looking number feeding
// redemption.Confirmations/Claimable and the reported indexer height).
// This now matches securityWatermark's identical guard.
func TestLastIndexedSlotZeroWhenAnyProgramHasNoCheckpointYet(t *testing.T) {
	cfg := slotTestCfg()
	repos := memory.New()
	ctx := context.Background()
	// Every program EXCEPT compliance has a checkpoint; compliance has
	// none at all.
	for pid, slot := range map[string]uint64{
		cfg.ProgramVault:            300,
		cfg.ProgramPricing:          700,
		cfg.ProgramRedemption:       600,
		cfg.ProgramSupplyController: 900,
	} {
		if err := repos.IndexerCheckpoints.Set(ctx, &models.IndexerCheckpoint{
			ChainID: cfg.ChainID, Address: pid, LastBlock: slot,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if got := lastIndexedSlot(cfg, repos); got != 0 {
		t.Errorf("lastIndexedSlot() = %d, want 0 (compliance has no checkpoint yet, so the reported height can't honestly cover it)", got)
	}
}

// erroringOneCheckpointRepo wraps a *memory.IndexerCheckpointRepository and
// returns a non-ErrNotFound failure for one specific address — so a test
// can distinguish "this program hasn't polled yet" (ErrNotFound) from "the
// repository itself is broken" (any other error).
type erroringOneCheckpointRepo struct {
	*memory.IndexerCheckpointRepository
	failAddress string
	failErr     error
}

func (r *erroringOneCheckpointRepo) Get(ctx context.Context, chainID int64, address string) (*models.IndexerCheckpoint, error) {
	if address == r.failAddress {
		return nil, r.failErr
	}
	return r.IndexerCheckpointRepository.Get(ctx, chainID, address)
}

// TestLastIndexedSlotZeroOnGenuineRepositoryError proves a real
// storage failure (not repository.ErrNotFound) also fails this call closed
// to 0, rather than being silently swallowed the way the earlier
// version treated every Get error identically.
func TestLastIndexedSlotZeroOnGenuineRepositoryError(t *testing.T) {
	cfg := slotTestCfg()
	repos := memory.New()
	ctx := context.Background()
	for pid, slot := range map[string]uint64{
		cfg.ProgramVault:            300,
		cfg.ProgramPricing:          700,
		cfg.ProgramRedemption:       600,
		cfg.ProgramSupplyController: 900,
	} {
		if err := repos.IndexerCheckpoints.Set(ctx, &models.IndexerCheckpoint{
			ChainID: cfg.ChainID, Address: pid, LastBlock: slot,
		}); err != nil {
			t.Fatal(err)
		}
	}
	repos.IndexerCheckpoints = &erroringOneCheckpointRepo{
		IndexerCheckpointRepository: repos.IndexerCheckpoints.(*memory.IndexerCheckpointRepository),
		failAddress:                 cfg.ProgramCompliance,
		failErr:                     errors.New("simulated storage failure"),
	}
	if got := lastIndexedSlot(cfg, repos); got != 0 {
		t.Errorf("lastIndexedSlot() = %d, want 0 on a genuine repository error", got)
	}
}

var _ repository.IndexerCheckpointRepository = (*erroringOneCheckpointRepo)(nil)
