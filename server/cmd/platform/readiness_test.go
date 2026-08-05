package main

import (
	"context"
	"testing"
	"time"

	"github.com/rwa-platform/server/internal/config"
	"github.com/rwa-platform/server/internal/dal/memory"
	"github.com/rwa-platform/server/internal/dal/models"
)

func readinessTestCfg() config.Config {
	return config.Config{
		ChainID:           900001,
		ProgramCompliance: "CompLiance111111111111111111111111111111111",
		MaxCheckpointAge:  5 * time.Minute,
	}
}

// TestComplianceReadinessNoPollYet is a "fail-open before the first
// event" regression test: the old check silently ignored
// repository.ErrNotFound, so a deployment whose compliance indexer had
// never completed a successful poll reported ready anyway. It must now
// report not-ready.
func TestComplianceReadinessNoPollYet(t *testing.T) {
	cfg := readinessTestCfg()
	repos := memory.New()
	if err := complianceReadinessCheck(context.Background(), repos, cfg); err == nil {
		t.Fatal("expected a non-nil error: no checkpoint row exists at all yet")
	}
}

// TestComplianceReadinessZeroHeartbeatNotReady covers a checkpoint row
// that exists (e.g. mid-first-sync backfill) but has never recorded a
// successful-poll heartbeat — same "can't prove healthy yet" state as no row
// at all.
func TestComplianceReadinessZeroHeartbeatNotReady(t *testing.T) {
	cfg := readinessTestCfg()
	repos := memory.New()
	if err := repos.IndexerCheckpoints.Set(context.Background(), &models.IndexerCheckpoint{
		ChainID: cfg.ChainID, Address: cfg.ProgramCompliance,
		BackfillCursor: "sig1", // a real row, but LastSuccessfulPollAt is the zero value
	}); err != nil {
		t.Fatal(err)
	}
	if err := complianceReadinessCheck(context.Background(), repos, cfg); err == nil {
		t.Fatal("expected a non-nil error: checkpoint row exists but has no heartbeat yet")
	}
}

// TestComplianceReadinessIdleButHealthyStaysReady is a "fail-closed
// on a healthy quiet chain" regression test: the old check measured
// staleness against UpdatedAt, which a healthy-but-idle program (nothing new
// to index) never refreshes, so it would flip not-ready
// chain.max_checkpoint_age after its last on-chain event even though every
// poll since has succeeded. Measuring LastSuccessfulPollAt instead must keep
// it ready through repeated successful EMPTY polls, however old the actual
// last event/UpdatedAt is.
func TestComplianceReadinessIdleButHealthyStaysReady(t *testing.T) {
	cfg := readinessTestCfg()
	repos := memory.New()
	now := time.Now().UTC()
	if err := repos.IndexerCheckpoints.Set(context.Background(), &models.IndexerCheckpoint{
		ChainID: cfg.ChainID, Address: cfg.ProgramCompliance,
		// The signature cursor's UpdatedAt is far older than
		// MaxCheckpointAge (the last on-chain event was a long time
		// ago), but the poll-health heartbeat is fresh (every poll since
		// has succeeded, just found nothing new).
		LastBlock: 100, LastBlockHash: "sig-old", UpdatedAt: now.Add(-2 * time.Hour),
		LastSuccessfulPollAt: now.Add(-1 * time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	if err := complianceReadinessCheck(context.Background(), repos, cfg); err != nil {
		t.Errorf("complianceReadinessCheck: %v, want nil (heartbeat is fresh even though the last EVENT was long ago)", err)
	}
}

// TestComplianceReadinessStalledAfterEventNotReady: a program that
// WAS healthy (it has a signature cursor from a past event) but whose
// poll-health heartbeat has now gone stale beyond chain.max_checkpoint_age
// must report not-ready — a genuinely wedged/erroring indexer.
func TestComplianceReadinessStalledAfterEventNotReady(t *testing.T) {
	cfg := readinessTestCfg()
	repos := memory.New()
	now := time.Now().UTC()
	if err := repos.IndexerCheckpoints.Set(context.Background(), &models.IndexerCheckpoint{
		ChainID: cfg.ChainID, Address: cfg.ProgramCompliance,
		LastBlock: 100, LastBlockHash: "sig-old", UpdatedAt: now.Add(-10 * time.Minute),
		LastSuccessfulPollAt: now.Add(-10 * time.Minute), // older than MaxCheckpointAge (5m)
	}); err != nil {
		t.Fatal(err)
	}
	if err := complianceReadinessCheck(context.Background(), repos, cfg); err == nil {
		t.Fatal("expected a non-nil error: the poll heartbeat is older than chain.max_checkpoint_age")
	}
}

// TestComplianceReadinessNoComplianceProgramConfiguredIsReady: an
// unset contract.programs.compliance disables this check entirely (mirrors
// the pre-existing `if cfg.ProgramCompliance != ""` guard).
func TestComplianceReadinessNoComplianceProgramConfiguredIsReady(t *testing.T) {
	cfg := config.Config{ChainID: 900001, MaxCheckpointAge: 5 * time.Minute}
	repos := memory.New()
	if err := complianceReadinessCheck(context.Background(), repos, cfg); err != nil {
		t.Errorf("complianceReadinessCheck: %v, want nil when contract.programs.compliance is unset", err)
	}
}
