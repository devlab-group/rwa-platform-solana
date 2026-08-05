package main

import (
	"context"
	"strings"
	"testing"

	"github.com/rwa-platform/server/internal/blockchain"
	"github.com/rwa-platform/server/internal/dal/memory"
	"github.com/rwa-platform/server/internal/dal/models"
	"github.com/rwa-platform/server/internal/dal/repository"
)

const (
	fxChainID = int64(900001)
	fxProgram = "VauLT1111111111111111111111111111111111111"
)

// prunedSource models the real failure: the RPC still answers, but its
// address→signature index no longer reaches back to the slots we hold
// locally. It returns an EMPTY page rather than an error — which is exactly
// what makes the failure silent in the indexer.
type prunedSource struct{ oldestAvailableSlot uint64 }

func (prunedSource) GetSlot(context.Context, string) (uint64, error) { return 50_000, nil }
func (p prunedSource) GetSignaturesForAddress(_ context.Context, _ string, limit int, before, _, _ string) ([]blockchain.SigInfo, error) {
	if before != "" {
		return nil, nil // one page of history and no more
	}
	return []blockchain.SigInfo{{Signature: "sig-recent", Slot: p.oldestAvailableSlot}}, nil
}
func (prunedSource) GetTransaction(context.Context, string, string) (*blockchain.Tx, error) {
	return nil, nil
}
func (prunedSource) GetGenesisHash(context.Context) (string, error) { return "", nil }

// emptySource is the extreme case observed against a local validator: the
// index has been purged entirely and every address returns zero signatures.
type emptySource struct{ prunedSource }

func (emptySource) GetSignaturesForAddress(context.Context, string, int, string, string, string) ([]blockchain.SigInfo, error) {
	return nil, nil
}

// retainedSource can still serve back past the oldest stored event.
type retainedSource struct{ prunedSource }

func (retainedSource) GetSignaturesForAddress(_ context.Context, _ string, _ int, before, _, _ string) ([]blockchain.SigInfo, error) {
	if before != "" {
		return nil, nil
	}
	return []blockchain.SigInfo{{Signature: "sig-new", Slot: 900}, {Signature: "sig-old", Slot: 10}}, nil
}

func seedEvent(t *testing.T, repos *repository.Repositories, slot uint64) {
	t.Helper()
	if err := repos.ChainEvents.Create(context.Background(), &models.ChainEvent{
		ChainID: fxChainID, Address: fxProgram, Name: "Purchased",
		TxHash: "sig1", LogIndex: 0, BlockNumber: slot,
	}); err != nil {
		t.Fatal(err)
	}
}

// TestVerifyHistoryRetainedRefusesWhenPruned is the guard for the incident
// this check exists to prevent: local events exist from slot 100, but the RPC
// only reaches back to 40_000, so dropping chain_events would be irreversible.
func TestVerifyHistoryRetainedRefusesWhenPruned(t *testing.T) {
	repos := memory.New()
	seedEvent(t, repos, 100)

	err := verifyHistoryRetained(context.Background(), prunedSource{oldestAvailableSlot: 40_000},
		fxChainID, "finalized", map[string]string{"vault": fxProgram}, repos.ChainEvents)
	if err == nil {
		t.Fatal("expected reindex to refuse when the RPC has pruned the stored history")
	}
	if !strings.Contains(err.Error(), "IRREVERSIBLE") {
		t.Errorf("error = %v, want it to spell out the consequence", err)
	}
}

// TestVerifyHistoryRetainedRefusesWhenIndexEmpty covers what was actually
// observed: every address returns zero signatures while events are held
// locally. This must refuse, not read as "no history needed".
func TestVerifyHistoryRetainedRefusesWhenIndexEmpty(t *testing.T) {
	repos := memory.New()
	seedEvent(t, repos, 100)

	if err := verifyHistoryRetained(context.Background(), emptySource{},
		fxChainID, "finalized", map[string]string{"vault": fxProgram}, repos.ChainEvents); err == nil {
		t.Fatal("expected reindex to refuse when the RPC returns no signatures at all")
	}
}

// TestVerifyHistoryRetainedAllowsWhenRetained: the RPC reaches back past the
// oldest stored event, so the rebuild really can restore everything.
func TestVerifyHistoryRetainedAllowsWhenRetained(t *testing.T) {
	repos := memory.New()
	seedEvent(t, repos, 100)

	if err := verifyHistoryRetained(context.Background(), retainedSource{},
		fxChainID, "finalized", map[string]string{"vault": fxProgram}, repos.ChainEvents); err != nil {
		t.Fatalf("verifyHistoryRetained: %v, want nil when history reaches past the oldest stored event", err)
	}
}

// TestVerifyHistoryRetainedSkipsProgramsWithNoEvents: a program that has never
// emitted anything has nothing to lose, so an empty index for it is not a
// reason to block the whole run.
func TestVerifyHistoryRetainedSkipsProgramsWithNoEvents(t *testing.T) {
	repos := memory.New()
	if err := verifyHistoryRetained(context.Background(), emptySource{},
		fxChainID, "finalized", map[string]string{"vault": fxProgram}, repos.ChainEvents); err != nil {
		t.Fatalf("verifyHistoryRetained: %v, want nil when nothing is stored for the program", err)
	}
}
