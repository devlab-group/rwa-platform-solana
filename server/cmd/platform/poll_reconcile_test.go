package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/rwa-platform/server/internal/assets"
	"github.com/rwa-platform/server/internal/blockchain"
	"github.com/rwa-platform/server/internal/config"
	"github.com/rwa-platform/server/internal/dal/memory"
	"github.com/rwa-platform/server/internal/dal/models"
	"github.com/rwa-platform/server/internal/project"
)

// alwaysFailingSource is a blockchain.Source whose
// GetSignaturesForAddress call always fails, for
// TestPollAndReconcileOneProgramFailureDoesNotSuppressOthers below —
// simulating a persistently unavailable/erroring RPC path for whichever
// program(s) idx is configured to scan. GetSlot must succeed
// so blockchain.Indexer.Poll actually reaches its per-program loop (see
// Indexer.Poll's doc comment: a GetSlot failure short-circuits before any
// program is attempted at all, which would prove nothing about per-program
// isolation).
type alwaysFailingSource struct{}

func (alwaysFailingSource) GetSlot(context.Context, string) (uint64, error) { return 100, nil }
func (alwaysFailingSource) GetSignaturesForAddress(context.Context, string, int, string, string, string) ([]blockchain.SigInfo, error) {
	return nil, fmt.Errorf("simulated persistent RPC failure")
}
func (alwaysFailingSource) GetTransaction(context.Context, string, string) (*blockchain.Tx, error) {
	return nil, fmt.Errorf("simulated persistent RPC failure")
}
func (alwaysFailingSource) GetGenesisHash(context.Context) (string, error) { return "", nil }

// TestPollAndReconcileOneProgramFailureDoesNotSuppressOthers is a
// regression test: the old startBackgroundLoops ticker body
// returned immediately when idx.Poll returned ANY joined error, which
// silently skipped every downstream reconciler (security/auditor/minted/
// compliance/redemption/sales) for EVERY program, even ones that scanned
// (or, as here, had already scanned in a prior tick) successfully. This
// drives pollAndReconcile directly with an idx configured to scan
// ONLY a permanently failing compliance program, while a genuine vault
// Purchased event is already persisted in chain_events (as if a prior,
// healthy tick had ingested it) — and asserts the sales/vault reconciler
// still projects it into repos.Purchases despite idx.Poll's compliance
// failure this same tick.
func TestPollAndReconcileOneProgramFailureDoesNotSuppressOthers(t *testing.T) {
	const chainID = int64(900001)
	const complianceProgramID = "CompLiance111111111111111111111111111111111"
	const vaultProgramID = "VauLT1111111111111111111111111111111111111"

	repos := memory.New()
	ctx := context.Background()

	// A vault Purchased event already persisted — standing in for a
	// program that indexed successfully (in this tick or a prior one);
	// pollAndReconcile's sales reconciler reads directly from
	// chain_events, independent of what idx itself is configured to scan.
	if err := repos.ChainEvents.Create(ctx, &models.ChainEvent{
		ChainID: chainID, Address: vaultProgramID, Name: "Purchased", TxHash: "sig1", LogIndex: 0, BlockNumber: 10,
		Data: map[string]any{
			"buyer": "Buyer111111111111111111111111111111111111", "recipient": "Recipient111111111111111111111111111111",
			"tokenAmount": "1000", "quoteAmount": "950",
		},
	}); err != nil {
		t.Fatal(err)
	}

	// idx only knows about the compliance program, and its source always
	// fails — Poll() returns a non-nil error naming compliance every tick.
	programIDs := map[blockchain.ProgramRole]string{blockchain.RoleCompliance: complianceProgramID}
	idx := blockchain.New(alwaysFailingSource{}, repos.IndexerCheckpoints, repos.ChainEvents, programIDs, chainID, "finalized", 0)

	// A projection-only RecordService (see startBackgroundLoops): the
	// four attestation-domain pubkeys just have to be well-formed 32-byte
	// base58 — nothing here builds or verifies an attestation, so their
	// exact values are irrelevant and the vault-config fixtures from
	// vault_config_test.go are reused rather than inventing more.
	records, err := assets.NewRecordService(repos.AssetRecords, repos.AuditPackages, repos.Attestations, nil,
		fxClusterGenesis, fxSupplyController, fxSupplyConfig, fxVaultConfigPDA, common.Address{})
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.Config{
		ChainID: chainID, ProgramVault: vaultProgramID,
		// ProgramCompliance deliberately left empty: this test only
		// cares about idx.Poll's error (from the program idx itself is
		// configured with) not suppressing the VAULT reconciler — leaving
		// the compliance reconciler's own cfg-gated branch off keeps the
		// test focused.
	}
	securityAddrs := project.ProgramAddrs{}

	// The security baseline reader needs a client, but cfg names no config
	// accounts (SupplyConfig/VaultConfig are empty), so ReadBaseline
	// short-circuits on every one of them and this client is never dialed.
	client := blockchain.NewRPCClient("http://127.0.0.1:1")

	pollAndReconcile(ctx, cfg, repos, client, idx, records, securityAddrs)

	purchases, err := repos.Purchases.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(purchases) != 1 {
		t.Fatalf("repos.Purchases has %d entries, want 1 — the vault/sales reconciler must still run despite idx.Poll's compliance-program failure this same tick", len(purchases))
	}
	if purchases[0].TokenAmount != "1000" {
		t.Errorf("purchase.TokenAmount = %q, want %q", purchases[0].TokenAmount, "1000")
	}

	// And the compliance program's checkpoint must genuinely have failed to
	// advance (proving idx.Poll's error was real, not a no-op) — otherwise
	// this test wouldn't actually be exercising the failure path it claims
	// to.
	if _, err := repos.IndexerCheckpoints.Get(ctx, chainID, complianceProgramID); err == nil {
		t.Error("compliance checkpoint exists despite every GetSignaturesForAddress call failing — the injected failure isn't actually taking effect")
	}
}

// TestPollAndReconcileRunsWithoutRecordService is the regression guard for a
// startup failure mode that presented as "the indexer is completely dead":
// startBackgroundLoops used to start the 5s ticker ONLY when
// assets.NewRecordService succeeded, so one construction error silently
// disabled idx.Poll and every reconciler with it — no chain_events ever
// written, every checkpoint stuck at lastBlock 0, every read model empty,
// with a single log line as the only symptom.
//
// Now records==nil costs exactly the two supply-controller projections and
// nothing else, so this drives pollAndReconcile with a nil RecordService and
// asserts the vault/sales reconciler still projects.
func TestPollAndReconcileRunsWithoutRecordService(t *testing.T) {
	const chainID = int64(900001)
	const vaultProgramID = "VauLT1111111111111111111111111111111111111"

	repos := memory.New()
	ctx := context.Background()

	if err := repos.ChainEvents.Create(ctx, &models.ChainEvent{
		ChainID: chainID, Address: vaultProgramID, Name: "Purchased", TxHash: "sig1", LogIndex: 0, BlockNumber: 10,
		Data: map[string]any{
			"buyer": "Buyer111111111111111111111111111111111111", "recipient": "Recipient111111111111111111111111111111",
			"tokenAmount": "1000", "quoteAmount": "950",
		},
	}); err != nil {
		t.Fatal(err)
	}

	idx := blockchain.New(alwaysFailingSource{}, repos.IndexerCheckpoints, repos.ChainEvents,
		map[blockchain.ProgramRole]string{}, chainID, "finalized", 0)

	cfg := config.Config{
		ChainID: chainID, ProgramVault: vaultProgramID,
		// Set so the supply-controller branch is reached and must be skipped
		// on the nil RecordService rather than panicking.
		ProgramSupplyController: "Supp11111111111111111111111111111111111111",
	}

	// The nil is the point of the test.
	pollAndReconcile(ctx, cfg, repos, blockchain.NewRPCClient("http://127.0.0.1:1"), idx, nil, project.ProgramAddrs{})

	purchases, err := repos.Purchases.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(purchases) != 1 {
		t.Fatalf("purchases = %d, want 1 — the sales reconciler must run even with no RecordService", len(purchases))
	}
}
