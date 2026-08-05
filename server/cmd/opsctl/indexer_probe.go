package main

import (
	"context"
	"fmt"
	"time"

	"github.com/rwa-platform/server/internal/blockchain"
	"github.com/rwa-platform/server/internal/config"
	"github.com/rwa-platform/server/internal/dal/repository"
)

// runIndexerProbe answers "why is chain_events empty?" by walking the exact
// chain the platform's indexer walks — same config, same RPC client, same
// getSignaturesForAddress/getTransaction calls — and printing what each step
// actually returns.
//
// It exists because the failure is silent by design: pollProgram treats "the
// RPC returned zero signatures" as an ordinary successful poll (there is
// genuinely nothing to do), so a deployment whose program ids are wrong, whose
// RPC has pruned history, or which is pointed at the wrong cluster looks
// exactly like a healthy idle one — no error, no log line, and a checkpoint
// frozen at lastBlock 0.
//
// READ-ONLY: it makes RPC reads and reads the checkpoint rows. It never
// writes, so it is safe to run against a live deployment.
func runIndexerProbe(ctx context.Context, cfg config.Config, checkpoints repository.IndexerCheckpointRepository) error {
	client := blockchain.NewRPCClient(cfg.RPCURL)

	fmt.Printf("rpc_url:    %s\n", cfg.RPCURL)
	fmt.Printf("commitment: %s\n", cfg.Commitment)
	fmt.Printf("chain_id:   %d\n", cfg.ChainID)
	fmt.Printf("start_slot: %d\n", cfg.StartSlot)

	// 1. Is the RPC reachable, and is it the cluster this deployment is bound
	//    to? A wrong-cluster RPC returns perfectly valid empty results for
	//    every one of this deployment's addresses.
	slotCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	slot, err := client.GetSlot(slotCtx, cfg.Commitment)
	cancel()
	if err != nil {
		return fmt.Errorf("getSlot failed — the indexer cannot poll at all: %w", err)
	}
	fmt.Printf("current slot: %d\n", slot)

	genCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	genesis, genErr := client.GetGenesisHash(genCtx)
	cancel()
	switch {
	case genErr != nil:
		fmt.Printf("genesis: UNAVAILABLE (%v)\n", genErr)
	case genesis != cfg.ClusterGenesis:
		fmt.Printf("genesis: MISMATCH — rpc reports %s, config says %s\n", genesis, cfg.ClusterGenesis)
		fmt.Println("  => this RPC is a DIFFERENT CLUSTER; every address below will look empty")
	default:
		fmt.Printf("genesis: %s (matches config)\n", genesis)
	}

	// 2. Per program: what does getSignaturesForAddress actually return, and
	//    does the newest transaction contain decodable events for it?
	programs := []struct {
		role blockchain.ProgramRole
		id   string
	}{
		{blockchain.RoleCompliance, cfg.ProgramCompliance},
		{blockchain.RoleVault, cfg.ProgramVault},
		{blockchain.RolePricing, cfg.ProgramPricing},
		{blockchain.RoleRedemption, cfg.ProgramRedemption},
		{blockchain.RoleSupplyController, cfg.ProgramSupplyController},
	}

	fmt.Println("\nper-program probe:")
	for _, p := range programs {
		fmt.Printf("\n  %-18s %s\n", p.role.String()+":", p.id)
		if p.id == "" {
			fmt.Println("    NOT CONFIGURED — this program is never polled")
			continue
		}

		cp, cpErr := checkpoints.Get(ctx, cfg.ChainID, p.id)
		switch {
		case cpErr == repository.ErrNotFound:
			fmt.Println("    checkpoint:   none yet (never completed a poll)")
		case cpErr != nil:
			fmt.Printf("    checkpoint:   ERROR %v\n", cpErr)
		default:
			// lastSuccessfulPollAt is the discriminator that matters: it is
			// written on every successful poll, so a zero value means the
			// poll loop is not running (or errors every time), while a recent
			// one with lastBlock 0 means it IS running and finding nothing.
			fmt.Printf("    checkpoint:   lastBlock=%d lastSuccessfulPollAt=%s backfillCursor=%q\n",
				cp.LastBlock, formatTime(cp.LastSuccessfulPollAt), cp.BackfillCursor)
			if cp.LastSuccessfulPollAt.IsZero() {
				fmt.Println("      => the poll loop has NEVER completed for this program")
			}
		}

		sigCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		sigs, sigErr := client.GetSignaturesForAddress(sigCtx, p.id, 5, "", "", cfg.Commitment)
		cancel()
		if sigErr != nil {
			fmt.Printf("    signatures:   ERROR %v\n", sigErr)
			continue
		}
		if len(sigs) == 0 {
			fmt.Println("    signatures:   NONE — the RPC reports no transactions for this address")
			fmt.Println("      => wrong program id, wrong cluster, or an RPC that has pruned this history")
			continue
		}
		fmt.Printf("    signatures:   %d most recent (newest slot %d)\n", len(sigs), sigs[0].Slot)
		if cfg.StartSlot > 0 && sigs[0].Slot < cfg.StartSlot {
			fmt.Printf("      => ALL of these are below chain.start_slot (%d) and are skipped on a first sync\n", cfg.StartSlot)
		}

		// 3. Do this program's own events actually decode out of its newest
		//    transaction? A tx whose events all belong to a CPI'd program is
		//    correctly ingested as zero events for THIS one.
		txCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		tx, txErr := client.GetTransaction(txCtx, sigs[0].Signature, cfg.Commitment)
		cancel()
		switch {
		case txErr != nil:
			fmt.Printf("    newest tx:    ERROR %v\n", txErr)
		case tx == nil:
			fmt.Println("    newest tx:    NOT RETURNED (pruned by this RPC?)")
		default:
			fmt.Printf("    newest tx:    slot=%d logs=%d %s\n", tx.Slot, len(tx.Meta.LogMessages), decodableSummary(p.role, tx.Meta.LogMessages))
		}
	}

	return nil
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format(time.RFC3339)
}

// decodableSummary reports how many "Program data:" lines in a transaction's
// logs decode as events for role — the last hop before a ChainEvent row, and
// the one place a schema/IDL drift would silently swallow everything.
func decodableSummary(role blockchain.ProgramRole, logs []string) string {
	names, undecodable := blockchain.ProbeDecodableEvents(role, logs)
	if len(names) == 0 && undecodable == 0 {
		return "(no program-data lines)"
	}
	return fmt.Sprintf("decoded=%v undecodable-data-lines=%d", names, undecodable)
}
