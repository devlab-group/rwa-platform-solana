package main

import (
	"context"
	"fmt"
	"sort"

	"github.com/rwa-platform/server/internal/blockchain"
	"github.com/rwa-platform/server/internal/dal/repository"
)

// historyProbePages/historyProbePageSize bound how far back this check pages.
// 20 x 1000 = 20,000 signatures per program is far beyond any single
// deployment's realistic history, so exhausting the cap means something is
// wrong (or the deployment is enormous) rather than "keep going" — either way
// it is not a proof that the history is retained, and the check fails closed.
const (
	historyProbePages    = 20
	historyProbePageSize = 1000
)

// verifyHistoryRetained proves the RPC can still supply the events reindex is
// about to delete, and returns an error naming what would be lost if it cannot.
//
// WHY THIS EXISTS: reindex's whole premise is "the chain is the source of
// truth, so deleting the derived state is safe." That premise silently expires.
// getSignaturesForAddress is the only way the indexer discovers anything, and
// it is served from the RPC's address→signature index, which every node prunes
// — `solana-test-validator` defaults to --limit-ledger-size 10000 shreds
// (minutes), and public endpoints keep days, not forever. Once a program's
// signatures age out, the RPC answers with an EMPTY ARRAY rather than an error,
// which the indexer correctly reads as "nothing new to do". A reindex run past
// that point deletes local state that can never be rebuilt, with no error at
// any step: chain_events stays 0, every checkpoint sits at lastBlock 0, and the
// only visible symptom is read models that silently never repopulate.
//
// The check per program is: we hold events back to slot S locally; page the
// RPC backwards and require it to still return a signature at or below S.
//   - reaches slot <= S            -> retained, safe to drop
//   - runs out of history first    -> PRUNED, dropping is irreversible
//   - hits the page cap            -> UNPROVEN, treated as unsafe
//
// A program with no local events has nothing to lose and is skipped.
func verifyHistoryRetained(
	ctx context.Context,
	src blockchain.Source,
	chainID int64,
	commitment string,
	programs map[string]string,
	events repository.ChainEventRepository,
) error {
	oldest, err := oldestEventSlotByAddress(ctx, events, chainID)
	if err != nil {
		return err
	}

	var lost []string
	for _, role := range sortedKeys(programs) {
		addr := programs[role]
		if addr == "" {
			continue
		}
		oldestSlot, held := oldest[addr]
		if !held {
			fmt.Printf("  %-16s no stored events — nothing to lose\n", role)
			continue
		}

		reached, minSeen, exhausted, err := pageBackTo(ctx, src, addr, commitment, oldestSlot)
		if err != nil {
			return fmt.Errorf("probing retained history for %s (%s): %w", role, addr, err)
		}
		switch {
		case reached:
			fmt.Printf("  %-16s OK — RPC still serves back to slot %d (oldest stored: %d)\n", role, minSeen, oldestSlot)
		case exhausted:
			fmt.Printf("  %-16s PAGE CAP — could not prove retention within %d pages\n", role, historyProbePages)
			lost = append(lost, fmt.Sprintf("%s (%s): unproven", role, addr))
		default:
			fmt.Printf("  %-16s PRUNED — RPC's oldest available signature is slot %d, but events are stored from slot %d\n",
				role, minSeen, oldestSlot)
			lost = append(lost, fmt.Sprintf("%s (%s): history before slot %d is gone from the RPC", role, addr, minSeen))
		}
	}

	if len(lost) > 0 {
		return fmt.Errorf(
			"the RPC can no longer supply the history this would delete:\n    %s\n"+
				"  Dropping chain_events now would be IRREVERSIBLE — the read models could not be rebuilt.\n"+
				"  Point --config at an RPC that retains this deployment's full history (an archival\n"+
				"  endpoint), or re-run with --force if you accept the loss",
			joinLines(lost))
	}
	return nil
}

// pageBackTo walks getSignaturesForAddress backwards looking for a signature at
// or below target. exhausted reports that the page cap was hit with history
// still remaining (as opposed to genuinely reaching the end of what the RPC
// holds).
func pageBackTo(ctx context.Context, src blockchain.Source, address, commitment string, target uint64) (reached bool, minSeen uint64, exhausted bool, err error) {
	before := ""
	minSeen = ^uint64(0)
	for page := 0; page < historyProbePages; page++ {
		sigs, err := src.GetSignaturesForAddress(ctx, address, historyProbePageSize, before, "", commitment)
		if err != nil {
			return false, 0, false, err
		}
		if len(sigs) == 0 {
			// End of what the RPC holds. If nothing was ever returned the
			// index is empty for this address entirely — minSeen stays at its
			// sentinel, which the caller renders as "oldest available" 0.
			if minSeen == ^uint64(0) {
				minSeen = 0
			}
			return false, minSeen, false, nil
		}
		for _, s := range sigs {
			if s.Slot < minSeen {
				minSeen = s.Slot
			}
			if s.Slot <= target {
				return true, minSeen, false, nil
			}
		}
		if len(sigs) < historyProbePageSize {
			return false, minSeen, false, nil // short page == true end of history
		}
		before = sigs[len(sigs)-1].Signature
	}
	return false, minSeen, true, nil
}

// oldestEventSlotByAddress returns the lowest stored block/slot per address,
// i.e. how far back the local data reindex is about to delete actually goes.
func oldestEventSlotByAddress(ctx context.Context, events repository.ChainEventRepository, chainID int64) (map[string]uint64, error) {
	all, err := events.ListAll(ctx, chainID)
	if err != nil {
		return nil, fmt.Errorf("listing stored events: %w", err)
	}
	oldest := map[string]uint64{}
	for _, e := range all {
		if cur, ok := oldest[e.Address]; !ok || e.BlockNumber < cur {
			oldest[e.Address] = e.BlockNumber
		}
	}
	return oldest, nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func joinLines(items []string) string {
	out := ""
	for i, it := range items {
		if i > 0 {
			out += "\n    "
		}
		out += it
	}
	return out
}
