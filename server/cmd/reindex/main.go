// Command reindex performs a "chain reindex rehearsal": drop this
// server's own indexed event log and every read model derived purely from
// it, reset every program's indexer checkpoint, then let the normal
// background reconcile loop (already running in the live `platform` process
// this tool targets — reindex itself does not run it) rebuild everything
// from the chain, which remains the actual source of truth throughout.
//
// This is a REHEARSAL/RECOVERY tool, not something a running deployment
// needs day to day: run it to prove disaster-recovery works, or for real
// after a Mongo restore whose read models might be stale relative to the
// chain. It does NOT touch off-chain-authored data (Asset Profiles,
// investor OwnershipVerified flags, audit logs, idempotency records) —
// only the collections that are derived purely from indexed chain events,
// never from server-side optimistic writes: chain_events,
// indexer_checkpoints, purchases, redemption_requests.
// See internal/indexer's TestReindexRehearsalReconstructsIdenticalReadModel
// for the same rehearsal proven on a fake chain, and
// server/ops/reindex_rehearsal.sh for the operator runbook that wraps this
// tool with a before/after collection-count sanity check.
//
// Usage: go run ./cmd/reindex --config <path> [--yes]
// Reads the same --config YAML file (MongoDB/program addresses) as
// the platform binary (internal/config). Requires --yes (or a "yes" typed
// at the confirmation prompt) since this is destructive to the local read
// model, even though it is recoverable by design.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/rwa-platform/server/internal/blockchain"
	"github.com/rwa-platform/server/internal/config"
	"github.com/rwa-platform/server/internal/dal"
	"github.com/rwa-platform/server/internal/dal/models"
	"github.com/rwa-platform/server/internal/dal/mongodb"
	"github.com/rwa-platform/server/internal/dal/repository"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

func main() {
	yes := flag.Bool("yes", false, "skip the interactive confirmation prompt (scripted use)")
	force := flag.Bool("force", false, "proceed even when the RPC can no longer supply the history this deletes — IRREVERSIBLE, see verifyHistoryRetained")
	configPath := flag.String("config", "", "path to the YAML configuration file (required)")
	flag.Parse()

	if *configPath == "" {
		log.Fatalf("reindex: --config <path> is required")
	}
	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		log.Fatalf("reindex: config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := dal.Connect(ctx, cfg.MongoURI)
	if err != nil {
		log.Fatalf("reindex: connecting to MongoDB: %v", err)
	}
	defer client.Disconnect(context.Background())
	db := client.Database(cfg.MongoDB)
	repos := mongodb.New(db)

	reindex(ctx, cfg, db, repos, *yes, *force)
}

// snapshotCounts is a simple before/after sanity signal for the operator
// running this interactively; server/ops/reindex_rehearsal.sh does the
// real wait-and-compare against a running platform server.
func snapshotCounts(ctx context.Context, db *mongo.Database) map[string]int64 {
	counts := map[string]int64{}
	for _, coll := range []string{"chain_events", "purchases", "redemption_requests"} {
		n, err := db.Collection(coll).CountDocuments(ctx, bson.M{})
		if err != nil {
			counts[coll] = -1
			continue
		}
		counts[coll] = n
	}
	return counts
}

// reindex drops chain_events for each configured program, resets its
// checkpoint (Set to the zero LastBlock/LastBlockHash — IndexerCheckpointRepository
// has no delete, only Get/Set, so a fresh zero-value row IS the reset), and
// drops the purely chain-derived read models (purchases, redemption_requests).
// Each of the 5 event-emitting business programs pages its own
// getSignaturesForAddress history independently and gets its own
// IndexerCheckpoint row keyed by (chainID, programID) — there is no single
// shared checkpoint. The running platform server's own background loop
// (startBackgroundLoops in cmd/platform) then re-scans from each
// program's genesis and rebuilds everything.
func reindex(ctx context.Context, cfg config.Config, db *mongo.Database, repos *repository.Repositories, yes, force bool) {
	programs := map[string]string{
		"compliance":       cfg.ProgramCompliance,
		"vault":            cfg.ProgramVault,
		"pricing":          cfg.ProgramPricing,
		"redemption":       cfg.ProgramRedemption,
		"supplyController": cfg.ProgramSupplyController,
	}

	fmt.Println("=== reindex rehearsal ===")
	fmt.Printf("chainId=%d mongoDb=%s\n", cfg.ChainID, cfg.MongoDB)
	for role, addr := range programs {
		fmt.Printf("  %-16s %s\n", role, addr)
	}
	fmt.Println("This will DROP chain_events, reset every program's indexer checkpoint, and")
	fmt.Println("drop purchases and redemption_requests, then rely on the platform server's")
	fmt.Println("own background reconcile loop to rebuild them from the chain. Asset profiles,")
	fmt.Println("investor ownership flags, and audit logs are NOT touched.")

	// PRECONDITION: prove the chain can still supply what is about to be
	// deleted. Skipping this is how a "rehearsal" becomes permanent data loss
	// — see verifyHistoryRetained's doc comment.
	fmt.Println("\nchecking the RPC still retains this deployment's history:")
	histErr := verifyHistoryRetained(ctx, blockchain.NewRPCClient(cfg.RPCURL),
		cfg.ChainID, cfg.Commitment, programs, repos.ChainEvents)
	switch {
	case histErr != nil && !force:
		fmt.Fprintf(os.Stderr, "\nREFUSING TO REINDEX: %v\n", histErr)
		os.Exit(1)
	case histErr != nil:
		fmt.Printf("\nWARNING: %v\n", histErr)
		fmt.Println("--force given: proceeding anyway. THIS DATA WILL NOT COME BACK.")
	}

	if !yes {
		fmt.Print("\nType \"yes\" to proceed: ")
		reader := bufio.NewReader(os.Stdin)
		line, _ := reader.ReadString('\n')
		if strings.TrimSpace(line) != "yes" {
			fmt.Println("aborted.")
			os.Exit(1)
		}
	}

	before := snapshotCounts(ctx, db)
	fmt.Printf("\nbefore: %+v\n", before)

	for role, addr := range programs {
		if addr == "" {
			continue
		}
		n, err := repos.ChainEvents.DeleteFromBlock(ctx, cfg.ChainID, addr, 0)
		if err != nil {
			log.Fatalf("reindex: dropping chain_events for %s (%s): %v", role, addr, err)
		}
		fmt.Printf("dropped %d chain_events for %s (%s)\n", n, role, addr)
		if err := repos.IndexerCheckpoints.Set(ctx, &models.IndexerCheckpoint{ChainID: cfg.ChainID, Address: addr}); err != nil {
			log.Fatalf("reindex: resetting checkpoint for %s (%s): %v", role, addr, err)
		}
	}
	if err := repos.Purchases.DeleteAll(ctx); err != nil {
		log.Fatalf("reindex: dropping purchases: %v", err)
	}
	if err := repos.RedemptionRequests.DeleteAll(ctx); err != nil {
		log.Fatalf("reindex: dropping redemption_requests: %v", err)
	}

	fmt.Println("\nDone. Read models are empty; they will repopulate as the running platform")
	fmt.Println("server's background reconcile loop (5s ticker) re-scans each program from its")
	fmt.Println("genesis signature.")
}
