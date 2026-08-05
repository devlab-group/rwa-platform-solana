package models

import "time"

// IndexerCheckpoint tracks the last scanned block per (chainId, address)
// (collection: indexer_checkpoints).
type IndexerCheckpoint struct {
	ChainID       int64     `json:"chainId" bson:"chainId"`
	Address       string    `json:"address" bson:"address"`
	LastBlock     uint64    `json:"lastBlock" bson:"lastBlock"`
	LastBlockHash string    `json:"lastBlockHash" bson:"lastBlockHash"`
	UpdatedAt     time.Time `json:"updatedAt" bson:"updatedAt"`
	// ReconciliationRequired is set by the indexer when a
	// detected reorg's common ancestor can't be verified within the
	// configured automatic-recovery policy (see
	// indexer.ErrReconciliationRequired). While true, Poll refuses to
	// advance — every derived read model that depends only on persisted
	// chain_events is frozen at a consistent, if stale, point rather than
	// silently continuing past an unresolved divergence. Cleared by
	// indexer.Indexer.ResetToTrustedCheckpoint.
	ReconciliationRequired bool `json:"reconciliationRequired,omitempty" bson:"reconciliationRequired,omitempty"`
	// BackfillCursor, BackfillTargetHash, and BackfillTargetSlot are used
	// by the indexer to close a backlog too deep to drain in a single poll
	// without silently skipping its middle.
	//
	// getSignaturesForAddress only pages BACKWARD from the chain tip, so when
	// the gap between a program's checkpoint and the tip exceeds the indexer's
	// per-poll page cap, one poll can ingest only the newest capped slice of
	// that gap — not the oldest, which is what a forward checkpoint would need
	// to advance over. Rather than jump LastBlock/LastBlockHash to the tip and
	// abandon everything below the ingested slice (the pre-fix behaviour),
	// the indexer freezes LastBlock/LastBlockHash at the contiguous prefix it
	// can still trust and records the backlog frontier here:
	//
	//   - BackfillCursor is the `before` signature the next poll resumes
	//     paging downward from — the OLDEST signature ingested so far while
	//     closing this gap. Empty means no gap is being closed (the steady
	//     state): LastBlockHash is then the true contiguous tip and polling
	//     pages from the chain tip as usual.
	//   - BackfillTargetHash / BackfillTargetSlot are the high-water signature
	//     first observed at the tip when the gap opened. They are promoted
	//     into LastBlockHash / LastBlock (and all three backfill fields
	//     cleared) once a poll finally pages down far enough to reach the
	//     frozen prefix — at which point [prefix, high-water] has been ingested
	//     contiguously across the intervening polls.
	//
	// Ingestion is idempotent (ChainEventRepository.Exists keyed on
	// txHash+logIndex), so a crash mid-backfill simply re-fetches the same
	// downward page on the next poll; the frontier only ever moves toward the
	// prefix, never skips it.
	BackfillCursor     string `json:"backfillCursor,omitempty" bson:"backfillCursor,omitempty"`
	BackfillTargetHash string `json:"backfillTargetHash,omitempty" bson:"backfillTargetHash,omitempty"`
	BackfillTargetSlot uint64 `json:"backfillTargetSlot,omitempty" bson:"backfillTargetSlot,omitempty"`
	// LastSuccessfulPollAt is a per-program poll-HEALTH heartbeat, written
	// on every successful blockchain.Indexer.pollProgram return, including a
	// poll that ingested zero signatures or only advanced the backfill
	// frontier.
	//
	// This is deliberately distinct from UpdatedAt, which
	// advanceProgramCheckpoint/setBackfillFrontier write only when the
	// signature CURSOR itself moves — i.e. only when new on-chain ACTIVITY
	// was observed. An idle-but-healthy program (nothing to index) never
	// advances the cursor, so UpdatedAt can go stale indefinitely even
	// though polling is working fine; readiness (cmd/platform's
	// complianceReadinessCheck) must measure staleness against
	// LastSuccessfulPollAt, not UpdatedAt, or a correctly-operating
	// deployment falsely reports not-ready five minutes after its last
	// event.
	LastSuccessfulPollAt time.Time `json:"lastSuccessfulPollAt,omitempty" bson:"lastSuccessfulPollAt,omitempty"`
	// Version is a monotonic counter bumped on every atomic chunk commit
	// (repository.ChainChunkRepository.CommitChunk). It is the
	// fencing token that makes the checkpoint advance conditional: a commit
	// layered on an expected version that no longer matches the stored one
	// (another indexer replica advanced it first) is rejected without writing
	// anything, so two active indexers can never interleave a stale
	// checkpoint over a newer one. Plain Set writes (rollback,
	// ResetToTrustedCheckpoint) reset it to 0, which is fine: those are
	// operator/reorg re-baselines after which the next CommitChunk simply
	// reads and layers on whatever version it finds.
	Version int `json:"version,omitempty" bson:"version,omitempty"`
}
