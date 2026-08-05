# Soak-test runbook

Load tests and short RPC-failure simulations (`testnet-qualification.md` step 5) aren't enough to
validate a continuously running indexer and API backend. This is the extra release-candidate gate
before a production deployment: run the real binary against real chain activity long enough to
catch memory leaks, goroutine growth, and state drift.

This is an **operator-run procedure** using the actual production `cmd/platform` binary against a
real Solana testnet/devnet cluster — there is no isolated in-repository replay harness (the former
`server/internal/shadow` package and its `server/ops/shadow` driver have been removed; they
predated the move to Solana's slot-based indexer, which has no reorg-rollback logic to exercise in
isolation). A soak run is therefore always a live extension of `testnet-qualification.md`, not a
separate offline dataset.

## 1. What this proves, and what it doesn't

Running the real binary means the soak exercises the real signing path too: point it at a
**testnet-only** `security.compliance_key`, never a production key. It proves the server is stable
under sustained real indexing load (checkpoint advancement, dead-letter handling, memory/goroutine
behavior); it does not by itself prove correctness under an adversarial or exhaustively-enumerated
event sequence — `testnet-qualification.md` step 5's short failure injections cover specific
adversarial cases (an RPC outage, a signature-history gap) that a soak run does not repeat except
as they occur naturally.

## 2. Preparing the environment

Reuse (or extend the duration of) a `testnet-qualification.md` deployment: a qualified cluster,
the six programs deployed and finalized, and a `security.compliance_key` scoped to that testnet. Line
up sustained realistic activity for the soak window — either drive it yourself (repeated
compliance whitelisting, mint attestations, buys, redemption request/fund/claim/cancel cycles) or
coordinate with whoever is generating testnet traffic — covering, over the run:

- mint attestations and burn attestations,
- whitelist additions and removals,
- transfers and on-chain `buy` purchases,
- redemption requests, funding, claims, and at least one timeout cancellation,
- at least one natural RPC hiccup or restart (see §3's disconnect/recovery requirement — inject
  this yourself by restarting the process if the RPC provider doesn't produce one on its own).

## 3. Running a soak

Run the real binary for the soak duration, pointed at the qualified testnet cluster and a scratch
MongoDB/IPFS pair (never production data):

```
./bin/platform --config path/to/testnet-soak-config.yaml
```

Sample its Prometheus `/metrics` (see `operator-guide.md` §7a) on a regular interval (e.g. every 5
minutes) for the duration of the run and retain the samples for the growth analysis in §5.

**Repeated disconnect/recovery cycles**: at least once during the soak, stop and restart the
process against the same config/database, and confirm from the logs and `/metrics` that indexing
resumed from the last persisted checkpoint slot rather than re-processing or losing events — this
exercises the same startup reconciliation path `cmd/platform` runs on every boot
(`operator-guide.md` §6).

## 4. Minimum duration

72 hours for a release-candidate gate; longer (a week+) is preferred before a production
deployment of a NEW release line. A patch release fixing an isolated, well-understood defect may
use operator judgement for a shorter soak, but must still pass this runbook's disconnect/recovery
requirement at least once.

## 5. What to monitor

The production server's own Prometheus `/metrics`, sampled across the run per §3:

- DB connections, RPC connection count, request/queue depth — standard Go/Mongo-driver/HTTP
  metrics already exposed.
- Event-processing lag — indexer checkpoint slot vs. the cluster's current slot.
- DLQ growth — `indexer_dead_letters` collection size over time (should track only genuine
  undecodable events encountered on the cluster, not grow unboundedly on its own).
- Redemption backlog — `RedemptionsPendingCount`, `RedemptionsFundedUnclaimedCount`
  (`internal/metrics`).
- CPU and memory (heap, goroutine count, open-FD count) — OS-level (`top`/`pidstat`) and Go's
  standard runtime metrics alongside the process.
- Restart recovery time — wall-clock time from process start to the indexer's first successful
  poll past the persisted checkpoint (logged at startup — see `operator-guide.md` §6's indexer
  recovery bullets).

Compare metrics across **multiple, time-separated windows** of the run (e.g. hour 1 vs. hour 36
vs. hour 71), not just start-vs-end, to distinguish "grew once during warmup then stabilized" from
"still climbing."

## 6. Failure criteria (fail the release-candidate gate)

- Continuously increasing memory usage without stabilization across the monitored windows.
- Unbounded goroutine growth.
- Unbounded DLQ growth not explained by genuine undecodable events actually observed on the
  cluster.
- Lost or duplicated canonical events — a locally-recorded event count that diverges from an
  independent chain-side count (see §7).
- Database state diverging from an independently reconstructed chain state (see §7).
- Inability to resume from the last verified checkpoint after a disconnect/recovery cycle (§3).
- Unavailable health checks (`/healthz`) while the process is otherwise running.

## 7. Independent final-state reconciliation

Before sign-off, perform a separately-implemented reconciliation: query the cluster directly (e.g.
`getSignaturesForAddress` against each watched program, or a block explorer API) for the canonical
event count over the run and compare it to the `chain_events` collection counts, and independently
recompute at least one derived read model — e.g. total minted supply from observed `Minted` events
— against the RWA mint's own on-chain supply.

## 8. Sign-off

Release-candidate hardening is complete only when:

- The soak ran for the required duration (§4) with resource usage within the failure criteria
  (§6), against real, sustained testnet activity (§2).
- At least one disconnect/recovery cycle (§3) succeeded.
- The independent final-state reconciliation (§7) matches.
- Any discovered leak or divergence defect is resolved (with a follow-up soak proving the fix) or
  explicitly accepted in the release notes before shipping.

Record the cluster, the config used, the metrics samples/duration actually run, and the operator
who signed off in the release notes — same convention as `testnet-qualification.md`'s sign-off.
