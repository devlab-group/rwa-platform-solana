# Public-testnet qualification runbook

Qualify a release on **at least two materially different** public Solana environments (e.g. devnet
and testnet, or devnet and a third-party RPC provider on mainnet-beta with a throwaway mint) —
different RPC providers, signature-history retention, and congestion behavior. This is a manual
runbook; it needs funded cluster keypairs and RPC endpoints not present in the CI sandbox.

## Per environment

1. **Config**: set the RPC URL, commitment (`finalized` unless you are deliberately testing a
   weaker one), start slot, explorer template, and the quote mint. Fund the deployer +
   compliance keypairs from the faucet. Where no stablecoin exists on the cluster, create the
   quote mint and fund the test wallets with
   `npm run create-test-quote-mint -- --url <RPC_URL> --mint-to <WALLET>,<WALLET>` from
   `solana/` (see its README section); keep the mint keypair it saves — it doubles as the
   faucet for topping testers up later.
2. **Deploy**: `anchor build && anchor keys sync && anchor build`, `solana program deploy` each of
   the six programs, then `node solana/scripts/bootstrap.mjs`; record all program ids, the mint,
   and every PDA in `shared/deployments/<cluster>-<date>.json`. Verify the programs on the
   explorer and check each deployed binary's sBPF hash against the CI-recorded hash.
3. **Post-deploy verification**: every program account exists with the expected owner and
   discriminator, the mint authority is the supply-controller PDA, the Vault + escrow authorities
   are pinned as compliance system addresses and allowed, `finalized` is set, and the deployer
   retains only the upgrade authority.
4. **Full lifecycle** through the server API, pointed at the cluster: compliance → record →
   `.rwa` → offline sign → broadcast the auditor-signed supply-controller mint from the admin
   wallet and confirm the server observes the `Minted` event → buy → request → fund → claim →
   burn; plus timeout → cancel. Confirm the indexer advances its checkpoint slot and honors the
   configured commitment.
5. **Failure injection**: underfunded fund attempt, quote-token failure on a funded claim (retry),
   an RPC outage (restart the server, confirm it resumes from checkpoint), and a signature-history
   gap (point at an RPC that has pruned below the checkpoint and confirm the poll fails loudly
   instead of skipping the gap).
6. **Fee/behavior notes**: record priority-fee levels needed to land under congestion, observed
   confirmation latency, the RPC's signature-history retention, and any provider-specific quirks.
   Confirm the commitment and start slot chosen are safe for that endpoint.

## Sign-off

Qualification passes for a cluster when steps 1–5 succeed and step 6 is documented. Record the two
qualified environments, dates, addresses, and operators in the release notes. Do **not** claim a
cluster is production-certified without completing this runbook for it.

This runbook's step 5 failure injection is necessarily short (a single restart, a single outage).
It does not replace the separate extended shadow-replay/soak-test gate required before a release
candidate ships — see `soak-runbook.md`.
