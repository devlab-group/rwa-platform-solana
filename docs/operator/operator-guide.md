# Operator & administrator guide — self-hosted RWA platform V1

Audience: the issuer running one deployment (one asset class). In V1 the operator and the
administrator are the same party — the single admin is the wallet that deployed the stack — so
this one guide covers both running the platform (provisioning, deployment, day-2 operations,
recovery) and administering its privileged on-chain roles (§4a). Pair it with redemption
operations (`redemption-ops.md`), the auditor guide (`../auditor/auditor-guide.md`), incident
response (`../security/incident-response.md`), public-testnet qualification
(`testnet-qualification.md`), and the shadow-replay/soak-test gate (`soak-runbook.md`).

## 1. Architecture recap

One deployment = one token, one Asset Profile, one quote token, one auditor, one server +
MongoDB + IPFS. Components:

- **Programs** (Anchor, on SPL Token-2022 + a transfer hook): `rwa-compliance`,
  `rwa-transfer-hook`, `rwa-supply-controller`, `rwa-pricing`, `rwa-vault`, `rwa-redemption`.
  Deployed once, then instantiated and cross-wired as PDAs by the bootstrap run.
- **Server** (Go/Gin): API, slot indexer, embedded SPA (`go:embed`).
- **Signer** (Go CLI): air-gapped auditor attestation signing. Never networked.
- **Web** (React): admin + investor SPA, served by the Go binary at `/`.

## 2. Prerequisites

- A Solana RPC endpoint + commitment policy, on a cluster whose Token-2022 supports the
  permissioned-burn extension (v11+).
- One conventional SPL quote token (no transfer fee / rebasing).
- MongoDB and an IPFS (Kubo) node, or the bundled `docker/docker-compose.yml`.
- Key custody plan: admin/treasury/redemption-manager/pricer are wallet/multisig actions
  broadcast from the connected admin wallet (never server hot keys). The server holds exactly
  **one** hot key — `compliance` (whitelists KYC'd investor wallets) — in KMS/Vault (see
  `KeyProvider`). Project deployment and the auditor-signed mint are also broadcast from
  the admin wallet, so the server has no deployer/relayer key.
- An offline machine for the auditor with the `signer` binary. **Hardware-backed signing
  (`--hardware ledger|trezor|yubikey|hsm`) is the recommended production configuration for the
  auditor key**; no device
  has a working integration in the current build (`internal/hardware` ships only the adapter seam
  and `StubAdapter`), so today every production deployment runs the hardened software-keystore
  fallback (`--keystore`, either this signer's own Argon2id format or an Ethereum V3 file — see
  `internal/keystore` and `docs/auditor/auditor-guide.md` §5) until a device is wired up. Treat
  that as an explicitly-approved fallback, not the target end state.

## 3. Deploy

**The bootstrap comes before the server, and the profile comes before the bootstrap.** The
supply-controller commits to `profileDigest` at `initialize`, permanently — so the Asset Profile
has to exist before the chain is bootstrapped, which is before there is a running server to
author it in. Authoring the profile offline is what breaks that cycle; do not expect to use the
Setup screen for it. (The alternative is below.)

1. Author the **Asset Profile** JSON offline (`docs/spec/asset-profile.md`,
   `shared/schemas/asset-profile.schema.json`) and compute its digest with the server's
   canonicalizer — the same code path the server itself uses, so the value you pin on-chain is
   the one it will later derive:
   ```bash
   cd server && go run ./cmd/canonicalize /path/to/asset-profile.json   # → digest=0x…
   ```
   Keep the file. `profileDigest = SHA-256(JCS(profile))` is immutable on-chain once bootstrapped.
2. Choose token name/symbol/decimals, quote token, fixed purchase/redemption prices, redemption
   timeout (14d default; program-bounded), authority holders, treasury.
3. Deploy the stack. Solana programs are deployed once and instantiated as PDAs, so there is no
   one-transaction factory deploy:
   - `anchor build && anchor keys sync && anchor build`, then put the six binaries on-chain with
     the funded deployer keypair (which becomes their upgrade authority):
     ```bash
     cd solana && scripts/deploy.sh --url <RPC_URL> --keypair <DEPLOYER_KEYPAIR>
     ```
     The script loops `solana program deploy` over all six programs so you don't substitute
     binary and keypair names by hand. Before it spends anything it checks that every `.so` and
     program keypair exists, that the deploy keypairs match the program ids in `Anchor.toml`,
     that the RPC is reachable, and how much SOL the payer has; a mainnet-beta genesis hash
     needs a typed confirmation. Deploys are resumable — each program writes through a fixed
     buffer keypair, so a large deploy that dies partway is retried into the same buffer, and
     re-running the script continues where it stopped instead of orphaning rent on-chain. On a
     public cluster add `--with-compute-unit-price <MICROLAMPORTS>` and use a paid RPC (the
     public endpoint rejects large deploys). `--dry-run` prints the commands, `--programs
     rwa_vault,rwa_redemption` re-deploys a subset (that is also the upgrade path: the same
     command upgrades an already-deployed program), `scripts/deploy.sh --help` lists the rest.
     The script only ships bytecode — nothing is initialized or wired until the bootstrap below.
   - `node solana/scripts/bootstrap.mjs` creates the mint, runs every program's `initialize`,
     pins the Vault + escrow authorities and the supply-controller/mint ids via
     `set_system_addresses`, and calls `finalize` to flip the deployment live. It logs every
     program id, mint, and PDA — these go into the server config's `chain:`/`contract:` blocks.
   - See `solana/README.md`'s deployment runbook for the full step-by-step and its sharp edges.
4. Start the platform against the bootstrapped deployment, then **submit the profile you authored
   in step 1** to `POST /api/v1/profile` (the Setup screen's editor accepts the raw document). The
   server recomputes its digest and refuses it unless it matches the one read from the on-chain
   supply-controller config — the profile is create-once and immutable, so a mismatch is rejected
   rather than stored. Nothing needs to be byte-identical: canonicalization normalizes key order
   and whitespace, but every value must be the same.
5. **Verify before use**: the server reads the on-chain supply-controller config account and
   checks its owner, discriminator, and `vault` field against the configured values before it will
   serve, then verifies the compliance registry's pinned system addresses and the mint authority.
   It surfaces this on the Security screen. A missing, unreadable, or mismatched account is a
   startup failure, not a silent skip (`production_overrides.allow_unverified_supply_config`
   exists only to allow a pre-`initialize` boot and must stay `false` in production).

**Alternative: author the profile in the Setup screen after all.** If you want the generated form
rather than hand-written JSON, you can boot the server *before* the bootstrap and swap steps 1 and
3. Every value the server needs is derivable without running `bootstrap.mjs`: `chain.cluster_genesis`
is `solana genesis-hash` (a property of the cluster, not the deployment), `contract.programs.*` come
from `anchor keys sync`, `contract.rwa_mint` is the pubkey of the mint keypair you pre-generate, and
`contract.supply_config` / `contract.vault_config` are single-seed PDAs — `findProgramAddress(["supply-config"],
supplyControllerProgramId)` and `findProgramAddress(["vault-config"], vaultProgramId)` — so they are
fixed as soon as the program ids are. Set `contract.project_id`, deploy the programs, start the
platform with `production_overrides.allow_unverified_supply_config: true`, author the profile, copy
the digest into `bootstrap.config.json`, bootstrap, then **restart with the override back to
`false`**. The cost is a startup window in which the supply-config cross-check is knowingly skipped;
that override exists for exactly this pre-`initialize` boot and for nothing else.

## 4. Day-2 operations

- **Compliance**: allow/block wallets (KYC webhook or manual). A wallet must prove ownership
  (challenge/verify) before a KYC webhook may set it Allowed, unless a documented manual override.
- **Assets → mint**: create a record → download the `.rwa` package → auditor signs offline →
  in the Setup/Assets screen upload `signed-result.json`; the console assembles the mint
  instruction (record + profile/project fields) and the admin **broadcasts the supply-controller
  mint from their own wallet** (it is permissionless — the auditor's secp256k1 attestation is the
  authorization). Tokens go to the Vault only. The server observes the `Minted` event and advances
  the record; it never relays the mint.
- **Sales**: on-chain vault `buy` (investor-built instruction) only. Withdraw proceeds to the
  treasury (treasurer).
- **Redemptions**: see `redemption-ops.md`.
- **Pricing**: the pricer updates fixed purchase/redemption prices independently.
- **Pause**: the pauser pauses all token movement + supply/sale/redemption state changes.

## 4a. Privileged roles & administration

All privileged actions are wallet transactions — never authority private keys in the browser. In
the admin console the connected admin wallet performs most of them directly: pause/unpause, price
updates, authority rotation, and the two-step admin handover (Security screen); treasury
withdrawal (Inventory & Sales); and redemption funding/rejection (Redemptions) are each encoded
client-side and broadcast from the wallet — the program's signer check against the stored
authority pubkey is the authorization. Investor buy/request/claim/cancel are instructions the
investor's own SPA builds and submits from their wallet.

### Authority matrix (see `../spec/roles.md`)

| Authority              | Production holder                    | Powers                                                 |
| ---------------------- | ------------------------------------ | ------------------------------------------------------ |
| `admin` (per program)  | issuer multisig                      | rotate that program's authorities and mutable settings |
| `pauser`               | issuer/security multisig             | pause/unpause the whole project                        |
| `compliance_authority` | server hot key and/or legal multisig | set wallet status/expiry                               |
| `pricer`               | issuer/pricer multisig               | update fixed prices                                    |
| `treasurer`            | treasury multisig                    | withdraw proceeds; fund exact redemption requests      |
| `redemption_manager`   | issuer/legal multisig                | reject pending unfunded requests with a reason code    |

Admin handover is two-step on every program — the current admin proposes and the incoming admin
accepts — so no single mistaken `set` hands the project to an unreachable key. The auditor is
stored authority in `rwa-supply-controller` (a 20-byte secp256k1 address), not a
transaction-sending role.

### Common admin actions

- **Rotate an authority**: the per-program setter (`set_compliance_authority`, `set_pauser`,
  `set_pricer`, `set_treasurer`, `set_redemption_manager`), signed by that program's admin.
  Security screen.
- **Transfer admin**: the current admin calls `propose_admin(newAdmin)` on every program; the
  incoming admin then calls `accept_admin` on each. Both steps are in the Security screen.
- **Rotate auditor**: `set_auditor(newAuditorEthAddress)` on the supply controller → emits
  `AuditorChanged`. Re-issue any un-signed `.rwa` packages to the new auditor. Nonces/record keys
  already used stay used. This is immediate and single-signature, so hold admin behind a multisig.
- **Change treasury**: the vault's `set_treasury`. Verify on the Security screen afterward.
- **Update prices**: the pricing program's `set_purchase_price` / `set_redemption_price` (pricer).
- **Pause / unpause**: the compliance registry's `pause`/`unpause` (pauser). While paused,
  transfers, buy, mint, burn, and request/fund/claim all fail. Cancel is deliberately still
  possible — the transfer hook grants the escrow authority a pause bypass so a timed-out request
  can always be unwound; see `../spec/redemption-state-machine.md`.

### Security notes

- Minimize hot roles. Admin/treasury/redemption-manager should be multisig, not server keys.
- A compromised compliance key can allow/block wallets but cannot mint.
- All role changes emit events with previous/new/caller for a full audit trail.

## 5. Monitoring & alerts

Scrape the server `/metrics` (Prometheus). Alert on: pending-redemption SLA breach (age over
threshold), funded-but-unclaimed redemptions, indexer lag / checkpoint staleness, RPC errors,
and transaction-manager stuck nonces. Treat indexer data as unconfirmed until the finality depth.

## 6. Backup & recovery

- **MongoDB**: scheduled `mongodump`; test `mongorestore` regularly (see `server/ops/`).
- **IPFS replication** (`internal/ipfs.ReplicationManager`): a CID proves
  integrity, not availability, so a lone local Kubo node is NOT a production-safe configuration.
  Set `IPFS_BACKUP_ARCHIVE_DIR` (a local-filesystem reproducible content archive — no external
  commercial pinning service required) and/or `IPFS_BACKUP_KUBO_URL` (a second, independent Kubo
  node) to configure at least one backup destination; `IPFS_REPLICATION_THRESHOLD` (default 1) is
  how many of them must succeed before a package is treated as durably published
  (`PublicationReplicated`, not just `PinnedLocally`). Leaving both unset keeps the earlier
  single-node behavior — a documented gap, not silently hardened. The server verifies every known
  publication against every configured destination on a 30-minute ticker (fetch + digest match,
  not just a prior API success) and demotes a publication whose content can no longer actually be
  retrieved. Recover a lost local Kubo repository with an operator-triggered
  `ReplicationManager.RestoreLocal` call (re-pulls from whichever backup still has the content);
  a failed backup is retried with `ReplicationManager.Retry` once it's back.
- **Chain reindex**: read models are reconstructable from chain events. To rebuild, drop the
  read-model collections and replay from the configured start slot. Redemption status is derived
  only from events; server records annotate but never override chain state.
- **Indexer gap handling**: the indexer walks each watched program's transaction signatures
  forward from its persisted checkpoint slot. If the RPC cannot serve the range between the
  checkpoint and the oldest signature it returns — a pruned or lagging node — the poll fails
  loudly rather than silently skipping the gap, and the checkpoint does not advance, so a retried
  poll always resumes correctly. Set the start slot no earlier than what the configured RPC
  actually retains.
- **Event decoding failures**: an instruction/event the indexer cannot decode is recorded to the
  dead-letter queue (`indexer_dead_letters`) instead of blocking every later canonical event
  behind it — inspect and retry entries with `opsctl`.
- **Rollbacks**: read at the configured commitment (`finalized` in production). A dropped
  optimistically-confirmed slot is re-derived on the next poll from the checkpoint; nothing is
  written from below the configured commitment.

## 6a. Hot-key provider

The server holds exactly one hot key — the Solana compliance key, an ed25519 keypair used only to
sign `set_status` transactions against the `rwa-compliance` program. There is no backend-selection
abstraction any more: `internal/keys.Provider` is just a `Reload`/`Close` lifecycle interface that
the loaded key is wrapped in for rotation and shutdown zeroing (`server/internal/keys/keys.go`).

Configure the key via `security.compliance_key`, which accepts either form:

- an inline base58-encoded 64-byte ed25519 secret key, or
- a filesystem path to a `solana-keygen`-format JSON keypair file (a JSON array of 64 byte
  values).

`cmd/platform`'s `loadSolanaComplianceKey` tries the inline base58 decode first, then falls back to
reading the value as a file path. **Production must not keep the key inline in plaintext config**
unless you explicitly opt in: an inline base58 secret in production requires
`production_overrides.allow_plaintext_compliance_key: true`
(`PRODUCTION_ALLOW_PLAINTEXT_COMPLIANCE_KEY=true`), otherwise config validation fails
closed at startup. Prefer a keypair-file path sourced from your secret manager over the inline
form.

## 7. Key rotation

Admin/auditor/treasury/redemption-manager/strategy are all rotatable by the admin (§4a). Hot keys
rotate via `KeyProvider`: provision the new key, grant its on-chain role, cut over, then revoke
the old. Rehearse rotation on a testnet before production. Auditor rotation emits `AuditorChanged`;
in-flight unsigned packages must be re-issued to the new auditor.

### Rotation & recovery rehearsal

1. On a testnet copy, rotate each role and confirm the old holder loses power, the new gains it.
2. Rotate the auditor; sign + mint with the new auditor key end-to-end.
3. Rotate a hot key via `KeyProvider`; confirm the server signs with the new key and old is revoked.
4. Rehearse a **funded-redemption recovery**: blacklist a beneficiary at the quote-token level,
   confirm the funded claim reverts but the request stays Funded, lift the blacklist, retry claim.
Document each rehearsal's date, admin, and result.

## 7a. Deployment topology & observability

- **Multi-replica scaling.** There is no transaction manager and no nonce/fee-bump sequencing any
  more — the server never broadcasts a business transaction except the compliance hot key's
  `set_status` call, and unlike an EVM nonce, a Solana transaction doesn't need strict per-signer
  sequencing, so running more than one `cmd/platform` replica against the same
  `security.compliance_key` is not itself unsafe. The one distributed coordination primitive that
  does exist is `repository.LeaseRepository` (the `leases` collection): a short, fenced lease used
  purely for **reconciler leader election**. `cmd/platform`'s `runAsReconcilerLeader` wraps each
  periodic reconciler tick (e.g. the compliance status reconciler) so only one replica's tick
  actually executes it at a time, instead of every replica racing the same
  upsert/delete-stale-generation pass against the same collection. Multiple replicas require
  `PERSISTENCE_MODE=mongo`; a single-replica deployment (or `PERSISTENCE_MODE=memory` dev) always
  acquires the lease immediately since nothing else ever holds the key.
- **Trusted proxies.** `TRUSTED_PROXIES` defaults to none (trust no proxy), so `X-Forwarded-For`
  cannot be spoofed to bypass per-IP rate limits. If you run behind a real reverse proxy, set it
  to that proxy's address only.
- **Metrics** are served on a **separate** listener (`METRICS_ADDR`, default `:9090`), never the
  public API port — scrape it from your monitoring network only. Business gauges include Vault
  inventory, pending-redemption count/oldest-age, and funded-unclaimed count; alert evaluators
  (pending-redemption SLA, funded-claim-failure) fire on a 5-minute ticker into logs + audit log +
  the `rwa_alerts_fired_total` counter.
- **Reindex**: `cmd/reindex` drops only reconstructable read models (chain_events, checkpoints,
  purchases, redemption_requests) — never asset profiles, ownership flags, or audit
  logs. `server/ops/reindex_rehearsal.sh` proves before/after collection parity.

## 8. Honest limitations

- A redemption request is not a funding guarantee; funding is an issuer policy decision.
- De-whitelisting freezes a holder's balance in place (no force transfer in V1).
- The quote token can independently blacklist/fail; a funded claim stays claimable and is retryable.
- Do not put PII in metadata or public IPFS objects.
