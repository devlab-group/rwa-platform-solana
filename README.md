# Self-Hosted RWA Tokenization Platform

A self-hosted, single-tenant platform for tokenizing a real-world asset class as a permissioned
SPL Token-2022 token on **Solana**, with an auditor-attested supply lifecycle and on-chain cash
redemption. One deployment serves **one issuer, one token, one Asset Profile, one quote token, one
auditor**. To tokenize a materially different asset class, stand up a separate deployment.

> **Not** an SDK. The issuer deploys and operates its own programs, server, database, IPFS
> pinning, and admin interface. The investor interface is optional and issuer-owned — a
> self-contained example lives in [`investor-web/`](investor-web/README.md) to fork from.

**Stack:** Rust/Anchor (Token-2022 + transfer hook) · Go (server + offline signer) · React (Vite).
Runs against any Solana cluster whose Token-2022 supports the permissioned-burn extension (v11+),
with one conventional SPL quote token.

---

## What it does

- Deploys a permissioned fungible token representing claims on a real-world asset class.
- **Every supply increase requires a valid secp256k1 auditor attestation** bound to this cluster,
  this supply-controller program and its config PDA, this profile, one metadata record, one amount,
  one Vault, and one unused nonce. The admin broadcasts the auditor-signed mint from their own
  wallet; the server never relays it and cannot create supply.
- All minting targets a **Vault** (digital warehouse) — never directly to investors.
- Transfers require **both** sender and recipient to be currently allowed, enforced by the
  Token-2022 transfer hook (mint/burn don't fire the hook, so they're exempt).
- On-chain purchase with one quote token (`rwa-vault`'s `buy`).
- **On-chain cash redemption**: request → issuer fund → permissionless claim. Funded quote lives in
  an isolated escrow, is never withdrawable, and pays only the recorded beneficiary. Unfunded
  requests can be cancelled after a timeout.
- Auditor-attested de-tokenization burn from **unsold Vault inventory only**.
- Air-gapped auditor signing via an offline Go CLI (zero network during signing).

It does **not** establish legal title, custody, regulatory classification, or a guarantee that
every redemption is funded — those remain issuer and jurisdiction responsibilities.

## How the pieces fit together

```
                        ┌───────────────────────── Issuer operator ─────────────────────────┐
   Offline / air-gapped │   React admin SPA               ── embedded in ──►  Go server       │
   ┌───────────────┐    │        │                                              │  │  │        │
   │  Signer (CLI) │    │        ▼ HTTP (OpenAPI)                               │  │  └► IPFS  │
   │  attestation  │    │   Go server: API · slot indexer · KeyProvider         │  └───► Mongo │
   └──────┬────────┘    └────────┼──────────────────────────────────────────────┘             │
          │ signed-result.json    │ Solana JSON-RPC (submit compliance status only)
          ▼                       ▼
   ┌────────────────────────────────────── Solana cluster ──────────────────────────────────┐
   │  rwa-compliance · rwa-transfer-hook · rwa-supply-controller ·                            │
   │  rwa-pricing · rwa-vault · rwa-redemption          (+ SPL Token-2022)                    │
   └────────────────────────────────────────────────────────────────────────────────────────┘
```

## Monorepo layout

| Path               | What                                                                                                                     | README                                           |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------ |
| `solana/`          | Anchor programs, host-testable core crates, bootstrap scripts, TS integration suite                                      | [solana/README.md](solana/README.md)             |
| `signer/`          | Offline Go auditor signer + `.rwa` package/validation library                                                            | [signer/README.md](signer/README.md)             |
| `server/`          | Go API, Solana RPC integration, slot indexer, embedded web                                                               | [server/README.md](server/README.md)             |
| `web/`             | React admin console SPA (built and served by the Go binary)                                                              | [web/README.md](web/README.md)                   |
| `investor-web/`    | Standalone example investor SPA — a self-contained reference to fork for your own investor UI (not served by the binary) | [investor-web/README.md](investor-web/README.md) |
| `shared/`          | Attestation types, golden vectors, JSON schemas, deployment manifests                                                    | —                                                |
| `api/openapi.yaml` | HTTP contract                                                                                                            | —                                                |
| `docs/`            | Specs, ADRs, operator/auditor/security guides                                                                            | [docs index](#documentation)                     |
| `docker/`          | Local solana-test-validator + MongoDB + IPFS compose (dev only)                                                          | —                                                |

`shared/`, `api/openapi.yaml`, `docs/spec/`, the `Makefile`, and the CI workflows are the contracts
between components. Change them through a reviewed decision record, since they're what keeps the
Rust, Go, and TypeScript sides in agreement.

## Setup

### Prerequisites

1. Docker
2. Rust, plus the Agave 4.x platform tools and `anchor-cli` 1.1.2 if you build the programs yourself
   (not needed to run the server against an already-deployed cluster)
3. Go 1.25+
4. Node.js 22+

Install every subrepo's dependencies once with `make bootstrap`.

### Dev environment

Runs against the local Docker stack (solana-test-validator + MongoDB + IPFS, all on loopback — dev
only). Deploying and wiring the programs is
[`solana/README.md`'s deployment runbook](solana/README.md); the short version:

1. Start the stack: `make up`
2. Build and deploy the six programs to the local validator, then run
   `node solana/scripts/bootstrap.mjs` to create the mint and initialize/wire every program. Keep
   the program ids, mint, and PDAs it prints — the server config needs them.
3. Copy the example config: `cp server/config.example.yaml server/config.yaml`
4. Set `security.admin_pubkey` to the base58 pubkey of the wallet that logs into the admin console.
5. Set `security.jwt_secret` to a random 64-character string (`openssl rand -hex 32`).
6. Fill in `chain:` and `contract:` from step 2 — `chain.rpc_url` and `chain.cluster_genesis`, then
   `contract.programs.*`, `contract.rwa_mint`, `contract.supply_config` and `contract.vault_config`.
   Set `security.compliance_key` to the on-chain compliance authority's keypair (an inline secret is
   dev-only; use a keypair-file path otherwise).
7. Set `contract.project_id` to a fresh UUID (`uuidgen`). The admin console reads it from
   `GET /api/v1/config` and every Asset Profile is gated against it, so it must be set before you
   create a profile.
8. Build the platform binary (with a fresh embedded SPA): `make platform`
9. Run it: `./server/bin/platform --config ./server/config.yaml`

The console is served at `http.addr` (default `:8080`). Connect the `admin_address` wallet and
create the Asset Profile.

### Reset dev data

Wipes the local cluster, database, and IPFS state for a clean run:

1. `make down`
2. `rm -rf ./docker/data`
3. Repeat the dev steps (redeploying gives fresh program ids and PDAs, so the `contract:` block —
   and `chain.cluster_genesis` — must be updated again).

### Production environment

Production runs the same binary against a real Solana cluster, managed MongoDB, and durable IPFS
pinning, with `environment: production` — which turns on fail-closed startup checks (the server
refuses to start if any of the below is missing or weak). Qualify the cluster
with [`docs/operator/testnet-qualification.md`](docs/operator/testnet-qualification.md) first.

1. Copy `server/config.example.yaml` to `server/config.yaml` and set `environment: production`.
2. `security.admin_pubkey` — the real admin wallet (a multisig is strongly recommended).
3. `security.jwt_secret` and `security.kyc_webhook_hmac_secret` — strong secrets (≥ 32 bytes each);
   both are required.
4. `contract.project_id` — a fresh UUID; required and immutable for the life of the deployment.
5. `keys.provider_mode` — `local-keystore` or `vault` (never `raw` or `kms-mock` in production). The
   compliance key is the server's only hot key; keep it out of plaintext config — supply
   `security.compliance_key` as a keypair **file path**, not an inline secret.
6. `mongo.*` — a real MongoDB URI (`persistence_mode: mongo`; `memory` is refused in production).
7. `ipfs.*` — a real Kubo endpoint plus at least one backup destination (`backup_archive_dir` or
   `backup_kubo_url`) and a `replication_threshold`.
8. `chain.*`/`contract.*` — the target cluster RPC, commitment, program ids, mint, and PDAs from
   the bootstrap run, plus the indexer's slot bounds.
9. Deploy and bootstrap on the target cluster with a real deployer keypair, following
   [`solana/README.md`](solana/README.md)'s runbook, then move the programs' upgrade authority
   somewhere safer once the deployment is live.
10. Build and run behind TLS / a reverse proxy: `make platform`, then
    `./server/bin/platform --config ./server/config.yaml`.

The quote token is your real SPL token (not the test token). Broadcast the auditor-signed mint from
the admin wallet through the console — the server never holds a deployer, relayer, or pricer key —
and set the admin transfer delay to ≥ 24h in the project config for production.

### Root commands

`make <target>`: `bootstrap · format · lint · signer-test · server-test · web-test ·
investor-web-test · solana-test · solana-anchor-build · solana-anchor-test · vectors-check · ci ·
up · down · platform`. `make ci` is the PR gate (lint, all tests, cross-language vectors).

### End-to-end lifecycle demo

```bash
make solana-anchor-test   # live validator: bootstrap → allow → mint → buy → request → fund
                          # → claim → burn, plus timeout → cancel (real transactions)
```

## The lifecycle

1. **Setup** — the admin authors an Asset Profile (a JSON Schema subset), which is canonicalized
   (RFC 8785 JCS) and hashed (SHA-256 → `profileDigest`). This happens *offline, before the
   bootstrap*: the supply-controller commits to the digest at `initialize` and never lets it
   change, so the profile has to be fixed before the chain is wired — `server/cmd/canonicalize`
   derives the digest without a running server. The six programs are deployed and then
   instantiated as PDAs by the bootstrap run, which ends in the wired state the server verifies
   before treating the project as usable: mint authority = supply-controller PDA, Vault + Escrow
   pinned as compliance system addresses and allowed, compliance authority set. The platform then
   accepts the same profile document — refusing any that doesn't hash to the on-chain digest — and
   pins it to IPFS.
2. **Onboard** — the investor proves wallet ownership (ed25519 `signMessage`); external KYC (via a
   signed webhook or a manual action) sets the wallet `Allowed` in `rwa-compliance`.
3. **Record + attest** — the admin creates a metadata record, the server builds a `.rwa` package,
   the auditor validates and signs it **offline**, and the admin uploads `signed-result.json` and
   broadcasts the supply-controller mint from their wallet (tokens go to the Vault).
4. **Sell** — an allowed investor buys from the Vault with the quote token (on-chain purchase only).
5. **Redeem** — the investor requests redemption (snapshots the quote, escrows RWA), the treasury
   funds it (re-checks compliance, escrows the exact quote), and anyone can claim (pays the
   beneficiary, returns RWA to the Vault). Unfunded requests can be cancelled after the timeout.
6. **Retire** — the auditor signs a `BurnAttestation` and the controller burns Vault inventory only.

## Testing & CI

- **Programs** — `cargo test` over the host-testable core crates (pricing math, attestation digest,
  compliance predicate, redemption state machine), `anchor build` as a per-PR SBF compile gate
  (catches account-constraint and 4 KB-stack failures), and the full `anchor test` integration suite
  against a validator with Token-2022 v11 injected.
- **Server** — `go test ./... -race`.
- **Signer** — `go test ./...`, including byte-for-byte reproduction of `shared/vectors`.
- **Web** — `tsc` typecheck, Vitest, Playwright (mock and live modes), axe accessibility.
- **Cross-language parity** — the attestation digest/signature and the JCS/CID canonicalization are
  identical across the Rust programs, the Go signer, and the Go server. This is the thing most
  likely to go subtly wrong, so the golden vectors in `shared/vectors` pin it down for all three.

The CI workflow runs the signer/server/web/solana jobs plus a dependency scan on every PR.

## Security

- The server holds exactly **one** hot signing key — `compliance` (whitelists KYC'd wallets) —
  behind a `KeyProvider` (`vault` / `kms` / `local`; `raw` env-hex is dev-only). Everything else,
  including the auditor-signed mint and all admin/treasury/redemption-manager/pricer actions, is
  broadcast as instructions from the connected admin wallet or multisig — never a server hot key.
  There is no deployer or relayer key.
- Request size and rate limits, security headers (strict CSP, `X-Frame-Options: DENY`, `nosniff`),
  atomic idempotency, webhook replay protection, and constant-time HMAC.
- The Vault and redemption escrow are pinned as compliance system addresses so a
  compromised compliance key cannot freeze core flows.
- Threat model and acceptance matrix live under `docs/spec/`; incident response is in
  [`docs/security/incident-response.md`](docs/security/incident-response.md).

## Deployment

Solana programs are deployed once and instantiated as PDAs, so there is no one-transaction factory
deploy: the equivalent is the per-program `initialize` sequence run by
`solana/scripts/bootstrap.mjs`, which creates the mint, wires every program, and flips the
deployment live. The server verifies the resulting on-chain state (supply config, mint authority,
pinned system addresses) before treating a project as usable. Qualify each target cluster with
[`docs/operator/testnet-qualification.md`](docs/operator/testnet-qualification.md).

## Documentation

- **Specs:** `docs/spec/` — roles, redemption state machine, asset profile and limits.
- **Operator:** `docs/operator/` — [operator &amp; admin](docs/operator/operator-guide.md),
  [redemption ops](docs/operator/redemption-ops.md),
  [testnet qualification](docs/operator/testnet-qualification.md).
- **Auditor:** [`docs/auditor/auditor-guide.md`](docs/auditor/auditor-guide.md).
- **Security:** incident response under `docs/security/`.

## Scope

V1 deliberately leaves out: instant, pooled, or partial redemption; redemption
fees; native-SOL purchases; multiple quote tokens; oracle/PoR/DEX integrations; force
transfer/burn/clawback; upgradeable program governance beyond the deployer's upgrade authority;
cross-chain; and provider-specific KYC/payment adapters.

## License

MIT (see SPDX headers in sources).
