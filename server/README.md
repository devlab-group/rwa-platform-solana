# server — self-hosted RWA platform: Go API + Solana chain integration

Module: `github.com/rwa-platform/server`. Go 1.25. Framework: [Gin](https://github.com/gin-gonic/gin).

This is the platform's single deployable binary (`cmd/platform`): a Gin HTTP API implementing
every operation in the frozen `api/openapi.yaml` contract, a Solana RPC client and slot-based
event indexer (no transaction manager — the server only observes on-chain events, except for the
one compliance hot key that submits `set_status`), and — via `go:embed` — the built admin React
SPA (`web/dist`, copied into `internal/webui/dist` at build time), served same-origin from the
same process and port. One running `platform` process is one deployment: one RWA mint, one Asset
Profile, one quote mint, one auditor.

See `docs/operator/operator-guide.md` for the operator-facing deployment/runbook document (this
README is the code-facing counterpart).

## Contents

- [Module map](#module-map)
- [How it implements api/openapi.yaml](#how-it-implements-apiopenapiyaml)
- [Compliance hot key](#compliance-hot-key)
- [Configuration (the `--config` YAML file)](#configuration-the---config-yaml-file)
- [Production hardening](#production-hardening)
- [Dependency baseline](#dependency-baseline)
- [Observability](#observability)
- [Backup, restore, and reindex](#backup-restore-and-reindex)
- [Build, test, and verify](#build-test-and-verify)
- [Security posture](#security-posture)

## Module map

Everything lives under `internal/` (not importable outside this module) except the binaries in
`cmd/`.

| Package | Responsibility |
|---|---|
| `internal/api` | Gin routers/handlers matching every `api/openapi.yaml` operationId one-to-one. Handlers are thin: they translate HTTP ↔ the workflow packages below and apply auth/idempotency/rate-limit/size-limit/security-header middleware. Owns nothing else — no business logic lives here. Response shapes live in `internal/api/dto` (a pure view layer over the persisted models). |
| `internal/auth` | Admin authentication (Solana ed25519 Wallet-Standard `signMessage` → HMAC JWT, verified from `Authorization: Bearer`), the investor `X-Wallet-Session` manager, the idempotency store's HTTP integration, per-IP rate limiting, request-size limiting, and the security-header baseline (`SecurityHeaders`/CSP — see [Security posture](#security-posture)). |
| `internal/config` | Parses the single `--config` YAML file into a `Config`, then resolves defaults and runs every validation through one pure, I/O-free engine (`LoadFromMap`), so it's unit-testable without a live chain/Mongo. See [Configuration](#configuration-the---config-yaml-file). |
| `internal/dal` | The data-access layer, and the only place persistence shapes or storage code live. `dal/models` — every persisted/derived struct (Project, AssetRecord, RedemptionRequest, Transaction, ChainEvent, ...) with its `bson`/`json` tags, one file per model, no behavior. `dal/repository` — storage interfaces only (one per collection) plus the `Repositories` aggregate; business logic depends on these, never on a concrete backend. `dal/memory` — in-memory fakes, what every unit test uses (`go test ./...` needs no live Mongo). `dal/mongodb` — the real backend, including `EnsureIndexes` and every unique-index/atomic-insert guarantee the interfaces document. `dal/db.go` — the Mongo connection itself. |
| `internal/blockchain` | The Solana JSON-RPC client and the slot-based event indexer. Each of the five event-emitting programs (compliance, vault, pricing, redemption, supply-controller) pages its own `getSignaturesForAddress` history independently and gets its own `IndexerCheckpoint` row keyed by program id — there is no single per-chain checkpoint the way a block-height indexer would have. Every RPC call is made at a fixed commitment (normally `finalized`), so results are by construction never rolled back: there is no reorg-rollback logic here. |
| `internal/project` | There is no on-chain factory to deploy from — every program/mint address is provisioned independently and the single Project record is seeded directly from config at boot (`SeedProject`), Active immediately (no deploy-and-observe step). Also projects the live security state (paused flags, role holders, prices) from indexed events **layered over an on-chain account baseline**: no program's `initialize` emits an event, so the authorities and prices fixed at bootstrap live only in the config PDAs. `blockchain.ReadBaseline` reads them every reconcile tick and events override them, which is why a freshly bootstrapped deployment reports a populated Security screen without waiting for its first rotation. |
| `internal/assets` `internal/auditpkg` | Asset Profile validation/canonicalization (RFC 8785 JCS) + digest/CID computation, `.rwa` audit package assembly, and local verification of the auditor's `signed-result.json`. The mint attestation reuses the keccak256 + secp256k1 EIP-712-style digest over Solana-shaped domain fields (frozen — see `internal/eip712/attestation.go`); the auditor-signed mint is broadcast independently on-chain, and this server only observes the resulting `Minted` event and advances the record — it never relays a mint. |
| `internal/compliance` | Wallet-ownership challenge/verify (Solana ed25519 `signMessage`), the HMAC-signed KYC webhook (constant-time-compared, replay-protected via an atomic unique-`payloadHash` insert), and `rwa-compliance::set_status` transaction submission — the one and only place a server hot key signs. |
| `internal/sales` `internal/redemption` | Read models only: vault inventory and indexed purchase history; redemption requests and their status, derived **exclusively** from indexed events. Neither package builds or submits a transaction — there is no server-held chain client to read a live balance from, so `GET /sales/inventory` always 501s and the SPA reads vault/mint balances directly via `@solana/web3.js`. Every action (investor buy/request/claim/cancel, admin fund/reject/withdraw) is encoded client-side from the deployed program IDLs and signed by the caller's own wallet. |
| `internal/ipfs` | Kubo HTTP API client for pinning canonicalized profile/metadata blobs, plus the replication manager that only treats a package as durably published once enough independent backup destinations have pinned it. |
| `internal/auditlog` | Append-only operational audit trail (`GET /api/v1/audit-logs`), also used by the alert evaluators (below) to record findings. |
| `internal/metrics` | Prometheus registry: HTTP request count/latency by route template, and the business gauges — see [Observability](#observability). |
| `internal/alerts` | Pure (no I/O) SLA evaluators over `models.RedemptionRequest` slices — see [Observability](#observability). |
| `internal/webui` | `go:embed`s its own `dist/` and serves it same-origin via a Gin `NoRoute` SPA-fallback handler, with the security-header baseline applied directly (not only inherited from `internal/auth`'s router-wide middleware). The built bundle is *not* committed — only `dist/.gitkeep` is tracked, and the release build copies `web/dist` over it before `go build`, so the binary embeds whatever is on disk at build time. |
| `internal/eip712` | The keccak256/secp256k1 EIP-712-style typed-data domain/hashing shared by the compliance challenge and the mint/burn attestation verification path — a deliberately retained cryptographic primitive on the Solana attestation path, not EVM chain integration. |

**`cmd/`:**

- `cmd/platform` — the real binary: reads the `--config` YAML file, connects Mongo (falls back to
  in-memory if unreachable — see its doc comment, this is a dev convenience, never rely on it in
  production) and the Solana RPC endpoint, wires every workflow service, starts the indexer/
  reconcile/metrics/alert background loops, and serves the API + embedded SPA + a separate
  `/metrics` listener.
- `cmd/opsctl` — the audited operator CLI: a CLI rather than new HTTP routes precisely so the
  frozen `api/openapi.yaml` contract stays untouched. It reads the same `--config` file and talks
  straight to the same MongoDB the server uses, so its writes are immediately visible to a running
  `platform`. Deliberately **not** credential-gated — anyone who can run it already holds every
  secret in that config file, so access control is filesystem/host access, exactly as for
  `platform` itself; it keeps only an `--actor` label, and records one `audit_logs` entry per
  invocation whether it succeeds or fails. Subcommands cover IPFS pin recovery (`ipfs retry` /
  `ipfs restore-local`).
- `cmd/reindex` — the actual "drop and let it rebuild" tool behind the reindex rehearsal — see
  [Backup, restore, and reindex](#backup-restore-and-reindex).
- `opsctl indexer probe` — read-only diagnosis of "why is `chain_events` empty?": walks the
  exact path the indexer walks (same config, same RPC) and prints, per program, the checkpoint
  (including `lastSuccessfulPollAt`, which separates "the poll loop is not running" from "it is
  running and the RPC returns nothing"), how many signatures the RPC actually serves, and
  whether the newest transaction's `Program data:` lines decode for that program.
- `cmd/canonicalize` — prints the JCS-canonical SHA-256 digest + CIDv1 of a JSON file using the
  exact same `internal/auditpkg` logic the server uses. This is a required deployment step, not a
  convenience: the supply-controller commits to `profileDigest` at `initialize`, so the Asset
  Profile must be authored and hashed *before* the bootstrap — which is before this server can
  run. See `docs/operator/operator-guide.md` §3.

## How it implements api/openapi.yaml

`api/openapi.yaml` is a frozen, lead-owned contract. `internal/api.NewRouter` wires one Gin
route per operationId; handler names match operationIds. The router-wide middleware chain
(outermost to innermost) is: `gin.Recovery` → Prometheus request metrics
(`metrics.GinMiddleware`) → security headers (`auth.SecurityHeaders`) → request-size limit
(`auth.MaxRequestBody`) → rate limit (`auth.RateLimit`, when enabled) → `auth.Authenticate`.
Per-route, on top of that: `auth.RequireRole(auth.RoleAdmin)` on every admin route →
`auth.Idempotency` (state-changing routes only) → the handler.

`auth.Authenticate` reads an `Authorization: Bearer <jwt>` admin token and verifies it against
the configured HMAC secret: a valid token means `RoleAdmin` (with the admin wallet address as
the request principal), anything else falls through to `RoleReadOnly` so public reads keep
working unauthenticated. `RequireRole` is what actually rejects; `Authenticate` never does.

The admin gets that token by proving control of the configured `security.admin_pubkey` wallet:
`POST /auth/challenge` returns a single-use nonce message, `POST /auth/session` verifies the
Solana Wallet-Standard `signMessage` signature and — only if the signer equals
`security.admin_pubkey` — issues the HMAC JWT. Both steps are public by necessity (this *is* the
login) and carry their own strict per-IP limiter on top of the global one. There is no `DELETE`:
the JWT is stateless, so logout is client-side. V1 is single-admin — one wallet, one role, no
operator tier.

Investors never touch that path. `POST /api/v1/compliance/challenge/verify` mints a narrow,
subject-scoped wallet session presented as `X-Wallet-Session`, which gates exactly one route
(`GET /api/v1/me/wallet-status`) to the address that proved ownership. It is a separate
mechanism from the admin JWT, not a weaker role within it.

Every state-changing endpoint honors `Idempotency-Key`: a byte-identical retry under the same
key replays the original response; the same key with a different body is a 409 conflict; a
reservation that's still in flight (concurrent identical request) is also a 409, not a second
execution — see [Security posture](#security-posture) for why this is atomic, not just "usually
works." All errors use the stable `{code, message}` shape from `internal/api/errors.go`.

`GET /healthz`/`GET /readyz` and every route under `/api/v1/**` are registered explicitly; any
other path falls through to `internal/webui`'s SPA handler (or, under `/api/`, a plain JSON 404
— it never falls through to the SPA).

## Compliance hot key

**Compliance is the only server hot key.** Nothing else on this server signs: every program/mint
address is provisioned independently, the auditor-signed mint, treasury withdrawals,
funding/rejecting a redemption, pausing, price updates and role changes are all broadcast from
the admin's own connected wallet (or multisig), and every investor action from the investor's.
There is no relayer, pricer, or deployer key.

The compliance key is a raw ed25519 keypair (`security.compliance_key` — either an inline base58
64-byte secret key, or a filesystem path to a Solana CLI-style keypair JSON file). It does not go
through a pluggable key-provider abstraction (no keystore/Vault/KMS backend yet — a deliberate V1
simplification, see `cmd/platform`'s `loadSolanaComplianceKey` doc comment); production refuses
the inline form unless `production_overrides.allow_plaintext_compliance_key` is explicitly
set, since it keeps key material directly in the plaintext config file. The key's in-memory bytes
are zeroed at process shutdown (best-effort, not a hard guarantee against GC/stack copies).

**Operational constraint**: run exactly one `platform` process per configured compliance key —
there is no distributed nonce/lease coordination for it (unlike a block-height chain's
transaction manager), so two replicas sharing the same key could race a `set_status` submission.

## Configuration (the `--config` YAML file)

Every binary here — `platform`, `opsctl`, `reindex` — takes exactly one `--config <path>` flag
pointing at a single YAML file. There are no environment variables and no flags for individual
settings:

```bash
./bin/platform --config /etc/rwa/config.yaml
./bin/opsctl   --config /etc/rwa/config.yaml ipfs retry --id=<id> --file=<path>
```

`server/config.example.yaml` is the annotated reference copy — every key, its default, and what
it does. Read that file, not this table, when you're actually writing a config.

**Secrets live in this file too** (the compliance hot key, the KYC webhook HMAC secret, the admin
JWT signing key). That's a deliberate, accepted posture: treat it exactly like a
`.env` or a supervisor config — `chmod 600`, owned by the service user, out of version control.

`config.LoadFile` reads and decodes the YAML with `KnownFields(true)`, so an unknown or misspelled
key is a startup **error**, never a silent fall back to a default. It then flattens the document
into a flat key/value view and hands it to `load`, the pure, I/O-free engine that resolves defaults
and runs every validation — the same engine `LoadFromMap` exposes to the table-driven config tests,
so what CI validates is byte-for-byte what production runs. Every numeric/duration value that
fails to parse is a startup error too. Numeric and boolean keys are pointer-typed in the schema so
"omitted" stays distinguishable from "explicitly 0/false": an omitted key takes its default, an
explicit `0` is honored (and, in production, rejected where a zero would disable a control).

| Section | Keys | Notes |
|---|---|---|
| *(top level)* | `environment` (`development`) | `development` or `production`. `production` enables the fail-closed startup checks — see [Production hardening](#production-hardening). |
| `http:` | `addr` (`:8080`), `metrics_addr` (`127.0.0.1:9090`), `read_header_timeout` (`5s`), `read_timeout` (`30s`), `write_timeout` (`60s`), `idle_timeout` (`120s`), `max_header_bytes` (32 KiB), `max_request_body_bytes` (2 MiB), `trusted_proxies` (`[]`), `cors_allowed_origins` (`[]`) | `addr` is the public API + embedded SPA listener; the timeouts and header cap apply to it *and* the metrics listener (slowloris hardening). `max_request_body_bytes: 0` disables the limit; empty `trusted_proxies` trusts none — see [Security posture](#security-posture). `cors_allowed_origins` is empty by default (CORS off — the embedded console is same-origin); set it to the standalone investor SPA's exact origin(s), e.g. `["http://localhost:5173"]`. `"*"`, a trailing slash, or a missing scheme is refused at startup in every environment. |
| `contract:` | `project_id`, `programs.*` (compliance/vault/pricing/transfer_hook/redemption/supply_controller — all required, base58), `rwa_mint`, `rwa_decimals` (required), `quote_mint`, `quote_decimals`, `redemption_timeout` (`1209600`s, bounded to [1 day, 365 days]), `supply_config`, `vault_config` (mint-attestation domain inputs, required, base58, sourced from the bootstrap deployment manifest — never derive them in Go) | What was deployed: `project_id` is the UUID this deployment is pinned to (the admin SPA reads it from `GET /api/v1/config` and the server rejects any profile whose `projectId` differs). There is no on-chain factory: every program/mint address is provisioned independently and lives here. |
| `chain:` | `rpc_url`, `commitment` (`finalized`), `chain_id`, `start_slot` (`0`), `cluster_genesis` (mint-attestation domain input, required, base58, sourced from the bootstrap deployment manifest), `max_checkpoint_age` (`5m`) | How the server reaches and follows the chain. `rpc_url` is the server's OWN backend RPC (never surfaced to the browser — the SPA's endpoint is a build-time-only value). `commitment` must be `finalized` in production unless overridden — the indexer has no reorg handling, so correctness rests entirely on it. |
| `mongo:` | `uri` (`mongodb://127.0.0.1:27017`), `db` (`rwa_platform`), `persistence_mode` (`mongo`) | `memory` is an explicit dev/CI opt-in, refused in production. A `mongo`-mode connect/ping/index failure falls back to in-memory repositories with a loud warning in development, but is fatal at startup in production. |
| `ipfs:` | `api_url` (`http://127.0.0.1:5001`), `backup_archive_dir`, `backup_kubo_url`, `replication_threshold` (`1`) | With no backup destination configured the platform falls back to a single local Kubo node with no replication tracking; production requires at least one independent destination and `1 <= threshold <= destination count`. |
| `security:` | `kyc_webhook_hmac_secret`, `jwt_secret`, `jwt_ttl` (`24h`), `idempotency_ttl` (`24h`), `wallet_challenge_ttl` (`15m`), `wallet_session_ttl` (`15m`), `rate_limit_rps` (`50`), `rate_limit_burst` (`100`), `admin_pubkey`, `compliance_key` | Every identity and secret the server carries. `admin_pubkey` is the single admin wallet the JWT login authenticates against, `jwt_secret` the HMAC key that signs those tokens — production requires both. The webhook secret empty means the webhook feature is disabled entirely; set-but-under-32-bytes fails startup in any environment. `rate_limit_rps <= 0` disables per-IP rate limiting. |
| `alerts:` | `pending_redemption_sla` (`48h`), `funded_claim_failure_sla` (`24h`) | Thresholds for the evaluators in [Observability](#observability). |
| `production_overrides:` | `allow_unbounded_request_body`, `allow_disabled_rate_limit`, `allow_weak_commitment`, `allow_unverified_supply_config`, `allow_plaintext_compliance_key` (all `false`) | Narrowly-named emergency escape hatches for the production fail-closed checks. Nothing else has an override. |

## Production hardening

`environment: production` turns several otherwise-permissive defaults fail-closed at config load,
so a misconfiguration is a refused startup rather than a quietly weakened guarantee:

- `security.kyc_webhook_hmac_secret` must be set — an empty secret makes webhook HMAC
  verification a publicly-computable no-op, and a forged KYC decision is one the compliance hot
  key relays on-chain. It must also be at least 32 bytes and not a known placeholder.
- `security.admin_pubkey` and `security.jwt_secret` must both be set (same 32-byte and
  placeholder rules for the secret) — otherwise no admin JWT could be issued or verified and the
  admin routes would have nothing to authenticate against.
- `security.compliance_key`, if configured, must not be an inline base58 secret unless
  `production_overrides.allow_plaintext_compliance_key` is set — that form keeps the
  private key in plaintext in this file; a keypair-file path is required instead.
- `chain.commitment` must be `finalized` unless `production_overrides.allow_weak_commitment`
  is set — the indexer has no reorg handling, so correctness rests entirely on it.
- `mongo.persistence_mode` must be `mongo`, and a Mongo connect/ping/index failure at startup is
  fatal rather than a silent fall back to volatile in-memory repositories that still reports
  `/readyz` healthy.
- `contract.project_id` must be set — it fixes which Asset Profile this deployment will ever
  accept, before anything is created. Unset, the first caller would choose it.
- `ipfs.api_url` requires at least one backup destination, so mint evidence isn't sitting on a
  single unreplicated node.
- Every security duration and the header cap must be positive — a non-positive value there is
  never a legitimate choice, only ever a mistake, so none of them has an override. The two
  genuinely "disabled control" checks (request-body limit, rate limit) each do, under
  `production_overrides:`.
- The boot-time cross-check against the on-chain `rwa-supply-controller` Config account (owner,
  Anchor discriminator, vault/admin/token_mint/cluster fields) must pass unless
  `production_overrides.allow_unverified_supply_config` is set — otherwise this instance
  would seed the project Active with an attestation domain that cannot be trusted to match what
  the on-chain program reconstructs.

`/readyz` itself also checks a live Mongo ping (when a persistent backend is in use) and the
Solana RPC's cluster identity (genesis hash) and compliance-program indexer poll heartbeat, not
just bare RPC connectivity, and a background ticker degrades `rwa_storage_up` / fires a
`storage_degraded` alert on ping failure after startup.

## Dependency baseline

A `govulncheck` run flagged 13 Go-stdlib advisories (toolchain 1.25.7). Remediated: `go.mod`'s `go`
directive is now `1.25.12`. `govulncheck ./...` now reports **0 vulnerabilities affecting this
module's code**.

One remaining advisory (`GO-2026-5932`, `golang.org/x/crypto/openpgp` — unmaintained package, no
fix available) is a **documented reachability exception**: `go mod why golang.org/x/crypto/openpgp`
confirms `github.com/rwa-platform/server` does not need that package at all (a transitive
dependency of some other module in the graph imports it; this server never does), and
`govulncheck` itself confirms the code doesn't call it. Re-run `govulncheck ./...` at release time
regardless — this is a point-in-time snapshot.

## Observability

**Structured request logging**: every HTTP request is tagged with a request id, method, path
template, status, and latency via the metrics middleware and Gin's own logger; see
`internal/metrics.GinMiddleware`.

**`/metrics`** is served on its **own** listener (`http.metrics_addr`, default `127.0.0.1:9090`) —
deliberately not a route on the public API port, so it's an operational surface for Prometheus
scraping, not something reachable by arbitrary API callers. Exposes standard Go runtime metrics
plus:

- `rwa_http_requests_total{method,path,status}` / `rwa_http_request_duration_seconds{method,path}`
  — `path` is the registered route *template* (`/api/v1/redemptions/:id`), never the raw URL, so
  cardinality stays bounded regardless of how many distinct redemption ids get requested.
- `rwa_sales_inventory_tokens` — best-effort; the Solana sales service has no server-held chain
  client to read live inventory from, so this stays at its previous value.
- `rwa_redemptions_pending_count` / `rwa_redemptions_pending_oldest_age_seconds` /
  `rwa_redemptions_funded_unclaimed_count`.
- `rwa_alerts_fired_total{kind}` — incremented by the alert evaluators below, per finding, per tick.

**Alert evaluators** (`internal/alerts`, pure functions — tested against fake
`models.RedemptionRequest` slices, no I/O): `EvaluatePendingRedemptionSLA` flags any `Pending`
redemption older than `alerts.pending_redemption_sla`; `EvaluateFundedClaimFailure` flags any
`Funded` redemption that hasn't reached `Completed` within `alerts.funded_claim_failure_sla` of
its last state change. `cmd/platform` runs both on a 5-minute ticker; every finding is logged,
appended to the audit log (`category: "alerts"`, visible via `GET /api/v1/audit-logs`), and
counted in `rwa_alerts_fired_total`.

## Backup, restore, and reindex

`server/ops/backup.sh` — `mongodump` of the platform database plus an IPFS pin export (every
currently-pinned CID, as a portable `.car` archive via `ipfs dag export`) into one timestamped
directory. `server/ops/restore.sh` — the inverse (`mongorestore --drop` + `ipfs dag import`).

> **The chain is only a source of truth for as long as your RPC retains the address index.**
> `getSignaturesForAddress` is the *only* way the indexer discovers anything, and every node
> prunes that index — `solana-test-validator` defaults to `--limit-ledger-size 10000` shreds
> (minutes; the docker stack raises it), public endpoints keep days. Past that horizon the RPC
> returns an **empty array, not an error**, so the indexer reads it as "nothing new", every
> checkpoint sits at `lastBlock 0`, `chain_events` stays empty, and the read models silently
> never repopulate. `cmd/reindex` therefore refuses to run unless it can first prove the RPC
> still serves back to the oldest event it is about to delete (`--force` overrides, and the
> loss is permanent). `opsctl indexer probe` diagnoses the state directly, and the indexer
> itself now warns when it has polled successfully for minutes without ever ingesting anything.

**Chain reindex rehearsal** proves the platform's core claim — every event-derived read
model is fully reconstructable from the chain alone — by actually exercising
it. `cmd/reindex` drops only the collections that claim is about: `chain_events`,
`indexer_checkpoints` (reset per program), `purchases`, `redemption_requests` — never Asset
Profiles, investor ownership flags, or the audit log, since those aren't chain-derived.
`server/ops/reindex_rehearsal.sh` wraps it with a before/after collection-count comparison
against an already-running `platform` process (whose background reconcile loop does the actual
rebuilding — `cmd/reindex` only drops). `internal/indexer`'s
`TestReindexRehearsalReconstructsIdenticalReadModel` proves the same thing on a fully fake chain
(no live infra needed for `go test`).

## Build, test, and verify

```bash
go build ./...
go vet ./...
go test ./...              # none need a live Mongo/Solana RPC
go test ./... -race        # clean
```

Every workflow package is tested against `dal/memory`'s in-memory fakes and Solana RPC fakes —
no external services required. Concurrency-sensitive fixes (idempotency reservation, webhook
replay, wallet-challenge single-use) have dedicated goroutine-racing tests, run under `-race`.

## Security posture

- **Request-size limits**: `auth.MaxRequestBody` wraps every request body in
  `http.MaxBytesReader` (`http.max_request_body_bytes`, default 2 MiB). `internal/api/errors.go`'s
  `failErr` centrally detects `*http.MaxBytesError` and always reports `413`, regardless of what
  status the specific call site asked for — one fix covers every body-reading handler (raw
  `io.ReadAll` paths like `validateProfile`/the KYC webhook, and every `c.ShouldBindJSON` path)
  without each needing its own detection code. The KYC webhook's read (which happens before HMAC
  verification, since the signature covers the raw body) is explicitly covered so an oversized
  delivery never reaches HMAC computation.
- **Idempotency is atomic, not check-then-act**: `IdempotencyRepository.Reserve` is a genuine
  insert-or-fail (Mongo's automatic unique `_id` index + `InsertOne`, never `upsert`) — two
  concurrent identical requests can't both fall through and both execute the handler's side
  effect. A non-2xx outcome releases the reservation so a legitimately failed request stays
  retryable instead of getting stuck "in progress" forever. The KYC webhook's replay protection
  (`kyc_events.payloadHash`, now uniquely indexed) and the wallet-ownership challenge's
  single-use guarantee (`MarkUsed` is a conditional `used:false→true` compare-and-swap, not an
  unconditional set) follow the identical pattern.
- **Security headers**: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `Strict-Transport-Security`, and a strict
  `Content-Security-Policy` (`internal/auth.ContentSecurityPolicy` — the single source of truth;
  `internal/webui` reuses it directly rather than keeping its own copy) validated against the
  real production SPA build with wallet flows exercised, no `unsafe-inline`/`unsafe-eval`
  anywhere. `frame-ancestors 'none'` in the CSP is genuine clickjacking protection (browsers
  ignore that directive in a `<meta>` tag; it only works as a real response header, which this
  is). Applied router-wide **and** directly inside `internal/webui`'s SPA handler.
- **Trusted proxies**: `gin.Engine.SetTrustedProxies` is wired explicitly
  (`http.trusted_proxies`, default none) so `X-Forwarded-For` cannot be spoofed to reset the
  per-IP rate limiter's bucket unless you've explicitly configured a real reverse proxy's address.
- **No key material in logs**: the compliance hot key is never logged; only its *derived pubkey*
  and, where relevant, an explicit non-production warning are. Its in-memory bytes are zeroed on
  shutdown.
- **The server builds no transaction calldata at all**: not for investors
  (`buy`/`requestRedemption`/`claimRedemption`/`cancelRedemption`), and not for the admin
  (mint, fund/reject, treasury withdrawal, pause, price update, role change, admin transfer).
  Every one of those is encoded client-side by the SPA from the deployed program IDLs and signed
  by the caller's own wallet, with the program's own authority checks as the real authorization —
  so a compromised server cannot redirect a transfer or a mint, only lie about what it has
  observed. The one thing this server ever signs is `rwa-compliance::set_status`.
