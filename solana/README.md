# solana/ — Anchor programs

The on-chain half of the RWA token stack: an [Anchor](https://www.anchor-lang.com/)
workspace on **SPL Token-2022 + a transfer hook** for compliance enforcement.

## Program set (`programs/`)

| Program                 | Responsibility                                                                                                                                              |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `rwa-compliance`        | Per-wallet allowlist + KYC expiry, pinned system addresses, project-wide pause. Read by everything.                                                         |
| `rwa-transfer-hook`     | Token-2022 hook: rejects a transfer unless both owners are allowed; enforces pause with the escrow-only bypass. Mint/burn don't fire it, so they're exempt. |
| `rwa-supply-controller` | secp256k1 auditor-attestation verify + Token-2022 mint/burn to the Vault.                                                                                   |
| `rwa-pricing`           | Admin/pricer fixed purchase & redemption prices.                                                                                                            |
| `rwa-vault`             | Inventory, on-chain `buy`, `withdraw_proceeds`.                                                                                                             |
| `rwa-redemption`        | request → fund → {claim \| reject \| cancel} state machine.                                                                                                 |

There is no one-transaction deploy+wire step — Solana programs are
deployed once and instantiated as PDAs. The equivalent is the per-program
`initialize` instructions run in sequence at bootstrap (see the TS tests), which
end in the same wired state the factory asserts: mint authority = supply
controller PDA, Vault + Escrow pinned as compliance system addresses and allowed,
compliance authority set.

## Shared logic crates (`crates/`) — host-testable, and actually tested

The security- and money-critical *pure* logic lives in plain Rust crates with no
Solana dependency, so it runs under `cargo test` on any machine (no SBF toolchain
or validator needed) **and** is reused verbatim by the programs:

| Crate             | What it proves                                                                                                                                  |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `pricing-math`    | `mulDiv` purchase=Ceil / redemption=Floor, incl. the frozen `shared/vectors/arithmetic.json` parity vectors.                                    |
| `attestation`     | The Solana-bound EIP-712-style digest + `secp256k1_recover` → eth-address pipeline, incl. a sign→recover round-trip with the frozen test auditor key. |
| `compliance-core` | `is_allowed` (status + expiry boundary) and the system-address invariant.                                                                       |
| `redemption-core` | The state-machine transition guards + timeout boundary.                                                                                         |

```bash
# host tests of the four core crates only (no SBF toolchain / validator):
cargo test --locked -p pricing-math -p compliance-core -p redemption-core -p attestation
```

## Auditor attestations — same key, Solana-bound domain

Signatures stay **secp256k1 / ECDSA**, so the existing offline signer and auditor
key secure both chains. The digest keeps the EIP-712 shape
`keccak256(0x1901 ‖ domainSeparator ‖ hashStruct)` but binds the domain to a
Solana deployment instead of `(chainId, verifyingContract)`:

```
domainSeparator = keccak256(
    keccak256("SolanaSupplyAttestation(string name,string version,bytes32 cluster,bytes32 program,bytes32 config)")
    ‖ keccak256("RWA-Supply-Attestation-Solana") ‖ keccak256("1")
    ‖ cluster ‖ program ‖ config)
```

`cluster` = cluster genesis hash, `program` = supply-controller program id,
`config` = supply-controller config PDA. Every message field is ABI-word-encoded
to 32 bytes exactly as `abi.encode` (see `crates/attestation`). The signer only
needs this new message encoding — no new key type. The `rwa-supply-controller`
program verifies with the `secp256k1_recover` syscall and requires the recovered
eth address to equal the configured auditor.

## Building & testing the programs

The plain crates test anywhere. The **programs** need the Solana SBF toolchain
and a validator, which are *not* required for `cargo test`. The stack is
**Anchor 1.1.2 + Agave 4.x + Token-2022 v11** (v11 is required for the
permissioned-burn extension):

```bash
# one-time: install the toolchains (not needed for `cargo test`)
sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"    # Agave 4.x: solana + cargo-build-sbf
avm install 1.1.2 && avm use 1.1.2                                # anchor-cli

anchor keys sync     # regenerate real program ids (placeholders are committed)
anchor build         # cargo-build-sbf all programs (NOTE: use anchor build, not a
                     # bare cargo-build-sbf — its default arch is not deployable)
anchor test          # spins up solana-test-validator and runs tests/*.ts
```

`anchor test` needs a validator whose **on-chain Token-2022 supports permissioned
burn** (program v11+). The bundled test-validator Token-2022 does not, so for a
self-contained local run, build Token-2022 v11 from the crate source and inject it,
and deploy our programs over RPC (custom ports break the CLI's TPU client):

```bash
# build the v11 Token-2022 program once
cp -r ~/.cargo/registry/src/*/spl-token-2022-11.0.0 /tmp/tok22 && (cd /tmp/tok22 && cargo-build-sbf)

solana-test-validator --reset \
  --bpf-program TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb /tmp/tok22/target/deploy/spl_token_2022.so \
  --deactivate-feature B8JJXCy5amZyWG9r7EnUYLwzXSXTxG7GZ1qZ1qggo83g   # SIMD-0500 (else v0 deploy rejected)
# deploy all six: scripts/deploy.sh --url http://127.0.0.1:8899 --keypair <WALLET_KEYPAIR>
# then: ANCHOR_PROVIDER_URL=... ANCHOR_WALLET=... npx ts-mocha -p ./tsconfig.json tests/fullflow.ts
```

> The committed program ids in `Anchor.toml` / `declare_id!` are placeholders. Run
> `anchor keys sync` once on a machine with the toolchain to mint real keypairs.
> `Anchor.toml [toolchain]` is intentionally left empty (uses the toolchain on PATH).

The TS test/deploy tooling's `package.json` pins
`overrides: { "utf-8-validate": "5.0.10" }`. Do not drop it. Inside the
`@solana/web3.js` tree, `jayson`'s nested `ws@7` peer-depends on `^5.0.2` of that
optional native accelerator while `rpc-websockets` lists `^6.0.0`, and no single
hoisted version satisfies both. The tree installs anyway, but the invalid edge
makes `npm sbom` fail outright (`ESBOMPROBLEMS`) and makes npm 10 and npm 11
disagree on the lockfile, so `npm ci` breaks under whichever major did not write
it. `5.0.10` satisfies every consumer at once. This is off-chain tooling only —
nothing here ships in a program.

## Deployment process

A start-to-finish runbook for taking the stack from source to a live, wired
deployment on a public cluster (devnet or mainnet-beta). Steps 1–4 put the six program
binaries on-chain; step 5 fixes the Asset Profile the deployment permanently commits to;
step 7 (`scripts/bootstrap.mjs`) creates the token, initializes and wires every program,
and flips the deployment live; step 8 is the first auditor-signed mint. The section right
after this one, _Deploying to a public cluster_, has the background and the sharp edges
behind each step — read it once before a mainnet run.

What you need before you start:

- **A deployer keypair**, funded on the target cluster. It signs the program deploys and
  the whole bootstrap, and it's the programs' upgrade authority — which the final
  go-live step needs. You move that authority somewhere safer once the deployment is
  live (step 9).
- **The auditor key**, which lives in the offline Go signer (`signer/`) and never on
  this machine. You only put its 20-byte Ethereum-style address in the config; it signs
  the mint attestations out of band.
- **A quote mint** — an already-deployed stablecoin (USDC or similar) on the target
  cluster. Bootstrap doesn't create it; it only checks that its decimals match the config.
  On devnet/testnet there's nothing to point at, so make a throwaway one and fund your
  test wallets from it (see [A test quote token](#a-test-quote-token-devnettestnet-only)):

  ```bash
  npm run create-test-quote-mint -- --url <RPC_URL> --mint-to <WALLET>,<WALLET>
  ```

Paths in the config are resolved from wherever you run `node`, so run these commands
from the `solana/` directory.

### 1. Fix the program ids

Pick a deliberate keypair for each of the six programs, write their pubkeys into the
matching `declare_id!` and `Anchor.toml`, and build against those. Back the keypairs up
— on mainnet these addresses are permanent, and there's no changing them later.

```bash
solana-keygen new -o target/deploy/rwa_compliance-keypair.json
# …one per program, then set declare_id!/Anchor.toml to the six pubkeys
```

### 2. Build and record the hashes

```bash
anchor build                     # six programs → target/deploy/*.so
sha256sum target/deploy/*.so     # note these; they should match your CI build
```

### 3. Check the cluster first (free, read-only)

```bash
npm run verify-cluster -- --url <RPC_URL> --payer <DEPLOYER_PUBKEY>
```

This simulates only — it signs and spends nothing — and exits non-zero if the cluster
can't run the stack: its Token-2022 must support permissioned burn, and old program
formats must still be deployable. It also prints the genesis hash, the permanent cluster
fingerprint the programs bind to.

### 4. Deploy the six programs

Use a paid RPC endpoint; the public one rate-limits and rejects large program deploys.
`scripts/deploy.sh` loops the per-program deploy below over all six binaries, upgradeable
with the deployer as upgrade authority — go-live needs that authority:

```bash
scripts/deploy.sh --url <PAID_RPC_URL> --keypair <DEPLOYER_KEYPAIR> \
  --with-compute-unit-price <MICROLAMPORTS>
```

It preflights before spending: every `.so` and `<p>-keypair.json` present, each deploy
keypair matching the program id in `Anchor.toml` (a mismatch means the bytecode's own
`declare_id!` is not the address it lands on — it aborts), the RPC reachable, the payer's
balance against the rent a first-time deploy needs. A mainnet-beta genesis hash prompts for
a typed confirmation (`--yes` for CI). `--dry-run` prints the commands it would run,
`--programs rwa_vault,rwa_redemption` narrows to a subset (the same command upgrades an
already-deployed program), `--help` lists the rest.

Each program writes through a fixed buffer keypair
(`target/deploy/<p>-upgrade-buffer.json`), so the large ones are resumable: a deploy that
dies partway is retried — and a re-run of the script continues — into the same buffer
instead of leaving a rent-funded orphan behind. `solana program close --buffers` reclaims
any that are stranded. What the script runs per program:

```bash
solana program deploy target/deploy/<p>.so \
  --program-id target/deploy/<p>-keypair.json \
  --url <PAID_RPC_URL> --use-rpc \
  --keypair <DEPLOYER_KEYPAIR> \
  --upgrade-authority <DEPLOYER_KEYPAIR> \
  --with-compute-unit-price <MICROLAMPORTS> \
  --buffer target/deploy/<p>-upgrade-buffer.json
```

### 5. Author the Asset Profile and compute its digest

The bootstrap needs `profileDigest` — the SHA-256 of the RFC 8785 canonical form of this
deployment's Asset Profile — and it burns that value into the supply-controller at
`initialize`, permanently. So the profile has to exist **before** the bootstrap, which
means before there is a running server to author it in.

Write the profile JSON by hand (see `docs/spec/asset-profile.md` and
`shared/schemas/asset-profile.schema.json`), then compute its digest with the server's
`canonicalize` tool. That tool exists for exactly this: it runs the same
canonicalization the server does, so the digest you pin here is the one the server will
later derive from the same document.

```bash
cd ../server && go run ./cmd/canonicalize /path/to/asset-profile.json
# digest=0x…   <- this is profileDigest
# cid=bafkrei…
```

Keep that JSON file. After the platform is up you submit the **same bytes** to
`POST /api/v1/profile`, and the server checks that it hashes to the digest recorded
on-chain here — a mismatch is refused before anything is stored. Byte-for-byte is not
required (canonicalization normalizes key order and whitespace), but the content must be
identical: change one value and the digest changes with it.

> **Why not author it in the admin console first?** The Setup screen can only run once
> the server is up, and the server won't start until `contract.supply_config`,
> `contract.vault_config`, and `chain.cluster_genesis` are configured — values this
> bootstrap produces. Authoring offline here is what breaks that cycle. (The reverse
> order also works — see `docs/operator/operator-guide.md` §3 — but it needs a
> deliberately unverified first boot.)

### 6. Write the bootstrap config

```bash
cp scripts/bootstrap.config.example.json scripts/bootstrap.config.json
solana-keygen new -o scripts/bootstrap.rwa-mint.json   # becomes the RWA mint address
```

Fill in `scripts/bootstrap.config.json`:

- `rpcUrl` and `payerKeypair` (the deployer), and `rwaMintKeypair` (the file you just made)
- `quoteMint` with `quoteDecimals` (must match the on-chain mint), and `rwaDecimals`
- `purchasePrice` / `redemptionPrice` in quote base units, and `redemptionTimeout` in
  seconds (between one day and one year)
- `profileDigest` (32-byte hex) — the digest from step 5, not a value you invent here —
  and `auditorEth` (the offline signer's 20-byte address)
- every entry under `roles`: `admin` (the deployer / registry admin), plus
  `complianceAuthority`, `pauser`, `pricer`, `treasurer`, `redemptionManager`, `treasury`

### 7. Run the bootstrap

```bash
node scripts/bootstrap.mjs --config scripts/bootstrap.config.json
```

It creates the Token-2022 RWA mint (transfer hook + permissioned burn, mint authority
handed to the supply-controller PDA, hook made immutable), the four custody token
accounts, initializes all six programs, pins the vault and escrow as system addresses,
then prints the values that become permanent — cluster, mints, admin, profile digest,
timeout — and asks you to confirm before it finalizes. On success it writes
`deployment-manifest.json`.

The whole run is safe to repeat: each step is skipped if it's already done, so an
interrupted run just resumes. The system-address pinning stays editable until finalize,
so a mistyped vault/escrow/mint is correctable right up to go-live (pass the old record
and it's reset). Add `--yes` only when you want an unattended re-run with no prompt.

### 8. First mint

Minting is a separate step after go-live, not part of the bootstrap. Build the mint
attestation, sign it with the offline signer in `signer/`, and submit it to the
supply-controller `mint` instruction. All supply is minted to the Vault, never straight
to an investor.

### 9. Lock it down — only after finalize

Once the deployment is live, move the program upgrade authority to a hardware wallet or
multisig (or drop it entirely, accepting that this rules out future upgrades), and hand
the config `admin` role to that multisig with the two-step transfer. Do this only after
finalize — doing it earlier stops go-live from completing. Keep the manifest with the six
program ids and their hashes, the on-chain Token-2022 program hash, the genesis hash, and
the quote mint's freeze authority.

### 10. Confirm

Re-read the deployment against the cluster: the registry reads finalized, the mint
authority is the supply-controller PDA, the vault and escrow are pinned and allowed, and
the recorded hashes still match.

> Rehearse on devnet first. The steps are identical and the same checks pass there, so do
> a full devnet run before mainnet, where every permanent value and program id is one-way.

## A test quote token (devnet/testnet only)

Every priced flow — buy, redeem, fund, withdraw — moves the **quote** token, and the
bootstrap requires that mint to already exist. Mainnet has USDC; devnet doesn't, so
create a stand-in and fund the wallets you'll test with:

```bash
npm run create-test-quote-mint -- \
  --url https://api.devnet.solana.com \
  --mint-keypair ./test-quote-mint.json \
  --mint-to <INVESTOR_WALLET>,<TREASURY_WALLET> \
  --amount 250000
```

It prints the two config snippets to paste (`quoteMint`/`quoteDecimals` for
`bootstrap.config.json`, `contract.quote_mint`/`contract.quote_decimals` for the server)
and, with `--out <file>`, writes them as JSON.

- It's a **legacy SPL Token** mint with **6 decimals** and **no freeze authority** — the
  same shape as real USDC, and the case `validate_quote_mint` accepts unconditionally.
  (Token-2022 quote mints work too, but only with transfer-neutral extensions.)
- **Keep the mint keypair.** It's the mint authority; without it you can't top testers up.
  Passing `--mint-keypair` makes re-runs idempotent — an existing mint is reused and the
  recipients just get another `--amount`, so it doubles as a faucet.
- It **refuses to run on mainnet-beta**. This is an unbacked token minted from a laptop key.

Run it before step 6 so you have the mint address to put in the bootstrap config.

## Deploying to a public cluster (preconditions & gotchas)

The `--bpf-program` / `--deactivate-feature` flags in the local recipe above are
**test-validator scaffolding only** — they make the bundled validator behave like a
current public cluster. In production you don't inject Token-2022 or toggle features
(you can't: Token-2022 is Anza-maintained and you're not its upgrade authority).
Instead, the two things those flags stand in for become preconditions you verify on the
target cluster.

### Run the pre-deploy check first

```bash
npm run verify-cluster -- --url <RPC_URL> [--payer <FUNDED_PUBKEY>]
```

Read-only and free — it simulates, signing and spending nothing. It checks the two hard
gates below and exits non-zero on a blocker. As of this writing both **mainnet-beta** and
**devnet** pass (`✅ SUPPORTED` / `✅ INACTIVE`), so the stack is deployable to mainnet
today. Re-run it against your exact RPC at deploy time.

### Hard precondition — Token-2022 permissioned burn

The RWA mint carries the Token-2022 **PermissionedBurn** extension, so the target
cluster's on-chain Token-2022 program must support it (program **v11+**). If it doesn't,
the deployment **fails closed at bootstrap** — `validate_rwa_mint` rejects the mint, so
you find out before any asset exists, never after. There's no on-chain workaround you can
apply yourself; you'd have to deploy to a cluster that has it. (Present on mainnet-beta
and devnet today.)

### Hard precondition — SIMD-0500 must be inactive

SIMD-0500 (`B8JJXCy5…`) disables deployment of SBPF v0/v1/v2 programs. It's currently
**inactive on mainnet-beta, devnet, and testnet**, so the programs deploy as-built with
no flag. You can't deactivate features on a public cluster. Looking ahead: SIMD-0500 is a
staged deprecation and will activate eventually; once it does you can no longer deploy or
upgrade old-sBPF programs. Keep `anchor build` on current platform-tools so it emits a
supported sBPF version, and redeploy your (upgrade-authority-gated) programs before that
activation — otherwise a future patch couldn't ship.

### Use a dedicated/paid RPC — not the public endpoint

The programs are large (`rwa_redemption.so` ≈ 525 KB). `api.mainnet-beta.solana.com`
rate-limits (429s) and routinely rejects large program deploys. Deploy through a paid
RPC (Helius / Triton / QuickNode):

```bash
scripts/deploy.sh --url <PAID_RPC_URL> --keypair <DEPLOYER_KEYPAIR> \
  --with-compute-unit-price <MICROLAMPORTS>       # priority fee; helps land the deploy
# large deploys can fail partway — the script's fixed per-program buffer makes a
# retry (and a re-run) resume into it; see step 4 for the raw per-program command.
```

The RPC node is only a submission gateway — it doesn't change the runtime rules (the
cluster's validators enforce the feature set and Token-2022 version). "Which node"
affects only reliability; "which cluster" (mainnet vs devnet) is what governs the
preconditions above.

### Program keypairs are your permanent program ids

`anchor keys sync` rewrites `declare_id!`s to local deploy keypairs — that churn is a
local-test convenience. For a real deployment, choose deliberate program keypairs, set
`declare_id!` / `Anchor.toml` to their pubkeys once, build against those, and back the
keypairs up (on mainnet the addresses are permanent). Keep the **upgrade authority** in
hardware/multisig custody — it can upgrade every program, so decide the end state
deliberately: a named multisig with a threshold and timelock, or revocation with the
understanding that no future patch can ship.

### Finalize before revoking the upgrade authority or rotating the admin

Go-live is deployer-bound: the `set_finalized` CPI requires the *compliance* program's
upgrade authority to sign. So do the whole bootstrap — including `finalize` — **before**
revoking any upgrade authority or rotating the config admin. `set_system_addresses` is
re-runnable until `finalize`, so a mistyped permanent pin (vault / escrow /
supply-controller id / RWA mint) is correctable right up to go-live; after `finalize`
everything freezes.

### What to record in the deployment manifest

Capture these at go-live:

- **Program ids + sBPF build hashes.** The toolchain is pinned (`Anchor.toml [toolchain]`
  = anchor 1.1.2 / solana 4.1.1; CI installs the same) and CI records each program's
  `sha256`. Capture the six ids + hashes and re-check them against the cluster after deploy.
- **Token-2022 program hash** on the target cluster — `verify-cluster` prints its id/owner
  and the genesis hash; record both (the genesis hash is the `cluster` value that
  `initialize`/`finalize` bind to).
- **Quote mint's freeze authority.** `validate_quote_mint` deliberately allows a freeze
  authority because real stablecoins keep one — record it and accept it explicitly. There's
  no on-chain unwind of a `Funded` request whose quote leg can't settle: a frozen
  beneficiary quote account strands the position. Handle stranded positions off-chain per
  the runbook.
- **Beneficiary-not-allowed recovery.** `fund` / `reject` / `cancel` all require the
  beneficiary to be `Allowed`. If a KYC expiry strands an escrow, the recovery is one
  atomic tx: re-allow → `reject` → re-block (needs the compliance authority and redemption
  manager together).
- **Disclosed-attestation handling.** A landed-but-failed `mint` publishes a still-valid,
  replayable signature until its nonce is consumed. The destination pin means it can only
  ever land in the canonical inventory ATA, but consume the nonce (or keep `valid_until`
  short) regardless.
- **Bootstrap from the tool + a pinned environment.** Use `scripts/bootstrap.mjs` (the
  idempotent bootstrap that prints every permanent value for confirmation and emits the
  manifest), and sign the attestations and the `finalize` call with the offline Go signer
  (`signer/`, which supports the Solana encoding). Run from a known-good image and record
  its digest.

Two things worth calling out about `finalize` and system pins:

- **`finalize` proves the whole transfer mesh.** It requires `registry.rwa_mint == mint`
  and that the mint's transfer-hook `ExtraAccountMetaList` PDA exists, is hook-owned, and
  carries the canonical entries. So a deployment that finalizes can both mint and transfer
  — the "mint but can't move" launch-time DoS is closed at the gate. Don't revoke any
  upgrade authority until `finalize` has passed.
- **Corrected system pins are cleared atomically.** A corrective `set_system_addresses`
  resets any superseded vault/escrow record to `Unknown` (pass the old record for a pin you
  change). A few behaviours are deliberately left unhardened: `set_auditor` is immediate
  and single-signature, the pricer is unbounded, and attestations have no maximum TTL —
  hold the admin and pricer roles behind a threshold multisig to mitigate the first two.

## Verification status

- `crates/*` unit tests **run and pass** (`cargo test`); the `redemption-core` state
  machine is the frozen set `Pending → {Funded → Completed | Rejected | Cancelled}`
  (`docs/spec/redemption-state-machine.md`).
- `programs/*`: `anchor build` compiles all six to SBF with **zero stack-frame overflows**,
  under the pinned toolchain (anchor 1.1.2 / solana 4.1.1).
- `tests/*.ts` (Anchor 0.32 client) **run and pass end-to-end** against an Agave 4.1.1
  validator with Token-2022 v11 injected — **17 passing / 0 pending / 0 failing**. They
  cover the happy path (bootstrap → mint → buy → request/fund/claim → reject-restore →
  burn) plus the negatives: non-upgrade-authority init, double-finalize
  (`AlreadyFinalized`), a freeze-authority mint, a mutable-account receipt, a direct hook
  `Execute`, a direct holder burn, delegate rejection, a direct `set_finalized`, a mint to
  a non-canonical Vault-owned account, a malleable high-S signature, an early cancel
  rejected by the 1-day timeout plus a rent-reclaiming `close_request`, and — folded into
  the bootstrap flow — `finalize` rejecting a mis-pinned RWA mint and a wrong
  `ExtraAccountMetaList`, plus a corrective `set_system_addresses` clearing a superseded
  pin. The successful post-timeout cancel and the hook's escrow pause-bypass can't be
  real-time warped in the validator harness and are covered by `redemption-core::can_cancel`.
  Note: a local run may need `anchor keys sync` (which rewrites the placeholder
  `declare_id!`s to the local deploy keypairs); the supply-controller id is stored as
  Registry data precisely so it survives that.

## Security

The stack holds the platform's non-negotiable invariants, enforced on Solana's
account model. The main protections:

- **Minting is auditor-gated and Vault-only.** New supply exists only through the
  supply-controller, which verifies a secp256k1 auditor attestation (`secp256k1_recover`)
  bound to the cluster, program, and config, and mints to the Vault — never to an investor.
  Each attestation is single-shot (a nonce replay marker is consumed) and carries a
  `valid_until`.
- **Burns can't be self-served.** The RWA mint carries the Token-2022 **PermissionedBurn**
  extension with the supply-controller PDA as burn authority, so a plain holder `Burn` is
  rejected; every burn goes through the attested supply-controller ⇄ Vault handshake. This
  is why the target cluster needs Token-2022 v11+.
- **Transfers are compliance-gated.** The Token-2022 transfer hook rejects any transfer
  unless both owners are currently allowed, and enforces the project-wide pause with a
  single escrow-return bypass. Both token accounts must be `ImmutableOwner` and the transfer
  authority must be the source owner itself — no delegates, no ownership handoff. The hook
  also checks the Token-2022 `transferring` flag to reject forged direct `Execute` calls,
  and confirms the mint is the one pinned on the registry.
- **Custody accounts are pinned to canonical ATAs.** The mint path doesn't run the hook, so
  every PDA-owned custody account (Vault inventory/quote, escrow RWA/quote, the
  returned-inventory target) is pinned to `ATA(authority, mint)`. That closes the
  redirect-to-shadow-account class: a leaked or front-run attestation can only ever land in
  the canonical inventory account.
- **Go-live is a single, verified gate.** Nothing mints, burns, buys, or redeems until
  `finalize` flips the global `Registry.finalized` flag. `finalize` cross-checks the whole
  cross-program wiring against the canonical sibling PDAs — including `registry.rwa_mint`
  and the mint's transfer-hook `ExtraAccountMetaList` — so a deployment that finalizes can
  both mint and transfer. It's deployer-bound (the `set_finalized` CPI must be signed by the
  compliance program's upgrade authority) and can only be flipped by `finalize`.
- **Redemption is a strict state machine.** `Pending → {Funded → Completed | Rejected |
  Cancelled}`; a funded quote is never withdrawable and pays only the recorded beneficiary.
  `fund` / `reject` / `cancel` require the beneficiary to be allowed, the timeout is bounded
  to [1 day, 365 days], and terminal requests can reclaim their rent via `close_request`.
- **Signatures and encoding.** Attestations are secp256k1/ECDSA with the EIP-712-shaped,
  Solana-bound digest above; malleable high-S signatures are rejected, and duplicate-TLV
  metadata is rejected.
- **Supply chain.** Every crate is a workspace member built `--locked` with a committed
  `Cargo.lock`; `solana/` commits a `package-lock.json` used via `npm ci`; the build
  toolchain is pinned and CI records each program's sBPF `sha256`.

A few behaviours are deliberately left unhardened rather than tightened further:
`set_auditor` is immediate and single-signature, the pricer can set any non-zero price, and
attestations have only a `valid_until` floor (no maximum TTL). Hold the admin and pricer
roles behind a threshold multisig to mitigate the first two. There's no on-chain unwind of a
`Funded` redemption whose quote leg can't settle (a frozen beneficiary quote account strands
it) — handle those off-chain per the runbook.
