# Solana Programs Security Review — Audit 1

**Date:** 2026-07-29  
**Scope:** `solana/programs/*`, `solana/crates/*`, `solana/tests/*`, and the Solana bootstrap/build configuration  
**Method:** Manual source review of instruction handlers, Anchor account constraints, PDA derivations, Token-2022 CPIs, transfer-hook resolution, attestation/replay logic, pricing arithmetic, redemption transitions, privileged roles, and bootstrap/test paths.

## Executive summary

The reviewed code has a sound core design in several areas: compliance records are re-derived before use, the supply attestations are deployment-bound and replay-protected, quote-token transfers use balance-delta checks, and the shared pricing/compliance/redemption/attestation logic is well unit-tested.

The deployment is nevertheless **not safe to launch in its current state**:

1. Any account can win the race to initialize the singleton configuration PDAs and take over or permanently misconfigure every program.
2. The transfer-hook extra-account-meta PDA is never allocated, so its initializer cannot succeed and compliant Token-2022 transfers cannot operate.
3. The programs do not enforce that the configured RWA mint is a Token-2022 mint using the expected transfer hook, so an unsafe bootstrap can entirely bypass the transfer compliance invariant.
4. The documented burn-delegate bootstrap cannot be performed because the Vault PDA owns the inventory account but exposes no instruction that can approve the supply-controller PDA.

These issues are reinforced by the fact that the Anchor integration test is not run in CI and currently contains bootstrap steps that cannot succeed.

### Finding summary

| ID | Severity | Finding |
| --- | --- | --- |
| C-01 | Critical | Permissionless singleton initialization permits deployment takeover |
| H-01 | High | Transfer-hook metadata PDA is never created or allocated |
| H-02 | High | RWA mint and transfer-hook security properties are not enforced |
| M-01 | Medium | Supply-controller burn authority cannot be bootstrapped |
| M-02 | Medium | RWA transfers do not verify exact balance deltas |
| M-03 | Medium | Pricing decimals are not bound to the configured RWA mint |
| M-04 | Medium | Most privileged roles cannot be rotated or revoked |
| L-01 | Low | Pinning system addresses does not make or verify them permanently allowed |
| L-02 | Low | The claimed cluster binding is operator-supplied and the test encodes it incorrectly |
| L-03 | Low | Program dependency resolution is not reproducible |
| I-01 | Informational | Program integration tests are neither run in CI nor complete |

## Severity definitions

- **Critical:** Direct compromise of the complete deployment or its core trust model.
- **High:** Complete bypass of a primary security invariant, or a blocker that makes the deployed system unusable.
- **Medium:** Material loss, insolvency, or security/availability impact requiring particular configuration or privileged-key conditions.
- **Low:** Defense-in-depth, recoverability, or configuration-hardening issue with limited direct impact.
- **Informational:** Testing, maintainability, or operational issue that increases the chance of future vulnerabilities.

---

## C-01 — Permissionless singleton initialization permits deployment takeover

**Severity:** Critical

### Evidence

Every stateful program creates a singleton PDA with `init`, paid for by an arbitrary signer, while accepting the actual admin and operational authorities as unconstrained instruction arguments:

- `programs/rwa-compliance/src/lib.rs:34-57`, `201-214`
- `programs/rwa-pricing/src/lib.rs:21-40`, `96-103`
- `programs/rwa-supply-controller/src/lib.rs:45-63`, `230-241`
- `programs/rwa-vault/src/lib.rs:34-52`, `202-213`
- `programs/rwa-redemption/src/lib.rs:35-58`, `387-398`

None of these initializers proves that the payer is the program upgrade authority, an expected deployment authority, or the supplied `admin`.

### Impact

As soon as a program is deployed, an observer can submit the first initialization transaction and:

- assign themselves as admin, pricer, compliance authority, pauser, treasurer, redemption manager, or auditor;
- bind the singleton to attacker-selected mints, registries, strategies, vaults, and cluster identifiers;
- permanently occupy the canonical PDA, causing every legitimate `init` to fail;
- take control of the single-tenant instance or force a program upgrade/redeployment before the platform can be used.

The risk is especially severe because several configured fields and roles have no setter or recovery path. Initializing five independent programs in sequence is not an atomic substitute for authorization.

### Recommendation

Authorize every singleton initializer. A standard Anchor approach is to require:

1. the current program account;
2. its canonical upgradeable-loader `ProgramData` account; and
3. a signer equal to `ProgramData.upgrade_authority_address`.

Alternatively, compile in a one-use bootstrap authority or use a separately authenticated deployment-controller program. Require the supplied initial admin to sign as well. Add adversarial tests proving an unrelated payer cannot initialize any singleton.

After bootstrap, transfer the upgrade authority and admin roles to the intended multisig or make the programs immutable according to the deployment policy.

---

## H-01 — Transfer-hook metadata PDA is never created or allocated

**Severity:** High

### Evidence

`initialize_extra_account_meta_list` immediately borrows the metadata account's data and passes it to `ExtraAccountMetaList::init`:

- `programs/rwa-transfer-hook/src/lib.rs:46-54`

The account context only marks the PDA as mutable and checks its seeds:

- `programs/rwa-transfer-hook/src/lib.rs:167-180`

It does **not** use `init`, allocate `ExtraAccountMetaList::size_of(4)` bytes, fund rent, or assign ownership to the hook program. The `payer` and `system_program` accounts are therefore unused. The integration test passes the as-yet nonexistent PDA directly:

- `tests/fullflow.ts:179-182`

An external client cannot pre-create this off-curve PDA because only the hook program can sign for its seeds. On an empty account buffer, the SPL TLV initializer cannot unpack or allocate the required list.

### Impact

The bootstrap instruction cannot successfully initialize the extra-account-meta list. Token-2022 cannot resolve the compliance registry and source/destination compliance records for hook execution, so RWA transfers—and therefore Vault purchases and redemption transfers—cannot operate.

### Recommendation

Create the PDA in the Anchor context:

```rust
#[account(
    init,
    payer = payer,
    space = ExtraAccountMetaList::size_of(4).unwrap(),
    seeds = [EXTRA_META_SEED, mint.key().as_ref()],
    bump
)]
pub extra_account_meta_list: UncheckedAccount<'info>,
```

If a fallible expression is undesirable in the account macro, define and test a constant for the exact serialized size, or create/allocate/assign the account with a system-program CPI signed by the PDA seeds. Add an integration assertion for the PDA owner, data length, and decoded four metadata entries before attempting any transfer.

---

## H-02 — RWA mint and transfer-hook security properties are not enforced

**Severity:** High

### Evidence

The supply controller, Vault, and redemption programs accept the RWA mint as `InterfaceAccount<Mint>`:

- `programs/rwa-supply-controller/src/lib.rs:231-237`
- `programs/rwa-vault/src/lib.rs:202-209`
- `programs/rwa-redemption/src/lib.rs:387-394`

This token interface accepts both legacy SPL Token and Token-2022 accounts. No initializer parses the mint extensions or verifies all of the following:

- the mint owner is specifically the Token-2022 program;
- the `TransferHook` extension exists;
- its program ID equals `rwa-transfer-hook`;
- the mint authority is the canonical supply-controller PDA;
- the transfer-hook update authority has the intended governance/immutability policy.

Vault and redemption consequently support a legacy SPL RWA transfer path through `invoke_transfer_checked` (`programs/rwa-vault/src/lib.rs:110-122`, `programs/rwa-redemption/src/lib.rs:326-349`). A legacy mint or Token-2022 mint without the expected hook transfers successfully without executing compliance.

The test bootstrap also leaves the transfer-hook update authority with the admin and never revokes it (`tests/fullflow.ts:137-146`).

### Impact

An incorrectly or maliciously initialized deployment can mint apparently valid RWA tokens while allowing holders to transfer them outside the allowlist and pause controls. That completely violates the primary invariant that every non-mint/non-burn transfer checks both wallet owners.

Retaining a mutable transfer-hook authority also lets that authority later replace or remove the expected hook at the mint layer, independently of the compliance program.

### Recommendation

During authenticated bootstrap:

1. require `rwa_mint.to_account_info().owner == spl_token_2022::ID`;
2. unpack `StateWithExtensions<Mint>`;
3. require a `TransferHook` extension whose program ID is `rwa_transfer_hook::ID`;
4. require the mint authority to be the canonical supply-controller config PDA;
5. reject unsupported extensions, especially transfer-fee or permanent-delegate configurations unless explicitly designed for them; and
6. revoke the hook update authority or assign it to the documented governance authority.

Store and cross-check the same mint across the supply, Vault, redemption, pricing, and compliance wiring. Add negative integration tests for a legacy SPL mint, a Token-2022 mint without a hook, and a mint pointing at the wrong hook.

---

## M-01 — Supply-controller burn authority cannot be bootstrapped

**Severity:** Medium

### Evidence

`burn_supply` assumes the supply config PDA is an approved delegate on the Vault inventory account and signs the burn as that delegate:

- `programs/rwa-supply-controller/src/lib.rs:148-160`

The inventory account is owned by the Vault config PDA (`programs/rwa-vault/src/lib.rs:231-232`). The Vault program exposes `buy`, `withdraw_proceeds`, and `set_treasury`, but no instruction that signs an SPL `Approve` CPI for its inventory account.

The integration test attempts to approve the delegate using `payer`:

- `tests/fullflow.ts:200-210`

That signature is not the token account authority—the authority is `vaultConfig`—so Token-2022 rejects the approval. The Vault PDA cannot sign an off-chain transaction.

### Impact

Auditor-authorized supply contraction is unusable. `burn_supply` will always fail unless authority was somehow established by code outside the reviewed deployment path. Returned Vault inventory can never be permanently burned, breaking the documented de-tokenization workflow.

### Recommendation

Prefer a narrowly scoped CPI handshake:

- the supply controller verifies the burn attestation;
- it CPIs into a Vault `controller_burn` instruction; and
- the Vault verifies the calling supply-controller PDA/program and signs the Token-2022 burn as inventory owner.

This avoids a standing unlimited delegate. If delegation is retained, add a Vault-admin bootstrap instruction that validates the canonical mint, inventory account, and supply config PDA, then signs `approve_checked` with Vault PDA seeds. Test approval, successful burn, replay failure, wrong-source failure, and delegation exhaustion/renewal.

---

## M-02 — RWA transfers do not verify exact balance deltas

**Severity:** Medium

### Evidence

`request_redemption` transfers `rwa_amount` and immediately records the full amount without reloading or comparing either token-account balance:

- `programs/rwa-redemption/src/lib.rs:84-107`

The reject, cancel, and claim RWA legs similarly assume the requested amount was received by the destination:

- `programs/rwa-redemption/src/lib.rs:166-175`
- `programs/rwa-redemption/src/lib.rs:203-212`
- `programs/rwa-redemption/src/lib.rs:227-240`

By contrast, quote-token legs explicitly compare before/after destination balances. The normative redemption specification says every transfer verifies the exact balance delta (`../docs/spec/redemption-state-machine.md:25-26`).

### Impact

If the configured Token-2022 RWA mint has transfer fees or another balance-affecting extension, a request can record a larger liability than escrow actually received. Cancel/reject/claim can then:

- return less than the promised amount;
- consume pooled RWA deposited for other requests;
- leave escrow insolvent; or
- fail indefinitely when the escrow balance no longer covers recorded liabilities.

The same issue means completed redemptions may re-shelve less inventory than recorded.

### Recommendation

The strongest fix is to reject all RWA mint extensions that can change transfer amounts, as recommended in H-02. Also add defense-in-depth balance checks around every RWA CPI:

- snapshot source and destination base amounts;
- execute the transfer;
- reload both accounts;
- use `checked_sub`;
- require exact source debit and destination credit equal to the recorded amount.

Keep request status changes atomic with these checks and add transfer-fee mint negative tests.

---

## M-03 — Pricing decimals are not bound to the configured RWA mint

**Severity:** Medium

### Evidence

The pricing strategy accepts an arbitrary `token_decimals` argument:

- `programs/rwa-pricing/src/lib.rs:21-39`

Vault and redemption store a strategy and RWA mint independently, but neither initializer requires:

```text
strategy.token_decimals == rwa_mint.decimals
```

- `programs/rwa-vault/src/lib.rs:202-209`
- `programs/rwa-redemption/src/lib.rs:387-394`

### Impact

A decimals mismatch changes purchase and redemption values by powers of ten. For example, pricing configured for 6 decimals against a 9-decimal mint overcharges or overpays by a factor of 1,000 depending on the direction of the mismatch. This can cause severe inventory or treasury loss even though the arithmetic itself is overflow-safe.

### Recommendation

Bind each strategy to a specific mint and derive/store `token_decimals` from that mint during authenticated initialization. At minimum, require equality in both Vault and redemption initializers. Add mismatch tests for both purchase and redemption and reject impractical decimal values for `u64` token amounts.

---

## M-04 — Most privileged roles cannot be rotated or revoked

**Severity:** Medium

### Evidence

The architecture states that single-holder roles use admin-controlled rotation, but only the compliance program implements a two-step admin transfer and operational-role setters.

Elsewhere:

- pricing stores `admin`, but no instruction ever uses it; only the immutable `pricer` can change prices (`programs/rwa-pricing/src/lib.rs:21-59`);
- supply admin can rotate the auditor but cannot rotate itself (`programs/rwa-supply-controller/src/lib.rs:167-175`, `294-299`);
- Vault admin can change only `treasury`, not `treasurer`, strategy, or admin (`programs/rwa-vault/src/lib.rs:161-165`, `272-277`);
- redemption stores `admin`, but exposes no admin instruction and cannot rotate treasurer, redemption manager, strategy, or admin (`programs/rwa-redemption/src/lib.rs:35-58`).

### Impact

Lost or compromised keys cannot be revoked through the intended governance plane. A compromised pricer can set an economically destructive price and combine the update with purchases before a pauser can respond. Lost treasury/redemption-manager keys can permanently disable operational paths. Recovery requires exercising the more powerful program upgrade authority.

### Recommendation

Implement consistent, event-emitting, two-step admin rotation in every program plus admin-authorized setters for each operational role and mutable dependency intended by the architecture. Reject zero addresses, consider pause requirements for sensitive changes, and test old-key/new-key behavior before and after rotation.

---

## L-01 — Pinning system addresses does not make or verify them permanently allowed

**Severity:** Low

### Evidence

`set_system_addresses` stores `vault` and `escrow` without loading their compliance records:

- `programs/rwa-compliance/src/lib.rs:63-75`

The invariant is enforced only on future `set_status` calls:

- `programs/rwa-compliance/src/lib.rs:80-104`

Therefore a system address may already have an `Unknown`, `Blocked`, or expiring record when pinned. A missing record also remains disallowed until a later transaction creates it. The integration test itself pins first and allowlists in separate transactions (`tests/fullflow.ts:184-190`).

### Impact

The deployment can enter a state that contradicts the accepted ADR-001 invariant and blocks Vault purchases, cancellations, or funded claims. A compromised compliance key can pre-block the deterministic system PDAs before they are pinned, extending its system-wide denial-of-service window.

### Recommendation

Make pinning and permanent allowlisting atomic. Pass the canonical Vault and escrow record PDAs to `set_system_addresses`, create them if needed, and set both to `Allowed` with `valid_until = 0`; or require and verify those exact values before setting `system_set`. Require `vault != escrow` and add pre-blocked/pre-expired regression tests.

---

## L-02 — The claimed cluster binding is operator-supplied and the test encodes it incorrectly

**Severity:** Low

### Evidence

The supply initializer accepts `cluster: [u8; 32]` directly from the caller and stores it without independent validation:

- `programs/rwa-supply-controller/src/lib.rs:45-63`

The attestation domain then trusts that stored value (`programs/rwa-supply-controller/src/lib.rs:181-186`).

The integration test takes the **UTF-8 bytes of the base58 genesis-hash string**, truncates/pads them, and calls that value the cluster hash:

- `tests/fullflow.ts:131-135`

That is not the 32-byte value represented by the base58 genesis hash.

### Impact

The domain is cluster-bound only if deployment tooling supplies the correct bytes. Reusing or mis-encoding the value can make the same signature valid on another cluster where the program ID and config PDA are the same, allowing cross-cluster replay before the destination chain's nonce marker exists.

### Recommendation

Decode the RPC genesis hash from base58 to exactly 32 bytes and include a frozen known-cluster vector. Because a program cannot safely infer this value from the current code path, bind initialization to the authenticated deployer, compare against a deployment-specific compiled constant or governed allowlist where feasible, and verify the stored domain off-chain before accepting any signature.

---

## L-03 — Program dependency resolution is not reproducible

**Severity:** Low

### Evidence

The root workspace excludes every Anchor program:

- `Cargo.toml:12-19`

The root `Cargo.lock` therefore covers only the four shared crates. Program-local lockfiles are ignored by `solana/.gitignore`, while manifests use compatible version ranges such as `"0.30.1"` and `"0.6.3"`.

The root release profile (`Cargo.toml:27-30`) also does not govern these excluded packages when they are built as standalone manifest workspaces, so its explicit `overflow-checks = true` policy is not reliably applied to the on-chain programs.

As observed during this review, checking the transfer-hook manifest resolved `spl-transfer-hook-interface` and `spl-tlv-account-resolution` to `0.6.5`, not the literal `0.6.3` written in the manifest.

### Impact

The audited dependency graph and build profile are not guaranteed to be the graph and compiler settings used for a later deployment. A compatible upstream release can change serialization, CPI behavior, or introduce a vulnerability without any repository diff; release arithmetic may also differ from the intended checked-overflow policy.

### Recommendation

Commit a lockfile that covers all six program builds, or commit one lockfile per excluded program. Pin especially sensitive Anchor/Solana/SPL dependencies exactly, e.g. `=0.6.5`, after confirming compatibility. Build deployment artifacts with `--locked` and record artifact hashes/SBOMs.

---

## I-01 — Program integration tests are neither run in CI nor complete

**Severity:** Informational

### Evidence

The normal Solana CI job runs only formatting and the four shared-crate tests:

- `../.github/workflows/ci.yml:69-80`

The scheduled Anchor job performs `anchor build` but not `anchor test`:

- `../.github/workflows/ci.yml:81-96`

The only full-flow test claims coverage for burn, timeout cancellation while paused, and not-allowed cases, but implements only bootstrap, mint/buy/request/fund/claim, and nonce replay:

- claim in `tests/fullflow.ts:1-4`
- implemented tests in `tests/fullflow.ts:153-312`

It also contains the nonfunctional extra-meta initialization from H-01 and invalid burn-delegate approval from M-01. No burn instruction is ever submitted.

### Impact

Program-level account wiring, CPI behavior, Token-2022 hook resolution, pause semantics, and authority setup can regress or remain completely broken while all required CI jobs pass.

### Recommendation

Run `anchor test` against a pinned validator in CI, at least on every change under `solana/`. Make the job blocking before release. Add tests for:

- unauthorized initialization races;
- metadata PDA creation and actual hook execution;
- every allowlist and pause branch;
- successful and replayed mint/burn;
- valid Vault-signed burn authority;
- fee-bearing/wrong-hook/legacy RWA mints;
- pricing-decimal mismatch;
- reject/cancel/claim races and timeout boundaries;
- role rotation and pre-blocked system addresses.

## Positive observations

- Compliance record PDAs are re-derived against the wallet/token-account owner before records are trusted.
- Registry and strategy accounts use Anchor ownership and PDA constraints in operational instructions.
- Mint/burn attestations bind the auditor, profile, operation data, amount, nonce, expiry, Vault, program, and config.
- Nonce plus record/operation marker PDAs provide shared replay protection and are transactionally rolled back on failure.
- Pricing uses `u128` intermediates, explicit rounding direction, and checked conversion to `u64`.
- Quote-token purchase, funding, withdrawal, and claim legs compare the received balance delta.
- Redemption status transitions are set before external CPIs but remain safe because Solana transaction failure rolls all account changes back.

## Verification performed

- `cargo test --locked` in `solana/`: **23 tests passed** across the four shared crates.
- Host `cargo check` succeeded for the transfer-hook, supply-controller, Vault, and redemption program manifests; these checks also compiled the compliance/pricing dependencies.
- `anchor test` and SBF execution were **not run** because the Solana CLI/SBF toolchain is unavailable in the review environment.

Host compilation and pure-logic tests do not validate Solana runtime ownership, signer, CPI, transfer-hook, or validator behavior. Findings H-01, M-01, and I-01 should therefore be resolved before relying on the current test status.
