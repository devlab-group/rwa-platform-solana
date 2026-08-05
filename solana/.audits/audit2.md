# Solana Programs Security Review — Audit 2

**Date:** 2026-07-30  
**Scope:** `solana/programs/*`, the security-critical logic in `solana/crates/*`,
the Solana test suite, and Solana-specific build/bootstrap configuration  
**Method:** Manual review of every instruction handler and Anchor account
context; cross-program PDA and authority tracing; Token-2022 transfer, burn,
freeze, account-authority, and extension analysis; attestation/replay review;
pricing and escrow accounting review; and targeted host build/test/lint checks.

## Executive summary

The programs contain strong controls around authenticated singleton
initialization, attestation replay protection, exact token balance deltas,
canonical compliance-record derivation, pricing arithmetic, and redemption
state transitions. The fixes described in `audit1.md` are present.

The deployment is nevertheless **not ready for production**. Two native
Token-2022 capabilities bypass assumptions inherited from the Solidity token:

1. Any RWA token-account owner or approved delegate can call Token-2022
   `Burn`/`BurnChecked` directly. This bypasses the auditor attestation,
   supply-controller replay markers, Vault-only source restriction, and project
   pause.
2. The programs accept mutable, non-ATA token accounts and the transfer hook
   ignores the transfer authority. An allowed owner can therefore transfer
   control of a funded token account with `SetAuthority`, or approve an
   unallowed delegate to operate it, without the intended actor being checked by
   the compliance hook.

Both are protocol-design issues rather than ordinary Anchor constraint bugs.
They require changes to the accepted mint/account extensions and integration
tests, not merely off-chain policy.

### Finding summary

| ID   | Severity      | Finding                                                                                        |
| ---- | ------------- | ---------------------------------------------------------------------------------------------- |
| H-01 | High          | Native Token-2022 burns bypass auditor authorization, pause, and the Vault-only burn invariant |
| H-02 | High          | Mutable token-account ownership and unchecked delegates bypass per-wallet compliance           |
| M-01 | Medium        | RWA mint validation permits an independent freeze authority and unsupported extensions         |
| M-02 | Medium        | Cross-program bootstrap wiring is trusted but never canonically validated or finalized         |
| L-01 | Low           | Attestation cluster binding is an unvalidated operator-supplied value                          |
| L-02 | Low           | JavaScript dependencies and deployment tests have no lockfile                                  |
| I-01 | Informational | The hook does not prove that `Execute` came from an active Token-2022 transfer                 |
| I-02 | Informational | SBF integration tests are not PR-blocking and omit native-token escape-hatch cases             |

No Critical-severity issue was identified. High-severity findings H-01 and H-02
should be fixed before minting production assets.

## Severity definitions

- **Critical:** Direct compromise of the complete deployment, unrestricted
  theft, or loss of the core trust model with little or no precondition.
- **High:** Complete bypass of a primary security invariant, material asset
  control violation, or system-wide integrity failure.
- **Medium:** Material availability, governance, or asset-accounting impact
  requiring a privileged-key condition or deployment/configuration error.
- **Low:** Defense-in-depth, replay-domain, reproducibility, or operational
  hardening issue with limited direct impact.
- **Informational:** Testing or maintainability weakness without a demonstrated
  present exploit.

---

## H-01 — Native Token-2022 burns bypass auditor authorization, pause, and the Vault-only burn invariant

**Severity:** High

### Evidence

The intended burn path verifies an auditor signature, pause state, nonce,
operation ID, amount, and Vault inventory before the supply controller CPIs to
the Vault:

- `programs/rwa-supply-controller/src/lib.rs:140-197`
- `programs/rwa-supply-controller/src/lib.rs:345-372`
- `programs/rwa-vault/src/lib.rs:70-100`

The architecture requires that only the controller can burn, every supply
operation has a valid auditor signature, and burn always debits Vault inventory.
However, the RWA is a standard Token-2022 mint pinned to
`spl-token-2022 3.0.5`:

- `Cargo.lock:2387-2409`
- `programs/rwa-transfer-hook/src/lib.rs:179-223`

Token-2022's standard `Burn` and `BurnChecked` instructions authorize the source
token-account owner or delegate. They do not require the mint authority, do not
invoke a transfer hook, and do not know about this supply-controller program.
Consequently, any holder can submit a burn directly to the canonical
Token-2022 program.

The current mint validator checks for the expected transfer hook and rejects
transfer-fee/permanent-delegate extensions, but the pinned Token-2022 version
does not have or require a permissioned-burn extension. The transfer hook cannot
repair this because burns deliberately do not execute it.

This behavior is also documented by Solana: token-account owners and delegates
may burn, including for non-transferable tokens. Current Token-2022 releases
provide a `PermissionedBurn` extension specifically to require a configured
burn authority to co-sign burns:

- <https://solana.com/docs/tokens/basics>
- <https://solana.com/docs/tokens/extensions/permissioned-burn>
- <https://github.com/solana-program/token-2022/releases>

### Impact

An investor or delegate can reduce the mint's total supply without:

- an auditor-approved `BurnAttestation`;
- consuming a nonce or operation marker;
- returning the tokens to Vault inventory;
- respecting the project pause; or
- emitting the application's `Burned` event.

This breaks supply-to-backing reconciliation and the asserted property that
every supply operation is current, unique, and auditor-approved. A holder cannot
burn another holder's balance, so this is not an unrestricted theft primitive,
but it is a complete bypass of the supply-governance invariant.

### Recommendation

Upgrade the Token-2022 program/client integration to a release that supports the
`PermissionedBurnConfig` mint extension, after verifying that the extension is
active on every target cluster.

Initialize the mint with:

1. the supply-controller config PDA as permissioned-burn authority;
2. an immutable or governance-controlled permissioned-burn update policy; and
3. the existing supply-controller config PDA as mint authority.

Update `validate_rwa_mint` to require the permissioned-burn extension and its
exact authority. Update the supply-controller → Vault handshake to invoke the
permissioned burn instruction with both required PDA signers: Vault config as
the token-account owner and supply-controller config as burn co-signer.

If the target Token-2022 deployment cannot support permissioned burns, the
project must either use a bespoke token/custody architecture or explicitly
weaken and redesign the audited-supply invariant. A transfer hook alone cannot
enforce this property.

Add validator tests proving:

- direct holder `Burn` and `BurnChecked` fail;
- an approved delegate cannot burn directly;
- standard burn fails while permissioned burn succeeds through the controller;
- wrong burn authority, wrong Vault source, replayed nonce, and pause all fail;
- only the attested amount changes both Vault balance and mint supply.

---

## H-02 — Mutable token-account ownership and unchecked delegates bypass per-wallet compliance

**Severity:** High

### Evidence

Compliance is evaluated against the `owner` fields of the source and destination
token accounts:

- `programs/rwa-transfer-hook/src/lib.rs:72-99`

The hook receives the actual transfer authority at Execute account index 3, but
explicitly leaves it unchecked and never compares it with the source owner:

- `programs/rwa-transfer-hook/src/lib.rs:275-294`

The Vault and redemption programs accept any Token-2022 token account with the
right mint/authority. They do not require a canonical associated token account
or parse the token account for `ImmutableOwner`:

- `programs/rwa-vault/src/lib.rs:374-382`
- `programs/rwa-redemption/src/lib.rs:603-606`
- `programs/rwa-redemption/src/lib.rs:654-660`
- `programs/rwa-redemption/src/lib.rs:681-686`
- `programs/rwa-redemption/src/lib.rs:711-720`

Token-2022 permits a normal token account's `AccountOwner` authority to be
changed with `SetAuthority` unless that account was initialized with the
`ImmutableOwner` extension. It also permits an owner to approve a delegate that
may transfer or burn up to its allowance. These instructions do not execute the
RWA transfer hook.

Although the integration test uses associated token accounts, which Token-2022
creates with immutable ownership, the on-chain constraints do not require ATAs:

- `tests/fullflow.ts:246-254`

Solana's Immutable Owner documentation confirms both that ordinary accounts
need the extension explicitly and that Token-2022 ATAs receive it by default:

- <https://solana.com/docs/tokens/extensions/immutable-owner>
- <https://solana.com/docs/tokens/basics>

### Exploit sequence

1. An allowed Alice creates a non-ATA Token-2022 account for the RWA mint,
   initialized without `ImmutableOwner`.
2. Alice buys or receives RWA into that account. The hook sees Alice as the
   allowed destination owner.
3. Alice calls Token-2022 `SetAuthority(AccountOwner)` and assigns the funded
   account to unallowed Bob. No transfer hook executes.
4. Bob now controls the funded RWA account despite never being an allowed
   recipient. Bob can also use the unauthorized native burn described in H-01.

Separately, Alice can approve Bob as a delegate. Bob may then initiate transfers
from Alice's allowed account to any allowed destination because the hook checks
Alice and the destination but ignores Bob, the actual transfer authority.

### Impact

Economic control of RWA can be handed to an unallowlisted key without a
compliant transfer. Unallowed delegates can also operate allowed accounts,
undermining a per-wallet KYC model if the transaction actor—not only the nominal
token-account owner—must be authorized.

After owner reassignment, the hook will stop Bob from transferring to another
account while Bob remains unallowed, but that does not undo the transfer of
control and does not prevent native burn.

### Recommendation

Enforce immutable RWA token-account ownership:

1. Parse both source and destination token accounts as Token-2022 extension
   accounts inside the hook.
2. Require `ImmutableOwner` on every non-system RWA token account, or require the
   canonical Token-2022 ATA for `(owner, mint)`.
3. Apply the same check to Vault and redemption custody accounts during
   bootstrap and every asset-moving instruction.
4. Reject receipt into a mutable token account so a user cannot fund one and
   mutate it later.

Also define the delegation policy explicitly. For the strictest per-wallet
model, require Execute's transfer-authority key to equal the source token
account's owner, thereby disallowing delegates. If delegates are required,
derive and load a compliance record for the transfer authority (base Execute
account index 3), add it to the extra-account-meta list, and require both the
source owner and authority to be allowed. Test multisig behavior separately.

Add adversarial validator tests for:

- receipt into a mutable non-ATA account;
- owner reassignment after receipt;
- an unallowed delegate transferring;
- an unallowed delegate burning;
- valid Token-2022 ATA transfers and any intended multisig flow.

---

## M-01 — RWA mint validation permits an independent freeze authority and unsupported extensions

**Severity:** Medium

### Evidence

`validate_rwa_mint` verifies Token-2022 ownership, the expected immutable hook
when requested, optional mint authority, and the absence of only two extensions:

- `programs/rwa-transfer-hook/src/lib.rs:171-223`

It does not inspect `state.base.freeze_authority`. It also uses a denylist that
rejects only `TransferFeeConfig` and `PermanentDelegate`; other mint extensions
remain accepted.

The test mint happens to set `freeze_authority = null`, but the on-chain
initializer does not enforce that property:

- `tests/fullflow.ts:174-198`

### Impact

A retained freeze authority exists outside the compliance registry's admin and
pauser roles. It can freeze Vault inventory, redemption escrow, or investor
token accounts directly through Token-2022, preventing transfers, burns,
delegate changes, cancellations, or claims. This can strand pooled assets and
bypass the documented role and pause/recovery model.

Other currently accepted extensions can make the product unusable or invalidate
operational assumptions. Examples include `NonTransferable`,
`DefaultAccountState(Frozen)`, mint-close authority, and confidential-balance
features that the application's accounting/indexing layer has not declared
support for.

### Recommendation

Prefer an allowlist over the current two-item extension denylist:

- require exactly the extensions the product supports, including
  `TransferHook` and, after H-01, `PermissionedBurn`;
- explicitly decide whether metadata pointer/group extensions are permitted;
- reject all other mint extensions until their instruction-level interaction is
  reviewed and tested.

Require `freeze_authority == None`. If an issuer freeze role is intentional,
require it to equal a documented governance PDA/multisig, include that role in
the incident-response model, and test Vault/escrow recovery under frozen states.
Validate these properties again in a finalization instruction, not only in
individual initializers.

---

## M-02 — Cross-program bootstrap wiring is trusted but never canonically validated or finalized

**Severity:** Medium

### Evidence

Singleton initialization is correctly gated by each program's upgrade authority,
but several permanent trust edges are accepted as raw pubkeys or unchecked
accounts:

- Supply controller stores an unchecked `vault_authority`:
  `programs/rwa-supply-controller/src/lib.rs:300-317`.
- Vault accepts an arbitrary `supply_controller` argument:
  `programs/rwa-vault/src/lib.rs:35-67`.
- Redemption accepts an arbitrary `vault_authority` argument:
  `programs/rwa-redemption/src/lib.rs:35-68`.
- Compliance pins unchecked Vault/Escrow account keys:
  `programs/rwa-compliance/src/lib.rs:277-309`.
- Vault and redemption initializers accept typed registry/strategy accounts but
  do not require their canonical external PDAs:
  `programs/rwa-vault/src/lib.rs:310-327` and
  `programs/rwa-redemption/src/lib.rs:536-553`.

There is no finalization instruction that cross-checks all stored values before
mint, buy, or redemption becomes live. Several immutable fields have no recovery
setter.

### Impact

A deployment typo or stale address can permanently split the singleton stack.
More dangerous examples include:

- a regular signer accidentally stored as `vault.supply_controller` can call
  `controller_burn` directly and make the Vault PDA burn inventory;
- an attacker-controlled key pinned as compliance escrow receives the
  escrow-only pause bypass;
- an incorrect supply `vault_authority` causes signed mint attestations to
  credit inventory controlled outside the intended Vault;
- mismatched registry, quote mint, or Vault addresses can strand redemption
  liabilities and proceeds.

These require a privileged bootstrap error rather than an unprivileged account
substitution, but the resulting singleton configuration is difficult or
impossible to repair without a program upgrade/redeployment.

### Recommendation

Add a separate, upgrade-authority/admin-gated `finalize` phase after all
singleton PDAs exist. It should:

1. derive the canonical config PDAs using the compiled program IDs;
2. deserialize each sibling config and cross-check registry, mint, quote mint,
   strategy, Vault, escrow, supply controller, and token decimals in both
   directions;
3. verify compliance's pinned addresses equal the canonical Vault and redemption
   config PDAs;
4. re-run the complete mint-extension/authority validation;
5. set an irreversible `finalized` flag; and
6. gate mint, buy, funding, redemption, and burn on that flag.

Where no cyclic initialization issue exists, replace raw arguments with
`address = canonical_pda` or typed accounts plus external `seeds::program`
constraints. Add one negative test for every cross-wire.

---

## L-01 — Attestation cluster binding is an unvalidated operator-supplied value

**Severity:** Low

### Evidence

The supply initializer stores an arbitrary `[u8; 32]` `cluster` argument:

- `programs/rwa-supply-controller/src/lib.rs:43-76`

The value is included in the attestation domain:

- `programs/rwa-supply-controller/src/lib.rs:246-255`
- `crates/attestation/src/lib.rs:70-90`

The test correctly base58-decodes the validator genesis hash, but the program
cannot prove that the submitted bytes are the current cluster's genesis hash:

- `tests/fullflow.ts:170-172`

### Impact

If operators deploy the same program IDs on multiple clusters and supply the
same wrong cluster value, an otherwise valid auditor signature can be replayed
once on each deployment. Per-deployment nonce markers do not prevent the first
cross-cluster use.

### Recommendation

Treat cluster identity as a deployment-ceremony invariant:

- use distinct supply-controller program IDs per production cluster where
  practical;
- have deployment tooling query and base58-decode `getGenesisHash`, compare it
  with an environment allowlist, pass it to initialize, then read back and
  independently recompute the domain separator;
- store the expected domain separator in a signed deployment manifest; and
- fail release qualification if the on-chain domain differs.

Add a test showing that an attestation for domain A fails under domain B.

---

## L-02 — JavaScript dependencies and deployment tests have no lockfile

**Severity:** Low

### Evidence

`solana/package.json` uses caret ranges for Anchor, SPL Token, and test tooling,
but `solana/` has no `package-lock.json`, `yarn.lock`, or `pnpm-lock.yaml`.

The scheduled integration job masks this by running:

```text
npm ci || npm install
```

- `.github/workflows/ci.yml:101-106`

During this review, `npm audit --omit=dev` failed with `ENOLOCK` because no
lockfile exists.

### Impact

The same commit can resolve different client and transitive dependency versions
over time. This weakens reproducibility of bootstrap transactions, hook account
resolution, program-ID synchronization, and validator tests. A compromised or
incompatible newly resolved package would run inside deployment/test tooling.

### Recommendation

Choose one package manager, generate and commit its lockfile, pin the package
manager version, and make CI use only the frozen/clean install command (`npm ci`,
`pnpm --frozen-lockfile`, or equivalent). Remove the fallback to an unlocked
install. Prefer exact direct dependency versions for deployment tooling and run
dependency advisory scanning against the committed lock.

---

## I-01 — The hook does not prove that `Execute` came from an active Token-2022 transfer

**Severity:** Informational

### Evidence

The fallback accepts a raw `Execute` payload and dispatches directly into the
Anchor handler:

- `programs/rwa-transfer-hook/src/lib.rs:102-117`

The handler validates records and policy but does not inspect the
`TransferHookAccount.transferring` flag:

- `programs/rwa-transfer-hook/src/lib.rs:72-99`

Solana's transfer-hook guidance recommends checking this flag at the start of
every hook:

- <https://solana.com/docs/tokens/extensions/transfer-hook>

### Impact

Anyone can invoke the hook directly with matching accounts. The present handler
is read-only and its success is not consumed as an authorization by another
program, so no current asset bypass was identified. The missing provenance check
becomes dangerous if later versions add counters, fees, approvals, or other
state changes.

### Recommendation

Parse the source token account as a Token-2022 extension account, load
`TransferHookAccount`, and require `transferring == true` before applying policy.
Add a test that direct `Execute` fails while a real Token-2022 transfer succeeds.

---

## I-02 — SBF integration tests are not PR-blocking and omit native-token escape-hatch cases

**Severity:** Informational

### Evidence

The pull-request job runs formatting and the four host-testable shared crates:

- `.github/workflows/ci.yml:69-81`

The SBF build and validator suite runs only weekly or on manual dispatch:

- `.github/workflows/ci.yml:83-106`

The integration suite covers the intended mint/buy/redeem/burn path, replay,
pause cancellation, and non-allowed recipients, but does not attempt:

- direct holder/delegate Token-2022 burn;
- mutable token-account owner reassignment;
- unallowed transfer delegates;
- retained freeze authority or unsupported mint extensions;
- cross-program miswiring; or
- a direct hook `Execute`.

During this review, the suite could not run locally because the installed Anchor
binary required `GLIBC_2.39`, which was unavailable.

### Impact

Changes to Anchor constraints, Token-2022 CPIs, hook resolution, or bootstrap
wiring can merge without execution against an SBF runtime. The missing negative
tests allowed H-01 and H-02 to remain outside the executable security model.

### Recommendation

Make SBF build plus the focused security integration suite a required PR check.
The complete economic flow may remain in a slower job, but PRs should block on:

- all initializer authorization/canonical-address negatives;
- direct native burn and account-authority/delegate negatives;
- transfer-hook resolution and direct-Execute provenance;
- pause behavior;
- attestation signature/replay/domain checks; and
- exact balance/supply deltas.

Pin a container/toolchain image with compatible Solana, Anchor, Rust, Node, and
glibc versions so local and CI execution match.

---

## Positive observations

The following controls were reviewed and found well designed:

- Every singleton initializer is gated to the canonical upgradeable-loader
  `ProgramData` and current upgrade authority.
- Mint attestations are deployment-domain-bound and include auditor, profile,
  record key, metadata digest, amount, nonce, validity, and Vault.
- Nonce markers are shared across mint and burn; record/operation markers add
  action-specific replay protection, and failed instructions roll marker
  creation back atomically.
- The RWA mint is required to be Token-2022 with the expected hook; transfer-fee
  and permanent-delegate mint extensions are rejected.
- Compliance record accounts are re-derived from wallet owners before use.
- System-address records are atomically initialized as permanently allowed and
  cannot later be blocked or expired through `set_status`.
- Buy and redemption paths use slippage/deadline controls, checked pricing, and
  exact destination balance deltas. RWA transfer paths also check exact deltas.
- Redemption requests are canonical ID-derived PDAs with guarded one-way status
  transitions.
- Privileged roles are rotatable, and admin transfer is a two-step handshake.
- Rust release overflow checks are enabled and the shared pricing code uses
  checked `u128` arithmetic with explicit `u64` bounds.

## Verification performed

The following commands were run from `solana/`:

| Command                                                                                    | Result                                                             |
| ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------ |
| `cargo test --locked -p pricing-math -p compliance-core -p redemption-core -p attestation` | Passed: 21 tests                                                   |
| `cargo check --locked --workspace`                                                         | Passed; Anchor 0.30.1 macro `unexpected_cfgs` warnings only        |
| `cargo clippy --locked --workspace --all-targets -- -A unexpected_cfgs`                    | Passed                                                             |
| `npm test -- --grep "attestation parity"`                                                  | Not run: installed Anchor binary requires unavailable `GLIBC_2.39` |
| `npm audit --omit=dev`                                                                     | Not run: no JavaScript lockfile                                    |
| `cargo audit --version`                                                                    | Not available in the environment                                   |

Host tests and `cargo check` do not execute SBF account privileges, Token-2022
runtime CPIs, or validator feature behavior. A production decision should remain
blocked until H-01/H-02 are fixed and the revised SBF suite passes on the exact
target-cluster Token-2022 version.
