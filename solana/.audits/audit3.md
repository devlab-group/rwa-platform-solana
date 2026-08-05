# Solana Programs Security Review — Audit 3

**Date:** 2026-07-31
**Scope:** `solana/programs/*` (all six Anchor programs), the security-critical logic in
`solana/crates/*`, the Anchor integration suite, and the Solana-specific
build/bootstrap/CI configuration
**Method:** Manual review of every instruction handler and `#[derive(Accounts)]` context;
cross-program PDA and authority tracing; Token-2022 extension, transfer, burn and
account-authority analysis (verified against the `spl-token-2022`/`spl-token-2022-interface`
sources the lockfile resolves, not from documentation); transfer-hook account-resolution
review; attestation digest and replay analysis; escrow and inventory accounting review; and
host build/test/lint/dependency-audit runs.

## Executive summary

The audit-1 and audit-2 remediations are present and are real fixes, not paper ones. Both
audit-2 High findings are closed at the protocol layer: the RWA mint carries the Token-2022
`PermissionedBurn` extension with the supply-controller PDA as burn authority, and the
transfer hook enforces `ImmutableOwner` on both token accounts plus a strict "transfer
authority must be the source owner" rule that eliminates delegates. I independently verified
the hand-rolled Token-2022 encodings this depends on — the extension type numbers, the
`PermissionedBurnExtension`/`BurnChecked` opcodes, the instruction data layout, the account
order, and the single-field `PermissionedBurnConfig` layout — against
`spl-token-2022-interface 3.1.1`. All five are correct.

The transfer path itself is now genuinely fail-closed. A missing extra-account-meta list, a
wrong token program, a legacy mint, an account without `ImmutableOwner`, a delegate, or a
forged direct `Execute` all revert rather than skip compliance.

**One High-severity issue was identified**, and it is not in the transfer path — it is in the
mint path, which the transfer hook does not protect. Token-2022 `MintTo` does not fire the
hook, the mint destination is constrained only by owner (not to the canonical ATA), and the
auditor attestation binds the Vault *authority* rather than the destination *account*. An
attestation that is front-run or recovered from a landed-but-failed transaction can therefore
be redirected into a Vault-owned account from which no transfer can ever succeed, permanently
consuming the record key so that asset record can never be tokenized again. No privilege is
required.

The remaining findings cluster in bootstrap and custody plumbing rather than token logic: the
go-live flag can be flipped directly by the compliance admin (and flipping it first
permanently bricks issuance), custody accounts are unpinned generally, and the quote mint is
never validated at all.

### Finding summary

| ID | Severity | Finding |
| --- | --- | --- |
| H-01 | High | A leaked or front-run mint attestation can be redirected into an unspendable Vault-owned account, permanently burning the record key |
| M-01 | Medium | The `finalized` go-live gate is bypassable by the compliance admin, and setting it first permanently disables mint and burn |
| M-02 | Medium | Vault and escrow custody token accounts are not pinned to canonical ATAs |
| M-03 | Medium | The quote mint is never validated for program, extensions, or authorities |
| L-01 | Low | The RWA token-program account is unconstrained; safety rests on a third-party crate's internal check |
| L-02 | Low | The `ExtraAccountMetaList` can never be updated or closed |
| L-03 | Low | Admin handshakes accept a zero pending admin, cannot be cancelled, and most role rotations emit no event |
| L-04 | Low | `set_strategy` accepts any pricing-program-owned account rather than the canonical Strategy PDA |
| L-05 | Low | `solana/`'s deployment tooling has open advisories and is excluded from the dependency-scan gate |
| L-06 | Low | `cancel_redemption` binds the payout account to the caller rather than to the recorded beneficiary |
| L-07 | Low | Nothing rejects `rwa_mint == quote_mint`, and two balance snapshots are taken across an unrelated CPI |
| I-01 | Informational | The SBF integration suite is still not PR-blocking, and the delegate negative test is skipped |
| I-02 | Informational | Token-2022 v11 on the target cluster is an unverified deployment precondition; a doc comment overstates `finalize`'s gating |

## Severity definitions

- **Critical:** Direct compromise of the complete deployment, unrestricted theft, or loss of
  the core trust model with little or no precondition.
- **High:** Complete bypass of a primary security invariant, material asset-control
  violation, or permanent, unprivileged destruction of protocol capability.
- **Medium:** Material availability, governance, or asset-accounting impact requiring a
  privileged-key condition, a deployment error, or attacker-funded griefing.
- **Low:** Defense-in-depth, recoverability, supply-chain, or operational hardening issue
  with limited direct impact.
- **Informational:** Testing or maintainability weakness with no demonstrated present
  exploit.

---

## H-01 — A leaked or front-run mint attestation can be redirected into an unspendable Vault-owned account, permanently burning the record key

**Severity:** High

### Evidence

`mint` has **no authority signer**. The only gate is the secp256k1 auditor signature, which is
an ordinary instruction argument; `payer` is a fee payer, nothing more:

- `programs/rwa-supply-controller/src/lib.rs:467-491` — the `MintSupply` context. The sole
  `Signer` is `payer` (`:487-488`).
- `programs/rwa-supply-controller/src/lib.rs:226-283` — the handler.

The destination is constrained by owner only, and the doc comment above it asserts an
invariant the constraint does not enforce:

```rust
/// The Vault inventory token account (ATA of `config.vault` for `mint`).
#[account(mut, token::mint = mint, token::authority = config.vault)]
pub vault_token: Box<InterfaceAccount<'info, TokenAccount>>,
```

- `programs/rwa-supply-controller/src/lib.rs:480-482`

The signed payload binds the Vault **authority**, not the destination **account**:

- `programs/rwa-supply-controller/src/lib.rs:242-251` — `vault: c.vault.to_bytes()`

So the destination token account is the one field an attacker can freely choose while the
signature still verifies. Three properties make that choice damaging:

1. **`MintTo` does not fire the transfer hook.** This is intentional and documented
   (`programs/rwa-transfer-hook/src/lib.rs:5-6`), and it is correct for parity — but it means
   none of the audit-2 H-02 protections apply on the mint leg. In particular, the destination
   is never checked for `ImmutableOwner`; that check exists only in the hook, at transfer time
   (`programs/rwa-transfer-hook/src/lib.rs:104-105`).
2. **Creating a Token-2022 account owned by an arbitrary PDA is permissionless.**
   `InitializeAccount` takes the owner as a plain argument. The repository's own test builds
   exactly this shape — a raw account sized for the mint's required extensions but
   deliberately without `ImmutableOwner` (`tests/fullflow.ts:541-554`).
3. **Replay markers are permanent.** `nonce_marker` and `record_marker` are only ever created
   with `init` (`programs/rwa-supply-controller/src/lib.rs:483-486`); there is no close or
   clear instruction anywhere in the program.

### Exploit sequence

1. The attacker pre-creates Token-2022 account **T** with `owner = <Vault config PDA>`, sized
   for the mint's extensions, and deliberately **without** `ImmutableOwner`.
2. The attacker obtains a valid, unconsumed mint attestation. Two realistic sources: front-run
   the operator's in-flight transaction (via a malicious or compromised RPC endpoint, or as
   the leader), or recover it from a **landed-but-failed** mint transaction. The second is the
   more likely: Solana records failed transactions on-chain with their full instruction data,
   and this program deliberately rolls the markers back on failure — described as a feature in
   the module doc (`programs/rwa-supply-controller/src/lib.rs:16-18`). Any mint that lands and
   fails on compute budget, an expired `valid_until`, or a pause therefore publishes a
   still-valid signature that anyone can replay.
3. The attacker submits the same instruction with `vault_token = T`. Every check passes: the
   signature verifies, `T`'s authority is `config.vault`, and both markers are created.

### Impact

- **The record key is permanently destroyed.** `record_marker` is seeded on `record_key`, so
  that asset record can never be minted again — by anyone, ever. There is no administrative
  path to clear a marker. Re-tokenizing the same real-world asset requires the issuer to
  allocate a fresh record key and re-run the offline auditor ceremony, and the on-chain record
  of the original is a mint the issuer never authorized to that destination.
- **The minted supply is unspendable.** Because `T` lacks `ImmutableOwner`, every transfer out
  of it is rejected by the hook (`programs/rwa-transfer-hook/src/lib.rs:104`). The tokens
  cannot be sold through `buy`, cannot be moved, and cannot be reached by any instruction other
  than a burn. They still count toward the mint's total supply, breaking the
  supply-to-backing reconciliation that the whole attestation scheme exists to guarantee.
- **Recovery requires the offline auditor.** `burn_supply` can clear `T` — permissioned burn
  does not fire the hook, and `T` satisfies the `token::authority = config.vault` constraint
  (`programs/rwa-supply-controller/src/lib.rs:509-510`) — but only with a fresh burn
  attestation and a fresh nonce. The record key remains dead regardless.
- Cost to the attacker is rent plus fees. No role, no allowlist entry, and no key are needed.

A less destructive variant of the same gap: even directing the mint to a *well-formed* shadow
Vault-owned account makes the supply invisible to any indexer watching the inventory ATA,
while remaining sellable through `buy` (which has the same unpinned constraint).

### Recommendation

Fix both halves — the account constraint and the signed payload:

1. **Pin the destination.** Add `associated_token::mint = mint, associated_token::authority =
   config.vault` to `MintSupply.vault_token`, or store the canonical inventory account key in
   `Config` at `initialize` and use `address = config.vault_token`. This alone closes the
   exploit. Apply the same to `BurnSupply.vault_token`
   (`programs/rwa-supply-controller/src/lib.rs:509-510`) and
   `rwa_vault::ControllerBurn.vault_token` (`programs/rwa-vault/src/lib.rs:354-355`).
2. **Bind the destination into the attestation.** Add the destination token account to
   `MintAttestation` and the corresponding type string, so the auditor authorizes *where* the
   supply lands and not merely which authority owns it. This requires a coordinated change in
   `crates/attestation`, the offline signer, and `shared/vectors/`, so treat it as the
   follow-up to (1) rather than a substitute for it.
3. Consider requiring `ImmutableOwner` on the mint destination as well, so the mint leg is not
   dependent on the transfer leg for that property.
4. Treat a landed-but-failed mint transaction as a **disclosed attestation** in operational
   procedure: the signature is public and replayable until its nonce is consumed. Either have
   the operator immediately consume the nonce with a deliberate no-op-equivalent mint to the
   canonical account, or narrow `valid_until` to a very short window so the disclosure expires
   quickly.

Add tests: a mint to a non-ATA Vault-owned account must fail; a replay of a valid attestation
with a substituted destination must fail.

---

## M-01 — The `finalized` go-live gate is bypassable by the compliance admin, and setting it first permanently disables mint and burn

**Severity:** Medium

### Evidence

Audit-2's M-02 introduced a two-part go-live gate. `rwa-supply-controller::finalize`
cross-checks every stored trust edge against the canonical sibling PDAs, sets its own
`Config.finalized` (which gates mint and burn), then CPIs into compliance to set
`Registry.finalized` (which gates buy and every redemption leg):

- `programs/rwa-supply-controller/src/lib.rs:103-222`, with the flag set at `:202` and the CPI
  at `:205-211`

But `rwa_compliance::set_finalized` is an ordinary public instruction whose only authorization
is the registry admin's signature. It performs no wiring verification of its own and has no
way to tell whether it was reached through `finalize` or called directly:

- `programs/rwa-compliance/src/lib.rs:69-78`
- `programs/rwa-compliance/src/lib.rs:341-350` — `SetFinalized` is `has_one = admin` plus
  `admin: Signer`, nothing more

The registry flag is what actually gates the asset-moving instructions:

- `programs/rwa-vault/src/lib.rs:128` (`buy`)
- `programs/rwa-redemption/src/lib.rs:131`, `211`, `268`, `327`, `386`

`Config.finalized` in the supply controller is written in exactly two places — `false` at
`initialize` (`:87`) and `true` in `finalize` (`:202`) — and there is no un-finalize anywhere.
Its guards are at `:237` and `:298`.

### Impact

**Bypass.** The registry admin can call `set_finalized` directly, making `buy` and all five
redemption legs live without any cross-program check in `finalize` ever running — precisely
the state audit-2's M-02 was created to make unreachable (a rogue or mistyped
`vault.supply_controller` that can drive `controller_burn`, an escrow pin that is not the
redemption config PDA, a mismatched mint or strategy). Since the intended path requires the
same registry-admin signature anyway (`programs/rwa-supply-controller/src/lib.rs:576-577`),
the control adds no assurance beyond "the operator chose to run the right instruction." The
two admin roles are separately configurable, so a compliance admin can do this without the
supply-controller admin's involvement.

**Permanent denial of service.** `finalize` sets its own flag and *then* CPIs; the CPI requires
`!registry.finalized` (`programs/rwa-compliance/src/lib.rs:72`). If `set_finalized` was called
directly first, every subsequent `finalize` reverts with `AlreadyFinalized`, `Config.finalized`
never becomes `true`, and `mint` and `burn_supply` refuse to run forever — while buy and
redemption are enabled. The deployment ends up able to trade but never to issue or retire
supply, recoverable only by a program upgrade. This is reachable by a single mis-ordered
bootstrap transaction, and `set_finalized` sits in the IDL under an inviting name.

### Recommendation

Make `set_finalized` provable as a CPI from `finalize`:

1. Add the supply-controller config PDA to `SetFinalized` as a `Signer`. It already signs via
   `CpiContext::new_with_signer` seeds elsewhere, so `finalize` can sign for it here too — the
   same pattern `rwa_vault::controller_burn` already uses
   (`programs/rwa-vault/src/lib.rs:74-79`).
2. `require_keys_eq!` that signer against the canonical
   `find_program_address(&[CONFIG_SEED], &<supply controller id>)`, with the program id as a
   compiled constant so no dependency cycle is introduced.
3. Keep `has_one = admin`, so both the registry admin and the verified controller are required.

Separately, make the failure mode non-terminal: check `!registry.finalized` at the top of
`finalize` with a distinct error, or make the CPI idempotent (treat an already-set flag as
success) so a partially completed bootstrap can still be driven to a correct end state.

Add negative tests for a direct `set_finalized`, and for `finalize` after a direct
`set_finalized`.

---

## M-02 — Vault and escrow custody token accounts are not pinned to canonical ATAs

**Severity:** Medium

### Evidence

This is the general form of the gap H-01 exploits. Every instruction that moves
protocol-custodied tokens identifies the account by mint and authority only; there is no
`associated_token::` constraint anywhere in the subrepo, and no config field records a
canonical account:

- Supply controller: `programs/rwa-supply-controller/src/lib.rs:481`, `509`
- Vault: `programs/rwa-vault/src/lib.rs:394`, `396` (buy), `427`, `429` (withdraw), `354`
  (`controller_burn`)
- Redemption: `programs/rwa-redemption/src/lib.rs:634` (request escrow), `662` (escrow quote),
  `685`, `712`, `740`, `742`, `745` (reject/cancel/claim)

Creating a second token account owned by one of these PDAs needs no signature from the PDA,
and pairing `InitializeImmutableOwner` with `InitializeAccount` produces one the transfer hook
also accepts.

### Exploit sequence

1. Mallory creates RWA account **B** with `ImmutableOwner`, owner = the redemption config PDA.
2. Mallory calls `request_redemption` with `escrow_token = B`. The exact-delta check
   (`programs/rwa-redemption/src/lib.rs:176-183`) is satisfied against B, so the request is
   recorded `Pending` while the canonical escrow account **A** — holding every other pending
   request's RWA — is untouched.
3. After the timeout, Mallory calls `cancel_redemption` with `escrow_token = A`. A pays out the
   full recorded amount from other users' escrowed balance; B holds an equal amount nobody will
   think to reference.

The mirror cases: `claim_redemption` is permissionless, so any caller can divert the RWA that
should return to inventory into a shadow Vault-owned account
(`programs/rwa-redemption/src/lib.rs:745`), and `buy` can route quote proceeds into a shadow
Vault-owned quote account (`programs/rwa-vault/src/lib.rs:396`).

### Impact

For the escrow and quote legs this is not theft — every such account is PDA-owned, balances are
globally conserved, and the attacker's own deposit is stranded in B, which is why this is
Medium rather than High. The damage is accounting desynchronization and availability: honest
`claim_redemption` and `cancel_redemption` calls against the canonical account begin failing
for insufficient balance, and off-chain reconciliation (which watches the ATA, and on which the
supply-to-backing guarantee depends) reports balances that no longer describe the protocol's
real position. Recovery needs an operator to discover the shadow accounts and hand-route each
affected instruction; the redemption program has no rescue instruction, matching the Solidity
escrow, which has no sweep either (`contracts/src/RedemptionEscrow.sol`).

### Recommendation

Constrain every custody account. Either add `associated_token::mint` /
`associated_token::authority` to each context listed above — a one-line change per account,
matching how the bootstrap already creates them — or store the canonical inventory, escrow, and
proceeds account keys in each `Config` at `initialize`, use `address = config.<field>`
afterwards, and cross-check them in `finalize` alongside the other trust edges. Prefer the
second if the deployment manifest should name these accounts explicitly. Add a negative test
that a non-ATA custody account is rejected on every asset-moving instruction.

---

## M-03 — The quote mint is never validated for program, extensions, or authorities

**Severity:** Medium

### Evidence

`validate_rwa_mint` (`programs/rwa-transfer-hook/src/lib.rs:222-320`) is thorough — Token-2022
ownership, the transfer hook, a revoked hook authority, `freeze_authority == None`, a strict
two-item extension allowlist, the mint authority, and the permissioned-burn authority. None of
it is applied to the quote mint, which enters both programs as a bare `InterfaceAccount<Mint>`
and is stored without inspection:

- `programs/rwa-vault/src/lib.rs:335` and `63`
- `programs/rwa-redemption/src/lib.rs:571` and `62`

`finalize` only cross-checks that the two configs name the *same* quote mint
(`programs/rwa-supply-controller/src/lib.rs:168-172`); it never validates what that mint is.
Every quote leg then depends on an exact balance delta:

- `programs/rwa-vault/src/lib.rs:173-175` (buy), `232-234` (withdraw)
- `programs/rwa-redemption/src/lib.rs:246-250` (fund), `436-440` (claim)

### Impact

**Availability, discovered after go-live.** A quote mint carrying `TransferFeeConfig`, a
transfer hook, `InterestBearingConfig`, or `ScaledUiAmount` makes all of those delta checks
fail. `buy` and `fund_redemption` become permanently unusable, and because `finalize` never
inspects the quote mint, nothing surfaces this during bootstrap — it surfaces on the first real
purchase.

**Seizure.** A `PermanentDelegate` on the quote mint lets its issuer move Vault proceeds and
escrowed redemption funds straight out of the PDA-owned accounts, with no instruction in this
codebase involved.

**Stranded positions.** A retained freeze authority — which real stablecoins have — can freeze
`escrow_quote` while a request is `Funded`. The beneficiary's RWA is already escrowed,
`claim_redemption` cannot settle the quote leg, `cancel_redemption` requires `Pending`
(`crates/redemption-core/src/lib.rs:84`) and so is unavailable, and no admin recovery exists.
The position is permanently stuck. The RWA mint is protected from exactly this by the
`freeze_authority == None` rule added for audit-2's M-01; the quote mint has no equivalent and,
for a fiat-backed stablecoin, cannot get one.

### Recommendation

Add a `validate_quote_mint`, call it from both initializers, and re-run it in `finalize`:

1. Require the quote-mint owner to be the legacy SPL Token program or Token-2022.
2. If Token-2022, reject every extension that changes transferred amounts, invokes code, or
   seizes balances: `TransferFeeConfig`, `TransferHook`, `PermanentDelegate`,
   `InterestBearingConfig`, `ScaledUiAmount`, `DefaultAccountState`, `Pausable`,
   `MintCloseAuthority`, and the confidential-balance extensions.
3. Record the quote mint's freeze authority in the deployment manifest and require the release
   checklist to accept it explicitly, since it cannot be eliminated for a real stablecoin.

Independently, add a treasurer- or admin-gated transition that can return a `Funded` request to
its beneficiary when the quote leg cannot settle. That is the only state in the machine with no
exit, and it is reachable through an external freeze rather than through any protocol action.

---

## L-01 — The RWA token-program account is unconstrained; safety rests on a third-party crate's internal check

**Severity:** Low

### Evidence

Five contexts accept the RWA token program as a completely unchecked account, with a
`/// CHECK` comment asserting it is "validated by invoke":

- `programs/rwa-vault/src/lib.rs:408-409`
- `programs/rwa-redemption/src/lib.rs:638-639`, `693-694`, `719-720`, `750-751`

The only thing that rejects a wrong program id is `check_spl_token_program_account` inside
`spl_token_2022_interface::instruction::transfer_checked`
(`spl-token-2022-interface-2.1.0/src/lib.rs:42-47`), reached from
`programs/rwa-transfer-hook/src/lib.rs:380`. I confirmed against that source that it permits
**both** Token-2022 and the legacy SPL Token program; the legacy path then fails only
incidentally, because SPL Token refuses to operate on Token-2022-owned accounts.

`build_permissioned_burn_checked_ix` (`programs/rwa-transfer-hook/src/lib.rs:333-359`) is
hand-encoded and performs **no** program-id check at all; its caller passes
`ctx.accounts.token_program.key()` from a context typed `Interface<'info, TokenInterface>`
(`programs/rwa-vault/src/lib.rs:91-99`, `358`), which also accepts legacy SPL Token.

### Impact

Not exploitable today: an arbitrary program id is rejected before the CPI is built, and the
legacy id fails on account ownership. The concern is that the property is neither stated nor
enforced where a reviewer would look, and it is not owned by this codebase. Any refactor that
hand-builds an instruction — which the permissioned-burn path already does — loses the
guarantee silently, and the consequence would be a PDA signature delivered to an
attacker-chosen program with the Vault or escrow token account writable.

### Recommendation

State the constraint in the contexts: `#[account(address = anchor_spl::token_2022::ID)]` on
every `rwa_token_program`, and the same on `ControllerBurn.token_program`. Add an explicit
program-id check to `build_permissioned_burn_checked_ix`. Update the `/// CHECK` comments to
describe what is actually enforced.

---

## L-02 — The `ExtraAccountMetaList` can never be updated or closed

**Severity:** Low

### Evidence

`initialize_extra_account_meta_list` allocates the PDA with `init`
(`programs/rwa-transfer-hook/src/lib.rs:68-79`, `484-503`) and has no counterpart instruction,
even though SPL provides `ExtraAccountMetaList::update`. The list embeds `rwa_compliance::ID`
as a literal pubkey and derives the registry and both record PDAs from it
(`programs/rwa-transfer-hook/src/lib.rs:165-212`), and the hook's `Execute` context pins
`compliance_program` with `address = rwa_compliance::ID` (`:520-521`).

### Impact

Fail-closed but unrecoverable. If the compliance program is ever redeployed at a new address,
or the hook's extra-account layout changes, every transfer of the RWA mint begins reverting
with no on-chain path to repair it — the mint would have to be replaced and all holders
migrated. The same applies if the list is initialized against the wrong deployment during
bootstrap.

### Recommendation

Add an upgrade-authority-gated `update_extra_account_meta_list` that reallocates as needed and
calls `ExtraAccountMetaList::update::<ExecuteInstruction>`. Document in `docs/adr/ADR-009` and
the deployment runbook that the compliance program id is a permanent, immutable dependency of
every mint created against this hook, so redeploying compliance to a new address is a breaking
migration rather than a routine upgrade.

---

## L-03 — Admin handshakes accept a zero pending admin, cannot be cancelled, and most role rotations emit no event

**Severity:** Low

### Evidence

All five `propose_admin` implementations accept any value, including `Pubkey::default()`, with
no validation — unlike the initializers and other setters, which all `require_keys_neq!`
against the default:

- `programs/rwa-compliance/src/lib.rs:205`, `programs/rwa-pricing/src/lib.rs:64`,
  `programs/rwa-supply-controller/src/lib.rs:369`, `programs/rwa-vault/src/lib.rs:273`,
  `programs/rwa-redemption/src/lib.rs:105`

The matching `accept_admin` handlers compare the signer against `pending_admin` without first
requiring it to be non-default (`programs/rwa-compliance/src/lib.rs:211`,
`programs/rwa-pricing/src/lib.rs:70`, `programs/rwa-supply-controller/src/lib.rs:375`,
`programs/rwa-vault/src/lib.rs:279`, `programs/rwa-redemption/src/lib.rs:111`), and there is no
instruction to cancel a pending transfer.

Event coverage is inconsistent. `set_auditor` (`programs/rwa-supply-controller/src/lib.rs:355`)
and `set_pricer` (`programs/rwa-pricing/src/lib.rs:51`) emit events. These do not:
`set_compliance_authority` and `set_pauser` (`programs/rwa-compliance/src/lib.rs:188`, `198`);
`set_treasury`, `set_treasurer`, `set_strategy` (`programs/rwa-vault/src/lib.rs:244`, `251`,
`258`); `set_treasurer`, `set_redemption_manager`, `set_strategy`
(`programs/rwa-redemption/src/lib.rs:72`, `83`, `90`); and every `propose_admin` /
`accept_admin`.

### Impact

The zero-key case is not exploitable — `Pubkey::default()` is the System Program address, for
which no signature can be produced — but it leaves a proposal that can never be accepted and
never withdrawn, so a fat-fingered `propose_admin` is unrecoverable state on a handshake that is
two-step precisely to be reversible. The missing events are the more concrete gap: the EVM
deployment's indexer projects live governance state from emitted events, and the Solana
equivalents leave most role changes invisible to any observer not polling every config account.

### Recommendation

Reject `Pubkey::default()` in `propose_admin`, require a non-default `pending_admin` in
`accept_admin`, and add a `cancel_admin_transfer` gated on the current admin. Emit an event from
every state-changing governance instruction, carrying the previous value, the new value and the
caller — matching the shape `AuditorChanged` and `PricerChanged` already use — so the indexer
can source Solana governance state the same way it sources the EVM's.

---

## L-04 — `set_strategy` accepts any pricing-program-owned account rather than the canonical Strategy PDA

**Severity:** Low

### Evidence

`new_strategy` is typed `Box<Account<'info, Strategy>>` (`programs/rwa-vault/src/lib.rs:367`,
`programs/rwa-redemption/src/lib.rs:597`), enforcing only that the account is owned by
`rwa-pricing` and deserializes as a `Strategy`. The initializers do the same
(`programs/rwa-vault/src/lib.rs:336`, `programs/rwa-redemption/src/lib.rs:572`). Neither adds
`seeds = [rwa_pricing::STRATEGY_SEED], seeds::program = rwa_pricing::ID`, which
`rwa-supply-controller::finalize` does correctly
(`programs/rwa-supply-controller/src/lib.rs:570-575`).

### Impact

Presently theoretical: `rwa_pricing::initialize` creates a `seeds = [STRATEGY_SEED]` singleton
behind an upgrade-authority gate (`programs/rwa-pricing/src/lib.rs:146`), so exactly one
`Strategy` can exist and `finalize` cross-checks it. The exposure is that `set_strategy` runs
*after* finalize with no re-verification, so the moment the pricing program gains a second
strategy account — plausible, since `set_strategy` exists to swap strategies — an admin can
repoint the Vault and escrow at an unvetted one, subject only to the decimals check.

### Recommendation

Add the canonical PDA constraint to every `Strategy` account in the Vault and redemption
programs. If multiple strategies are intended later, give them a discriminating seed, pin
`seeds::program`, and re-run the `finalize` cross-check whenever a strategy is swapped.

---

## L-05 — `solana/`'s deployment tooling has open advisories and is excluded from the dependency-scan gate

**Severity:** Low

### Evidence

Running `npm audit --omit=dev` in `solana/` during this review reports **10 advisories (3 high,
7 moderate)** in the *production* dependency tree, including `bigint-buffer` buffer overflow via
`@solana/spl-token` (GHSA-3gc7-fjrx-p6mg, high) and `uuid` missing buffer-bounds check via
`jayson` / `@solana/web3.js` (GHSA-w5hq-g745-h8pq). npm reports a fix available for nine of ten.

The repository's dependency-scan gate does not cover this subrepo. `make security-scan`
(`Makefile:112-118`) and the CI `security-scan` job (`.github/workflows/ci.yml:179-193`) audit
`web/` (npm) and `server/` + `signer/` (govulncheck) only. There is no `cargo audit` or
`cargo deny` step for the Rust and SBF dependency graph anywhere in the repository.

### Impact

Not on-chain code, but on the trust path for the deployment ceremony: this package tree builds,
signs, and submits the bootstrap transactions, the auditor attestation payloads, and the
`finalize` call. A compromised or vulnerable package there can alter what actually reaches the
chain during the one ceremony that establishes every permanent trust edge. The scanning gap also
means these advisories accumulated silently after `package-lock.json` was committed to close
audit-2's L-02.

### Recommendation

Add `cd solana && npm ci && npm audit --omit=dev --audit-level=high` to both `make
security-scan` and the CI job, and add `cargo audit --locked` (or `cargo deny check advisories`)
for `solana/`. Bump the packages with available fixes. Given what this tooling signs, consider
running the bootstrap ceremony from a pinned, offline-verified container image and recording its
digest in the deployment manifest alongside the expected attestation domain separator.

---

## L-06 — `cancel_redemption` binds the payout account to the caller rather than to the recorded beneficiary

**Severity:** Low

### Evidence

```rust
#[account(mut, token::mint = rwa_mint, token::authority = beneficiary)]
pub beneficiary_token: Box<InterfaceAccount<'info, TokenAccount>>,
```

- `programs/rwa-redemption/src/lib.rs:714`, where `beneficiary` is the `Signer` at `:718`

Its sibling `RejectRedemption` correctly binds to the recorded value:
`token::authority = request.beneficiary` (`programs/rwa-redemption/src/lib.rs:688`), as does
`ClaimRedemption.beneficiary_quote` (`:748`).

**This is not exploitable today.** `can_cancel` returns `NotBeneficiary` unless
`caller_is_beneficiary` (`crates/redemption-core/src/lib.rs:83-85`, called at
`programs/rwa-redemption/src/lib.rs:333-342`), which forces `beneficiary.key() ==
request.beneficiary`. I checked this path specifically and it is closed.

### Impact

The escrow's payout destination is protected by an invariant that lives in a different crate
rather than by the account constraint itself. The module doc describes cancel in terms of
"timed-out `cancelRedemption`" semantics (`programs/rwa-redemption/src/lib.rs:12-14`); if that
guard is ever relaxed to permissionless-after-timeout — a natural-sounding change, and the shape
several redemption designs use — this constraint would immediately become direct theft of
escrowed RWA by any caller. The asymmetry with `reject` also makes the two paths harder to
review together.

### Recommendation

Change the constraint to `token::authority = request.beneficiary`, matching `reject` and
`claim`. It costs nothing, is behaviour-preserving today, and removes the dependency on an
off-file invariant.

---

## L-07 — Nothing rejects `rwa_mint == quote_mint`, and two balance snapshots are taken across an unrelated CPI

**Severity:** Low

### Evidence

Neither initializer asserts that the two mints differ:

- `programs/rwa-vault/src/lib.rs:36-54`
- `programs/rwa-redemption/src/lib.rs:36-54`

Two balance snapshots are read after an intervening CPI without a `reload()`:

- `programs/rwa-vault/src/lib.rs:181-182` — `vault_before` / `recipient_before` are read after
  the quote `transfer_checked`
- `programs/rwa-redemption/src/lib.rs:420` — `before = beneficiary_quote.amount` is read after
  the RWA transfer and hook CPIs

### Impact

Neither snapshot is stale unless the RWA and quote mints alias, so this is a deployment footgun
behind the upgrade-authority gate rather than an attack. If they did alias, the exact-delta
checks that the whole payment path relies on would be measuring overlapping balances and could
be satisfied by the wrong leg. Every other post-CPI read in both programs correctly calls
`reload()` (`programs/rwa-vault/src/lib.rs:112`, `173`, `195-196`;
`programs/rwa-redemption/src/lib.rs:176`, `246`, `301`, `364`, `413`, `436`), so these two are
the outliers.

### Recommendation

Add `require_keys_neq!(rwa_mint.key(), quote_mint.key())` to both initializers and re-assert it
in `finalize`. Move the two snapshots above the preceding CPI, or add the `reload()`, so the
checks do not depend on the mints being distinct.

---

## I-01 — The SBF integration suite is still not PR-blocking, and the delegate negative test is skipped

**Severity:** Informational

### Evidence

The per-PR Solana job runs formatting and the four host crates only
(`.github/workflows/ci.yml:74-81`), and `make ci` includes `solana-test` alone
(`Makefile:109`). The SBF build plus validator suite still runs only on a schedule or manual
dispatch (`.github/workflows/ci.yml:93-94`). Audit-2's I-02 recommended making it blocking;
unchanged.

Within the suite, the delegate half of the ADR-010 H-02 policy has no executed test:

- `tests/fullflow.ts:623` — `it.skip("H-02: an approved delegate cannot move an allowed owner's RWA")`

So `DelegateNotAllowed` (`programs/rwa-transfer-hook/src/lib.rs:112-116`), one of the two halves
of a High-severity remediation, is asserted only by inspection. The `ImmutableOwner` half
(`tests/fullflow.ts:537`) and the direct-`Execute` provenance check (`tests/fullflow.ts:576`)
are properly exercised.

Also unexercised: a mint to a non-canonical Vault-owned account and an attestation replay with a
substituted destination (H-01), a direct `set_finalized` (M-01), non-ATA custody accounts
(M-02), any quote-mint negative (M-03), `reject_redemption`, `withdraw_proceeds`, any role
rotation or admin handshake, a transfer by a holder whose `valid_until` has passed, and a burn
larger than the Vault's balance.

### Recommendation

Promote the SBF build plus a focused security subset to a required PR check, leaving the slower
full economic flow on the scheduled job. Implement the skipped delegate test — `approve`
followed by a hook-aware `transferChecked` with the delegate as authority, which must fail with
`DelegateNotAllowed`. Add the cases above; each maps to a finding in this report or a prior one.

---

## I-02 — Token-2022 v11 on the target cluster is an unverified deployment precondition, and a doc comment overstates `finalize`'s gating

**Severity:** Informational

### Evidence

The H-01 remediation from audit 2 depends entirely on the target cluster's on-chain Token-2022
program supporting the `PermissionedBurn` extension (v11+), as documented in `README.md:144-153`
and `docs/adr/ADR-011`. CI builds Token-2022 v11 from crate source and injects it into the local
validator, so a green integration run demonstrates the mechanism works — not that the target
cluster provides it. The program does fail closed: `validate_rwa_mint` requires the extension and
its exact authority (`programs/rwa-transfer-hook/src/lib.rs:301-309`), so a cluster without it
cannot complete bootstrap.

Separately, the `finalize` doc comment claims it is "Runnable only by the deployer (upgrade
authority)" (`programs/rwa-supply-controller/src/lib.rs:92-94`), but the context gates on
`config.admin` plus the registry admin (`:546-548`, `:576-577`) — there is no upgrade-authority
constraint. `initialize` does have one (`:459-463`).

### Recommendation

Add a release-qualification step that queries the deployed Token-2022 program's version on the
target cluster and fails if it predates the permissioned-burn extension, recording the observed
program hash in the deployment manifest. Either correct the `finalize` comment or add the
upgrade-authority gate it promises — given that `finalize` establishes go-live for the entire
deployment, adding the gate is the better choice and composes with the M-01 fix.

---

## Positive observations

These controls were reviewed adversarially and found sound:

- **The audit-2 H-01 fix is real and correctly encoded.** Verified against
  `spl-token-2022-interface 3.1.1` that `ExtensionType::PermissionedBurn` is 28 and
  `TransferHook` is 14 (`src/extension/mod.rs`), that `TokenInstruction::PermissionedBurnExtension`
  is 46 and `PermissionedBurnInstruction::BurnChecked` is 2, that `BurnCheckedInstructionData`
  is `{ amount: u64 LE, decimals: u8 }`, that the account order is source(w), mint(w),
  permissioned-burn authority(signer), owner(signer), and that `PermissionedBurnConfig` holds a
  **single** 32-byte authority field. The hand-rolled encoding
  (`programs/rwa-transfer-hook/src/lib.rs:333-359`) and the TLV parse (`:266-310`) match on all
  five points — in particular, reading the first 32 bytes of the extension value really is the
  burn authority and not an update authority, so `require_permissioned_burn_authority` checks
  the field it intends to.
- **The transfer path is fail-closed at every substitution point.** Token-2022 v11 invokes the
  hook via `spl_transfer_hook_interface::onchain::invoke_execute`
  (`spl-token-2022-11.0.0/src/processor.rs:579-587`), and that helper appends resolved extra
  accounts only if the validation PDA is present among those it was given
  (`spl-transfer-hook-interface-2.1.0/src/onchain.rs:34-51`). Omitting it yields an `Execute`
  with four accounts, which the hook's nine-account context rejects — compliance cannot be
  skipped by withholding accounts. A wrong token program is rejected before the CPI is built, a
  legacy SPL account passed where a Token-2022 one is expected is rejected by the token program,
  and a mint that is not Token-2022-with-this-hook cannot be wired at all.
- **The `transferring` provenance check is sound.** Token-2022 sets the flag on both source and
  destination immediately before the hook CPI and clears it after
  (`spl-token-2022-11.0.0/src/processor.rs:572-591`), so the hook's `source_is_transferring`
  guard (`programs/rwa-transfer-hook/src/lib.rs:93-96`, `449-457`) reads `false` for any
  standalone invocation.
- **Extra-account resolution cannot be steered.** The compliance program is a literal pubkey in
  the meta list and the registry and record PDAs are derived from it, with the record seeds
  reading the owner field at offset 32 of the source and destination token accounts. The hook
  then independently re-derives both record PDAs (`programs/rwa-transfer-hook/src/lib.rs:120-121`,
  `459-464`) and checks account ownership and discriminator before trusting them.
- **Anchor's write-back semantics do not clobber the CPI.** `finalize` takes the compliance
  `Registry` as `mut` and CPIs `set_finalized`. This is safe only because `Account<T>::exit`
  delegates to `exit_with_expected_owner`, which persists solely when `T::owner() == program_id`
  (`anchor-lang-1.1.2/src/accounts/account.rs:255-268`, `365-371`); `Registry::owner()` is the
  compliance program, so the supply controller does not write its stale pre-CPI copy over the
  flag the CPI just set. Worth remembering if that context ever holds sibling state the
  controller does own.
- **Replay markers cannot be griefed into existence.** The nonce and record/operation marker PDAs
  can only be created inside `mint` / `burn_supply`, so a third party cannot pre-burn a nonce,
  and marker creation rolls back atomically when the handler errors so a rejected attestation
  never consumes one. (The flip side of that rollback is H-01's disclosure vector.)
- **Attestations are bound tightly.** The domain covers cluster, program id and config PDA; the
  struct covers auditor, profile digest, record key or operation id, metadata digest, amount,
  nonce, validity and Vault authority. The auditor address is bound both inside the hash and by
  the recovered-address comparison. Signature malleability is irrelevant because replay is keyed
  on the nonce, not the signature. The one field it does **not** bind is the destination token
  account — see H-01.
- **All six upgrade-authority bootstrap gates are correctly formed.**
  `Program<'info, crate::program::X>` pins the address, `programdata_address()` binds
  `program_data`, and `Account<ProgramData>` enforces the loader owner
  (`programs/rwa-compliance/src/lib.rs:279-283`, `programs/rwa-pricing/src/lib.rs:151-155`,
  `programs/rwa-vault/src/lib.rs:341-345`, `programs/rwa-redemption/src/lib.rs:577-581`,
  `programs/rwa-supply-controller/src/lib.rs:460-464`,
  `programs/rwa-transfer-hook/src/lib.rs:498-502`).
- **`init_if_needed` in the compliance program is safe.** `set_system_addresses` is one-shot
  (`require!(!registry.system_set)` before any write, plus `require_keys_neq!(vault, escrow)` so
  the two accounts cannot resolve to the same address and double-init), and `set_status` has no
  invariant reinitialization could violate since every field is unconditionally rewritten. The
  authority check runs after `try_accounts`, but an unauthorized call reverts wholesale, so the
  attacker pays only their own fee.
- **All eight `SPACE` constants are exactly correct** (borsh size plus the 8-byte discriminator),
  verified field by field. Note they are exact-fit with zero slack, so any future field addition
  needs a realloc and migration.
- **Arithmetic is safe.** `pricing-math` uses `u128` intermediates with explicit rounding
  direction and a checked narrowing to `u64`; `[profile.release] overflow-checks = true` applies
  to all six programs because they are workspace members; the redemption timeout uses
  `saturating_add` so a pathological config cannot make a deadline reachable early.
- **Self-transfer and cross-PDA confusion are blocked.** The exact-delta checks reject a buy
  whose recipient is the Vault's own inventory account, and the differing `token::authority`
  constraints make it impossible to pass the Vault's account where the escrow's is expected, or
  vice versa.
- **The cancel-while-blocked behaviour is a recorded decision, not a defect.**
  `cancel_redemption` deliberately keeps the beneficiary-allowed check
  (`programs/rwa-redemption/src/lib.rs:343-350`); this is the accepted compliance stance and
  should not be "fixed."

## Accepted risks (parity with the Solidity deployment, not new findings)

- **Unbounded price moves.** A compromised pricer can set `purchase_price` to 1 and, with any
  allowlisted wallet, drain inventory for nearly nothing; `buy`'s only protection is the buyer's
  own `max_quote_amount`. `contracts/src/pricing/FixedPriceStrategy.sol:59-71` has the identical
  shape, so this is inherited design. If it is ever tightened, tighten both.
- **Single-key supply governance.** The supply admin can rotate `auditor_eth` at will
  (`programs/rwa-supply-controller/src/lib.rs:355`) and thereby authorize arbitrary mints. This
  matches the EVM role model for a single-tenant deployment; the mitigation is operational
  (multisig or hardware custody of the admin key), not code.
- **No rent reclamation.** Redemption request accounts and replay markers are never closed, so
  their rent is permanently locked. Intentional for markers, since closing one would re-enable a
  nonce — which is also why H-01's record-key consumption is irreversible.

## Verification performed

Run from `solana/` on the host:

| Command | Result |
| --- | --- |
| `cargo fmt --check` | Passed |
| `cargo test --locked -p pricing-math -p compliance-core -p redemption-core -p attestation` | Passed: **21 tests** |
| `cargo check --locked --workspace` | Passed (Anchor macro `unexpected_cfgs` warnings only) |
| `cargo clippy --locked --workspace --all-targets -- -A unexpected_cfgs` | Passed, zero warnings |
| `npm audit --omit=dev` | **10 advisories: 3 high, 7 moderate** (see L-05) |
| `anchor build` / `anchor test` (SBF + validator) | **Not run** — no SBF toolchain or Token-2022 v11 validator in this environment |
| `cargo audit` | Not available in this environment |

Token-2022 and Anchor behavioural claims were verified by reading the resolved crate sources
directly (`spl-token-2022` 11.0.0, `spl-token-2022-interface` 2.1.0 and 3.1.1,
`spl-transfer-hook-interface` 2.1.0, `anchor-lang` 1.1.2) rather than from documentation.

Host compilation, lints, and pure-logic tests do not execute SBF account privileges, Token-2022
runtime CPIs, transfer-hook resolution, or validator feature behaviour. The findings here were
derived by source analysis; H-01's redirection sequence, M-01's denial-of-service path, and
M-02's escrow-fragmentation sequence should each be reproduced against a validator before and
after the fixes.
