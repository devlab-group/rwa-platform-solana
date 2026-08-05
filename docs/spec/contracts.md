# Program specification

The six Anchor programs in `solana/programs/*/src/lib.rs`, together with this file, describe
how the on-chain stack behaves. Implementations follow them; changing a program's account
layout, instruction checks, or error set means writing an ADR for it first.

Anchor 1.1.2, Agave/Solana 4.1.1, on SPL Token-2022 v11 (required for the permissioned-burn
extension) + a transfer hook. Every program is non-upgradeable in intent but deployed
upgradeable (the deployer keeps the upgrade authority) so an audited fix can ship; see
`solana/README.md`'s deployment runbook for the upgrade-authority custody discipline.

## Project pause

`rwa-compliance`'s `Registry.paused` is the single project-wide emergency flag, set/unset by
`pause()`/`unpause()` (pauser-gated). Every asset-moving instruction across the other five
programs (`rwa-supply-controller::mint`/`burn_supply`, `rwa-vault::buy`/`withdraw_proceeds`,
`rwa-redemption::request_redemption`/`fund_redemption`/`reject_redemption`/`claim_redemption`)
reads the registry and requires `!paused`. The Token-2022 **transfer hook**
(`rwa-transfer-hook::transfer_hook`) reads the same registry on every plain transfer, so pause
also blocks ordinary holder-to-holder movement — with one deliberate bypass: while paused, the
hook still allows a transfer whose **source owner is the pinned `escrow` authority** (and only
to a still-allowed recipient), which is what lets `rwa-redemption::cancel_redemption` return a
timed-out request's RWA during an emergency pause without opening a general backdoor.
`cancel_redemption` itself has no `!paused` guard (the hook enforces the bypass instead);
`claim_redemption` keeps its own explicit `!paused` guard and therefore never reaches that
bypass path.

## rwa-compliance

**State**: `Registry` (singleton PDA, seed `"registry"`) — `admin`, `pending_admin`,
`compliance_authority`, `pauser`, `vault`, `escrow`, `supply_controller` (program id),
`rwa_mint`, `system_set`, `paused`, `finalized`, `bump`. `ComplianceRecord` (PDA per wallet,
seeds `["record", wallet]`) — `wallet`, `status` (0=Unknown, 1=Allowed, 2=Blocked),
`valid_until` (unix seconds, 0 = no expiry), `bump`.

- `initialize`: upgrade-authority-gated (deployer only, via `ProgramData`); rejects a zero
  `admin`/`compliance_authority`/`pauser`.
- `set_status(status, valid_until)` — compliance-authority-gated:
  1. caller == `registry.compliance_authority` else `NotComplianceAuthority`
  2. `status` parses to a valid `ComplianceStatus` else `InvalidStatus`
  3. if the wallet is a pinned system address (`system_set && wallet ∈ {vault, escrow}`),
     the change must keep it `Allowed` with `valid_until == 0` else `SystemAddressCannotBeBlocked`
  4. writes `record.{status, valid_until}`, emits `StatusChanged`
- `set_system_addresses` — admin-gated, one-time-until-`finalize`:
  1. `!registry.finalized` else `AlreadyFinalized`
  2. `vault != 0` and `escrow != 0` else `ZeroAddress`; `vault != escrow` else
     `VaultEscrowMustDiffer`
  3. the passed supply-controller account must be executable else `NotExecutable`
  4. atomically pins `vault` and `escrow` as `Allowed`/`valid_until=0` compliance records,
     stores `supply_controller` and `rwa_mint` on the registry, and — if a pin is being
     corrected — resets the superseded old vault/escrow record to `Unknown` (the caller must
     supply that old record or the call fails with `MissingPrevRecord`/`WrongPrevRecord`)
  5. re-runnable any number of times before `finalize`, so a bootstrap typo is correctable
- `set_finalized` — reachable **only** as a CPI from `rwa-supply-controller::finalize`
  (signed by the re-derived supply-controller config PDA, checked against
  `registry.supply_controller`, else `NotSupplyController`); additionally requires this
  compliance program's own upgrade authority to equal the registry-admin signer
  (`NotUpgradeAuthority` otherwise), binding go-live to the deployer regardless of who pinned
  the supply-controller id. Requires `system_set` else `SystemAddressesNotSet`. Idempotent —
  already-`finalized` returns `Ok` rather than erroring, so it can never brick the real
  `finalize` call.
- `pause`/`unpause` — pauser-gated, flips `registry.paused`, emits `PauseSet`.
- `set_compliance_authority`/`set_pauser` — admin-gated, reject a zero new value, emit
  `RoleChanged`.
- `propose_admin(new_admin)` / `accept_admin` — two-step handover: `propose_admin` (current
  admin, rejects a zero `new_admin`) sets `pending_admin`; `accept_admin` requires the caller
  == `pending_admin` (`NotPendingAdmin`) and a non-zero pending admin (`NoPendingAdmin`), then
  swaps it in. `cancel_admin_transfer` (current admin) clears a mistaken proposal.

## rwa-transfer-hook

**State**: no persistent account of its own beyond the per-mint `ExtraAccountMetaList` PDA
(seeds `["extra-account-metas", mint]`) Token-2022 reads to resolve the hook's extra accounts.

- `initialize_extra_account_meta_list` / `update_extra_account_meta_list` — upgrade-authority
  gated; validate the mint actually uses this hook (`validate_rwa_mint`) before writing the
  canonical 4-entry list (compliance program id, its `Registry` PDA, and the source/destination
  owners' `ComplianceRecord` PDAs, all resolved from the transfer's own accounts).
- `transfer_hook` (the Token-2022 `Execute` entrypoint, routed through `fallback`) — checks,
  in order:
  1. `mint == registry.rwa_mint` else `WrongMint`
  2. the source token account's Token-2022 `transferring` flag is set, proving this is a real
     in-flight transfer and not a forged direct `Execute` call, else `NotTransferring`
  3. both source and destination token accounts carry `ImmutableOwner` else
     `MutableTokenAccount`
  4. the transfer authority equals the source account's own owner (no delegates) else
     `DelegateNotAllowed`
  5. the passed source/destination record accounts are the canonical
     `["record", owner]` PDAs else `RecordMismatch`
  6. if `registry.paused`: source owner must be the pinned `escrow` authority
     (`system_set && src_owner == registry.escrow`) else `Paused`, and the destination must
     still be allowed else `RecipientNotAllowed` — this is the pause-bypass described above
  7. if not paused: both source and destination must be allowed
     (`SenderNotAllowed` / `RecipientNotAllowed`)
- `validate_rwa_mint` (shared helper, called by every program's `initialize`/`finalize`):
  requires Token-2022 ownership, a `TransferHook` extension pointing at this program, no
  freeze authority (`FreezeAuthoritySet`), and only the `TransferHook`/`PermissionedBurn`
  extension types present on the mint (`DisallowedMintExtension`); optionally pins the mint
  authority and requires the hook's own update authority to be revoked
  (`HookAuthorityNotRevoked`) and the `PermissionedBurn` authority to equal a given PDA.
- `validate_quote_mint` (shared helper): accepts the legacy SPL Token program as-is, or
  Token-2022 carrying only transfer-neutral metadata/group extensions
  (`DisallowedQuoteMintExtension` otherwise); a retained freeze authority is deliberately
  **not** rejected (real stablecoins keep one — see the operator runbook for the resulting
  frozen-beneficiary risk).
- `validate_extra_account_meta_list` (shared helper, used by `finalize`): re-derives the
  canonical PDA and re-encodes the expected list, then compares byte-for-byte against what's
  stored, so a missing/stale/mismatched list fails `WrongMetaList` rather than letting a
  deployment finalize into a mint nothing can actually transfer.

## rwa-supply-controller

**State**: `Config` (singleton PDA, seed `"supply-config"`) — `admin`, `pending_admin`,
`auditor_eth` (20-byte secp256k1 address), `token_mint`, `vault` (Vault authority PDA),
`registry`, `profile_digest`, `cluster` (32-byte genesis hash), `finalized`, `bump`. Replay
protection is two families of one-byte PDA markers whose mere existence means "used":
`Marker` at `["nonce", nonce]` and `["record-key", record_key]` (mint) or
`["operation", operation_id]` (burn).

Attestation domain/digest and field order are frozen in `shared/eip712/types.md`; this file
does not restate them.

- `initialize`: rejects a zero `admin` (`ZeroAddress`), a zero `auditor_eth`
  (`ZeroAuditor`), or a zero `cluster` (`ZeroCluster` — the cluster genesis hash is the only
  per-deployment entropy separating two deployments that reuse program keypairs); requires the
  RWA mint to pass `validate_rwa_mint` with this config PDA as mint authority, an immutable
  hook, and this config PDA as the permissioned-burn authority, else `UnsafeMint`.
- `mint(record_key, metadata_digest, amount, nonce, valid_until, signature, recovery_id)`
  checks IN ORDER:
  1. `config.finalized` else `NotFinalized`
  2. `!registry.paused` else `ProjectPaused`
  3. `valid_until >= now` else `AttestationExpired`
  4. `amount != 0` else `ZeroAmount`
  5. the attestation digest (built from `config.auditor_eth`/`profile_digest`/`vault` plus the
     call's `record_key`/`metadata_digest`/`amount`/`nonce`/`valid_until`) recovers, via
     `secp256k1_recover`, to `config.auditor_eth` — a high-`s` (malleable) signature is
     rejected first (`MalleableSignature`), then a failed/mismatched recovery is
     `InvalidSignature`
  6. the nonce and record-key markers must not already exist (enforced by the `init` accounts
     context — an existing marker fails the instruction before the handler body runs, and a
     rejected attestation never consumes a nonce because Anchor rolls back a failed `init`)
  7. the vault inventory token account passed in must be the canonical ATA of `config.vault`
     for the mint, else `NotCanonicalAta` (closes the redirect-to-shadow-account class)
  8. mint `amount` to that account (mint authority = this config PDA), emit `Minted`
- `burn_supply(operation_id, metadata_digest, amount, nonce, valid_until, signature,
  recovery_id)`: same checks 1–5 (using `operation_id` in the digest and an `["operation",
  operation_id]` marker instead of the record-key marker), plus `amount != 0` and
  `vault_token.amount >= amount` else `InsufficientVaultInventory`; burns via a CPI into
  `rwa-vault::controller_burn` (signed by this config PDA, which the Vault checks against its
  own stored `supply_controller`), emits `Burned`. Nonce namespace is shared across `mint` and
  `burn_supply`; distinct type hashes (see `shared/eip712/types.md`) prevent cross-type replay.
  `mint`/`burn_supply` are permissionless to call — the auditor's signature is the
  authorization, not the caller's identity.
- `finalize(cluster)` — admin-gated (config admin), one-shot (`AlreadyFinalized` if already
  set). Cross-checks the entire wired mesh before flipping go-live: the restated `cluster`
  argument must equal the pinned one (`ClusterMismatch`); this config's own
  `vault`/`registry`/`token_mint` must match the accounts passed; the Vault config must point
  back at this supply-controller, mint, registry, and pricing strategy; the redemption config
  must share the Vault, mint, registry, quote mint, and pricing strategy; the RWA and quote mints must differ
  (`MintQuoteSame`); the registry must have `system_set` with its pinned `vault`/`escrow`
  matching this controller's `vault`/redemption-config PDA and its pinned `supply_controller`
  equal to this program; the registry's pinned `rwa_mint` must equal the mint everything else
  is wired to; pricing decimals must match the mint (`DecimalsMismatch`) and the Vault/escrow
  quote decimals must agree (`QuoteDecimalsMismatch`); the mint must re-pass `validate_rwa_mint`
  (`UnsafeMint`); and the mint's transfer-hook `ExtraAccountMetaList` must validate
  byte-for-byte (`MetaListInvalid`). Any mismatch is `WiringMismatch` unless a more specific
  error applies. On success it sets `config.finalized` and CPIs
  `rwa_compliance::set_finalized` (signed as this config PDA) to flip the registry's global
  flag, emitting `Finalized`.
- `set_auditor(new_auditor_eth)` — admin-gated, rejects a zero address (`ZeroAuditor`), emits
  `AuditorChanged`. Immediate and single-signature — see `docs/spec/roles.md`.
- `propose_admin`/`accept_admin`/`cancel_admin_transfer` — same two-step pattern as
  `rwa-compliance`.

## rwa-pricing

**State**: `Strategy` (singleton PDA, seed `"strategy"`) — `admin`, `pending_admin`, `pricer`,
`token_decimals`, `purchase_price`, `redemption_price`, `bump`.

Rounding (shared `pricing-math` crate, reused verbatim by Vault and redemption): purchase
quotes round up (Ceil), redemption quotes round down (Floor); `quote = mulDiv(tokenAmount,
price, 10**token_decimals, rounding)`.

- `initialize`: rejects a zero `purchase_price`/`redemption_price` (`ZeroPrice`),
  `token_decimals` above the shared max (`DecimalsTooLarge`), or a zero `admin`/`pricer`
  (`ZeroAddress`).
- `set_purchase_price`/`set_redemption_price` — pricer-gated, reject a zero price
  (`ZeroPrice`), emit `PurchasePriceUpdated`/`RedemptionPriceUpdated`. Unbounded otherwise —
  see `docs/spec/roles.md` on holding `pricer` behind a multisig.
- `set_pricer` — admin-gated, rejects a zero address, emits `PricerChanged`.
- `propose_admin`/`accept_admin`/`cancel_admin_transfer` — same two-step pattern.

## rwa-vault

**State**: `Config` (singleton PDA, seed `"vault-config"`) — `admin`, `pending_admin`,
`treasurer`, `treasury`, `supply_controller` (the PDA allowed to call `controller_burn`),
`rwa_mint`, `quote_mint`, `quote_decimals`, `strategy`, `registry`, `bump`. The config PDA
itself is the authority owning the canonical inventory (RWA) and quote-proceeds ATAs, and is
the `vault` pinned as a compliance system address / named in every attestation.

- `initialize`: rejects a zero `admin`/`treasurer`/`treasury`/`supply_controller`
  (`ZeroAddress`); validates the RWA mint (`UnsafeMint`) and the quote mint
  (`UnsafeQuoteMint`); requires the two mints differ (`MintQuoteSame`); requires pricing
  `token_decimals` to match the RWA mint (`DecimalsMismatch`) and the passed `quote_decimals`
  argument to match the quote mint's actual decimals (`QuoteDecimalsMismatch`).
- `buy(token_amount, max_quote_amount, deadline)` checks IN ORDER:
  1. `registry.finalized` else `NotFinalized`
  2. `!registry.paused` else `ProjectPaused`
  3. `deadline >= now` else `DeadlineExpired`
  4. `token_amount != 0` else `ZeroAmount`
  5. the recipient RWA account must not be the vault's own inventory ATA else `SelfTransfer`
     (a self-transfer would bypass the hook's compliance check on that one path)
  6. buyer allowed else `CallerNotAllowed`; recipient allowed else `RecipientNotAllowed`
     (the hook re-checks the recipient again on the RWA leg)
  7. `token_amount <= inventory` else `InsufficientInventory`
  8. compute `quote = quote_purchase(token_amount, purchase_price, token_decimals)`
     (`PricingFailed` on overflow); `quote <= max_quote_amount` else `QuoteAboveMax`
  9. pull exactly `quote` from the buyer's quote account into the vault's quote ATA, verified
     by an exact balance-delta check (`QuoteDeltaMismatch` otherwise)
  10. send exactly `token_amount` RWA from the vault's inventory ATA to the recipient (through
      the hook), verified by exact balance-delta checks on both legs
      (`RwaDeltaMismatch` otherwise); emit `Purchased`
- `withdraw_proceeds(amount)` — treasurer-gated: `registry.finalized` else `NotFinalized`,
  `!registry.paused` else `ProjectPaused`, transfers `amount` quote from the vault's quote ATA
  to the treasury's canonical quote ATA with an exact-delta check, emits `ProceedsWithdrawn`.
- `controller_burn(amount)` — callable only by the pinned `supply_controller` PDA (a CPI
  signer, checked against `config.supply_controller` else `NotSupplyController`); burns
  through the Token-2022 `PermissionedBurnChecked` instruction, which itself requires both the
  permissioned-burn authority (the supply-controller PDA, signing via the propagated CPI
  privilege) and the token-account owner (this Vault config PDA) — a plain holder `Burn` is
  rejected by the mint extension, so supply can only shrink through this attested handshake.
  Verified by an exact balance-delta check (`BurnDeltaMismatch`).
- `set_treasury`/`set_treasurer` — admin-gated, reject a zero address, emit `RoleChanged`.
- `propose_admin`/`accept_admin`/`cancel_admin_transfer` — same two-step pattern.

## rwa-redemption

**State**: `Config` (singleton PDA, seed `"redemption-config"`) — `admin`, `pending_admin`,
`treasurer`, `redemption_manager`, `vault` (the Vault authority PDA RWA returns to),
`rwa_mint`, `quote_mint`, `quote_decimals`, `strategy`, `registry`, `redemption_timeout`
(immutable per deployment, bounded `[86_400, 31_536_000]` seconds = [1 day, 365 days]),
`next_id`, `bump`. The config PDA is the escrow authority owning the escrowed RWA/quote ATAs
and is the `escrow` pinned as a compliance system address. `RedemptionRequest` (PDA per
request, seeds `["request", id.to_le_bytes()]`) — `id`, `beneficiary`, `rwa_amount`,
`quote_amount`, `created_at`, `status` (`redemption_core::RedemptionStatus` as `u8`), `bump`.

State machine and per-transition guard detail: `docs/spec/redemption-state-machine.md`.

- `initialize`: rejects a zero `admin`/`treasurer`/`redemption_manager`/`vault` authority
  (`ZeroAddress`); validates both mints, requires them distinct, requires pricing/quote
  decimals to match (same pattern as `rwa-vault`), and requires `redemption_timeout` within
  `[MIN_REDEMPTION_TIMEOUT, MAX_REDEMPTION_TIMEOUT]` else `InvalidTimeout`.
- `request_redemption(rwa_amount, min_quote_out, deadline)` checks IN ORDER: `finalized` else
  `NotFinalized`; `!paused` else `ProjectPaused`; caller (beneficiary) allowed else
  `CallerNotAllowed`; `rwa_amount != 0` else `ZeroAmount`; `deadline >= now` else
  `DeadlineExpired`; computes `quote = quote_redemption(...)` (`PricingFailed` on overflow),
  `quote != 0` else `ZeroQuote`, `quote >= min_quote_out` else `QuoteBelowMin`; pulls exactly
  `rwa_amount` RWA from the beneficiary into escrow with an exact-delta check
  (`RwaDeltaMismatch`); creates the request `Pending`, emits `RedemptionRequested`.
- `fund_redemption(id)` — treasurer-gated: `finalized`, `!paused`, status must be `Pending`
  (`ensure_pending`, else `NotPending`), beneficiary still allowed else
  `BeneficiaryNotAllowed`; pulls exactly `request.quote_amount` from the treasurer into escrow
  with an exact-delta check; sets status `Funded`, emits `RedemptionFunded`.
- `reject_redemption(id, reason_code)` — redemption-manager-gated: `finalized`, `!paused`,
  `reason_code != 0` else `ZeroReasonCode`, status must be `Pending` else `NotPending`,
  beneficiary still allowed else `BeneficiaryNotAllowed`; sets status `Rejected`, returns
  exactly `rwa_amount` from escrow to the beneficiary (escrow-authority-signed, through the
  hook) with an exact-delta check, emits `RedemptionRejected`.
- `cancel_redemption(id)` — beneficiary-gated, **no explicit `!paused` guard** (see the pause
  section above): requires `finalized`; the shared `can_cancel` guard checks, in order, status
  `Pending` (`NotPending` — or a status/timeout combination the crate allows; see the
  state-machine doc for the exact table), caller == `request.beneficiary` (`NotBeneficiary`),
  and `now >= created_at + redemption_timeout` (`TimeoutNotReached`); beneficiary still allowed
  else `BeneficiaryNotAllowed` (so a de-whitelisted beneficiary cannot even reclaim via
  timeout until compliance restores them); sets status `Cancelled`, returns exactly
  `rwa_amount` from escrow to the beneficiary (escrow-authority-signed — this is the leg the
  hook's pause bypass exists for) with an exact-delta check, emits `RedemptionCancelled`.
- `claim_redemption(id)` — permissionless: `finalized`, `!paused`, status must be `Funded`
  (`ensure_funded`, else `NotFunded`); sets status `Completed`; returns exactly `rwa_amount`
  from escrow to the **Vault's** canonical inventory ATA (escrow-authority-signed, through the
  hook) with an exact-delta check; pays exactly `quote_amount` from escrow to the
  beneficiary's own canonical quote ATA (address-pinned — the one custody leg not otherwise
  covered by `ImmutableOwner`, since the quote leg fires no hook) with an exact-delta check;
  emits `RedemptionCompleted`. Never re-checks the beneficiary's compliance status — see the
  state-machine doc's "Compliance changes during redemption funding" section.
- `close_request(id)` — permissionless, requires the request status is terminal (`Completed` /
  `Rejected` / `Cancelled`) else `RequestNotTerminal`; closes the account, refunding its rent
  to `request.beneficiary` (enforced by `has_one`, else `NotBeneficiary`), emits
  `RequestClosed`.
- `set_treasurer`/`set_redemption_manager` — admin-gated, reject a zero address, emit
  `RoleChanged`.
- `propose_admin`/`accept_admin`/`cancel_admin_transfer` — same two-step pattern.

## Cross-cutting invariants

- **Two-step admin handover**, identical shape on every program: `propose_admin` (current
  admin, rejects a zero proposal) → `accept_admin` (only the proposed key, rejects no-pending
  or wrong-caller) → `cancel_admin_transfer` (current admin withdraws a mistaken proposal). See
  `docs/spec/roles.md`.
- **`system_set`/`finalized` go-live latch**: `rwa-compliance::set_system_addresses` pins the
  Vault and escrow authorities plus the supply-controller program id and RWA mint;
  `rwa-supply-controller::finalize` cross-checks the whole wired mesh and CPIs
  `rwa_compliance::set_finalized`. Nothing mints, burns, buys, or moves through a redemption
  state until both flags are set.
- **Canonical-ATA pinning**: every PDA-owned custody account (Vault inventory/quote, escrow
  RWA/quote, the beneficiary's claim-quote destination) is pinned by `address` to
  `ATA(authority, mint)`, not merely checked for mint+authority — this is what closes the
  redirect-to-shadow-account class for a leaked or front-run attestation.
- **Exact balance-delta checks** on every token transfer in every instruction above — the
  Solana analogue of the EVM contracts' `SafeERC20` + exact-received-amount pattern.
