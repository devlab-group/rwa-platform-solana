# Solana Programs Security Review — Audit 6

**Review date:** 2026-07-31
**Scope:** `solana/programs/*/src/lib.rs` (all six Anchor programs), the security-critical shared
crates in `solana/crates/*` (attestation, pricing-math, compliance-core, redemption-core),
workspace/toolchain configuration, and `scripts/bootstrap.mjs` + the integration tests as
supporting evidence.
**Revision reviewed:** working-tree snapshot supplied for this review, post audit-5 remediation
(the `finalize` mint/meta-list proofs and the `set_system_addresses` stale-pin clearing are
present). The `solana/` directory is still untracked by Git, so no immutable commit hash can
identify this snapshot.
**Prior audits:** this is the sixth review round. Findings from audits 1–5 that were fixed were
re-verified as fixed in this snapshot; findings the project explicitly accepted as EVM-parity
design are **not** re-reported as new findings but are listed once in
[Standing accepted risks](#standing-accepted-risks) so this report is self-contained.

## Executive summary

The codebase is in the strongest state of any snapshot reviewed so far. The layered defenses
introduced across the previous five rounds are all present and correct in this snapshot:
upgrade-authority-gated singleton initialization; typed, owner-checked, PDA-pinned cross-program
accounts; canonical-ATA pinning of every custody account; an immutable Token-2022 transfer hook
that fails closed on foreign mints, forged invocations, non-canonical compliance records, and
mutable-owner token accounts; permissioned burn requiring a two-authority handshake;
domain-separated, replay-protected, low-S-enforced secp256k1 attestations; exact balance-delta
checks on every asset leg under `overflow-checks = true`; and a `finalize` gate that
cross-verifies the entire program mesh — including, since audit 5, the registry's pinned mint and
the hook's `ExtraAccountMetaList` — before anything can mint, buy, or redeem.

No Critical or High-severity vulnerability was found.

One new Medium-severity finding remains in the go-live proof: `finalize` verifies the mint's
*configuration* exhaustively but never checks its **supply**. Because every legitimate mint
instruction is gated on `finalized`, an honest deployment necessarily reaches `finalize` with
supply exactly zero — so a one-line check would make the platform's core invariant ("every supply
increase carries an auditor attestation") *provable on-chain at go-live*. Today, a deployment
whose bootstrap tooling pre-minted before handing the mint authority to the supply-controller PDA
would finalize successfully and carry unattested supply forever.

Two Low findings cover custody-account edge cases on the redemption return legs and the vault
`buy` recipient. Four informational notes cover operational behaviors worth documenting. The
previously accepted parity/trust dispositions are unchanged and are re-listed for completeness.

### Finding summary

| ID | Severity | Finding | Status |
|---|---|---|---|
| M-01 | Medium | `finalize` does not prove the RWA mint's supply started at zero | Open, new |
| L-01 | Low | `reject`/`cancel` return escrowed RWA to any beneficiary-owned account, not the canonical ATA | Open, new |
| L-02 | Low | `buy` can deliver RWA into the redemption escrow's inventory ATA, permanently stranding it | Open, new |
| I-01 | Informational | Replay-marker and record accounts are permanent rent | Operational, by design |
| I-02 | Informational | Attestation front-running changes only the fee payer; operator tooling must treat it as success | Operational |
| I-03 | Informational | The hook's strict no-delegate policy is a deliberate EVM divergence integrators must know about | Operational |
| I-04 | Informational | `withdraw_proceeds` accepts a zero amount and emits a no-op event | Hygiene |

Standing accepted risks from audits 4–5 (not re-counted above): see
[Standing accepted risks](#standing-accepted-risks).

## Severity model

- **Critical:** direct, permissionless loss or arbitrary minting with systemic impact.
- **High:** practical loss, supply-integrity failure, or permanent protocol compromise under
  normal trust assumptions.
- **Medium:** material denial of service, loss under a privileged-role compromise, or a deployment
  invariant failure requiring a realistic configuration or tooling condition.
- **Low:** limited-impact weakness, defense-in-depth gap, or issue requiring operator error and
  retaining a straightforward recovery.
- **Informational:** trust/operational assumption or hardening opportunity without a direct
  exploit.

---

## M-01 — `finalize` does not prove the RWA mint's supply started at zero

**Severity:** Medium
**Affected code:**

- `programs/rwa-supply-controller/src/lib.rs:114-305` (`finalize` — no supply check)
- `programs/rwa-supply-controller/src/lib.rs:309-366` (`mint` — gated on `config.finalized`)
- `programs/rwa-transfer-hook/src/lib.rs:101-171` (`transfer_hook` — no `finalized` gate)
- `scripts/bootstrap.mjs:99-110` (reference mint-creation ordering, not enforced on-chain)

### Description

The platform's non-negotiable invariant is that **every supply increase requires a valid auditor
attestation**. On-chain, that is enforced from `finalize` onward: `mint` requires
`config.finalized` (`rwa-supply-controller/src/lib.rs:320`), the mint authority must be the
supply-controller config PDA, and holders cannot burn or mint through Token-2022 directly
(permissioned-burn extension, hook-gated transfers).

The window this leaves open is **before** `rwa_supply_controller::initialize`. The RWA mint must
exist — with *some* mint authority — before the supply controller can validate it, because
`validate_rwa_mint` checks the mint's **current** authority. The reference bootstrap
(`scripts/bootstrap.mjs`) creates the mint with its authority already set to the supply-config
PDA, so the deployer's key never holds mint rights. But nothing on-chain forces that ordering:

### Failure sequence

1. Bootstrap tooling (malicious, compromised, or simply home-grown by a forking issuer — this is a
   self-hosted platform whose deployments are run from cloned tooling) creates the Token-2022 mint
   with the deployer key as mint authority.
2. It mints N tokens to an arbitrary allowlisted-later account.
3. It calls `SetAuthority`, handing the mint authority to the supply-config PDA, then runs the
   normal bootstrap: `initialize` (passes — `validate_rwa_mint` sees the config PDA as the
   *current* authority), `set_system_addresses`, `initialize_extra_account_meta_list`, `finalize`.
4. `finalize` verifies the cluster restatement, the full wiring mesh, decimals, the mint's
   extension set, and the hook meta list — every check passes. The deployment is now globally
   finalized while carrying N tokens of supply that no `Minted` event and no auditor attestation
   accounts for.
5. The transfer hook enforces only allowlist/pause rules — it has no `registry.finalized` gate —
   so the pre-minted balance is freely transferable between allowed wallets (even before
   `finalize`, for what it's worth, since compliance records can be created at any time).

### Impact

The supply-attestation invariant holds for every unit minted **after** go-live but is not
*provable at* go-live, which is precisely the property `finalize` exists to provide (it was
extended in audits 4 and 5 for exactly this class of bootstrap-integrity gap: cluster restatement,
registry mint binding, meta-list proof). An off-chain reconciler comparing
`mint.supply` against `Σ Minted − Σ Burned` would flag the discrepancy — but only after the
deployment is live and the pins are frozen.

### Recommendation

In `finalize`, before setting the flags:

```rust
require!(ctx.accounts.mint.supply == 0, SupplyError::NonZeroInitialSupply);
```

This check is exact and free of false positives: every legitimate mint path requires
`config.finalized`, so an honest deployment cannot reach `finalize` with non-zero supply.
Defense-in-depth options, in descending value:

1. Also assert `supply == 0` in `rwa_supply_controller::initialize` (catches the tampered
   bootstrap earlier, while everything is still correctable).
2. Add a `registry.finalized` gate to `transfer_hook` so no RWA can move at all before go-live —
   consistent with `buy` and every redemption leg, and it costs nothing on the hot path (the
   registry is already loaded).

---

## L-01 — `reject`/`cancel` return escrowed RWA to any beneficiary-owned account, not the canonical ATA

**Severity:** Low
**Affected code:**

- `programs/rwa-redemption/src/lib.rs:803-805` (`RejectRedemption.beneficiary_token`)
- `programs/rwa-redemption/src/lib.rs:840-845` (`CancelRedemption.beneficiary_token`)
- `programs/rwa-redemption/src/lib.rs:910-918` (`ClaimRedemption.beneficiary_quote` — the
  contrasting, fully pinned case)

### Description

Audit 4's M-08 fix pinned `claim_redemption`'s quote destination to the beneficiary's *canonical
ATA* because claim is permissionless. The two RWA return legs were left constrained only by
`token::mint = rwa_mint, token::authority = request.beneficiary`:

```rust
#[account(mut, token::mint = rwa_mint, token::authority = request.beneficiary)]
pub beneficiary_token: Box<InterfaceAccount<'info, TokenAccount>>,
```

Funds cannot leave the beneficiary — the ownership constraint plus the hook's `ImmutableOwner`
requirement guarantee the receiving account is theirs and can never be re-authorized. But the
*choice* of account is the transaction builder's:

- On `cancel` the beneficiary signs, so they pick their own account — benign.
- On `reject` the **redemption manager** picks which of the beneficiary's RWA token accounts
  receives the return. Any immutable-owner account whose owner field is the beneficiary
  qualifies, including non-ATA accounts the beneficiary created.

### Impact

No theft path. The impact is determinism and reconciliation: an indexer that watches the
beneficiary's canonical ATA (the account every other leg of the protocol uses) can miss the
credit, and the manager can steer a return into an account the beneficiary's wallet software does
not display. It is also an avoidable asymmetry with `claim`, which solved exactly this problem.

### Recommendation

Pin `beneficiary_token` in both `RejectRedemption` and `CancelRedemption` to
`get_associated_token_address_with_program_id(&request.beneficiary, &rwa_mint, owner)` — the same
pattern `ClaimRedemption.beneficiary_quote` already uses. (The EVM twin has no equivalent choice —
ERC-20 balances are per-address — so this pin *restores* parity rather than diverging from it.)

---

## L-02 — `buy` can deliver RWA into the redemption escrow's inventory ATA, permanently stranding it

**Severity:** Low
**Affected code:**

- `programs/rwa-vault/src/lib.rs:159-167` (self-transfer guard covers only the vault's own ATA)
- `programs/rwa-vault/src/lib.rs:499-500` (`recipient_token` constraint)

### Description

`buy` rejects `recipient_token == vault_token` (audit-4 L-08) but accepts every other allowed
destination — including the redemption program's canonical escrow RWA ATA. That account passes
every check by construction: its owner (the redemption config PDA) is a permanently-Allowed
compliance system address, the ATA carries `ImmutableOwner`, and the hook approves the transfer.

Tokens that land there are recorded against no `RedemptionRequest`, and every escrow-outflow
instruction (`reject`, `cancel`, `claim`) moves only per-request recorded amounts with exact
delta checks. The stranded balance is therefore unspendable by anyone, forever, and
`escrow_token.amount > Σ open request amounts` permanently desynchronizes any reconciler that
asserts escrow-balance conservation.

### Impact

The buyer pays full price for the strand, so there is no profit motive — this is a
user-error/griefing-your-own-funds hazard plus a permanent accounting wart. The EVM twin has the
same behavior (`buy(recipient = escrowContract)`), so this is parity; but on Solana the reject is
one line, and unlike the EVM there is no `rescue`/sweep of any kind on the escrow.

### Recommendation

Reject the known custody destination: require
`recipient_token != get_associated_token_address_with_program_id(&registry.escrow, &rwa_mint, owner)`
(the registry is already loaded in `buy`). Alternatively document it as accepted parity in the
operator runbook so a support case is recognizable.

---

## Informational observations

### I-01 — Replay-marker and record accounts are permanent rent

Each `mint` creates two 9-byte marker accounts (nonce + record-key) and each `burn_supply` two
more (nonce + operation-id); at current rent rates that is ≈0.0009 SOL per marker, paid by the
transaction's `payer`, locked forever — markers must never be closable or the replay protection
dies with them (`rwa-supply-controller/src/lib.rs:569-576`). Compliance records are likewise
permanent. This is correct; it should simply be a documented, budgeted operational cost
(≈0.0018 SOL per attestation consumed).

### I-02 — Attestation front-running changes only the fee payer; tooling must treat it as success

`mint` and `burn_supply` are deliberately permissionless given a valid attestation — audit-3 H-01
made the outcome invariant (funds can only reach the canonical vault ATA, markers pin the
attestation). A mempool observer who lands the operator's attestation first therefore produces the
*identical* on-chain result, while the operator's own transaction fails on the already-existing
marker PDAs. Operator tooling should treat "marker exists and the `Minted`/`Burned` event is
present" as success, not retry or alarm.

### I-03 — The hook's strict no-delegate policy is a deliberate EVM divergence

`transfer_hook` requires the transfer authority to *be* the source owner
(`rwa-transfer-hook/src/lib.rs:144-148`), so Token-2022 `approve`/delegate flows fail with
`DelegateNotAllowed`. The EVM twin permits `transferFrom` by any spender the holder approved.
This is stricter and intentional (the KYC'd owner always acts), but custodial or DeFi
integrations built on delegation will not work against this mint. Worth a prominent note in the
integrator documentation.

### I-04 — `withdraw_proceeds` accepts a zero amount and emits a no-op event

`buy`, `mint`, `burn_supply`, and `request_redemption` all reject zero amounts;
`withdraw_proceeds` (`rwa-vault/src/lib.rs:253-287`) does not, so a zero-amount call succeeds and
emits a `ProceedsWithdrawn { amount: 0 }` event — indexer noise. Add `require!(amount != 0, …)`
for consistency.

---

## Standing accepted risks

These were reported in audits 4–5, considered, and explicitly kept as EVM-parity or accepted
trust-model behavior (ADR-013/ADR-014). They remain present in this snapshot and remain accurate
as described there; they are listed so this report stands alone, and none is re-counted as a new
finding.

| Origin | Behavior kept | Consequence accepted |
|---|---|---|
| a4 M-02 / a5 M-03 | `fund`/`reject`/`cancel` all require the beneficiary currently Allowed | An expired/blocked beneficiary can strand a Pending request (and its escrowed RWA) with no unwind |
| a4 M-03 (removal) / a5 M-04 | No funded-state reversal; quote-mint freeze authority tolerated | A frozen beneficiary quote ATA permanently strands a Funded redemption |
| a4 M-06/L-06 / a5 M-05 | `set_auditor` immediate, signatures not epoched | Rotating back to a prior auditor re-arms that epoch's unused signatures |
| a4 M-07 / a5 M-06 | Pricer sets any non-zero price instantly (mirrors `FixedPriceStrategy`) | A compromised pricer key mis-prices `buy`/new requests until rotated |
| a4 L-10 / a5 L-02 | No protocol-side maximum attestation validity | A long-dated leaked attestation stays live until its own expiry |
| a4 L-09 (partial) | Monotonic `next_id` kept (rent made reclaimable via `close_request`) | Request creation serializes on the config account and is front-runnable for transient DoS |
| a5 I-01 | Program upgrade authorities retained until the operator revokes them | Upgrade authority overrides every on-chain control; revocation is a runbook step **after** `finalize` |
| a5 I-02 | `cluster` domain value supplied by the deployer, restated at `finalize` | Binding is verified off-chain (`scripts/verify-cluster.mjs`), not by the runtime |

## Security properties reviewed and found sound

- **Attestation verification.** Digest structure matches the EVM EIP-712 layout with a
  Solana-bound domain (cluster ‖ program ‖ config PDA); the golden vector pins it. High-S
  signatures are rejected with the constant verified against the true curve half-order
  (`7FFF…5D57 6E73 57A4 501D DFE9 2F46 681B 20A0`), matching the OpenZeppelin boundary
  (`s ≤ n/2` accepted). The recovered key is reduced to an eth address and compared to the stored
  auditor. Nonce, record-key, and operation-id replay markers are `init` PDAs, so a failed handler
  rolls them back and a rejected attestation never burns its nonce. The shared mint/burn nonce
  namespace exactly mirrors the EVM `nonceUsed` mapping (verified against
  `contracts/src/SupplyController.sol`).
- **Custody pinning.** Every protocol-held token account (vault inventory, vault proceeds, escrow
  RWA, escrow quote, claim payout, treasury payout) is pinned to a canonical ATA of a pinned
  authority; both token programs are pinned (Token-2022 for the RWA leg, the quote mint's own
  owner for the quote leg); the hand-built permissioned-burn instruction asserts Token-2022 before
  any PDA-signed invoke.
- **Funded-quote conservation.** `fund` adds exactly `quote_amount` once (Pending→Funded,
  delta-checked); `claim` removes exactly `quote_amount` once (Funded→Completed, one-shot); no
  other instruction can move escrowed quote — the frozen "funded quote is never withdrawable and
  pays only the recorded beneficiary" invariant holds. Escrowed RWA is conserved symmetrically
  across request/reject/cancel/claim.
- **Go-live proof chain.** `finalize` cross-checks every stored trust edge in both directions
  against seed-pinned sibling configs, restates the cluster, re-validates the mint's extension
  set/authorities and the exact hook meta-list bytes, and flips the registry flag only through a
  CPI authenticated by the supply-config PDA signer plus the registry admin plus the
  compliance-program deployer binding; the registry flip is idempotent so it cannot brick the
  one-shot config flip.
- **Hook fail-closed behavior.** Foreign mints fail `WrongMint`; direct invocations fail the
  `transferring` flag check; record accounts are re-derived in-handler; missing/foreign records
  evaluate to not-allowed; mutable-owner token accounts are rejected on both sides; the pause
  bypass is limited to the pinned escrow as source with the recipient still checked.
- **Parsers.** The two hand-rolled TLV walks (RWA mint allowlist {TransferHook, PermissionedBurn},
  quote-mint benign-extension allowlist) bound every read, reject duplicate entries (first-match
  parity with Token-2022), and default-deny unknown extension types. The meta-list proof is an
  exact byte comparison against a freshly encoded canonical list.
- **Arithmetic.** All quoting flows through `pricing-math` (u128 intermediates, `MAX_DECIMALS`
  36, explicit u64 clamp, ceil-purchase/floor-redemption matching the frozen
  `shared/vectors/arithmetic.json`); every balance movement is delta-checked; the workspace builds
  with `overflow-checks = true`, `lto = "fat"`.
- **Governance.** All six programs use upgrade-authority-gated one-shot initialization, two-step
  admin handshakes with zero-key rejection and cancellation, and role-change events for the
  indexer. System addresses can only ever be Allowed-without-expiry; corrective re-pins clear the
  superseded record or refuse to run.

## Verification performed

### Manual review

Full line-by-line read of all six programs and four crates (5,141 lines of Rust), plus
`Anchor.toml`, workspace `Cargo.toml`, `scripts/bootstrap.mjs`, and cross-checks against the EVM
twins (`contracts/src/SupplyController.sol`, `contracts/src/Vault.sol`) for the parity claims made
in this report.

### Host tests

All four host crates pass on this snapshot:

- `cargo test -p pricing-math` — 6 passed (includes the frozen arithmetic vectors)
- `cargo test -p compliance-core` — 5 passed
- `cargo test -p redemption-core` — 7 passed
- `cargo test -p attestation` — 3 passed (includes the frozen golden digest)

### Not run in this environment

- `anchor build` / SBF compilation and the on-chain 17-test mocha suite (validator harness with
  the injected Token-2022 v11 build) — last reported green after the audit-5 remediation on this
  same working tree; nothing in this review changed code.
- Fuzzing/property testing of the TLV parsers and pricing math.

## Recommended remediation order

1. **M-01** — add the `mint.supply == 0` assertion to `finalize` (and optionally `initialize`);
   consider the hook `finalized` gate. One-line change, closes the last unproven bootstrap
   property before pins freeze.
2. **L-01** — ATA-pin the `reject`/`cancel` return legs to match `claim`.
3. **L-02** — reject the escrow ATA as a `buy` recipient, or document the strand as accepted.
4. **I-04** — zero-amount guard on `withdraw_proceeds`.
5. **I-01/I-02/I-03** — fold into the operator runbook and integrator documentation.
