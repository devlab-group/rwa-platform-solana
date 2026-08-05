# Solana Programs Security Review — Audit 5

**Review date:** 2026-07-31  
**Scope:** `solana/programs/*/src/lib.rs`, the security-critical shared crates in
`solana/crates/*`, workspace configuration, and the integration tests as supporting evidence.  
**Revision reviewed:** working-tree snapshot supplied for this review. The entire `solana/`
directory is currently untracked by Git, so no immutable commit hash can identify this snapshot.

## Executive summary

The six Anchor programs implement a generally strong defensive design: singleton initialization is
upgrade-authority gated; operational accounts are mostly typed, owner-checked and PDA-pinned;
Token-2022 program IDs and canonical custody ATAs are pinned; RWA transfers route through an
immutable compliance hook; mint and burn attestations are domain-separated and replay-protected;
and token movements use exact balance-delta checks.

No Critical or High-severity vulnerability was found.

Two new Medium-severity deployment-integrity findings remain in the `finalize` proof. First,
`finalize` does not compare `Registry.rwa_mint` with the controller/vault/redemption RWA mint.
Second, it does not require the transfer-hook `ExtraAccountMetaList` to exist and contain the
expected entries. Either omission lets the deployment become globally finalized and accept an
auditor-attested mint while every RWA transfer fails. This contradicts the stated purpose of
`finalize`: proving the whole mesh before assets can exist.

Four additional Medium risks are current, documented design choices carried forward for
completeness: compliance expiry can strand Pending redemptions; a quote-mint freeze can strand a
Funded redemption; auditor replacement is immediate and old signatures become valid again if an
old auditor is restored; and the pricer can change prices without bounds or delay. Two Low findings
cover stale allowlist records after correcting system pins and unlimited attestation lifetimes.

### Finding summary

| ID | Severity | Finding | Status |
|---|---|---|---|
| M-01 | Medium | `finalize` does not bind `Registry.rwa_mint` to the actual RWA mint | Open, new |
| M-02 | Medium | `finalize` does not prove the transfer-hook metadata account exists or is correct | Open, new |
| M-03 | Medium | Compliance expiry can make a Pending redemption impossible to reject or cancel | Open, accepted design |
| M-04 | Medium | A frozen beneficiary quote ATA permanently strands a Funded redemption | Open, accepted external-token risk |
| M-05 | Medium | Auditor rotation is immediate and can re-arm unused signatures from a prior auditor epoch | Open, accepted design |
| M-06 | Medium | The pricer can apply an arbitrary non-zero price immediately | Open, accepted design |
| L-01 | Low | Correcting system pins leaves the former system addresses indefinitely allowlisted | Open, new |
| L-02 | Low | Attestations have no maximum validity period | Open, accepted design |
| I-01 | Informational | Retained program upgrade authorities override every on-chain control | Operational |
| I-02 | Informational | The attestation cluster binding is supplied by the deployer, not verified by the runtime | Operational |

## Severity model

- **Critical:** direct, permissionless loss or arbitrary minting with systemic impact.
- **High:** practical loss, supply-integrity failure, or permanent protocol compromise under normal
  trust assumptions.
- **Medium:** material denial of service, loss under a privileged-role compromise, or a deployment
  invariant failure requiring a realistic configuration or external-token condition.
- **Low:** limited-impact weakness, defense-in-depth gap, or issue requiring operator error and
  retaining a straightforward recovery.
- **Informational:** trust/operational assumption or hardening opportunity without a direct exploit.

---

## M-01 — `finalize` does not bind `Registry.rwa_mint` to the actual RWA mint

**Severity:** Medium  
**Affected code:**

- `programs/rwa-compliance/src/lib.rs:129-159`
- `programs/rwa-transfer-hook/src/lib.rs:101-116`
- `programs/rwa-supply-controller/src/lib.rs:114-246`

### Description

`set_system_addresses` accepts `rwa_mint` as an unchecked account and stores its key in the
registry. This is reasonable during correctable bootstrap because `finalize` is intended to verify
the permanent topology.

The transfer hook later treats that stored key as authoritative and rejects every invocation whose
mint differs:

```rust
require_keys_eq!(
    ctx.accounts.mint.key(),
    registry.rwa_mint,
    HookError::WrongMint
);
```

The supply-controller `finalize` verifies that the controller, vault, and redemption configs share
the same `mint`, and it re-validates that mint's extensions and authorities. It also verifies the
registry's vault, escrow, and supply-controller fields. It never verifies:

```text
registry.rwa_mint == mint
```

The one registry field that the transfer chokepoint relies on is therefore outside the go-live
proof.

### Failure sequence

1. During bootstrap, the registry admin passes the wrong mint to `set_system_addresses`.
2. The controller, vault, redemption, strategy, real RWA mint, and every other checked edge are
   configured correctly.
3. `finalize` succeeds and sets both `Config.finalized` and `Registry.finalized`.
4. A valid auditor attestation can mint real RWA into the canonical vault inventory ATA because
   minting does not invoke the transfer hook.
5. `buy`, `request_redemption`, and every ordinary RWA transfer invoke the hook with the real mint.
   The hook compares it with the incorrectly pinned registry mint and fails with `WrongMint`.

If upgrade authority has already been revoked, the registry pin is frozen and the deployed stack
cannot be repaired. Even with upgrade authority retained, recovery requires a program upgrade,
not an administrative instruction.

### Impact

The protocol can attest that it is finalized and mint supply while that supply is non-transferable.
This is a material launch-time denial of service and can trap newly minted inventory in a deployment
whose explicit safety gate reported success. It requires a privileged bootstrap mistake or a
malicious registry admin, so it is not rated High.

### Recommendation

Add this check to `rwa_supply_controller::finalize` before either finalized flag is written:

```rust
require_keys_eq!(
    ctx.accounts.registry.rwa_mint,
    mint,
    SupplyError::WiringMismatch
);
```

Add an integration negative that pins a different mint and proves `finalize` fails. Keep the
existing hook-side check as defense in depth.

---

## M-02 — `finalize` does not prove the transfer-hook metadata account exists or is correct

**Severity:** Medium  
**Affected code:**

- `programs/rwa-transfer-hook/src/lib.rs:70-97`
- `programs/rwa-transfer-hook/src/lib.rs:195-244`
- `programs/rwa-transfer-hook/src/lib.rs:608-643`
- `programs/rwa-supply-controller/src/lib.rs:114-279`

### Description

Token-2022 needs the hook program's canonical `ExtraAccountMetaList` PDA to resolve the compliance
program, registry, and source/destination compliance records for each transfer. The account is
created by a separate upgrade-authority-gated instruction:

```text
PDA = find_program_address(["extra-account-metas", mint], transfer_hook_program)
```

The supply-controller `Finalize` context does not include this account and the handler neither
checks its existence/owner nor parses its contents. `validate_rwa_mint` only proves that the mint's
hook extension points to the expected hook program; it says nothing about the separate resolution
account.

### Failure sequence

1. All programs and mints are initialized, but
   `initialize_extra_account_meta_list` is accidentally omitted or fails.
2. `finalize` succeeds because the metadata PDA is not part of its context.
3. The supply controller can mint inventory because minting does not execute the hook.
4. The first RWA transfer cannot resolve the hook's required accounts and fails before a compliant
   transfer can complete.
5. If the hook program's upgrade authority was revoked after the apparently successful finalize,
   the missing PDA can no longer be created by the only authorized instruction.

A present but stale/corrupted list has the same availability effect. Only the upgrade authority can
legitimately create or update it, but `finalize` should verify the state rather than infer that the
bootstrap step happened.

### Impact

As in M-01, a finalized deployment can mint but cannot transfer RWA. Before authority revocation the
deployer can still create/update the metadata account, but the current one-shot finalization gate
does not enforce that recovery happens before launch.

### Recommendation

Extend `Finalize` with the canonical metadata PDA and the transfer-hook program. Before setting any
flag:

1. derive the PDA from `[EXTRA_META_SEED, mint]` and `rwa_transfer_hook::ID`;
2. require the passed key to match, its owner to be the hook program, and its data to deserialize as
   `ExtraAccountMetaList<ExecuteInstruction>`;
3. compare all four entries with `extra_account_metas()` or expose a read-only validation helper
   from the hook crate; and
4. add a negative integration test showing finalize fails when the metadata PDA is absent or has an
   unexpected entry.

At minimum, existence + canonical key + owner checks close the accidental-omission case. Exact
content validation is preferable because this instruction is explicitly the topology proof.

---

## M-03 — Compliance expiry can make a Pending redemption impossible to reject or cancel

**Severity:** Medium  
**Affected code:**

- `programs/rwa-redemption/src/lib.rs:319-374`
- `programs/rwa-redemption/src/lib.rs:376-435`

### Description

Both Pending-state exits re-check the beneficiary's current allowlist status:

- `reject_redemption`, controlled by the redemption manager; and
- `cancel_redemption`, controlled by the beneficiary after timeout.

If a beneficiary's KYC expires or the compliance authority blocks the wallet after RWA was
escrowed, both exits fail with `BeneficiaryNotAllowed`. Funding also fails for the same reason.
There is no transition that returns the RWA to vault inventory, quarantines it, or otherwise closes
the Pending request without first re-allowing the beneficiary.

This is documented as EVM parity and an accepted operating procedure, but it remains an on-chain
availability weakness because ordinary expiry—not only a compromised role—can trigger it.

### Impact

The beneficiary's RWA remains indefinitely pooled in the redemption escrow. Cancellation during a
project pause does not help because the hook's pause bypass still requires an allowed destination.
Recovery requires coordinated privileged action outside the request state machine.

### Recommendation

Add a manager-only quarantine/recovery transition for disallowed beneficiaries that returns the
request's RWA to the canonical vault ATA, never to an arbitrary address. Require the beneficiary to
be disallowed, bind every account to the existing config/request, emit a distinct event, and make
the request terminal.

If strict EVM parity must be retained, formalize and test the documented atomic recovery transaction:
`set_status(Allowed) -> reject_redemption -> set_status(Blocked)`, and require the compliance and
redemption-manager authorities to be independent multisigs. This mitigates but does not remove the
on-chain liveness dependency.

---

## M-04 — A frozen beneficiary quote ATA permanently strands a Funded redemption

**Severity:** Medium  
**Affected code:**

- `programs/rwa-transfer-hook/src/lib.rs:369-436`
- `programs/rwa-redemption/src/lib.rs:438-511`
- `programs/rwa-redemption/src/lib.rs:854-925`

### Description

`validate_quote_mint` deliberately permits a quote mint with a freeze authority, which is necessary
for many fiat-backed stablecoins. After a request is Funded, `claim_redemption` is its only valid
transition. The quote payout is pinned to the beneficiary's canonical ATA.

If that ATA is frozen after funding, Token/Token-2022 rejects the payout. The transaction rolls back
the preceding RWA transfer and status update, leaving the request Funded forever. Funded requests
cannot be rejected or cancelled, and there is intentionally no quote refund/recovery instruction.

### Impact

Both the beneficiary's RWA and the treasurer-funded quote amount remain locked in pooled escrow.
The freeze may be an external stablecoin issuer action outside the RWA operators' control.

### Recommendation

Choose and document one explicit policy:

- require a quote mint without freeze authority;
- add a narrowly scoped Funded-state recovery jointly authorized by governance and the beneficiary,
  with value returning only to canonical/configured accounts; or
- retain the current parity model but treat quote-freeze status as a hard pre-funding check and
  monitor every Funded request until claim lands.

The last option is operational mitigation only; no preflight check can prevent the quote authority
from freezing the account before transaction execution or later.

---

## M-05 — Auditor rotation is immediate and can re-arm unused signatures from a prior auditor epoch

**Severity:** Medium  
**Affected code:**

- `programs/rwa-supply-controller/src/lib.rs:284-410`
- `programs/rwa-supply-controller/src/lib.rs:413-424`
- `programs/rwa-supply-controller/src/lib.rs:477-521`

### Description

The config admin can replace `auditor_eth` in one transaction, with no pending/accept handshake or
delay. A compromise of the config admin can therefore install an attacker-controlled auditor and
immediately mint any amount up to `u64::MAX` per valid instruction (subject only to unique marker
seeds).

Attestations contain the auditor address and verification compares it with the currently configured
address, but they contain no auditor epoch. Rotating A -> B invalidates unused A signatures only
temporarily; rotating B -> A makes every still-unexpired, unused A signature valid again.

### Impact

A single admin-key compromise crosses the intended separation between administration and the
offline auditor. Re-arming old signatures also complicates incident response after auditor-key
rotation.

### Recommendation

Use a two-step, delayed auditor rotation and bind an incrementing `auditor_epoch` to every mint and
burn attestation. Increment the epoch on every auditor change, including a change back to a previous
address. The verifier must require the signed epoch to equal the current config epoch. Put the admin
behind a threshold multisig and monitor proposed rotations during the delay.

---

## M-06 — The pricer can apply an arbitrary non-zero price immediately

**Severity:** Medium  
**Affected code:**

- `programs/rwa-pricing/src/lib.rs:109-133`
- `programs/rwa-vault/src/lib.rs:144-250`
- `programs/rwa-redemption/src/lib.rs:179-261`

### Description

`set_purchase_price` and `set_redemption_price` accept every non-zero `u64` and take effect in the
same transaction. There is no deviation limit, timelock, round/epoch, or stale-price concept.

User-provided `max_quote_amount` and `min_quote_out` are important protections, but clients commonly
derive them from the current on-chain price with a tolerance. A compromised pricer can front-run or
bundle a price change against transactions with permissive limits, or halt activity by selecting a
price that causes quote overflow or exceeds practical limits.

### Impact

Compromise or error of one hot pricer key can cause user loss within slippage tolerances or deny all
buys/redemptions. The admin can replace the pricer, but that is reactive.

### Recommendation

Use a bounded update policy: cap percentage deviation per update, enforce a minimum update interval,
and require a delayed or multisig emergency override for larger changes. Add an explicit price epoch
to `buy` and `request_redemption` so callers can require the quote to use the price version they
observed, in addition to existing min/max checks.

---

## L-01 — Correcting system pins leaves the former system addresses indefinitely allowlisted

**Severity:** Low  
**Affected code:** `programs/rwa-compliance/src/lib.rs:116-177`

### Description

`set_system_addresses` is intentionally re-runnable until finalization so bootstrap mistakes can be
corrected. Every call force-writes the new vault and escrow records to `Allowed` with no expiry.
When the pins change, the previous vault/escrow records are not cleared or returned to their prior
status.

Consequently, correcting a mistakenly pinned arbitrary wallet leaves that wallet indefinitely
allowlisted after finalization unless the compliance authority notices and explicitly blocks it.
The emitted events also report `previous_status = 0` and `previous_valid_until = 0` unconditionally,
even if `init_if_needed` reused and overwrote an existing record.

### Impact

A launch correction can silently preserve KYC permission for an unintended address. Exploitation
requires a privileged bootstrap error and the compliance authority can repair the record, so the
issue is Low.

### Recommendation

On a corrective call, require the previous vault and escrow record accounts. If an old address is
not one of the new system addresses, restore it to `Unknown` (or a caller-specified validated prior
state) and emit its real previous values. Alternatively, disallow mutation in the on-chain
instruction and introduce an explicit correction instruction that atomically removes the old system
permissions and installs the new ones.

Add a test covering `set_system_addresses(A, B)` followed by `(C, D)` and assert A/B no longer pass
`record_is_allowed` unless independently allowlisted by the compliance authority.

---

## L-02 — Attestations have no maximum validity period

**Severity:** Low  
**Affected code:**

- `programs/rwa-supply-controller/src/lib.rs:284-315`
- `programs/rwa-supply-controller/src/lib.rs:345-380`

### Description

Mint and burn only require `valid_until >= now`. The auditor may sign `u64::MAX`, creating a
practically permanent authorization. Replay markers prevent repeated successful execution but do
not revoke an unused signature that was disclosed, copied, or queued for later use.

Destination and amount binding sharply limit abuse, but a long-lived mint authorization can be
executed long after the underlying off-chain record or operational intent changed.

### Recommendation

Enforce `valid_until <= now + MAX_ATTESTATION_TTL` using checked/saturating arithmetic and choose a
short policy window appropriate for the offline workflow. Optionally add a signed `issued_at` and
current `auditor_epoch`. Provide an admin/auditor nonce-revocation instruction only if it cannot be
used to erase successful replay history; used markers themselves must remain permanent.

---

## Informational observations

### I-01 — Retained program upgrade authorities override every on-chain control

Every program remains upgradeable unless its authority is revoked. The authority can deploy bytecode
that ignores all account constraints, signatures, pauses, and replay markers. This is inherent to
Solana upgradeable programs, not a defect in the reviewed handlers.

Record the six program IDs, reviewed sBPF hashes, loader/ProgramData accounts, and upgrade authorities
in the release manifest. Use a threshold multisig with a public timelock, or revoke authority after
bootstrap while explicitly accepting that future security patches then require migration.

### I-02 — The attestation cluster binding is supplied by the deployer

The runtime exposes no genesis-hash syscall, so `Config.cluster` cannot be compared on-chain with the
actual cluster. `initialize` rejects zero and `finalize` requires the value to be restated, which
catches some errors but cannot prove correctness. Deployment tooling must derive the genesis hash
from the target RPC, independently verify it, and record it in the signed release manifest. A
compromised RPC or deployment environment can still establish the wrong domain.

---

## Security properties reviewed and found sound

The following areas were specifically traced and did not produce an additional finding:

- singleton initialization is gated by the executable program's actual ProgramData upgrade
  authority;
- operational registry/strategy/config accounts are typed, owner-checked and canonical-PDA pinned;
- the RWA mint is Token-2022, its transfer hook is immutable, freeze authority is absent, mint
  extensions are allowlisted, and permissioned-burn authority is verified at supply initialization
  and finalization;
- mint and burn use distinct type hashes, a deployment-bound domain, canonical vault custody,
  nonce/record/operation marker PDAs, low-S signature enforcement, amount checks, and expiry checks;
- permissioned burn requires signatures from both the supply-controller PDA and vault-owner PDA;
- ordinary RWA transfer delegates and mutable-owner token accounts are rejected by the hook;
- the hook proves a real in-flight Token-2022 transfer through `TransferHookAccount.transferring`;
- source and destination compliance-record PDAs are re-derived from token-account owners;
- all custody accounts used by asset-moving handlers are bound to their intended mint and authority,
  with protocol custody and claim destinations pinned to canonical ATAs;
- quote-token program accounts are pinned to the quote mint owner and unsafe Token-2022 quote
  extensions are rejected;
- purchase and redemption rounding use `u128` intermediates, explicit u64 bounds, purchase ceiling,
  redemption floor, and zero-redemption-quote rejection;
- all material token movements are atomic and exact-delta checked;
- redemption request accounts are ID-seeded, state transitions are one-way, terminal requests close
  only to the recorded beneficiary, and cancellation timeout addition saturates; and
- RWA and quote mints must differ, preventing balance-aliasing across asset legs.

## Verification performed

### Host tests

Command:

```bash
cargo test --locked -p pricing-math -p compliance-core -p redemption-core -p attestation
```

Result: **21 passed, 0 failed** (3 attestation, 5 compliance, 6 pricing, 7 redemption).

### Workspace compilation

Command:

```bash
cargo check --locked --workspace
```

Result: **passed**. The build emits Anchor macro `unexpected_cfgs` warnings (`anchor-debug`, and
for the supply controller `custom-heap`/`custom-panic`/`target_os = "solana"`); no compilation error
was produced. This is a host check, not a substitute for `anchor build` under the pinned SBF
toolchain.

### Not run in this environment

The validator-backed TypeScript integration suite and an SBF `anchor build` were not re-run during
this review. They require the pinned Anchor/Agave SBF environment and Token-2022 v11 permissioned
burn support described in `solana/README.md`. The repository states that the suite previously passed
17 tests; that historical statement was treated as context, not as fresh audit evidence.

## Recommended remediation order

1. Fix M-01 and M-02 together and add negative finalization tests. Do not launch or revoke upgrade
   authorities while either go-live proof gap remains.
2. Decide explicit product policies for M-03 and M-04 before mainnet; both can permanently strand
   live redemptions under current rules.
3. Add auditor epochs/delayed rotation (M-05) and bounded/versioned prices (M-06).
4. Make system-pin correction atomically remove stale permissions (L-01) and cap attestation TTL
   (L-02).
5. Re-run `anchor build` and the complete validator-backed integration suite, capture all six sBPF
   hashes, and audit the deployed program IDs/ProgramData authorities against the release manifest.
