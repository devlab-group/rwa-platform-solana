# Solana Programs Security Review — Audit 4

**Date:** 2026-07-31
**Commit:** working tree at `87cc294` (`solana/` is untracked)
**Scope:** `solana/programs/*` (all six Anchor programs), `solana/crates/*` (the shared
security-critical logic), the Anchor integration suite, the workspace build profile and
toolchain pinning, the `solana/` CI jobs, and the deployment/bootstrap tooling. `signer/`
and `contracts/` were examined only where the Solana programs' safety depends on them.

**Method:** Manual review of every instruction handler and every `#[derive(Accounts)]`
context; cross-program PDA, authority and signer-privilege tracing; Token-2022 extension,
transfer, burn and account-authority analysis verified against the crate sources the
lockfile actually resolves and against the deployed program version, not against
documentation — `anchor-lang`/`anchor-spl`/`anchor-syn 1.1.2`,
`spl-token-2022-interface 2.1.0`, `spl-token-2022 11.0.0` (the version the RWA mint
requires on-cluster), `spl-transfer-hook-interface 2.1.0`,
`spl-tlv-account-resolution 0.11.1`, `spl-associated-token-account 3.0.4`,
`agave-syscalls 3.1.4`, `libsecp256k1 0.6.0`; attestation digest and replay analysis;
escrow and inventory solvency accounting; liveness and stuck-state enumeration across
every reachable state; EVM-parity checks against `contracts/src/`; and host build, test
and dependency runs. Three independent adversarial re-reviews — of the transfer/custody
paths, the attestation/supply paths, and the redemption state machine — were run in
parallel and every claim they produced was re-verified against source before inclusion.

## Executive summary

The audit-1, audit-2 and audit-3 remediations are present and are real fixes. I
re-verified the load-bearing ones from source rather than taking them on trust, and the
results are worth stating because they are the foundation everything else rests on:

- **The hand-rolled Token-2022 encodings are correct.** `build_permissioned_burn_checked_ix`
  is byte-for-byte right — discriminants `[46][2]`, an 11-byte payload, and an account
  order matching `permissioned_burn::instruction::burn_checked` — confirmed against both
  `spl-token-2022-interface 3.1.1` and the deployed `spl-token-2022 11.0.0` processor.
  Every extension type number in `validate_rwa_mint` and `validate_quote_mint` is correct,
  the TLV walk cannot run out of bounds or loop, and the type-0 early break is *sound*
  because Token-2022 also terminates at `Uninitialized` and therefore cannot see anything
  written past it either.
- **The custody-account pinning genuinely delivers `ImmutableOwner`.**
  `spl-associated-token-account 3.0.4` unconditionally initializes `ImmutableOwner` before
  `InitializeAccount3`, and only the ATA program can allocate at an ATA address, so the
  `address = get_associated_token_address_with_program_id(...)` pins do subsume the
  ImmutableOwner requirement exactly as ADR-012 claims.
- **No compliance bypass exists on any RWA movement.** Unchecked `Transfer` is rejected
  once the source carries `TransferHookAccount`; `TransferChecked` always fires the hook;
  `Burn`/`BurnChecked` are rejected by the permissioned-burn extension; fee, permanent-
  delegate and confidential paths are excluded by the mint allowlist; `SetAuthority`
  ownership handoff is blocked by `ImmutableOwner`; delegates are blocked by
  `owner == src_owner`; and the hook-exempt mint path is pinned to the canonical inventory
  ATA. Escrow solvency holds under every sequence I could construct, and the `Box::leak` in
  the hook's `fallback` is sound under SBF's per-invocation bump allocator.

**No Critical or High-severity issue was identified.** The token-movement core — mint,
burn, buy, escrow, claim — withstood every substitution, aliasing, delta-manipulation and
forged-invocation attack attempted across four independent passes.

The findings cluster into three themes, and several of them contradict claims made in
ADR-012 or in the code's own comments:

1. **The redemption program's recovery paths are gated on the exact condition they exist
   to handle.** `fund`, `reject` and `cancel` all require the beneficiary to be currently
   `Allowed`, and so does `refund_funded` — the instruction audit-3 M-03 added as an escape
   hatch. A *routine KYC expiry* between a request and its funding therefore strands the
   beneficiary's escrowed RWA with no single-role recovery, and a deliberate block after
   funding leaves the operator unable to refund while `claim` remains permissionless. In
   the other direction, `refund_funded` is otherwise entirely unscoped — no grace period,
   no evidence of unsettleability — which makes a funded quote admin-revocable and
   contradicts the frozen root invariant that it "is never withdrawable".

2. **Bootstrap values are one-shot, unvalidated, and uncorrectable — and one of them is the
   attestation domain's only per-deployment entropy.** The domain is
   `(cluster, program, config)`, but `config` is a pure function of `program`, so two
   deployments of this stack that share program keypairs — the normal devnet-then-mainnet
   pattern the README's own guidance encourages — are separated *only* by the `cluster`
   field, which nothing on-chain validates and nothing can ever correct. Separately, the
   go-live flag is forgeable by the compliance admin without the deployer's
   upgrade-authority signature, which both skips every wiring check and permanently bricks
   the real `finalize`.

3. **Trust has migrated onto hot keys.** The platform's headline invariant is that supply
   increases require an offline auditor signature, yet `signer/` contains no Solana support
   at all, so those signatures can currently only be produced by unreviewed tooling outside
   the air-gapped WYSIWYS path. `set_auditor` is a single-signature, instantly-effective
   instruction — less ceremony than rotating the admin — and the pricer can move prices to
   any non-zero value in one transaction with no bound or delay.

### Finding summary

| ID | Severity | Finding |
| --- | --- | --- |
| M-01 | Medium | The attestation domain's only per-deployment entropy is an unvalidated, permanent `cluster` value, enabling cross-cluster replay |
| M-02 | Medium | Every redemption unwind path is gated on the beneficiary being `Allowed` — including the recoveries written for when they are not |
| M-03 | Medium | `refund_funded` is an unscoped admin reversal of a funded redemption, contradicting a frozen platform invariant |
| M-04 | Medium | The go-live flag is forgeable by the compliance admin, and the bootstrap pins are one-shot and uncorrectable |
| M-05 | Medium | The offline signer cannot produce Solana attestations, so auditor signatures must come from unreviewed tooling |
| M-06 | Medium | `set_auditor` takes effect instantly on one signature, collapsing the offline-auditor invariant onto a hot key |
| M-07 | Medium | The pricer can set any non-zero price instantly, with no bound, deviation cap, or delay |
| M-08 | Medium | `claim_redemption`'s quote destination is the protocol's only unpinned token account, and claim is permissionless |
| M-09 | Medium | The quote mint's decimals are never bound to the price scale |
| L-01 | Low | `secp256k1_recover` accepts malleable high-`s` signatures; the EVM twin rejects them |
| L-02 | Low | `validate_rwa_mint` reads the *last* `PermissionedBurn` TLV entry where Token-2022 reads the *first* |
| L-03 | Low | `redemption_timeout` is unbounded and immutable; the EVM enforces a 1-day–365-day range |
| L-04 | Low | Two RWA-leg token-program accounts were missed by the audit-3 L-01 pinning |
| L-05 | Low | Revoking the upgrade authority, or rotating the config admin, before `finalize` permanently bricks go-live |
| L-06 | Low | Auditor rotation is not epoched: rotating away and back re-arms every unused old signature |
| L-07 | Low | `set_strategy` is dead code in both the vault and the redemption program |
| L-08 | Low | `buy` permits `recipient_token == vault_token`, and Token-2022 skips the hook entirely on a self-transfer |
| L-09 | Low | The shared `next_id` counter lets one attacker front-run every redemption request; request rent is never reclaimable |
| L-10 | Low | Attestations have no maximum validity window |
| L-11 | Low | `finalize` verifies address topology but not role assignment or economic parameters |
| L-12 | Low | `rwa_mint` is needlessly writable, serializing every buy and every redemption leg |
| L-13 | Low | Three raw subtractions where the rest of the same file uses `checked_sub` |
| L-14 | Low | SBF builds are neither version-pinned nor verifiable, so deployed bytecode cannot be tied to this source |
| L-15 | Low | There is no committed bootstrap tooling; the only bootstrap sequence lives in a test file |
| I-01 | Informational | The attestation digest omits the RWA mint, its decimals, and the destination |
| I-02 | Informational | Mint and burn payloads are word-identical apart from the typehash, and `bytes32 auditor` is encoded as an `address` |
| I-03 | Informational | The `TransferHook` context does not pin the mint |
| I-04 | Informational | `invoke_transfer_checked` forwards arbitrary caller signers, diverging from upstream |
| I-05 | Informational | `quote_token_program` is not pinned to the quote mint's owning program |
| I-06 | Informational | `Registry` is not seeds-pinned in the three sibling initializers |
| I-07 | Informational | Replay markers and terminal requests are never closed; rent accumulates permanently |
| I-08 | Informational | Retained upgrade authority is unilateral control of every program, with no documented custody or revocation plan |
| I-09 | Informational | Two module doc comments state the opposite of what the code does |
| I-10 | Informational | `withdraw_proceeds` and `controller_burn` lack the finalization gate; there is no reserve constraint |
| I-11 | Informational | Donations to the custody ATAs are unrecoverable, and a self-aliasing config value bricks a leg permanently |

## Severity definitions

- **Critical:** Direct compromise of the complete deployment, unrestricted theft, or loss of
  the core trust model with little or no precondition.
- **High:** Complete bypass of a primary security invariant, material asset-control
  violation, or permanent, unprivileged destruction of protocol capability.
- **Medium:** Material availability, governance, or asset-accounting impact requiring a
  privileged-key condition, a deployment error, or attacker-funded griefing.
- **Low:** Defense-in-depth, recoverability, supply-chain, or operational hardening issue
  with limited direct impact.
- **Informational:** Testing, documentation or maintainability weakness with no demonstrated
  present exploit.

---

## M-01 — The attestation domain's only per-deployment entropy is an unvalidated, permanent `cluster` value

**Severity:** Medium
**Location:** `programs/rwa-supply-controller/src/lib.rs:50` (`initialize`), `:82-86`,
`:446-456` (`domain`, `config_pda`); `crates/attestation/src/lib.rs:81-92`

### Evidence

The domain separator binds three 32-byte values:

```rust
fn domain(c: &Config) -> Domain {
    Domain { cluster: c.cluster, program: crate::ID.to_bytes(), config: config_pda().to_bytes() }
}
fn config_pda() -> Pubkey { Pubkey::find_program_address(&[CONFIG_SEED], &crate::ID).0 }
```

`config` is `find_program_address([b"supply-config"], crate::ID)` — **a pure function of
`program`, contributing zero additional entropy.** The attestation's `vault` field is
likewise the vault program's config PDA, a pure function of `rwa_vault::ID`. `auditor` and
`profile_digest` are intended to be shared across deployments (the whole design goal is one
auditor key for both chains). That leaves `cluster` as the single value distinguishing two
deployments of this stack — and it is a raw `[u8; 32]` instruction argument that nothing
validates, at `initialize` or anywhere else:

```rust
c.cluster = cluster;    // :86 — no check; no setter exists anywhere
```

`finalize`, the instruction whose stated job is catching bootstrap errors, never inspects
it. Solana exposes no genesis-hash syscall, so it genuinely cannot be checked on-chain —
but it can be *restated*, and it is not. This exact class of error has already occurred once
in this codebase: audit-1 L-02 was "the claimed cluster binding is operator-supplied **and
the test encodes it incorrectly**."

### Exploit sequence

The precondition is reusing program keypairs across clusters, which `solana/README.md` §4
effectively encourages ("choose deliberate program keypairs, set `declare_id!` /
`Anchor.toml` to their pubkeys **once**, build against those").

1. The team deploys the production program keypairs to devnet for staging. All six program
   ids, and therefore `program`, `config`, and the attestation's `vault`, are identical to
   what mainnet will use.
2. Devnet runs the full flow. The auditor — the same key by design — signs test mint
   attestations. Every devnet transaction is public and permanently archived.
3. Mainnet `initialize` is called with `cluster` copied from the staging deploy config. The
   offline signer reads the same config, so mainnet mints work normally and the
   misconfiguration produces **no on-chain symptom whatsoever**.
4. Anyone replays an archived devnet attestation against mainnet: the domain matches,
   `auditor`, `profile_digest` and `vault` match, the nonce marker is unconsumed on the new
   cluster, and `finalized` is true.
5. `mint_to` executes — an unauthorized supply increase of the devnet test amount into the
   mainnet Vault inventory.

`config.cluster` has no setter, so the deployment cannot be repaired; recovery means
redeploying at fresh program ids, which cascades through the hook and therefore requires a
new RWA mint.

### Impact

Unauthorized supply creation, silently, against the platform's single non-negotiable
invariant. It requires a deployment misconfiguration and is not exploitable against a
correctly-configured deployment — hence Medium rather than High — but the misconfiguration
is invisible, permanent, and of a kind that has already been made once here.

### Recommendation

The robust fix is to add real per-deployment entropy that cannot be mistyped: **bind the
RWA mint pubkey into `Domain` (and ideally into both attestation structs — see I-01).** The
mint is a freshly generated keypair per deployment (`tests/fullflow.ts:192`), unlike every
PDA currently in the domain, so it separates deployments structurally rather than by
operator discipline.

Alongside that, and cheaply:

1. `require!(cluster != [0u8; 32], SupplyError::ZeroCluster)` in `initialize`.
2. Have `finalize` take `cluster` as an instruction argument and assert it equals
   `config.cluster`, forcing the deployer to derive it a second time, independently, at
   go-live (see L-11).
3. Have `scripts/verify-cluster.mjs` print the decoded genesis hash in exactly the byte form
   the instruction expects, and record it in the deployment manifest.

---

## M-02 — Every redemption unwind path is gated on the beneficiary being `Allowed`, including the recoveries written for when they are not

**Severity:** Medium
**Location:** `programs/rwa-redemption/src/lib.rs:281` (`fund_redemption`), `:339`
(`reject_redemption`), `:402` (`cancel_redemption`), `:532` (`refund_funded`)

### Evidence

All four instructions that can move RWA or quote out of an open request carry the same
guard:

```rust
require!(
    load_allowed(&ctx.accounts.beneficiary_record, &ctx.accounts.request.beneficiary, now)?,
    RedemptionError::BeneficiaryNotAllowed
);
```

and `refund_funded` — added by audit-3 M-03 and described in ADR-012 as "the exit for the
only otherwise-stuck state in the machine" — is additionally gated on `ensure_funded`, so it
cannot touch a `Pending` request at all. `redemption-core` confirms there is no other
transition out of `Pending`, and the program exposes no further instruction that reads a
`RedemptionRequest`.

Crucially, "not allowed" is not only the adversarial case. `compliance-core::is_allowed` is
`status == Allowed && (valid_until == 0 || valid_until >= now)`, so an ordinary record with
a KYC expiry silently becomes disallowed the instant the clock passes `valid_until`.

### Failure sequences

**(a) `Pending`, no adversary.** Alice's record has `valid_until = T`. She calls
`request_redemption` an hour before `T`; her RWA moves into the escrow ATA. The treasurer
does not fund before `T` — a multi-day funding cycle is the normal case, which is why the
timeout-cancel path exists at all. At `T` her record expires. Now `fund` fails, `reject`
fails, and `cancel` fails even after the timeout elapses. `refund_funded` returns
`NotFunded`. The escrowed RWA is immovable by any single role.

**(b) `Funded`, deliberate block.** A request is funded, then the compliance authority
blocks Alice for a legitimate reason. `claim_redemption` is permissionless, never re-checks
compliance, and both its legs succeed — the RWA goes escrow → Vault (both permanently-
allowed system addresses) and the quote leg is a plain transfer on a hook-less mint. So
**anyone** can push the cash to the blocked party. The admin's counter-move,
`refund_funded`, fails with `BeneficiaryNotAllowed`. The escape hatch is inverted: it works
only when it is not needed.

Note that simply deleting the guards would not fix (a): the RWA return leg fires the
compliance hook, which independently rejects a destination whose owner is not allowed
(`rwa-transfer-hook/src/lib.rs:141-155`, in both the paused and unpaused branches). Any
working recovery must send the RWA somewhere permanently allowed.

### Impact

In (a), a user's principal is frozen indefinitely, and the operator's own unwind tool
(`reject`) is disabled in exactly the scenario it exists for. In (b), the operator cannot
stop a payout to a newly-sanctioned beneficiary except by pausing the entire project — and
even while paused they still cannot refund.

Both are recoverable, but only by cooperation between roles and only in a way that leaves an
uncomfortable trail: an atomic transaction
`[compliance.set_status(Alice, Allowed), redemption.reject_redemption(id), compliance.set_status(Alice, Blocked)]`
works, because `set_status` is freely re-settable and `reject` needs only the redemption
manager. That requires the compliance authority and the redemption manager to act together,
briefly re-allows a possibly-sanctioned wallet on-chain, and is impossible if the compliance
authority key is lost. **It is not documented anywhere in the code, the comments, or the
runbook.**

This is exact parity with `contracts/src/RedemptionEscrow.sol`, so the decision belongs in
the shared spec rather than only in the port. It nonetheless contradicts ADR-012's "the only
otherwise-stuck state" claim: `Pending` has *three* independent guards that can strand it
versus `Funded`'s one, and it is the state that received no recovery path.

### Recommendation

Add a redemption-manager or admin-gated path that returns escrowed RWA to the **Vault
inventory ATA** rather than to the beneficiary, for both `Pending` and `Funded`. The Vault
authority is a pinned compliance system address that `validate_status_change` guarantees is
permanently `Allowed` with no expiry, so the hook accepts it regardless of the beneficiary's
status, and it works while paused via the existing escrow carve-out. Move the request to a
terminal state and emit an event carrying the beneficiary and both amounts so the off-chain
ledger records the liability. Omit `load_allowed` on that path — running when the
beneficiary is *not* allowed is its entire purpose.

For (b) specifically, the minimal change is to drop `load_allowed` from `refund_funded` and
route its RWA leg to the Vault when the beneficiary is not allowed; the hook still enforces
the destination rule, so it degrades gracefully.

If instead the intent is that a blocked beneficiary's assets stay frozen on-chain (the
previously accepted position for `cancel_redemption`), state that explicitly in
`docs/spec/redemption-state-machine.md` and the operator runbook, document the
re-allow/reject/re-block procedure, and correct ADR-012 — because as written the code reads
as an oversight rather than a decision.

---

## M-03 — `refund_funded` is an unscoped admin reversal of a funded redemption, contradicting a frozen platform invariant

**Severity:** Medium
**Location:** `programs/rwa-redemption/src/lib.rs:523-597`

### Evidence

The root `CLAUDE.md` lists among the non-negotiable invariants:

> Redemption is on-chain request → fund → permissionless claim; **funded quote is never
> withdrawable** and pays only the recorded beneficiary.

`refund_funded`'s only guards are `registry.finalized`, `status == Funded`, the beneficiary
being `Allowed`, and `has_one = admin`. There is **no** requirement that the quote leg is
actually unsettleable — nobody checks that the beneficiary's quote account is frozen — and
**no** delay after funding.

### Exploit sequence

1. The treasurer funds request 7 at the then-current redemption price.
2. The redemption price falls. Before anyone calls the permissionless `claim`, the admin
   calls `refund_funded(7)`.
3. The quote returns to the treasurer, the RWA returns to Alice, and the request moves to
   the terminal `Refunded` state.
4. Alice has lost the price she was contractually locked into and must re-request at the
   new, worse price.

Repeatable for every funded request. `fund` therefore becomes a revocable option written by
the treasury against redeemers, and it doubles as a censorship lever against any specific
beneficiary.

### Impact

No direct theft — the beneficiary keeps their RWA — but the "funded quote is never
withdrawable" property is exactly what makes on-chain funding meaningful rather than a
promise, and it is gone. ADR-012 §M-03 justifies the escape hatch (a frozen quote account
stranding a `Funded` position) but never scopes it to that situation, so the implemented
instruction is far broader than the problem it was written for.

### Recommendation

Scope the hatch to its stated purpose:

1. Add `funded_at: u64` to `RedemptionRequest`, set it in `fund_redemption`, and require
   `now >= funded_at + REFUND_GRACE` in `refund_funded`. During the grace window `claim` is
   exclusive, which is the property the invariant promises.
2. Require evidence of unsettleability: take the beneficiary's canonical quote ATA as an
   account and assert it is frozen (or that it does not exist), so the instruction can only
   fire in the circumstance it was designed for.
3. Keep it admin-gated and keep the `RedemptionRefunded` event; add the reason to the event.

Note this interacts with M-02(b): the fix there loosens `refund_funded`'s compliance guard
while the fix here tightens its economic guard. Both are needed, and they are compatible —
a frozen-or-missing quote ATA is precisely the state a blocked beneficiary is in.

---

## M-04 — The go-live flag is forgeable by the compliance admin, and the bootstrap pins are one-shot and uncorrectable

**Severity:** Medium
**Location:** `programs/rwa-compliance/src/lib.rs:89-98` (`set_finalized`), `:116-154`
(`set_system_addresses`), `:429-443` (`SetFinalized` context);
`programs/rwa-supply-controller/src/lib.rs:106` (`finalize`), `:200-204`

### Evidence

`set_finalized` derives the expected CPI signer from `registry.supply_controller`:

```rust
let (expected, _) = Pubkey::find_program_address(
    &[SUPPLY_CONFIG_SEED], &ctx.accounts.registry.supply_controller);
require_keys_eq!(ctx.accounts.supply_config.key(), expected, ComplianceError::NotSupplyController);
```

That field is admin-supplied data, written once at `set_system_addresses` with no validation
beyond `!= Pubkey::default()` — not `executable`, not loader-owned, nothing. The only thing
that "proves" it correct is `finalize`'s
`require_keys_eq!(registry.supply_controller, crate::ID)` — a check that lives *inside the
program being authenticated*, and is therefore skipped simply by never calling it.
`system_set` is never cleared and no instruction can rewrite `supply_controller`, `vault` or
`escrow`.

The doc comment at `rwa-compliance/src/lib.rs:82-88` — "a direct call — even by the registry
admin — cannot flip this flag and skip `finalize`'s cross-program wiring checks" — is
factually wrong.

### Exploit and failure sequences

**(a) Forged go-live.** The holder of `registry.admin` deploys a program `EVIL` with one
instruction that CPIs `rwa_compliance::set_finalized` signing seeds
`[b"supply-config", bump]`. At `set_system_addresses` they pass `supply_controller = EVIL`.
Calling `EVIL` sets `Registry.finalized = true`. This flips the global flag gating
`rwa_vault::buy` and every redemption leg **without the deployer's upgrade-authority
signature** that the real `finalize` requires (`Finalize` context:
`program_data.upgrade_authority_address == Some(admin.key())`) and without any of
`finalize`'s wiring checks. Where `registry.admin` and the deployer are different keys — a
normal separation of duties — this is a genuine role-boundary break.

**(b) Permanent brick.** Whether reached via (a) or otherwise, once `Registry.finalized` is
set the real `finalize` reverts forever: its CPI hits
`require!(!r.finalized, AlreadyFinalized)`. `Config.finalized`, which gates `mint` and
`burn_supply`, can never be set. Issuance is permanently dead.

**(c) The realistic version is a typo.** `Registry.supply_controller` is the supply
**program id**; `rwa_vault::Config.supply_controller` is the supply **config PDA**. Same
field name, different kind of value, and `tests/fullflow.ts` passes exactly those two
different things sixteen lines apart. Passing the config PDA — or any wrong key — makes both
`set_finalized` and `finalize` permanently unreachable, with no correction path, because
`set_system_addresses` cannot be re-run and the `Registry` is an `init` singleton PDA. The
same applies to a wrong `vault` or `escrow`, and to every other one-shot pin: none of
`supply::Config.{token_mint, vault, registry, profile_digest, cluster}` or
`vault::Config.{supply_controller, rwa_mint, quote_mint, registry}` has a setter or a
re-initialization path. `finalize`'s own comment — that a bootstrap typo "is caught while it
is still recoverable" — is therefore false.

This directly contradicts ADR-012's conclusion that "the permanent-DoS state is
unreachable." That holds only under the assumption that `registry.supply_controller` is the
honest controller, which nothing on-chain enforces. Audit-3's recommendation had two halves —
derive the signer from a compiled constant, *and* make the failure mode non-terminal — and
only the first was implemented, in a weakened form that moves the trust rather than removing
it.

### Impact

No funds are at risk: nothing has been minted before `finalize`, so there is nothing to buy
or redeem. The impact is a permanently unusable deployment requiring a full redeploy — and
because `rwa_compliance::ID` is a compile-time dependency of every other program *and* is
baked into the hook's `ExtraAccountMetaList`, "full" means essentially the whole stack plus a
new RWA mint. It is recoverable by program upgrade, so it is only truly permanent for a
deployment that has revoked its upgrade authority — which is the recommended end state, and
which L-05 shows is itself a trap.

### Recommendation

Four changes, all small:

1. **Bind go-live to the deployer.** Add the compliance program's own upgrade-authority gate
   to the `SetFinalized` context, reusing the exact `Program`/`ProgramData` constraint pair
   already in `Initialize` (`:368-371`). This makes the flag deployer-bound regardless of
   what id was pinned, and closes (a) outright.
2. **Validate the pin.** Take `supply_controller` as an account rather than a bare `Pubkey`
   and require `executable == true` — or, better, type it as `Program<'info, …>`.
3. **Make the pins correctable before go-live.** Gate `set_system_addresses` on
   `!registry.finalized` instead of `!registry.system_set`, and add admin setters gated on
   `!config.finalized` for the supply and vault config pins. Once `finalize` succeeds
   everything freezes forever, which is the property that actually matters.
4. **Make the flag transition idempotent.** In `set_finalized`, return `Ok(())` early when
   the flag is already set (or have `finalize` skip the CPI in that case). `finalize` keeps
   its own `AlreadyFinalized` guard on `Config.finalized`, so single-shot go-live semantics
   are preserved; only the ability of a stray pre-set to block issuance forever is removed.

Also rename one of the two `supply_controller` fields, and fix the two false comments.

---

## M-05 — The offline signer cannot produce Solana attestations, so auditor signatures must come from unreviewed tooling

**Severity:** Medium
**Location:** `signer/` (no Solana support); `solana/crates/attestation/src/lib.rs`;
`solana/tests/fullflow.ts:153`

### Evidence

A search for the Solana domain string across the repository returns exactly three
implementations:

```
solana/crates/attestation/src/lib.rs:37     the on-chain verifier's pre-image (Rust)
solana/tests/attestation-parity.ts:15       a test that re-derives it with ethers
solana/tests/fullflow.ts:157                an inline mocha helper that signs it
```

`signer/` — the offline Go EIP-712 signer that exists to give the auditor an air-gapped,
what-you-see-is-what-you-sign path — contains no reference to Solana in any Go file or
document. `solana/README.md` asserts "The signer only needs this new message encoding — no
new key type," which is accurate about what *would* be required, but the work has not been
done.

### Impact

There is currently no production path to produce a Solana mint or burn attestation. In
practice the auditor key would be used against ad-hoc tooling — the mocha helper, or a
hand-rolled script — to sign a 32-byte digest whose construction the auditor cannot inspect
or independently confirm. That is exactly the property the offline signer exists to provide.
A compromised or merely buggy helper can display one set of human-readable values while
hashing a different `(record_key, amount, nonce, vault)` tuple, and the auditor has no way to
detect it. The on-chain verification is sound; the weak link moves to where the signature is
created, which is the least observable point in the system.

The exposure is amplified by I-02: the mint and burn payloads are word-for-word identical
apart from their typehash, so a template error in unreviewed tooling turns a burn
authorization into a mint authorization for the same amount.

### Recommendation

Implement the Solana attestation encoding in `signer/` before any mainnet bootstrap:
`Domain{cluster, program, config}` plus both hash structs, reusing the existing secp256k1
key handling and the hardware-wallet path (ADR-006). Display the decoded fields — cluster
label, program id, config PDA, record key or operation id, human-readable amount, nonce,
expiry, Vault — for confirmation before signing, matching the EVM flow, and make the
mint-versus-burn distinction visually unmissable. Add
`solana/tests/vectors/mint-attestation.json` to the signer's own test suite and to
`make vectors-check`, so the Go, Rust and TypeScript encodings are gated against each other
in CI rather than only Rust against TypeScript.

Until that exists, treat the Solana deployment as not production-ready regardless of the
on-chain code quality.

---

## M-06 — `set_auditor` takes effect instantly on one signature

**Severity:** Medium
**Location:** `programs/rwa-supply-controller/src/lib.rs:382-393`

### Evidence

```rust
pub fn set_auditor(ctx: Context<AdminOnly>, new_auditor_eth: [u8; 20]) -> Result<()> {
    require!(new_auditor_eth != [0u8; 20], SupplyError::ZeroAuditor);
    c.auditor_eth = new_auditor_eth;      // effective immediately
```

`AdminOnly` requires only `has_one = admin`. Note the asymmetry within the same program:
rotating the *admin* uses a two-step propose/accept handshake with a cancel path
(`:397-439`), while rotating the *auditor* — the key that authorizes supply creation — is one
instruction with immediate effect.

### Impact

The point of an offline auditor key is that it is not hot, so compromise of the day-to-day
operations key cannot create supply. `set_auditor` erases that distinction: whoever holds the
supply-controller admin key can, in a single transaction, install an auditor address they
control and thereafter mint arbitrary supply under signatures that verify correctly.

The blast radius is bounded but not trivial. Minted supply lands only in the canonical Vault
inventory ATA, and the only ways out are `buy` (which requires paying the configured price)
and the attested burn — so a lone rogue admin inflates supply and desynchronizes it from the
real-world asset record without directly extracting value. Combined with M-07 (a pricer
setting `purchase_price = 1`) the inflated inventory becomes freely extractable. There is
also no on-chain signal distinguishing supply attested by the real auditor from supply
attested after a rotation: an indexer replaying `Minted` events sees both as valid.

This is parity with the EVM `DEFAULT_ADMIN_ROLE`, but it deserves stating plainly because the
invariant it undermines is advertised as non-negotiable.

### Recommendation

1. Give the rotation at least the ceremony of the admin rotation, and preferably a delay:
   store `pending_auditor` and `pending_auditor_effective_at = now + AUDITOR_ROTATION_DELAY`
   (7 days is a reasonable default), rejecting `mint`/`burn_supply` against the new auditor
   before that timestamp. The delay is the control that matters — it gives the operator a
   window to notice and `pause`.
2. Require the registry admin to co-sign, as `finalize` already does, so one compromised key
   is insufficient.
3. Make `AuditorChanged` a page-the-humans event in the indexer and say so in the runbook.

See also L-06: the rotation is not epoched, so rotating away and back re-arms old signatures.

---

## M-07 — The pricer can set any non-zero price instantly, with no bound, deviation cap, or delay

**Severity:** Medium
**Location:** `programs/rwa-pricing/src/lib.rs:109` (`set_purchase_price`), `:122`
(`set_redemption_price`)

### Evidence

The only validation on either price is `new_price != 0`. There is no floor, ceiling, maximum
per-update deviation, cooldown, or timelock, and `rwa_vault::buy` reads
`strategy.purchase_price` live at execution time.

### Impact

A single compromised or coerced pricer key converts directly into loss of the entire Vault
inventory: set `purchase_price = 1`, and any allowed wallet buys the whole inventory for
approximately nothing in the very next transaction. `max_quote_amount` protects the *buyer*
from an adverse price, not the protocol from a favourable one, and the buyer needs no
privilege beyond being on the allowlist.

In the other direction, inflating `redemption_price` raises the quote liability recorded on
every subsequent `request_redemption`. That one requires the treasurer to actually fund it,
so it is a check-and-balance rather than a direct drain — but pricer-plus-treasurer collusion
is a one-transaction treasury drain, and a rogue pricer alone can manufacture liabilities
that look legitimate on-chain.

This is inherited faithfully from `FixedPriceStrategy.sol`, so it is platform-wide rather
than a Solana regression, but the economic safety of the Vault currently rests entirely on
the operational custody of one ed25519 key with no on-chain damping.

### Recommendation

1. Store admin-settable `min_price`/`max_price` bounds and enforce them on every pricer
   update. This alone converts total inventory loss into a bounded loss.
2. Add a maximum per-update deviation (for example ±10%) plus a cooldown, so a large move
   requires many transactions over time and is visible to monitoring before it completes.
3. Require `!registry.paused` for price updates, so the emergency pause also freezes pricing.
4. At minimum, alert on every `PurchasePriceUpdated`/`RedemptionPriceUpdated` event and hold
   the pricer key in the same custody tier as the treasurer key.

---

## M-08 — `claim_redemption`'s quote destination is the protocol's only unpinned token account, and claim is permissionless

**Severity:** Medium
**Location:** `programs/rwa-redemption/src/lib.rs:965-967`

### Evidence

```rust
// Pays only the recorded beneficiary — bound to request.beneficiary.
#[account(mut, token::mint = quote_mint, token::authority = request.beneficiary)]
pub beneficiary_quote: Box<InterfaceAccount<'info, TokenAccount>>,
```

Every other custody account in the file is address-pinned to a canonical ATA — `escrow_token`,
`escrow_quote`, `vault_token`, and even `refund_funded`'s `treasurer_quote` (`:1018-1026`).
This is the only token account in the program that is neither ATA-pinned nor protected by the
hook's `ImmutableOwner` rule, because the quote leg fires no hook. And `claim_redemption`
requires no signer at all.

### Exploit sequence

1. The attacker creates token account `A` with `mint = quote_mint`, owner = attacker.
2. `SetAuthority(CloseAccount → attacker)`.
3. `SetAuthority(AccountOwner → beneficiary)`. Verified against
   `spl-token-2022-11.0.0/src/processor.rs:723-759`: the owner change clears `delegate` and
   `delegated_amount`, and clears `close_authority` **only for native accounts** — so for a
   normal stablecoin the attacker's close authority survives. `A` now satisfies both
   constraints.
4. The attacker calls `claim_redemption(id)` — permissionless — passing `beneficiary_quote = A`.
   The entire payout lands in an account of the attacker's choosing.

**This is not theft.** `CloseAccount` requires `amount == 0` for non-native accounts
(`processor.rs:1308`, `NonNativeHasBalance`), so the attacker cannot drain `A`; they can only
reclaim the rent after the beneficiary empties it. The beneficiary owns `A` and can spend
from it.

### Impact

Two real consequences. First, the payout lands somewhere the operator's reconciler almost
certainly is not watching — every other custody flow in the protocol is ATA-based — so
on-chain and off-chain ledgers silently diverge, and a legitimate payment looks like a
missing one. Second, and decisively: `beneficiary` is a `Signer`, so a **program** may
legitimately request a redemption for its own PDA via `invoke_signed`. A payout into a
non-ATA account is then unrecoverable unless that program happens to support arbitrary token
accounts — which most do not. That is user-funds loss triggerable by any unprivileged third
party.

### Recommendation

One line, matching the rest of the file:

```rust
#[account(
    mut,
    token::mint = quote_mint,
    token::authority = request.beneficiary,
    address = anchor_spl::associated_token::get_associated_token_address_with_program_id(
        &request.beneficiary, &quote_mint.key(), quote_mint.to_account_info().owner
    ) @ RedemptionError::NotCanonicalAta,
)]
pub beneficiary_quote: Box<InterfaceAccount<'info, TokenAccount>>,
```

---

## M-09 — The quote mint's decimals are never bound to the price scale

**Severity:** Medium
**Location:** `programs/rwa-vault/src/lib.rs:63-66`,
`programs/rwa-redemption/src/lib.rs:61-64`; `crates/pricing-math/src/lib.rs:89-122`

### Evidence

Both initializers validate `strategy.token_decimals == rwa_mint.decimals`, and
`validate_quote_mint` validates the quote mint's *program and extensions*. Nothing anywhere
ties the price's scale to `quote_mint.decimals`:

```rust
quote = token_amount * price_per_whole_token / 10^token_decimals   // token_decimals = RWA decimals
```

The result is only correct in quote base units if the operator happened to express
`price_per_whole_token` in quote base units per whole RWA token. That is pure convention,
checked by nothing, and `quote_mint` has no setter in either program.

### Impact

A decimals mismatch between what the operator priced against and the quote mint actually
deployed produces a silent, permanent, order-of-magnitude error in every trade. Pricing
against a 6-decimal USDC while deploying against a 9-decimal stablecoin underpays every
redeemer by 1000× and undercharges every buyer by 1000×, forever, with no on-chain symptom
and no way to correct the quote mint.

The severity is bounded by two things I verified: `finalize` *does* assert
`redemption_config.quote_mint == vault_config.quote_mint`
(`rwa-supply-controller/src/lib.rs:171-175`), so the vault and escrow cannot end up on
different quote mints; and `finalize` re-asserts the RWA-decimals binding. Neither touches
the quote side.

### Recommendation

Store `quote_decimals` in both `Config`s at `initialize`, read from `quote_mint.decimals`,
and require it to equal an explicit instruction argument so the deployer must state the scale
they priced against — the same "restate it independently" pattern recommended in M-01 and
L-11. Document the unit of `Strategy.purchase_price`/`redemption_price` in the type's doc
comment. Re-assert both stored `quote_decimals` values in `finalize`.

---

## L-01 — `secp256k1_recover` accepts malleable high-`s` signatures; the EVM twin rejects them

**Severity:** Low
**Location:** `programs/rwa-supply-controller/src/lib.rs:459-470`

Verified in the actual runtime: `agave-syscalls-3.1.4/src/lib.rs:930` uses
`libsecp256k1::Signature::parse_standard_slice`, and `libsecp256k1-0.6.0/src/lib.rs:497-510`
rejects only **overflow** (`r` or `s` ≥ `n`), not high-`s`. So given a valid `(r, s, v)`,
the mutated `(r, n−s, v^1)` also passes `verify_signature`.

**Not exploitable for a double mint or burn** — replay is keyed on the nonce, record-key and
operation marker PDAs, not on signature bytes, so a mutated encoding consumes the same
marker. The consequences are: (1) `contracts/src/SupplyController.sol:88,138` uses
OpenZeppelin `SignatureChecker` → `ECDSA.tryRecover`, which *rejects* high-`s`, so a
signature the Solana port accepts the EVM deployment rejects — a parity break for a stack
whose whole premise is one signer for both chains; and (2) any off-chain component that
dedupes attestations by signature hash can be confused by two distinct encodings of the same
authorization.

**Fix:** reject `s > n/2` before calling `secp256k1_recover` — compare the 32-byte
big-endian `s` against `7FFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 5D576E73 57A4501D DFE92F46 681B20A0`.

Explicitly checked and safe in the same code path: `recovery_id ≥ 4` yields
`InvalidRecoveryId`; `r == 0` or `s == 0` yields `InvalidSignature`; a recovered point at
infinity yields `InvalidSignature`, so **the recovered pubkey can never be the identity** and
the classic `ecrecover`-returns-zero pitfall does not apply. `auditor_eth` is a fixed
20-byte equality target not influenceable by an attacker.

---

## L-02 — `validate_rwa_mint` reads the *last* `PermissionedBurn` TLV entry where Token-2022 reads the *first*

**Severity:** Low (latent parser divergence, not currently reachable)
**Location:** `programs/rwa-transfer-hook/src/lib.rs:311-316`

```rust
if ext_type == EXT_PERMISSIONED_BURN {
    ...
    permissioned_burn_authority = Some(a);   // last wins
}
```

Token-2022's `get_extension_indices` returns on the **first** type match
(`spl-token-2022-interface-2.1.0/src/extension/mod.rs:163-165`), and the deployed processor
reads it there (`spl-token-2022-11.0.0/src/processor.rs:1143`). A mint laid out as
`[14/64/hook][28/32/ATTACKER][28/32/SUPPLY_PDA]` would pass
`validate_rwa_mint(..., Some(supply_pda))` while its live burn authority is `ATTACKER` —
permanently DoSing `controller_burn` and opening an unattested burn path.

**What stops it today:** Token-2022 cannot emit duplicate TLV entries — `init_extension`
resolves through `get_extension_indices(init = true)`, which returns the existing entry and
then errors `ExtensionAlreadyInitialized` — and the runtime forbids assigning a non-zeroed
account into Token-2022's ownership, so raw-crafted TLV bytes cannot be introduced. The
divergence is latent, not live.

**Fix:** reject duplicates rather than last-wins —
`require!(permissioned_burn_authority.is_none(), HookError::InvalidMint);` before the
assignment, and track and reject a second type-14 entry the same way. A hand-rolled parser
of a security-critical structure should not disagree with the authoritative one about
anything, even where the disagreement is currently unreachable.

---

## L-03 — `redemption_timeout` is unbounded and immutable; the EVM enforces a range

**Severity:** Low
**Location:** `programs/rwa-redemption/src/lib.rs:36-79`

`initialize` stores the raw argument with no validation beyond the zero-key loop, and there
is no `set_redemption_timeout` anywhere in the program — the value is permanent for the life
of the deployment.

`contracts/src/RWAFactory.sol:176-178` rejects anything outside
`[MIN_REDEMPTION_TIMEOUT = 1 days, MAX_REDEMPTION_TIMEOUT = 365 days]`. **The port dropped
that guard**, which makes this a parity regression rather than merely a missing check.

`can_cancel` correctly uses `saturating_add` (`redemption-core:93`), so there is no
wrap-around bug — but `timeout = u64::MAX` yields `available_at = u64::MAX` and
`now < available_at` is true forever, permanently removing the beneficiary's only
self-service exit from `Pending`. Combined with M-02 that is how principal gets stranded.
`timeout = 0` is the other extreme: cancel is available in the same block as the request, so
a user can race every `fund_redemption` the treasurer submits (the loser's transaction simply
fails, so this is operational churn rather than a vulnerability).

**Fix:** `require!((86_400..=31_536_000).contains(&redemption_timeout), RedemptionError::InvalidTimeout);`
in `initialize`, restoring EVM parity, plus an admin setter with the same bound that applies
only to requests created after the change so a rotation cannot retroactively extend live
escrows.

---

## L-04 — Two RWA-leg token-program accounts were missed by the audit-3 L-01 pinning

**Severity:** Low
**Location:** `programs/rwa-supply-controller/src/lib.rs:556` (`MintSupply.token_program`),
`:593` (`BurnSupply.token_program`)

ADR-012 records L-01 as "pinned **every** `rwa_token_program` account to
`anchor_spl::token_2022::ID`". These two were not — they are bare
`Interface<'info, TokenInterface>` with no address constraint, unlike
`rwa_vault::ControllerBurn` (`:439`), `rwa_vault::Buy` (`:513`) and all four redemption
contexts.

`MintSupply.token_program` is the target of a PDA-signed `mint_to` CPI where the config PDA
signs as mint authority. `Interface<TokenInterface>` accepts exactly two ids —
`anchor-spl-1.1.2/src/token_interface.rs:15` defines
`static IDS: [Pubkey; 2] = [spl_token_interface::ID, spl_token_2022_interface::ID]` — so the
only substitution available is the legacy Token program, which fails closed on its own
`check_account_owner` because the mint is Token-2022-owned. `BurnSupply.token_program` is
forwarded into `controller_burn`, where it *is* pinned, so that substitution is caught one
frame later.

Not exploitable, but this is the last place a PDA-signed CPI is delivered to a caller-chosen
program id, and its safety depends on a check inside a third-party program rather than a
local constraint — precisely the reasoning that motivated audit-3 L-01.

**Fix:** add `#[account(address = anchor_spl::token_2022::ID @ SupplyError::WrongTokenProgram)]`
to both, and a `WrongTokenProgram` variant to `SupplyError`.

---

## L-05 — Revoking the upgrade authority, or rotating the config admin, before `finalize` permanently bricks go-live

**Severity:** Low
**Location:** `programs/rwa-supply-controller/src/lib.rs:621` (`has_one = admin`), `:657-660`

The `Finalize` context requires both `config.admin == admin` and
`program_data.upgrade_authority_address == Some(admin.key())`. So `finalize` is only ever
callable while the config admin *is* the program's upgrade authority.

Two ordinary operational actions therefore brick go-live permanently:

- Revoking the upgrade authority before `finalize` — the standard immutability hardening step,
  and the one the deployment checklist naturally invites.
- Rotating the config admin via `propose_admin`/`accept_admin` to a key that is not the
  upgrade authority, before `finalize`.

Either makes `finalize` unreachable, so `Config.finalized` and `Registry.finalized` can never
be set and mint, burn, buy and every redemption leg stay disabled forever.

**Fix:** document the ordering as a hard release-checklist step (`finalize` **before** any
authority change), and preferably drop the upgrade-authority constraint from `finalize` — the
config-admin plus registry-admin signatures already gate it, and M-04's recommendation moves
the deployer-binding to `set_finalized` where it belongs.

---

## L-06 — Auditor rotation is not epoched: rotating away and back re-arms every unused old signature

**Severity:** Low
**Location:** `programs/rwa-supply-controller/src/lib.rs:382-393`;
`crates/attestation/src/lib.rs:125`, `:146`

Because `auditor` is a field of the signed struct, rotating A → B correctly invalidates all of
A's outstanding signatures — B's digest differs, and A's signature over A's digest recovers to
A ≠ B. That is a genuinely good implicit revocation primitive and worth keeping.

But rotating B → A restores them all. The markers do not help, because an *unused* nonce was
never consumed. Sequence: A signs `mint(record R, nonce N, amount X)`; it is never relayed; A
is believed compromised and rotated out; later A is restored (false alarm, or the same key
re-provisioned into a new HSM); anyone who archived the signature can now mint X.

**Fix:** add `auditor_epoch: u64` to `Config`, increment it in `set_auditor`, and bind it into
`Domain`. Rotation then invalidates old signatures permanently rather than conditionally.

---

## L-07 — `set_strategy` is dead code in both the vault and the redemption program

**Severity:** Low
**Location:** `programs/rwa-vault/src/lib.rs:292` + `:451`;
`programs/rwa-redemption/src/lib.rs:115` + `:749`

In both programs `new_strategy` is pinned to
`seeds = [STRATEGY_SEED], seeds::program = rwa_pricing::ID` — the singleton `Strategy` PDA,
which is already exactly what `initialize` stored in `config.strategy`. `rwa_pricing`'s
`Initialize` is `init` on that same PDA, so no second `Strategy` account can ever exist.
`set_strategy` can therefore only ever write back the value it already holds.

The ADR-012 L-04 pin removed the documented parallel to `Vault.setStrategy` without removing
the instruction, so the strategy-migration capability no longer exists: neither program can be
repointed at a new pricing deployment without a program upgrade.

**Fix:** either delete both instructions (and say in the ADR that strategy migration now
requires an upgrade), or keep the `Account<Strategy>` type and the `token_decimals` check
without the seeds pin, and gate acceptance on an admin-curated allowlist instead.

---

## L-08 — `buy` permits `recipient_token == vault_token`, and Token-2022 skips the hook entirely on a self-transfer

**Severity:** Low
**Location:** `programs/rwa-vault/src/lib.rs:504-505`, `:215-219`

`recipient_token` is constrained only by `token::mint = rwa_mint`, so it may be the vault's own
inventory ATA. Token-2022 v11 short-circuits self-transfers at
`spl-token-2022-11.0.0/src/processor.rs:503-509` — I verified the early `return Ok(())` sits
before the destination account is even unpacked, and therefore before the transfer hook is
invoked. **On that path the compliance hook never runs at all.**

The only thing catching it is the post-CPI delta assertion at `:215-219`, which does hold
(`vault_before - vault_after == 0 ≠ token_amount`). So this is not a free-RWA path — but a
single arithmetic line is the sole defence for an aliasing case the account constraints
explicitly permit, in the one situation where the hook is bypassed by design.

Related and same severity: `recipient_token` may legally be a *second* RWA account owned by the
vault config PDA or by the redemption escrow PDA. Both are permanently `Allowed` system
addresses, so the hook passes and `buy` succeeds — and the RWA lands where no instruction can
ever move it, because every custody path pins the canonical ATA. That is buyer-funded
self-griefing only.

**Fix:** `require_keys_neq!(ctx.accounts.recipient_token.key(), ctx.accounts.vault_token.key(), VaultError::SelfTransfer)`
at the top of `buy`, and consider requiring `recipient_token` to be the canonical ATA of its own
owner.

---

## L-09 — The shared `next_id` counter lets one attacker front-run every redemption request, and request rent is never reclaimable

**Severity:** Low
**Location:** `programs/rwa-redemption/src/lib.rs:777-783`

The request PDA is seeded from the live `config.next_id`, so the client must precompute
`PDA([b"request", next_id])`. Any request that lands first bumps `next_id` and every other
in-flight request dies on `ConstraintSeeds`.

A griefer holding any allowed wallet and one base unit of RWA can therefore front-run every
honest `request_redemption` indefinitely. The cost per grief is a transaction fee plus roughly
0.0014 SOL of rent that is **never recoverable**: there is no `close` instruction for
`RedemptionRequest` in any terminal state, so honest users also permanently burn that rent on
every redemption.

**Fix:** seed by `[REQUEST_SEED, beneficiary, client_nonce]` — no shared counter, no race — or
accept an `expected_id: u64` argument and fail with a distinguishable error. Separately, add a
`close_request` for the four terminal states returning rent to the beneficiary; request PDAs are
seeded on a monotonic counter so a closed address is never reused and closing introduces no
replay surface.

---

## L-10 — Attestations have no maximum validity window

**Severity:** Low
**Location:** `programs/rwa-supply-controller/src/lib.rs:266`, `:327`

The only constraint is `valid_until >= now()`, so an attestation signed with
`valid_until = u64::MAX` is valid forever, or until its nonce is consumed.
`solana/README.md` already identifies the risk — "treat any landed-but-failed mint as a
disclosed, replayable attestation until its nonce is consumed … keep `valid_until` short" — but
that guidance is enforced nowhere in code, and the component that would have to follow it is the
one that does not yet exist for this chain (M-05).

A leaked or disclosed attestation with long validity remains a live authorization to mint its
exact amount indefinitely. The audit-3 H-01 destination pin means it can only ever land in the
canonical inventory ATA, so this is a supply-integrity and reconciliation problem rather than a
theft vector — but the mitigation the design leans on is a convention, not a control.

**Fix:**

```rust
let now = now()?;
require!(valid_until >= now, SupplyError::AttestationExpired);
require!(valid_until <= now.saturating_add(MAX_ATTESTATION_TTL), SupplyError::AttestationTtlTooLong);
```

Pair it with an admin instruction that deliberately consumes a nonce marker (initializing the
marker and doing nothing else), giving operators a first-class way to revoke a disclosed
attestation rather than racing it.

---

## L-11 — `finalize` verifies address topology but not role assignment or economic parameters

**Severity:** Low
**Location:** `programs/rwa-supply-controller/src/lib.rs:106-249`

`finalize`'s stated purpose is that "a bootstrap typo is caught while it is still recoverable."
It checks nineteen conditions, all of them address wiring, mint safety, or RWA decimals. It never
reads a single privileged role or economic parameter — not
`registry.{compliance_authority, pauser, admin}`, `vault_config.{admin, treasurer, treasury}`,
`redemption_config.{admin, treasurer, redemption_manager, redemption_timeout}`,
`strategy.{admin, pricer, purchase_price, redemption_price}`, `config.auditor_eth`,
`config.profile_digest`, or `config.cluster` — nor whether the four canonical custody ATAs it has
just certified as the only valid destinations actually exist.

Most roles are recoverable after go-live through their own setters, which is why this is Low. The
exceptions are the permanent ones: `profile_digest` and `cluster` (M-01) and `redemption_timeout`
(L-03). The broader point is that the single ceremonial gate before a deployment handles real
assets certifies considerably less than its name and documentation imply, and the values it omits
are exactly the ones determining who can withdraw proceeds, set prices, and block wallets.

**Fix:** have `finalize` accept an `ExpectedConfig` struct as instruction data covering every role
and every permanent parameter, and assert each against on-chain state — so the deployer restates
the complete intended configuration in one place and any divergence aborts go-live. Also assert
the four custody ATAs exist with the expected mint and authority, so the first `mint` cannot fail
for a reason that was knowable at bootstrap. Emit the certified set in the `Finalized` event.

---

## L-12 — `rwa_mint` is needlessly writable, serializing every buy and every redemption leg

**Severity:** Low
**Location:** `programs/rwa-vault/src/lib.rs:477`;
`programs/rwa-redemption/src/lib.rs:775`, `:855`, `:891`, `:930`, `:990`

All six contexts mark `rwa_mint` as `mut`, but `transfer_checked` takes the mint **read-only** —
verified at `spl-token-2022-interface-2.1.0/src/instruction.rs:1686`
(`AccountMeta::new_readonly(*mint_pubkey, false)`). Only the supply controller's mint and burn
paths genuinely need the write lock.

Solana's scheduler serializes transactions that take a write lock on the same account, so as
written **the entire protocol serializes on the RWA mint**: no two `buy`s, no two redemption legs,
and no buy concurrent with any redemption leg can execute in parallel. For an asset platform
expecting concurrent investor activity that is a real throughput and liveness characteristic, and
the fix is free.

**Fix:** drop `mut` from `rwa_mint` in all six contexts.

---

## L-13 — Three raw subtractions where the rest of the same file uses `checked_sub`

**Severity:** Low
**Location:** `programs/rwa-redemption/src/lib.rs:307`, `:501`, `:585`

```rust
ctx.accounts.escrow_quote.amount - before == quote_amount        // :307
ctx.accounts.beneficiary_quote.amount - before == quote_amount   // :501
ctx.accounts.treasurer_quote.amount - before == quote_amount     // :585
```

while the same file correctly uses `checked_sub` at `:240`, `:365`, `:428`, `:478` and `:558`.

Not reachable today: `validate_quote_mint` bars `TransferFee`, transfer hooks, confidential
transfer and `PermanentDelegate` on the quote mint, so a quote transfer can only increase the
destination and no intervening CPI can decrement it. But with `overflow-checks = true` an
underflow here is a **panic**, not an `Err`, and if the quote-extension allowlist is ever widened
— adding a newly-introduced "transfer-neutral" extension to `ALLOWED_QUOTE_EXTENSIONS` is exactly
the kind of change that will be proposed — it becomes a live abort.

**Fix:** `.checked_sub(before) == Some(quote_amount)` in all three, matching the file's own
convention.

---

## L-14 — SBF builds are neither version-pinned nor verifiable

**Severity:** Low
**Location:** `Anchor.toml:1`; `.github/workflows/ci.yml:94`, `:121`

`Anchor.toml` declares an empty `[toolchain]` section, which `solana/README.md` notes is
"intentionally left empty (uses the toolchain on PATH)". CI pins the Anchor CLI
(`cargo install --git … --tag v1.1.2 anchor-cli --locked`) but installs the Solana toolchain from
a floating channel:

```yaml
sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"
```

so the platform-tools version — and therefore the emitted sBPF bytecode — drifts with whatever
`stable` resolves to on the day. No job produces a verifiable build (`anchor build --verifiable`
or `solana-verify`), and neither the README's deployment checklist nor the manifest items request
the build hash of *our own* programs, though §5 does correctly ask for the Token-2022 program hash
on the target cluster.

Nobody can therefore confirm that the bytecode running at a given program id was built from this
source. That is the mechanism by which an unauthorized upgrade would be detected, and it is a
prerequisite for the "revoke the upgrade authority" end state (I-08) — immutability is only
meaningful if you can prove what was made immutable. The floating toolchain additionally means a
security patch rebuilt months later may differ from the original in ways unrelated to the fix,
making the diff unreviewable.

**Fix:** pin `anchor_version` and `solana_version` in `Anchor.toml [toolchain]`, pin the installer
to that same version in both CI jobs, add a job running `anchor build --verifiable` (or
`solana-verify build`) that records each program's hash as a CI artifact, extend the manifest
checklist to require all six program hashes and ids, and verify them against the cluster with
`solana-verify verify-from-repo` after deploy.

---

## L-15 — There is no committed bootstrap tooling; the only bootstrap sequence lives in a test file

**Severity:** Low
**Location:** `solana/scripts/` (contains only `verify-cluster.mjs`);
`solana/tests/fullflow.ts:186-281`

The complete bootstrap — create the Token-2022 mint with exactly the `TransferHook` and
`PermissionedBurn` extensions, set the mint authority to the supply-controller PDA, revoke the
transfer-hook update authority, create the four canonical custody ATAs, initialize five programs
in dependency order, build the extra-account-meta list, pin the system addresses with the correct
supply-controller id, and finalize — exists only inside the mocha `before` hook and first `it`
block of `tests/fullflow.ts`.

Nearly every security property established by audits 1–3 is a property of *that exact sequence*,
and several steps are silently unrecoverable if done wrong or skipped: the one-shot
`set_system_addresses` (M-04), the permanent `cluster` and `profile_digest` (M-01), the permanent
`redemption_timeout` (L-03), the finalize-before-authority-change ordering (L-05), and the
hook-authority revocation without which `finalize`'s
`validate_rwa_mint(…, require_hook_authority_none = true)` fails. A production bootstrap driven by
copy-pasting from a test file is where those errors get made, and audit-3 L-05's requirement to
"bootstrap from a pinned, offline-verified environment and record its digest" has nothing to point
at.

**Fix:** promote the bootstrap to a first-class, reviewed, idempotent tool in `solana/scripts/`
(or an `opsctl` subcommand, matching the EVM side): driven by a checked-in config file,
re-runnable, verifying each step's on-chain result before proceeding, printing the values that
will become permanent for explicit confirmation, and ending by re-reading the deployment and
emitting the manifest. Have `tests/fullflow.ts` invoke that tool rather than reimplementing the
sequence, so the tested path and the production path are the same code.

---

## Informational

**I-01 — The attestation digest omits the RWA mint, its decimals, and the destination.**
(`crates/attestation/src/lib.rs:41-44`, `:122-161`.) Bound: `auditor`, `profileDigest`,
`recordKey`/`operationId`, `metadataDigest`, `amount`, `nonce`, `validUntil`, `vault`, plus
`(cluster, program, config)`. Not bound: the RWA mint, its decimals, the destination token
account, the token program. Today `config.token_mint` has no setter and the destination is
ATA-pinned, so the mint is fixed for a given (cluster, program) — but by convention, not by
construction. The programs are upgradeable, so any future instruction re-pointing `token_mint`
would silently re-target every pre-signed attestation; and because `amount` is raw base units with
decimals unbound, such a re-point would also silently re-scale every signed amount. Adding
`bytes32 mint` and `uint8 decimals` to both structs closes this and simultaneously fixes M-01.

**I-02 — Mint and burn payloads are word-identical apart from the typehash, and `bytes32 auditor`
is encoded as an `address`.** The two structs have the same eight fields, same encodings, same
positions, with `recordKey` and `operationId` both `bytes32` at word 3. The typehash is the *sole*
separator — correct, but a single point of failure: mis-template it in a signer, or swap the two
type strings, and a burn authorization for amount A becomes a mint for amount A at the same nonce.
Given M-05 (no reviewed signer exists yet) this deserves belt-and-braces: add an explicit
`uint8 op` discriminator field. Separately, the type string declares `bytes32 auditor` while
`word_address` (`:64-68`) encodes it as an ABI `address`; the words coincide only if the signer
supplies a left-padded 32-byte value, and ethers would reject a raw 20-byte address for a
`bytes32` field. Declare it `address auditor`. EVM↔Solana replay is properly blocked:
`shared/eip712/types.md` uses different struct type strings *and* a different domain typehash and
name.

**I-03 — The `TransferHook` context does not pin the mint.**
(`programs/rwa-transfer-hook/src/lib.rs:616-637`.) Anyone can create a Token-2022 mint pointing its
hook extension at this program. Confirmed non-exploitable: the handler is purely read-only, the
`registry` is hard-pinned via `seeds::program`, both records are re-derived, and an attacker cannot
create the `extra-account-metas` PDA for their own mint because
`initialize_extra_account_meta_list` is upgrade-authority gated — with it absent,
`invoke_execute` calls the hook with only four accounts, which Anchor rejects with
`NotEnoughAccountKeys`, so their token is simply non-transferable. Fails closed. Hardening: store
the RWA mint on `Registry` at `set_system_addresses` and add
`require_keys_eq!(ctx.accounts.mint.key(), registry.rwa_mint)`, so the guarantee stops depending on
the handler remaining side-effect-free.

**I-04 — `invoke_transfer_checked` forwards arbitrary caller signers.**
(`programs/rwa-transfer-hook/src/lib.rs:493-501`.) Every `is_signer` account in
`additional_accounts` — fully attacker-controlled in `buy` and `claim` — is threaded onto the
Token-2022 CPI as a readonly signer. Not exploitable: v11's `validate_owner` only consults those
extras when the authority is a token-program-owned account of exactly `Multisig::LEN` (355 bytes),
and the vault and escrow authorities are 297- and 313-byte `Config` PDAs, so the branch is
unreachable — and inside it each matched signer must genuinely be a signer, so nothing is forged.
Hardening: mirror upstream's `onchain.rs` and thread signers only when the authority really is a
multisig.

**I-05 — `quote_token_program` is not pinned to the quote mint's owning program.**
(`programs/rwa-vault/src/lib.rs:510`, `:553`; `programs/rwa-redemption/src/lib.rs:838`, `:971`,
`:1033`.) Either token program is accepted while the quote ATA address is derived from
`quote_mint.to_account_info().owner`. Not exploitable — whichever program is passed rejects
accounts it does not own, so the mismatch fails closed — but inconsistent with the
`rwa_token_program` pin sitting a few lines away. Fix:
`#[account(address = *quote_mint.to_account_info().owner @ …WrongTokenProgram)]`.

**I-06 — `Registry` is not seeds-pinned in the three sibling initializers.**
(`programs/rwa-supply-controller/src/lib.rs:510`, `programs/rwa-vault/src/lib.rs:408`,
`programs/rwa-redemption/src/lib.rs:724`.) All three accept a bare `Box<Account<'info, Registry>>`
and store its key, without the `seeds` + `seeds::program` constraint used in every operational
context. Safe today — `Account<Registry>` enforces the owning program and discriminator, and the
only instruction creating a `Registry` is `init` on the singleton `[b"registry"]` PDA. Adding the
constraint costs nothing and removes a dependency on a global uniqueness argument that a future
migration instruction would quietly invalidate. Worst case today is a deployer self-DoS of the
M-04 class.

**I-07 — Replay markers and terminal requests are never closed.** Markers accumulate one per nonce,
one per record key and one per operation id, permanently. They **must** never be closed — closing
one would restore the ability to replay its attestation — so document the accumulation as
deliberate and note the cost (three rent-exempt accounts per issuance event) in operating
projections. Terminal `RedemptionRequest` accounts, by contrast, can safely be closed; see L-09.

**I-08 — Retained upgrade authority is unilateral control of every program.** Each program's
upgrade authority can replace its bytecode outright, defeating every control in this report. The
README says to keep it in hardware or multisig custody, which is correct as far as it goes, but
there is no stated threshold, no named signers, no timelock, and no criterion for when authority is
revoked. Because `initialize`, `initialize_extra_account_meta_list` and `finalize` are all
upgrade-authority gated, revocation cannot happen before bootstrap completes — the decision point
is immediately after `finalize` (and see L-05, which makes doing it early a bricking operation).
Record the intended end state explicitly: either a named multisig with a threshold and a published
upgrade timelock (SPL Governance, Squads), or revocation with the acceptance that no future
security patch can ship — which also interacts with the SIMD-0500 deprecation the README flags and
with L-14, since immutability is only meaningful alongside a verifiable build.

**I-09 — Two module doc comments state the opposite of what the code does.**
`programs/rwa-transfer-hook/src/lib.rs:16-20` says the escrow pause carve-out "lets a timed-out
`cancelRedemption` / **`claimRedemption`** complete during an emergency pause" — but
`claim_redemption` carries an explicit `!paused` guard (`rwa-redemption/src/lib.rs:449-452`) and
cannot run while paused. Only `cancel` and `refund_funded` use the bypass. (The redemption module's
own header at `:10-14` describes this correctly.) Separately,
`programs/rwa-compliance/src/lib.rs:82-88` claims "a direct call — even by the registry admin —
cannot flip this flag", which M-04(a) disproves. Both comments describe security properties an
operator or future maintainer would reasonably rely on.

**I-10 — `withdraw_proceeds` and `controller_burn` lack the finalization gate, and there is no
reserve constraint.** (`programs/rwa-vault/src/lib.rs:230`, `:86`.) Both check `paused` and their
authority but not `registry.finalized`, unlike `buy` and every redemption leg. Harmless today —
before `finalize` there are no proceeds and no inventory — but gratuitously inconsistent.
Separately, the treasurer may withdraw 100% of `vault_quote` at any time regardless of outstanding
redemption liabilities. That is consistent with the design (redemptions are funded from the
treasurer's own account, so the Vault holds no reserve), but it means on-chain state carries no
solvency signal at all. If the operating model ever assumes proceeds back redemptions, that
assumption is unenforced.

**I-11 — Donations to the custody ATAs are unrecoverable, and a self-aliasing config value bricks a
leg permanently.** Anyone can transfer RWA or quote tokens into the vault or escrow ATAs; no sweep
instruction exists, so donated tokens are stuck forever (harmless, but it desynchronizes any
reconciler that compares balances to expected liabilities). More consequentially, only
`Pubkey::default()` is rejected for `vault_authority` and `treasurer`: setting either equal to the
redemption `Config` PDA makes `vault_token == escrow_token` or `treasurer_quote == escrow_quote`,
turning that leg into a self-transfer whose delta check then fails permanently, bricking `claim` or
`refund_funded` with no setter to repair it. `finalize` catches the `vault_authority` case (it must
equal the vault config PDA) but not `treasurer`.

Two further micro-items: `fund_redemption(_id)` carries no `expected_quote` argument, so the
treasurer signs blind on an id — not exploitable, since `quote_amount` is immutable after
`request_redemption`, but a cheap operational safety net; and `load_allowed` calls
`find_program_address` on every invocation (~1.5k CU) though the record stores its own bump, so
`create_program_address` after the owner check would be cheaper.

---

## Verified clean

Specifically attacked and held. Listed so a future reviewer knows these were covered rather than
skipped.

- **Hand-rolled Token-2022 encodings.** `build_permissioned_burn_checked_ix` is byte-for-byte
  correct: data `[46][2][amount u64 LE][decimals u8]` = 11 bytes, matching
  `TokenInstruction::PermissionedBurnExtension = 46`, `PermissionedBurnInstruction::BurnChecked = 2`,
  and `BurnCheckedInstructionData` as `#[repr(C)] { amount: U64([u8;8] LE, align 1), decimals: u8 }`
  with no padding. Accounts match `permissioned_burn::instruction::burn_checked` exactly:
  `source(w)`, `mint(w)`, `burn_authority(ro, signer)`, `owner(ro, signer)`. Confirmed against
  `spl-token-2022-interface 3.1.1` and the deployed `spl-token-2022 11.0.0` processor
  (`processor.rs:1129-1181`). The `token_program_id == TOKEN_2022_ID` assert is correctly placed
  before the instruction is built.
- **TLV parsing.** Base 165 + account-type byte; `[u16 LE type][u16 LE len][value]`;
  `off = off + 4 + len` matches upstream's `value_end = value_start + length`; `off` always advances
  by at least 4 so no infinite loop; `checked_add(...).filter(|e| *e <= data.len())` plus
  `off + 4 <= data.len()` rules out out-of-bounds reads and panics; unaligned offsets are fine
  because `Length` is a `PodU16` with align 1. **The type-0 early break is sound** — Token-2022 also
  terminates at `Uninitialized` in both `get_tlv_data_info` and `get_extension_indices`, so anything
  written past a zero entry is invisible to Token-2022 too and cannot hide a live extension. Every
  extension constant is correct: TransferHook 14, PermissionedBurn 28, MetadataPointer 18,
  TokenMetadata 19, GroupPointer 20, TokenGroup 21, GroupMemberPointer 22, TokenGroupMember 23.
  A `len` that does not match an extension's fixed size makes Token-2022's own `get_extension` fail
  the pod size check, and this code uses the same call, so that trick is symmetric. (The single
  divergence found is L-02.)
- **Custody-account pinning delivers `ImmutableOwner`.** `spl-associated-token-account 3.0.4`
  (`processor.rs:112-160`) unconditionally invokes `initialize_immutable_owner` before
  `initialize_account3`, and an account at an ATA address can only be allocated by the ATA program
  (the address is its PDA, and `SystemInstruction::Assign` requires the address to sign). The
  `address = get_associated_token_address_with_program_id(...)` pins therefore do guarantee
  `ImmutableOwner`, as ADR-012 claims.
- **No compliance bypass on any RWA movement.** Unchecked `Transfer` is rejected with
  `MintRequiredForTransfer` once the source carries `TransferHookAccount`; `TransferChecked` always
  fires the hook; `Burn`/`BurnChecked` are rejected by the permissioned-burn extension; transfer-fee,
  permanent-delegate and confidential paths are excluded by the mint allowlist;
  `SetAuthority(AccountOwner)` is blocked by the `ImmutableOwner` requirement; delegate transfers are
  blocked by `owner == src_owner`; and the hook-exempt mint path is pinned to the canonical inventory
  ATA so it cannot seed a mutable-owner account. The hook program id becomes immutable at
  `rwa_supply_controller::initialize` via `require_hook_authority_none = true`, re-asserted at
  `finalize`, and `finalized` is one-way — so the hook can never be repointed after go-live.
- **Marker replay protection.** Pre-creating a marker PDA is impossible for an external party (only
  the supply controller can `invoke_signed` for its own PDAs), and pre-*funding* the address does not
  block `init` — Anchor 1.1.2 falls back to transfer → allocate → assign
  (`anchor-syn-1.1.2/src/codegen/accounts/constraints.rs:1700-1743`). Markers cannot be closed and
  reused. A rejected attestation never consumes a nonce, because `init` is rolled back with the
  transaction when `verify_signature` fails.
- **Attestation type separation.** `MintAttestation` and `BurnAttestation` commit to distinct type
  strings as the first word of the hash struct, so a burn signature cannot be replayed as a mint
  despite identical field arity. The shared mint/burn nonce namespace matches EVM single-mapping
  semantics and is strictly safer than separating them.
- **Escrow solvency and double-pay.** `next_id` is monotonic with `checked_add`; the request PDA is
  `init` so an existing account aborts; there is no `close`, so a PDA can never be re-initialized.
  Every transition is one-way and written *before* the CPIs (proper CEI), and
  `ensure_pending`/`ensure_funded` make each of fund/reject/cancel/claim/refund fire at most once per
  request. Liabilities are recorded from the *measured* escrow delta (`received == rwa_amount`), and
  both quote legs are exact-delta checked, so the shared ATAs always hold at least the sum of open
  liabilities.
- **Reentrancy.** The Agave runtime rejects indirect reentrancy
  (`rwa_redemption → token-2022 → hook → rwa_redemption`). Even without that, statuses are written
  before every CPI, and the L-07 snapshot of `beneficiary_quote` taken *before* the RWA CPI means a
  hostile hook inflating balances mid-CPI could only make the delta check fail (a self-DoS), never
  over-pay.
- **Attacker-controlled `remaining_accounts`.** They cannot smuggle in a permissive compliance
  record, for four independent reasons: Token-2022 re-resolves the extras itself in `invoke_execute`,
  locating the validation PDA by `get_extra_account_metas_address(mint, hook_program)`;
  `ExtraAccountMetaList::add_to_cpi_instruction` resolves `Seed::AccountData{account_index: 0/2}`
  against the fixed `Execute` account list, using `additional_accounts` only as a key→AccountInfo
  lookup pool; `de_escalate_account_meta` force-clears `is_signer` on every resolved extra; and the
  hook re-derives both record PDAs with `find_program_address` regardless.
- **`Box::leak` in the hook's `fallback`.** anchor-syn 1.1.2 declares `__ix_data: &'info [u8]`, so a
  stack local genuinely cannot satisfy the lifetime. Under SBF the global allocator is a bump
  allocator over the 32 KiB heap that is reset per program invocation, and each `Execute` is its own
  invocation, so the 8 bytes are reclaimed at instruction end and cannot accumulate. No UB, no
  aliasing.
- **`buy` cannot underpay.** `quote_purchase` rounds **up** and returns 0 only when the product is 0;
  `price != 0` and `token_amount != 0` are both enforced, so `quote >= 1` always.
  `Strategy.token_decimals` has no setter and `Strategy` is a one-shot singleton, so `buy` not
  re-checking the decimals binding is safe. `buyer_quote == vault_quote` is impossible. All three
  balance accounts are `reload()`ed after their CPIs, and the RWA snapshots are taken before the
  quote leg so no cross-leg staleness exists. `vault_quote` cannot be drained: `withdraw_proceeds` is
  `has_one = treasurer` with both endpoints pinned to canonical ATAs, and redemption funding pulls
  from `treasurer_quote`, never from `vault_quote`.
- **Stealing a claim payout via a crafted `beneficiary_quote`** (the escalation of M-08) is blocked
  by the token program: `CloseAccount` on a non-native account requires `amount == 0`
  (`processor.rs:1308`), and for native accounts `SetAuthority(AccountOwner)` explicitly clears
  `close_authority`. The reverse ordering needs the beneficiary's signature. Delegates are wiped on
  the owner change and cannot be re-approved without the owner.
- **Compliance write access.** `set_status` compares `authority` to
  `registry.compliance_authority` in-handler and the record PDA is seed-bound to `wallet`, so even
  the compliance authority cannot write a record for a different wallet than the seed.
  `init_if_needed` is safe because the handler overwrites every field unconditionally and the seeds
  constraint is re-verified on a pre-existing account. System addresses can never be blocked or given
  an expiry (`validate_status_change`), so the hook's pause bypass and every PDA-signed leg cannot be
  self-DoSed, and the `registry.system_set && src_owner == registry.escrow` guard correctly prevents
  a default-zero `escrow` from matching. M-04 is the only role-boundary break found.
- **Account-size constants.** All seven `SPACE` constants match their field layouts exactly:
  `Registry` 236, `ComplianceRecord` 50, supply `Config` 254, `Marker` 9, vault `Config` 297,
  `Strategy` 122, redemption `Config` 313, `RedemptionRequest` 74.
- **Arithmetic.** `overflow-checks = true` on the workspace release profile means every balance-delta
  subtraction aborts rather than wraps. `pricing-math` keeps intermediates in `u128` where the bounds
  (`u64 × u64 < 2^128`, `10^36 < 2^128`) make overflow impossible, clamps back to `u64` explicitly,
  and `pow10` cannot return zero so no division by zero is reachable. `min_quote_out` is enforced in
  the correct direction, and floor rounding plus `require!(quote != 0)` prevents escrowing RWA
  against a zero payout. `redemption-core::can_cancel` uses `saturating_add`.
- **Host test suite.** `cargo test --locked -p pricing-math -p compliance-core -p redemption-core
  -p attestation` — **21 passed, 0 failed**, including the frozen `shared/vectors/arithmetic.json`
  parity vectors and the frozen attestation golden.

## Previously reported, still open by decision

Carried forward from earlier reviews for completeness, not as new findings.

- **Audit-2 L-01 / audit-1 L-02 — the cluster binding is operator-supplied.** Still true and
  unfixable on-chain. M-01 above shows it is more load-bearing than previously assessed and proposes
  binding the RWA mint as the structural fix.
- **Audit-3 M-03 — the quote mint may retain a freeze authority.** Deliberate, since fiat-backed
  stablecoins keep one; mitigated by the manifest entry and `refund_funded`. M-02 shows the `Pending`
  analogue has no equivalent exit, and M-03 shows `refund_funded` itself is unscoped.
- **`cancel_redemption` retains the beneficiary-allowed check** — a previously accepted decision.
  M-02 does not ask to change it; it asks for an *operator-side* path returning RWA to the Vault
  rather than to the blocked wallet, which the current design lacks entirely.
- **Audit-3 I-01 — the full SBF integration suite is not on the per-PR critical path.** The cheap
  `anchor build` gate is; the validator-backed suite runs weekly. Reasonable given the cost, worth
  revisiting before mainnet.
</content>
