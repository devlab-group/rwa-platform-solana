# Redemption state machine

Status: `None → Pending → {Funded → Completed | Rejected | Cancelled}`
(`redemption_core::RedemptionStatus`, `solana/crates/redemption-core/src/lib.rs`).

| From    | Instruction         | Caller                                     | Guard (ordered)                                                                                                                                              | To        | Asset effect                                                                          |
| ------- | -------------------- | ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | -------------------------------------------------------------------------------------- |
| None    | `request_redemption` | beneficiary (self, `Signer`)                | `registry.finalized`; `!registry.paused` (`ProjectPaused`); caller allowed (`CallerNotAllowed`); `rwa_amount != 0` (`ZeroAmount`); `deadline >= now` (`DeadlineExpired`); quote via `pricing_math::quote_redemption`, `!= 0` (`ZeroQuote`), `>= min_quote_out` (`QuoteBelowMin`) | Pending   | pulls exact `rwa_amount` from the beneficiary's RWA token account into the escrow ATA (delta-checked, `RwaDeltaMismatch`) |
| Pending | `fund_redemption`    | `treasurer` (`Config.treasurer`, `NotTreasurer`) | `registry.finalized`; `!registry.paused`; status `Pending` (`NotPending`); recorded beneficiary allowed (`BeneficiaryNotAllowed`)                            | Funded    | pulls exact `quote_amount` from the treasurer's quote token account into the escrow-quote ATA (`QuoteDeltaMismatch`) |
| Pending | `reject_redemption`  | `redemption_manager` (`Config.redemption_manager`, `NotRedemptionManager`) | `registry.finalized`; `!registry.paused`; `reason_code != [0;32]` (`ZeroReasonCode`); status `Pending` (`NotPending`); recorded beneficiary allowed (`BeneficiaryNotAllowed`) | Rejected  | returns exact `rwa_amount` from escrow to the recorded beneficiary (`RwaDeltaMismatch`) |
| Pending | `cancel_redemption`  | recorded beneficiary only (`NotBeneficiary`) | `registry.finalized` only — **no `!registry.paused` check**; status `Pending` (`NotPending`); timeout elapsed, `now >= created_at + redemption_timeout` (`TimeoutNotReached`); recorded beneficiary allowed (`BeneficiaryNotAllowed`) | Cancelled | returns exact `rwa_amount` from escrow to the recorded beneficiary (`RwaDeltaMismatch`) |
| Funded  | `claim_redemption`   | anyone (permissionless — no caller-identity check on the instruction) | `registry.finalized`; `!registry.paused`; status `Funded` (`NotFunded`)                                                                                    | Completed | `rwa_amount` → Vault inventory ATA (`RwaDeltaMismatch`); `quote_amount` → recorded beneficiary's quote ATA (`QuoteDeltaMismatch`) |

Terminal-state cleanup: `close_request` (status must be `Completed`/`Rejected`/`Cancelled`, else
`RequestNotTerminal`) is permissionless and closes the request PDA, refunding its rent to the
recorded beneficiary (`has_one = beneficiary`).

`can_cancel` / `ensure_pending` / `ensure_funded` (`solana/crates/redemption-core/src/lib.rs`) are
the host-tested pure guards behind the `Pending`/`Funded`/timeout checks above; the program
(`solana/programs/rwa-redemption/src/lib.rs`) applies the asset legs and the compliance re-checks
around them.

Invariants:
- A request's RWA leaves escrow exactly once — every exit instruction is guarded by
  `status == Pending`/`Funded` and flips status before transferring.
- A funded request's quote is paid exactly once, only to `request.beneficiary` as recorded at
  request time — no instruction on `rwa-redemption` ever mutates that field afterward, and
  `claim_redemption`'s `beneficiary_quote` account is address-pinned to the canonical ATA of
  `request.beneficiary`, not an arbitrary passed-in account.
- Completed sends RWA to the Vault's canonical inventory ATA and quote to the beneficiary; total
  RWA supply is unchanged (no mint/burn here).
- Reject/Cancel pay no quote and return exact RWA.
- No instruction can withdraw a funded escrow's quote back out except `claim_redemption`'s single
  payout — there is no admin/treasurer "defund" instruction.
- No partial funding/claim, no batching, no fees.
- Funding is irreversible: once `Funded`, `reject_redemption`/`cancel_redemption` both require
  status `Pending` and so revert `NotPending`.
- `request_redemption` snapshots `quote_amount = pricing_math::quote_redemption(rwa_amount,
  strategy.redemption_price, strategy.token_decimals)` at request time; later price changes never
  affect an existing request.
- `claim_redemption` does NOT re-check the beneficiary's compliance status — compliance is
  enforced at request time (caller) and at funding/reject/cancel time (recorded beneficiary), not
  at claim.
- If the recorded beneficiary is no longer allowed, `fund_redemption`/`reject_redemption`/
  `cancel_redemption` all revert `BeneficiaryNotAllowed` (RWA stays escrowed).
- Every transfer verifies the exact balance delta (`RwaDeltaMismatch`/`QuoteDeltaMismatch`).
- `redemption_timeout` is fixed at `initialize` (no setter — the Solana analogue of an EVM
  `immutable`), bounded to `[MIN_REDEMPTION_TIMEOUT, MAX_REDEMPTION_TIMEOUT]` =
  `[86_400, 31_536_000]` seconds (1 day … 365 days) — `InvalidTimeout` otherwise.
- No redemption instruction runs before the deployment's `finalize` (`registry.finalized`) —
  `NotFinalized` otherwise.

## Footnote: pause semantics

The Guard column above lists an explicit `!registry.paused` check on `request_redemption`,
`fund_redemption`, `reject_redemption`, and **`claim_redemption`**, but NOT on
**`cancel_redemption`**. That asymmetry is deliberate and load-bearing, not incidental (see the
doc comments at the top of `solana/programs/rwa-redemption/src/lib.rs` and
`solana/programs/rwa-transfer-hook/src/lib.rs`):

- **`cancel_redemption` can complete while paused.** A timed-out cancellation returns the
  beneficiary's *own* escrowed RWA (the redemption was never funded). Trapping that behind an
  indefinite emergency pause is an availability / incident-response weakness, so
  `cancel_redemption` omits the `registry.paused` check in the instruction itself. Its RWA-return
  leg still routes through the Token-2022 transfer hook (every RWA movement does, mint/burn
  excepted), and the hook grants a **narrow, escrow-only bypass**: when `registry.paused` is true,
  the hook requires the transfer's source owner to be the pinned `escrow` system address
  (`registry.system_set && src_owner == registry.escrow`) and still requires the destination owner
  to be currently allowed (`RecipientNotAllowed` otherwise). The bypass cannot become a general
  backdoor: only the redemption program's `Config` PDA (the pinned escrow authority) can ever be
  the source under this branch, it always debits the escrow's own token account — never an
  arbitrary `from` — it still enforces `ImmutableOwner` and the non-forgeable `transferring` flag
  on both accounts, and it can neither mint, burn, nor move any third party's RWA.
  `cancel_redemption`'s own handler additionally re-checks the beneficiary's compliance record
  directly (`BeneficiaryNotAllowed`) before attempting the transfer, independent of the hook's own
  destination check.

- **`claim_redemption` remains blocked while paused.** It keeps its explicit `!registry.paused`
  guard. A funded claim pays out value (the funded quote to the beneficiary, and returns RWA to
  the Vault); an emergency pause is intended to hold payouts, and the beneficiary's quote is
  already secured in escrow, so there is no availability need to force it through. (Its RWA leg
  also calls the same escrow-authority-signed transfer helper as `reject`/`cancel`, but it is only
  ever reached while not paused, since the instruction's own `!registry.paused` guard runs first —
  so claim's pause behavior is unchanged by the hook's bypass branch.)

No on-chain test currently drives a **successful** post-timeout `cancel_redemption` while paused
end-to-end — `anchor test`'s mocha harness cannot fast-forward the validator's clock past the
1-day minimum timeout. `solana/tests/fullflow.ts`'s "cancel before the 1-day timeout is rejected;
reject returns the escrow" test pauses the registry and then attempts `cancel_redemption` on a
fresh `Pending` request, but only asserts that the call throws (`catch { cancelThrew = true }`) —
it never inspects the returned error code. So, read strictly, this test does **not** positively
distinguish "blocked by pause" from "blocked by timeout": both `cancel_redemption`'s instruction
itself lacking a `!registry.paused` guard and the (hypothetical) opposite would produce the same
observable "the call threw" result here. By reading the program source directly — neither
`cancel_redemption`'s handler nor its `CancelRedemption` account-constraint list contains any
`registry.paused` check anywhere — the failure this test observes must in fact be
`TimeoutNotReached`, but that is established by code inspection, not by this test's assertions.

`solana/README.md`'s "Verification status" section states: "The successful post-timeout cancel and
the hook's escrow pause-bypass can't be real-time warped in the validator harness and are covered
by `redemption-core::can_cancel`." That is only partially accurate as a test-coverage claim:
`can_cancel`'s signature (`status`, `caller_is_beneficiary`, `created_at`, `timeout`, `now` —
`solana/crates/redemption-core/src/lib.rs`) has no `paused` parameter at all, so its host tests
(`cancel_timeout_boundary`, `cancel_requires_beneficiary`, `cancel_timeout_add_saturates`,
`funded_cannot_be_rejected_or_cancelled`) prove the **timeout/status/beneficiary** transition logic
is correct and is independent of pause state, which is consistent with `cancel_redemption` omitting
a paused check — but they cannot and do not exercise the transfer hook's escrow pause-bypass branch
itself (`rwa-transfer-hook`'s `if registry.paused { require!(registry.system_set && src_owner ==
registry.escrow, ...) }`), because that branch lives entirely in the Anchor program, which has no
`#[cfg(test)]` unit tests of its own. **No test in this repository — on-chain or host — currently
exercises the hook's escrow pause-bypass branch being taken and succeeding**, and none asserts that
an *ordinary* holder-to-holder transfer is rejected while paused. Both follow from the hook source
read above, but are documented design statements, not passing test claims.

## Compliance changes during redemption funding

Compliance status is read from the authoritative on-chain `rwa-compliance` `Registry`/
`ComplianceRecord` accounts during the same transaction that performs the state transition — there
is no "atomicity within a slot", only each transaction's own execution point at the configured
commitment. Required semantics, all satisfied by the Guard column above:

- `request_redemption` requires the caller allowed at its own execution time (`CallerNotAllowed`).
- `fund_redemption` re-checks the *recorded beneficiary* allowed at its own execution time
  (`BeneficiaryNotAllowed`) — independent of whether the beneficiary was allowed when the request
  was made.
- Once `Funded`, no later compliance change can prevent payment of the committed quote:
  `claim_redemption` never re-checks compliance.
- `claim_redemption` always pays `request.beneficiary` as recorded at request time; no instruction
  on `rwa-redemption` ever mutates that field after `request_redemption` sets it once.
- A `Funded` request cannot be rejected, cancelled, or defunded (both `reject_redemption` and
  `cancel_redemption` require status `Pending` — `NotPending` otherwise).

Because a Solana cluster settles one final transaction ordering, the outcome for any interleaving
of `{request, whitelist removal, whitelist restoration, funding, claim, timeout cancellation}` is
fully deterministic from that ordering alone. **No Solana test in this repository currently
exercises these specific orderings end-to-end** — `solana/tests/fullflow.ts` covers the happy path
(request → fund → claim) and a Pending-request reject, but not a de-whitelist-then-fund attempt, a
fund-then-de-whitelist sequence, or a de-whitelist/re-whitelist-before-funding sequence. The table
below states the required outcome per the Guard column and program logic above; the missing "Test"
column is an open gap, not a citation to invent:

| Ordering (funding/removal/restoration relative to each other) | Outcome | Test |
| --- | --- | --- |
| removal before funding | `fund_redemption` reverts `BeneficiaryNotAllowed`, stays `Pending` | none — not covered by any Solana test today |
| funding before removal | funding commits; later removal cannot unwind `Funded` (`reject_redemption`/`cancel_redemption` require `Pending`) | none — not covered by any Solana test today |
| removal, then restoration, before funding | funding proceeds normally | none — not covered by any Solana test today |
| removal after funding, before claim | claim still pays the recorded beneficiary in full (`claim_redemption` never re-checks compliance) | none — not covered by any Solana test today |
| funded request, any compliance state | reject/cancel attempts revert `NotPending` | `redemption-core::funded_cannot_be_rejected_or_cancelled` (host test only; no on-chain test) |

A fork that changes which of two competing transactions (e.g. funding vs. removal) actually landed
first changes which row above applies, but not the determinism itself — the program still behaves
per whichever ordering the cluster settles on at the configured commitment. Re-deriving state after
a dropped optimistically-confirmed slot is the server indexer's job (reads happen at a fixed
commitment, normally `finalized`, so nothing is written from below it), not something the program
tests exercise.

### Accepted V1 trust limitation: pre-funding removal, and its recovery path

An issuer or compliance operator (the `compliance_authority`) can observe a `Pending` request and
remove the beneficiary before `fund_redemption` executes, which blocks funding indefinitely while
that status holds. This is an accepted V1 governance limitation (a later version may add
compliance reason codes, independent compliance governance, or an appeal workflow), on the
condition that all of the following hold:

- The inability to fund is visible on-chain (`fund_redemption` reverts `BeneficiaryNotAllowed`;
  no silent failure).
- Compliance changes emit `rwa-compliance`'s `StatusChanged` event — auditable, indexable.
- The investor can recover the escrowed RWA via timeout `cancel_redemption` — **but recovery is
  gated on the same compliance check as funding**, not unconditional: `cancel_redemption`'s
  handler re-checks the beneficiary's compliance record directly (`BeneficiaryNotAllowed`), and its
  RWA-return leg still goes through the Token-2022 transfer hook, which itself enforces the
  platform-wide invariant that a transfer requires the recipient currently Allowed ("Transfers
  require both `from` and `to` currently Allowed") even under its own
  paused-escrow bypass branch — the bypass narrows *who may be the source* while paused, it never
  waives the destination-allowed check. So while the beneficiary remains blocked, timeout
  cancellation reverts too — the RWA is not lost or claimable by the issuer, just not yet movable.
  The instant compliance restores the beneficiary, the same timed-out `cancel_redemption` call
  succeeds. **No Solana test currently exercises this specific recovery sequence**
  (blocked-then-restored-then-cancel) end-to-end or at the host-test level; it follows from
  `cancel_redemption`'s explicit `BeneficiaryNotAllowed` check plus `redemption-core::can_cancel`'s
  timeout logic, but treat it as unverified-by-test if you are relying on this document as proof
  rather than as a design statement.
- The issuer can never retain both the RWA and the quote: while blocked, `fund_redemption` cannot
  run, so no quote is ever pulled from the treasurer — the RWA simply sits escrowed until
  compliance is resolved one way or the other.
- The admin console must surface a `Pending` request whose beneficiary is currently not allowed as
  blocked-by-compliance, distinctly from an ordinary pending request awaiting funding (server/UI
  concern, tracked outside this document).
