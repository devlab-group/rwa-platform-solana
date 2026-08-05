# Incident response guide

Audience: issuer/operator security team. Covers detection, containment, and recovery for
the key-compromise and system-failure scenarios this platform's trust model explicitly
anticipates, plus the honest limits of what any response can undo.

This guide assumes the role/mutability matrix in `docs/spec/roles.md`. Read that first if
anything below seems to promise a recovery path that doesn't exist — V1 has **no clawback, no
force-transfer, and no wallet-recovery module** (all explicitly deferred); several incident types
below are contained but not fully reversed on-chain.

## 0. General principles

- **Pause first, investigate second**, whenever an incident could plausibly affect a
  state-changing operation still in flight. `Registry.paused` (`rwa-compliance`) is the single
  project-wide emergency flag: every other program (`rwa-supply-controller`, `rwa-vault`,
  `rwa-redemption`) reads this same `Registry` account and refuses mint/burn/buy/redemption state
  changes while it is set, and the Token-2022 transfer hook reads it too, so an ordinary
  holder-to-holder transfer is also blocked while paused — with one deliberate exception, the
  escrow authority's pause bypass so a timed-out redemption can still be cancelled (see §5). Pausing
  does not undo anything already final on-chain.
- **Rotation beats deletion.** For every compromised authority, the correct first action is an
  admin-executed rotation (a new pubkey takes over that program's authority field), not merely
  disabling the old key locally. On-chain state only reflects the *current* authority holder.
- **Every admin action should be a multisig or hardware-wallet transaction**, not a single hot
  key — each program's `admin` authority should be a multisig in production. If your deployment's
  `admin` pubkey is not currently a multisig, treat that as a standing finding and prioritize
  fixing it before anything else on this page, since every containment step below assumes admin
  actions require multiple approvals — a single
  compromised admin key defeats them all. Note admin rotation itself is a two-step
  `propose_admin`/`accept_admin` handshake on every program (§3), which protects against handing
  the role to an unreachable or mistyped key, not against an attacker who already controls the
  current admin key.
- **Log everything you do.** `auditlog` and on-chain events are the only source of truth
  once state has diverged; write down timestamps, transaction signatures, and who authorized
  each step as you go, for the postmortem.

## 1. Compromised auditor key

**Detection:** unexpected `Minted`/`Burned` events (`rwa-supply-controller`) with a
`record_key`/`operation_id` your records don't recognize; the auditor reports a lost/stolen key
or device; a signed attestation surfaces that no one on the audit team remembers signing.

**Containment:**
1. Admin calls `rwa-supply-controller`'s `set_auditor(new_auditor_eth)` to rotate to a new
   20-byte secp256k1 address (emits `AuditorChanged`). Do this *immediately* — it is the actual
   fix, not a follow-up step. `set_auditor` is immediate and single-signature (`docs/spec/roles.md`),
   so this is exactly why the admin authority should be a multisig — a single approver can execute
   it fast, but that also means a compromised admin key can rotate the auditor to an attacker's
   own address just as fast.
2. Rotation has an important built-in property: the `mint`/`burn_supply` instructions build the
   attestation to verify from the **current** `Config.auditor_eth` value themselves (not from a
   caller-supplied auditor field), so a signature is only ever checked against whichever address
   is configured *at verification time*. The instant you rotate, every not-yet-submitted signature
   from the old key — no matter how many are outstanding, and even if you don't know how many
   exist — becomes permanently unusable. You do not need to track down or "cancel" individual
   signatures.
3. Pause the project (the `pauser` authority on `rwa-compliance`) if you cannot rotate the
   auditor immediately (e.g. waiting on multisig quorum), to stop any relay of a suspect signature
   in the interim — `mint`/`burn_supply` both check `!registry.paused` before verifying the
   signature.
4. Issue the outgoing auditor a fresh keystore and password for any future signing; treat
   the compromised keystore file as permanently burned, not reusable after a password
   change.

**What this does NOT undo:** any mint/burn already landed before you rotated. If a fraudulent
mint already landed, there is no burn-back-to-zero shortcut — the tokens exist and are subject to
the same permissioned-transfer rules (and the Token-2022 permissioned-burn extension) as any other
supply. Recovery is an off-chain/legal matter (recover the tokens through negotiation, or the
issuer initiates a compensating, properly-audited burn from Vault inventory if the tokens are
recovered there). Document this limitation to stakeholders honestly and immediately; overstating
an on-chain "undo" capability the platform doesn't have is worse than admitting the gap.

**Postmortem:** how was the key exposed (device compromise, password reuse, physical
theft)? Was the air-gapped machine actually air-gapped? Update `docs/auditor/auditor-guide.md`
key-hygiene guidance if the exposure vector reveals a gap in it.

## 2. Compromised compliance key (`compliance_authority`)

**Detection:** unexpected `StatusChanged` events; a previously-blocked wallet becomes
`Allowed` (or vice versa) without a corresponding KYC/webhook record; compliance-operator
reports credential compromise.

**Containment:**
1. Admin calls `rwa-compliance`'s `set_compliance_authority(new_authority)` to move the role off
   the compromised key onto a new one.
2. Review `StatusChanged` events since the suspected compromise window; for any wallet
   status change you cannot attribute to a legitimate KYC event, revert it with a new,
   correctly-attributed `set_status` call.
3. This authority **cannot mint, burn, or move funds** — its blast radius is limited to
   who is allowed to transact: a compromised compliance operator can approve or block wallets
   but cannot mint. A compromised compliance key is serious (it can wrongfully freeze legitimate
   holders or wrongfully allow a sanctioned/unverified wallet in) but is not a funds-at-risk
   incident by itself.
4. This role is also the server's one hot key (`security.compliance_key`, an ed25519 keypair —
   see `docs/operator/operator-guide.md` §6a). If the compromise is of that server-held key
   specifically, rotate the underlying key material (provision a new keypair, grant it the
   `compliance_authority` role per step 1, redeploy the server with the new key configured) and
   audit the webhook signature-verification path (`server/internal/compliance/webhook.go`) for
   whether the compromise came through a webhook HMAC bypass rather than direct key theft — those
   require different fixes.

**Never set the Vault or Escrow authority's compliance record to `Blocked`, under any
circumstance, including "just to be safe" during an incident.** The Token-2022 transfer hook
requires both the source and destination owner to be `Allowed` on an ordinary transfer, and the
Vault/Escrow authorities are one leg of every buy and claim. Blocking either one doesn't contain
an incident — it self-inflicts a platform-wide outage and, worse, can strand a `Funded`
redemption's escrowed quote mid-claim (the claim's transfer to the Vault fails, so the request
never reaches `Completed`). `rwa-compliance` pins both system
addresses `Allowed` for the life of the deployment (`set_status` rejects any attempt to give a
pinned system address a non-`Allowed` status or an expiry — `SystemAddressCannotBeBlocked`) — but
treat this note as defense-in-depth, not a reason to stop being careful with `set_status` calls
during an incident.

## 3. Compromised admin (multisig signer or, worse, a non-multisig admin key)

Each of the six programs (`rwa-compliance`, `rwa-transfer-hook` has none — it takes no admin
instructions, `rwa-supply-controller`, `rwa-pricing`, `rwa-vault`, `rwa-redemption`) stores its
own `admin` authority pubkey on its own state account. A deployment's bootstrap typically
configures the **same** admin key across every program (see `solana/README.md`'s bootstrap
config, one `roles.admin` entry used everywhere), so in practice a compromised admin key usually
endangers all of them together, not just one.

**Detection:** unexpected authority-rotation events (`RoleChanged`, `AuditorChanged`, a pricing
or treasurer/redemption-manager change) on any program; unexpected `AdminProposed`/`AdminChanged`
events; a multisig signer reports device compromise.

**Containment:**
1. If admin is a proper multisig: the remaining honest signers rotate out the compromised
   signer's key via the multisig's own signer-management process (outside this platform's
   programs) before quorum can be reached by an attacker plus any other compromised
   signer. Do this before anything else — every other containment step in this document
   assumes admin integrity.
2. If admin is (against recommendation) a single keypair and it's compromised: this is the
   worst-case incident in this platform's trust model. The compromised admin can rotate the
   auditor, treasury, redemption manager, and pricer authorities on the programs it administers,
   and can pause/unpause if it also holds `pauser`. There is no on-chain admin-recovery path in
   V1 (no veto, no social recovery). Immediate pause buys time only if the attacker hasn't already
   unpaused or doesn't control the `pauser` authority too. Treat this as an emergency requiring
   off-chain/legal escalation and likely a new deployment once contained — this is precisely why
   the admin should be a multisig or hardware wallet in production.
3. Admin rotation itself is a **two-step** `propose_admin`/`accept_admin` handshake on every
   program (`docs/spec/roles.md`) — this is your structural defense against a *mistaken* transfer
   (a typo'd or unreachable new admin can never take effect, since the incoming key must itself
   sign `accept_admin`), not a timed delay: there is no timelock on the transfer, so an attacker
   who already controls the current admin key can `propose_admin` and immediately `accept_admin`
   in the same or a following transaction if they also control the proposed key. Monitor
   `AdminProposed` events and treat any unexpected one as an active incident — the legitimate
   admin can still call `cancel_admin_transfer` to withdraw a pending proposal before it is
   accepted, which is the one recovery window this mechanism gives you.

## 4. Redemption not funded promptly / funding-SLA incident

This is an *operational*, not necessarily *security*, incident, but it belongs here because
mishandling it looks like a security failure to holders.

**Detection:** `RedemptionRequested` events with no corresponding `RedemptionFunded` event
approaching the configured redemption timeout.

**Response:**
1. This is not a bug to "fix" on-chain — a redemption request is deliberately not guaranteed
   to be funded, and V1 has no pooled/instant-redemption fallback. The correct response is
   operational: fund it (`fund_redemption`), communicate a delay honestly to the holder, or let it
   time out so the holder can call `cancel_redemption` and recover their RWA tokens.
2. Never describe a `Pending` request as funded, and never let it silently lapse without
   holder communication — the UI must distinguish Pending, Funded, and Claimable clearly.
3. Track this as an SLA metric (pending-redemption SLA alerts), not merely a support ticket
   queue.

## 5. Program bug discovered post-deployment

**Containment:**
1. Pause immediately (the `pauser` authority on `rwa-compliance`) if the bug is exploitable
   in a live, funds-affecting way. Pausing stops supply-controller, vault, and redemption
   state changes and — because the transfer hook reads the same registry — also blocks plain
   Token-2022 transfers between already-allowed holders, with one deliberate exception: the
   escrow authority keeps a pause bypass so a timed-out redemption can still be cancelled.
   If the bug is in the hook or the compliance program itself, pausing alone will not contain
   it; you may additionally need the `compliance_authority` to block specific wallets.
2. Programs are upgradeable only through the deployer's retained upgrade authority, which is a
   deliberate, audited, out-of-band action — not a routine patch path. Remediation is: pause to
   stop further damage, quantify the damage precisely from on-chain events, then either ship an
   audited program upgrade or stand up a new deployment once the fix is audited. Migrating holder
   balances/state to a new deployment is a manual, off-chain-coordinated process this platform
   does not automate.
3. Do not attempt an unaudited hot-fix under pressure. The audited-deploy discipline exists
   precisely because a same-day patch is exactly how a second bug gets introduced.

## 6. Indexer/database diverges from chain state

**Detection:** `make ci`'s reconciliation checks fail, or an operator notices a UI value that
doesn't match a block explorer or the `cmd/reindex` collection-parity rehearsal
(`server/ops/reindex_rehearsal.sh`).

**How the indexer actually works, so you know what "diverges" can mean here:** each
event-emitting program is scanned independently and gets its own `IndexerCheckpoint` row, keyed by
that program's address — a divergence can be scoped to a single program, not necessarily the whole
deployment. Every RPC read happens at a fixed commitment (`finalized` in production), so results
are by construction never rolled back: there is no reorg/rollback logic to reason about the way an
EVM indexer would need. If the RPC cannot serve the range between a program's persisted checkpoint
and the oldest signature it currently returns (a pruned or lagging node), the poll fails loudly and
the checkpoint does not advance, rather than silently skipping the gap — so an apparent divergence
is more likely a **stalled** checkpoint (visible as growing `checkpoint slot vs. chain head` lag)
than data quietly rewritten under you. An instruction or event the indexer cannot decode is
recorded to the dead-letter queue (`indexer_dead_letters`) instead of blocking every later
canonical event behind it — inspect and retry entries with `opsctl`.

**Response:** the indexer is designed to be authoritative-from-chain, not
authoritative-from-database: reconstruct state from chain events when database records diverge,
and derive redemption status only from chain events — server workflow records may annotate but
never override chain state. The fix is a targeted reindex (`cmd/reindex`) from a known-good
checkpoint slot, not a manual database edit. Manually editing read-model rows to "fix" a
discrepancy without also fixing the indexing or RPC-retention issue that caused it will silently
recur — check the dead-letter queue and the per-program checkpoint lag first, since those usually
explain the divergence directly.

## 7. Quote-token anomaly (freeze or failure)

**Detection:** a `buy`, `fund_redemption`, or `claim_redemption` call fails unexpectedly against
the configured SPL quote token.

**Response:** this is a known, accepted risk class: `validate_quote_mint` deliberately allows the
quote mint to carry a **freeze authority** (real stablecoins keep one), so the token issuer can
freeze a specific token account and cause a related instruction to fail independently of this
platform (see `solana/README.md`'s "Quote mint's freeze authority" note). A funded redemption
remains funded and claimable — retry after the underlying issue resolves (e.g. the beneficiary's
quote-token account is unfrozen by the token issuer). This is not a platform bug to patch;
communicate the dependency to the affected holder. There is no on-chain unwind of a `Funded`
request whose quote leg can't settle — a permanently frozen beneficiary quote account strands the
position and must be handled off-chain.

## 8. Escalation matrix

| Incident class                         | First responder                | Requires admin multisig action |
| --------------------------------------- | ------------------------------- | ------------------------------- |
| Compromised auditor key                 | Security on-call                | Yes (rotate auditor)            |
| Compromised compliance key              | Security on-call                | Yes (rotate role)               |
| Compromised admin signer                | All remaining multisig signers  | Yes (signer rotation)           |
| Redemption funding SLA breach           | Treasury/operations             | No (operational)                |
| Program bug (funds at risk)             | Security on-call + eng lead     | Yes (pause)                     |
| Indexer/DB divergence                   | Platform engineering            | No                               |
| Quote-token anomaly                     | Treasury/operations              | No                               |

Every row above ultimately needs a documented postmortem: timeline, root cause, on-chain
transactions involved, what was and was not recoverable, and any guide (this one, or the
auditor guide) that should be updated as a result.
