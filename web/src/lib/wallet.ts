// Minimal, abstracted wallet integration. Every call the console broadcasts is
// built as an instruction (lib/chain.ts) — the admin actions (mint,
// roles, pause/price, treasury withdrawal, redemption fund/reject). Nothing is
// ever submitted from server-supplied instruction data. Deliberately isolated
// behind this module so the rest of the app — and the production build —
// never needs a live wallet to run. Route components never import
// lib/chain.ts directly; they call the functions below.
import { PublicKey } from "@solana/web3.js";
import type { AdminProgramKey } from "./roles";
import {
  bigIntToBytes32,
  buildAcceptAdminIx,
  buildFundRedemptionIx,
  buildMintIx,
  buildProposeAdminIx,
  buildRejectRedemptionIx,
  buildSetPausedIx,
  buildSetPriceIx,
  buildSetRoleHolderIx,
  buildWithdrawProceedsIx,
  connectInjectedWallet,
  getConfig,
  getConnection,
  hexToBytes,
  fetchMintDecimals,
  fetchPendingAdmins,
  fetchVaultInventory,
  sendInstruction,
  signInjectedMessage,
  waitForSignature,
  type Hex,
  type Role,
} from "./chain";

export interface ConnectedWallet {
  address: string;
  /** Informational only (BootstrapConfig.solanaChainId) — no wallet call is gated on it. */
  chainId: number;
}

export async function connectWallet(): Promise<ConnectedWallet> {
  const wallet = await connectInjectedWallet();
  return { address: wallet.address, chainId: 0 };
}

/**
 * Signs `message` with the connected wallet's ed25519 signMessage over the
 * exact UTF-8 bytes, base58-encoded — per the frozen wallet-auth contract used
 * by the admin challenge/session login flow (see components/Login.tsx).
 */
export async function signMessage(message: string): Promise<string> {
  return signInjectedMessage(message);
}

/**
 * RWA token decimals. Project.decimals is not exposed by GET /api/v1/project
 * (only present on the deploy request), so it's read directly from the SPL
 * mint — trying Token-2022 (the RWA mint) then the legacy Token program (the
 * quote mint), since the caller only has an address, not which mint it is.
 */
export async function readMintDecimals(mint: string): Promise<number> {
  return fetchMintDecimals(new PublicKey(mint));
}

/**
 * What a purchase of `tokenAmount` RWA minimal units currently costs, in
 * quote-token minimal units. There is no on-chain preview instruction (the
 * pricing program only exposes setters), so `priceHint` — the current
 * purchasePricePerWholeToken and RWA decimals, both
 * already on GET /project — is used to compute the quote client-side:
 * quoteAmount = ceil(tokenAmount * price / 10^rwaDecimals), mirroring
 * `quote_purchase`'s fixed-price math, which rounds a purchase quote UP
 * (this used to floor, disagreeing with the on-chain rounding
 * direction; display-only since admins don't buy, but should still match).
 */
export async function readPreviewBuy(
  tokenAmount: bigint,
  priceHint?: { purchasePricePerWholeToken: string; rwaDecimals: number },
): Promise<bigint> {
  if (!priceHint) {
    throw new Error(
      "Missing price context for a purchase-quote preview (purchasePricePerWholeToken/rwaDecimals).",
    );
  }
  const price = BigInt(priceHint.purchasePricePerWholeToken);
  const scale = 10n ** BigInt(priceHint.rwaDecimals);
  const product = tokenAmount * price;
  return product === 0n ? 0n : (product - 1n) / scale + 1n;
}

export interface VaultInventory {
  /** RWA minimal units. */
  inventory: string;
  /** Quote-token minimal units. */
  quoteBalance: string;
}

/**
 * Reads the vault's live custody balances directly on-chain. GET
 * /api/v1/sales/inventory 501s by design — the server does not track live
 * on-chain balances — so InventorySales.tsx calls this instead. `vault`/
 * `rwaMint`/`quoteMint` come straight off GET /project's addresses.{vault,
 * token, quoteToken} — no separate on-chain lookup is needed for those.
 */
export async function readVaultInventory(
  vault: string,
  rwaMint: string,
  quoteMint: string,
): Promise<VaultInventory> {
  return fetchVaultInventory(
    new PublicKey(vault),
    new PublicKey(rwaMint),
    new PublicKey(quoteMint),
  );
}

/**
 * Which admin-owned programs currently have `wallet` recorded as their pending
 * (incoming) admin, read straight from each program's config account.
 *
 * The Security screen uses this to decide whether the "Accept admin transfer"
 * section applies to the connected wallet at all. GET /project's
 * `pendingAdmin` cannot answer that: it is a single aggregate value (the first
 * program the server's fold found a pending transfer on), so it neither tells
 * you WHICH programs are pending nor whether THIS wallet is the target.
 *
 * Returns the subset of `targets` whose pending admin equals `wallet`, in the
 * order given. A program that cannot be read contributes nothing.
 */
export async function readPendingAdminTargets(
  wallet: string,
  targets: { programKey: AdminProgramKey; address: string }[],
): Promise<{ programKey: AdminProgramKey; address: string }[]> {
  const pending = await fetchPendingAdmins(targets);
  return targets.filter((t) => pending[t.programKey] === wallet);
}

/**
 * Blocks until a submitted transaction's signature reaches "confirmed"
 * commitment. A short polling interval is fine here: the platform targets a
 * single, fast local/permissioned chain, not mainnet.
 */
export async function waitForTxReceipt(signature: string): Promise<void> {
  return waitForSignature(signature);
}

/**
 * compliance.pause()/unpause() — halts or resumes all token transfers
 * (trading). PAUSER_ROLE. Pause/unpause lives on the compliance program's
 * Registry, not the RWA mint — `compliance` here is addresses.compliance (see
 * roles.ts's ROLE_TARGET_FIELDS and Security.tsx).
 */
export async function sendSetPaused(
  from: string,
  compliance: string,
  pause: boolean,
): Promise<string> {
  const ix = buildSetPausedIx(
    new PublicKey(compliance),
    new PublicKey(from),
    pause,
  );
  return sendInstruction(from, ix);
}

/**
 * pricing.set_purchase_price/set_redemption_price — price is quote-token
 * minimal units per whole token. PRICER_ROLE.
 */
export async function sendSetStrategyPrice(
  from: string,
  strategy: string,
  side: "purchase" | "redemption",
  priceMinimalUnits: bigint,
): Promise<string> {
  const ix = buildSetPriceIx(
    new PublicKey(strategy),
    new PublicKey(from),
    side,
    priceMinimalUnits,
  );
  return sendInstruction(from, ix);
}

/**
 * `<program>.set_*(new_holder)` — replaces a role's holder on `contract`.
 * Role holders are single-address (`set_*` replaces the holder, unlike
 * a multi-holder grant/revoke set), so there is no separate "revoke" —
 * granting a different holder replaces the current one. `role` is the plain
 * role name (e.g. "PAUSER_ROLE") — Security.tsx passes it straight through
 * (see roles.ts's ROLES). `contract` is whichever program roleTargets()
 * resolved.
 */
export async function sendRoleChange(
  from: string,
  contract: string,
  role: string,
  account: string,
): Promise<string> {
  const config = getConfig();
  if (!config) throw new Error("Chain config not loaded yet.");
  const ix = buildSetRoleHolderIx(
    role as Role,
    new PublicKey(contract),
    new PublicKey(from),
    new PublicKey(account),
    config.programIds,
  );
  return sendInstruction(from, ix);
}

/**
 * `<program>.propose_admin(new_admin)` — step 1 of the two-step admin
 * transfer, on whichever of the five programs `programKey` selects
 * (roles.ts's adminContractTargets resolves this per admin-owned program).
 * Admins are PER-PROGRAM (5 independent `admin` fields — one per
 * governance program), so the caller (Security.tsx, via roles.ts's
 * adminContractTargets) drives one call per program rather than one combined
 * action.
 */
export async function sendBeginAdminTransfer(
  from: string,
  contract: string,
  newAdmin: string,
  programKey: AdminProgramKey,
): Promise<string> {
  const ix = buildProposeAdminIx(
    new PublicKey(contract),
    programKey,
    new PublicKey(from),
    new PublicKey(newAdmin),
  );
  return sendInstruction(from, ix);
}

/**
 * `<program>.accept_admin()` — step 2 of the two-step admin transfer,
 * broadcast by the PENDING (incoming) admin to complete a transfer begun with
 * sendBeginAdminTransfer. No args — the program already recorded the pending
 * admin.
 */
export async function sendAcceptAdminTransfer(
  from: string,
  contract: string,
  programKey: AdminProgramKey,
): Promise<string> {
  const ix = buildAcceptAdminIx(
    new PublicKey(contract),
    programKey,
    new PublicKey(from),
  );
  return sendInstruction(from, ix);
}

/**
 * vault.withdraw_proceeds(amount) — TREASURER_ROLE. Pays out the vault's
 * accumulated quote-token proceeds; no approve needed (the vault holds and
 * transfers the funds itself). `amount` is in quote-token minimal units.
 * Reads the vault Config account on-chain (quote_mint/treasury) to derive the
 * ATAs — see buildWithdrawProceedsIx.
 */
export async function sendWithdrawProceeds(
  from: string,
  vault: string,
  amount: bigint,
): Promise<string> {
  const connection = getConnection();
  const ix = await buildWithdrawProceedsIx(
    connection,
    new PublicKey(vault),
    new PublicKey(from),
    amount,
  );
  return sendInstruction(from, ix);
}

/**
 * redemption.fund_redemption(id) — TREASURER_ROLE. Transfers directly from
 * the treasurer's own token account (no approve step — there is no SPL
 * delegate/approve leg on this path at all); reads the redemption Config + the
 * request account on-chain to resolve the beneficiary's compliance record —
 * see buildFundRedemptionIx.
 */
export async function sendFundRedemption(
  from: string,
  escrow: string,
  id: bigint,
): Promise<string> {
  const connection = getConnection();
  const ix = await buildFundRedemptionIx(
    connection,
    new PublicKey(escrow),
    new PublicKey(from),
    id,
  );
  return sendInstruction(from, ix);
}

/**
 * redemption.reject_redemption(id, reason_code) — REDEMPTION_MANAGER_ROLE.
 * reasonCode is a 32-byte value, hex-encoded (see lib/redemption.ts's
 * encodeReasonCode). Moves the escrowed RWA back to the beneficiary through
 * the transfer hook, so it needs the hook's remaining accounts appended (see
 * buildRejectRedemptionIx, which mirrors solana/tests/fullflow.ts's
 * hookRemaining).
 */
export async function sendRejectRedemption(
  from: string,
  escrow: string,
  id: bigint,
  reasonCode: string,
): Promise<string> {
  const connection = getConnection();
  const ix = await buildRejectRedemptionIx(
    connection,
    new PublicKey(escrow),
    new PublicKey(from),
    id,
    hexToBytes(reasonCode),
  );
  return sendInstruction(from, ix);
}

/**
 * The supply_controller.mint(...) attestation, assembled client-side on
 * Assets from the record + project. Field names mirror the mint instruction's
 * args; bytes32-shaped fields are 0x-hex strings and the uint fields are
 * bigint. There is no `vault` field — buildMintIx derives the vault ATA from
 * on-chain config instead of taking it as an argument.
 */
export interface MintAttestationInput {
  auditor: string;
  profileDigest: Hex;
  recordKey: Hex;
  metadataDigest: Hex;
  amount: bigint;
  nonce: bigint;
  validUntil: bigint;
}

/**
 * Broadcasts supply_controller.mint(...) from the connected admin wallet.
 * There is no on-chain role gate — the auditor's secp256k1 signature over the
 * attestation (bound to an unused nonce) is the authorization, verified
 * on-chain. The server observes the Minted event and advances the record; it
 * no longer relays the mint.
 *
 * `signature` is the compact 64-byte [R||S] form plus a separate 1-byte
 * recovery id (see signer/internal/output/output.go), packed by Assets.tsx's
 * parseSignedResult into the same 65-byte hex string this function takes —
 * split back apart here rather than needing a new parameter.
 */
export async function sendMint(
  from: string,
  supplyControllerAddress: string,
  attestation: MintAttestationInput,
  signature: Hex,
): Promise<string> {
  const sigBytes = hexToBytes(signature);
  if (sigBytes.length !== 65) {
    throw new Error(
      "Mint signature must be 65 bytes: the 64-byte compact secp256k1 signature plus a 1-byte recovery id.",
    );
  }
  const connection = getConnection();
  const ix = await buildMintIx(
    connection,
    new PublicKey(supplyControllerAddress),
    new PublicKey(from),
    hexToBytes(attestation.recordKey),
    hexToBytes(attestation.metadataDigest),
    attestation.amount,
    // attestation.nonce is carried as a bigint (see the interface's doc
    // comment) but is a 32-byte bytes32 value — bigIntToBytes32 recovers
    // the exact original bytes since it round-trips through BigInt(hex).
    bigIntToBytes32(attestation.nonce),
    attestation.validUntil,
    sigBytes.slice(0, 64),
    sigBytes[64],
  );
  return sendInstruction(from, ix);
}
