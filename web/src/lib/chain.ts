// Chain-access layer that lib/wallet.ts's send*/read* functions dispatch into.
//
// Every instruction here is built by hand (account list + args), verified
// against `solana/tests/fullflow.ts` (the executable spec for account
// order/PDAs) and the checked-in Anchor IDLs (lib/idl/*.json, copied from
// solana/target/idl/) for exact instruction/account/field names. `@coral-xyz/
// anchor` is used ONLY as a Borsh instruction/account coder — never the full
// `Program`/`AnchorProvider` machinery — so every account and PDA is explicit
// here, the same way solana/tests/fullflow.ts uses `.accountsStrict(...)`.
//
// Anchor's BorshInstructionCoder/BorshAccountsCoder key instruction args and
// decoded account fields by the LITERAL (snake_case) names in the IDL JSON —
// there is no camelCasing at this layer (that only happens in the high-level
// `Program.methods` proxy, which this module deliberately does not use) — so
// every args object below uses snake_case keys exactly as they appear in
// web/src/lib/idl/*.json.
import { BorshCoder, BN, type Idl } from "@coral-xyz/anchor";
import {
  Connection,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  type AccountMeta,
} from "@solana/web3.js";
import { getAssociatedTokenAddressSync, getMint } from "@solana/spl-token";
import { Buffer } from "buffer";
import bs58 from "bs58";
import type { AdminProgramKey } from "./roles";

import complianceIdl from "./idl/rwa_compliance.json";
import vaultIdl from "./idl/rwa_vault.json";
import pricingIdl from "./idl/rwa_pricing.json";
import redemptionIdl from "./idl/rwa_redemption.json";
import supplyControllerIdl from "./idl/rwa_supply_controller.json";

// The RWA leg is always Token-2022 (transfer-hook + permissioned-burn
// extensions); the quote leg is always the legacy Token program — see
// solana/tests/fullflow.ts's mint/quote-mint setup. Hardcoded here rather than
// read from config: both are fixed, well-known program ids.
export const TOKEN_PROGRAM_ID = new PublicKey(
  "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
);
export const TOKEN_2022_PROGRAM_ID = new PublicKey(
  "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
);

// ---- chain config (set once at startup) ------------------------------------

export interface ProgramIds {
  compliance: string;
  vault: string;
  pricing: string;
  transferHook: string;
  redemption: string;
  supplyController: string;
}

export interface ChainConfig {
  programIds: ProgramIds;
  /** BootstrapConfig.solanaChainId — informational only (shown in the UI); no on-chain check depends on it. */
  solanaChainId?: number;
}

/**
 * The RPC endpoint the admin console's `Connection` reads/broadcasts
 * against — BUILD-TIME only (`VITE_SOLANA_RPC_URL`), not read from the
 * server's `GET /config`/`GET /project` responses. This is what makes CSP
 * work: the fetch-directive policy is baked into the built `index.html`'s
 * meta tag from the same env var (see vite.config.ts's `injectCsp` and
 * CSP-AUDIT.md), and a browser can only allow-list an origin it knows about
 * at build time, not one a compromised/misconfigured server could supply at
 * runtime. For this ADMIN console specifically that's a CSP-mechanics
 * reason, not a trust-boundary one — the server serves this very bundle, so
 * it's inherently server-trusted either way (unlike investor-web's build-time
 * RPC pin, which really is a trust boundary against a compromised server).
 * Empty string when no RPC endpoint is configured at build time.
 */
const RPC_URL: string = import.meta.env.VITE_SOLANA_RPC_URL ?? "";

/**
 * The WebSocket endpoint the `Connection`'s subscription transport
 * (account-change notifications, and `confirmTransaction`'s signature
 * subscription — see `waitForSignature`) uses — BUILD-TIME only
 * (`VITE_SOLANA_WS_URL`), same rationale as `RPC_URL` above. web3.js
 * derives a WS endpoint from the HTTP one when none is given explicitly
 * (conventionally swapping the scheme and bumping the port by one, e.g.
 * `http://localhost:8899` -> `ws://localhost:8900`), but that derived origin
 * is NOT necessarily what's baked into the CSP `connect-src` — this env var
 * makes the WS origin explicit so vite.config.ts's `injectCsp` can allow-list
 * the exact same origin the `Connection` actually opens.
 * Empty string when no separate WS endpoint is configured (falls back to
 * web3.js's own derivation, which then may not match the CSP — see
 * .env.example).
 */
const WS_URL: string = import.meta.env.VITE_SOLANA_WS_URL ?? "";

let activeConfig: ChainConfig | null = null;

/**
 * Records the deployment's program ids + RPC endpoint, read once from
 * GET /api/v1/config (or GET /api/v1/project) at app startup — see
 * WalletContext.tsx. This deployment is single-tenant and its chain config is
 * fixed for its lifetime, so this is set once and never changes.
 */
export function configure(config: ChainConfig | null): void {
  activeConfig = config;
}

export function getConfig(): ChainConfig | null {
  return activeConfig;
}

function requireConfig(): ChainConfig {
  if (!activeConfig) {
    throw new Error(
      "Chain config not loaded yet — GET /api/v1/config hasn't resolved. Reload and try again.",
    );
  }
  return activeConfig;
}

const connectionCache = new Map<string, Connection>();

function resolveConnection(rpcUrl?: string): Connection {
  const url = rpcUrl ?? RPC_URL;
  if (!url)
    throw new Error(
      "No RPC endpoint configured — VITE_SOLANA_RPC_URL was empty at build time.",
    );
  let conn = connectionCache.get(url);
  if (!conn) {
    // Explicit wsEndpoint (when configured) so the CSP's connect-src, baked
    // from the same VITE_SOLANA_WS_URL at build time, actually covers the
    // origin this Connection opens for confirmTransaction/subscriptions —
    // see WS_URL's doc comment.
    conn = new Connection(url, {
      commitment: "confirmed",
      wsEndpoint: WS_URL || undefined,
    });
    connectionCache.set(url, conn);
  }
  return conn;
}

/** Public accessor for the active Connection — wallet.ts uses this to build instructions that read on-chain state (Config accounts) before sending. */
export function getConnection(): Connection {
  return resolveConnection();
}

// ---- injected wallet (Wallet Standard / Phantom / Solflare) ---------------

export interface SignAndSendResult {
  signature: string;
}

export interface InjectedProvider {
  publicKey?: { toBase58(): string; toBytes(): Uint8Array } | null;
  isConnected?: boolean;
  connect(opts?: { onlyIfTrusted?: boolean }): Promise<{ publicKey: { toBase58(): string } }>;
  disconnect?(): Promise<void>;
  signTransaction<T extends Transaction>(tx: T): Promise<T>;
  signAllTransactions?<T extends Transaction>(txs: T[]): Promise<T[]>;
  signAndSendTransaction?(tx: Transaction): Promise<SignAndSendResult>;
  signMessage(
    message: Uint8Array,
    display?: string,
  ): Promise<{ signature: Uint8Array } | Uint8Array>;
  on?(event: string, handler: (...args: unknown[]) => void): void;
  removeListener?(event: string, handler: (...args: unknown[]) => void): void;
}

declare global {
  interface Window {
    solana?: InjectedProvider;
  }
}

/** The injected wallet provider (Phantom/Solflare, both implement this shape), or undefined. */
export function getInjectedProvider(): InjectedProvider | undefined {
  if (typeof window === "undefined") return undefined;
  return window.solana;
}

export interface ConnectedAccount {
  address: string;
}

export async function connectInjectedWallet(): Promise<ConnectedAccount> {
  const provider = getInjectedProvider();
  if (!provider)
    throw new Error(
      "No injected wallet found (e.g. Phantom or Solflare).",
    );
  const res = await provider.connect();
  return { address: res.publicKey.toBase58() };
}

/**
 * ed25519 signMessage per the frozen auth contract (docs above the client
 * section of the wallet-auth design): sign the exact challenge UTF-8 bytes,
 * return the base58-encoded 64-byte signature (never send a transaction for
 * auth — this is an off-chain message signature only).
 */
export async function signInjectedMessage(message: string): Promise<string> {
  const provider = getInjectedProvider();
  if (!provider) throw new Error("No injected wallet found.");
  const bytes = new TextEncoder().encode(message);
  const result = await provider.signMessage(bytes, "utf8");
  const signature = result instanceof Uint8Array ? result : result.signature;
  return bs58.encode(signature);
}

/**
 * Builds, signs (via the injected wallet), and sends a transaction with a
 * single instruction (every admin action here is one instruction), waiting
 * for a recent blockhash first. Returns the transaction signature (Solana's
 * analog of an EVM tx hash) as a base58 string.
 */
export async function sendInstruction(
  from: string,
  instruction: TransactionInstruction,
): Promise<string> {
  const provider = getInjectedProvider();
  if (!provider) throw new Error("No injected wallet found.");
  const connection = getConnection();
  const payer = new PublicKey(from);

  const tx = new Transaction().add(instruction);
  tx.feePayer = payer;
  const { blockhash } = await connection.getLatestBlockhash("confirmed");
  tx.recentBlockhash = blockhash;

  if (provider.signAndSendTransaction) {
    const { signature } = await provider.signAndSendTransaction(tx);
    return signature;
  }
  const signed = await provider.signTransaction(tx);
  const raw = signed.serialize();
  return connection.sendRawTransaction(raw, { skipPreflight: false });
}

/** Polls until `signature` reaches at least "confirmed" commitment, or times out. */
export async function waitForSignature(signature: string): Promise<void> {
  const connection = getConnection();
  const { blockhash, lastValidBlockHeight } =
    await connection.getLatestBlockhash("confirmed");
  await connection.confirmTransaction(
    { signature, blockhash, lastValidBlockHeight },
    "confirmed",
  );
}

// ---- byte helpers -----------------------------------------------------------

/** A `0x`-prefixed hex string — digests/signatures still travel the wire this
 * way (the auditor attestation reuses keccak256 + secp256k1), even
 * though addresses on this chain are base58, not hex. */
export type Hex = `0x${string}`;

/** Strips an optional "0x" prefix and decodes hex into raw bytes. */
export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error(`Odd-length hex string: ${hex}`);
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): Hex {
  return `0x${Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")}`;
}

/** Big-endian 32-byte encoding of a non-negative bigint (e.g. a bytes32-shaped nonce carried as a bigint). */
export function bigIntToBytes32(value: bigint): Uint8Array {
  if (value < 0n) throw new Error("bigIntToBytes32: value must be non-negative");
  const hex = value.toString(16).padStart(64, "0");
  if (hex.length > 64) throw new Error("bigIntToBytes32: value exceeds 32 bytes");
  return hexToBytes(hex);
}

/** Little-endian 8-byte encoding of a u64 id (redemption request PDA seed). */
export function u64LeBytes(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  let v = value;
  for (let i = 0; i < 8; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

// ---- PDA derivation ---------------------------------------------------------
// Seeds mirror solana/tests/fullflow.ts exactly (the executable spec).

const SEED = {
  registry: Buffer.from("registry"),
  strategy: Buffer.from("strategy"),
  supplyConfig: Buffer.from("supply-config"),
  vaultConfig: Buffer.from("vault-config"),
  redemptionConfig: Buffer.from("redemption-config"),
  nonce: Buffer.from("nonce"),
  recordKey: Buffer.from("record-key"),
  record: Buffer.from("record"),
  request: Buffer.from("request"),
  extraAccountMetaList: Buffer.from("extra-account-metas"),
};

function pda(seeds: (Buffer | Uint8Array)[], programId: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(seeds, programId)[0];
}

export function registryPda(complianceProgramId: PublicKey): PublicKey {
  return pda([SEED.registry], complianceProgramId);
}
export function strategyPda(pricingProgramId: PublicKey): PublicKey {
  return pda([SEED.strategy], pricingProgramId);
}
export function supplyConfigPda(supplyProgramId: PublicKey): PublicKey {
  return pda([SEED.supplyConfig], supplyProgramId);
}
export function vaultConfigPda(vaultProgramId: PublicKey): PublicKey {
  return pda([SEED.vaultConfig], vaultProgramId);
}
export function redemptionConfigPda(redemptionProgramId: PublicKey): PublicKey {
  return pda([SEED.redemptionConfig], redemptionProgramId);
}
export function recordPda(complianceProgramId: PublicKey, wallet: PublicKey): PublicKey {
  return pda([SEED.record, wallet.toBuffer()], complianceProgramId);
}
export function noncePda(supplyProgramId: PublicKey, nonce: Uint8Array): PublicKey {
  return pda([SEED.nonce, Buffer.from(nonce)], supplyProgramId);
}
export function recordKeyPda(supplyProgramId: PublicKey, recordKey: Uint8Array): PublicKey {
  return pda([SEED.recordKey, Buffer.from(recordKey)], supplyProgramId);
}
export function requestPda(redemptionProgramId: PublicKey, id: bigint): PublicKey {
  return pda([SEED.request, Buffer.from(u64LeBytes(id))], redemptionProgramId);
}
export function extraAccountMetaListPda(hookProgramId: PublicKey, mint: PublicKey): PublicKey {
  return pda([SEED.extraAccountMetaList, mint.toBuffer()], hookProgramId);
}

/** ATA for `mint`/`owner`, allowing PDA (off-curve) owners — vault/escrow accounts. */
function ata(mint: PublicKey, owner: PublicKey, offCurve: boolean, tokenProgram: PublicKey): PublicKey {
  return getAssociatedTokenAddressSync(mint, owner, offCurve, tokenProgram);
}

// ---- coders + config decode --------------------------------------------------

const complianceCoder = new BorshCoder(complianceIdl as Idl);
const vaultCoder = new BorshCoder(vaultIdl as Idl);
const pricingCoder = new BorshCoder(pricingIdl as Idl);
const redemptionCoder = new BorshCoder(redemptionIdl as Idl);
const supplyCoder = new BorshCoder(supplyControllerIdl as Idl);

/**
 * Resolves which SPL token program actually owns `mint` — legacy Token or
 * Token-2022 — by reading the mint account's own owner, mirroring the
 * on-chain `validate_quote_mint` check (`quote_token_program = *quote_mint.owner`)
 * instead of assuming every quote mint is legacy SPL. Cached
 * per mint per session since a mint's owning program never changes.
 */
const quoteTokenProgramCache = new Map<string, PublicKey>();

async function resolveTokenProgram(
  connection: Connection,
  mint: PublicKey,
): Promise<PublicKey> {
  const key = mint.toBase58();
  const cached = quoteTokenProgramCache.get(key);
  if (cached) return cached;
  const info = await connection.getAccountInfo(mint);
  if (!info) {
    throw new Error(`Mint account not found: ${mint.toBase58()}`);
  }
  const owner = info.owner;
  if (!owner.equals(TOKEN_PROGRAM_ID) && !owner.equals(TOKEN_2022_PROGRAM_ID)) {
    throw new Error(`Unsupported token program for mint ${mint.toBase58()}: ${owner.toBase58()}`);
  }
  quoteTokenProgramCache.set(key, owner);
  return owner;
}

async function fetchDecoded<T>(
  connection: Connection,
  coder: BorshCoder,
  accountName: string,
  address: PublicKey,
): Promise<T> {
  const info = await connection.getAccountInfo(address);
  if (!info) {
    throw new Error(
      `Account not found: ${accountName} @ ${address.toBase58()} — is the project deployed/finalized?`,
    );
  }
  return coder.accounts.decode(accountName, info.data) as T;
}

interface VaultConfigAccount {
  admin: PublicKey;
  treasurer: PublicKey;
  treasury: PublicKey;
  supply_controller: PublicKey;
  rwa_mint: PublicKey;
  quote_mint: PublicKey;
}

interface RedemptionConfigAccount {
  admin: PublicKey;
  treasurer: PublicKey;
  redemption_manager: PublicKey;
  vault: PublicKey;
  rwa_mint: PublicKey;
  quote_mint: PublicKey;
}

interface RedemptionRequestAccount {
  id: BN;
  beneficiary: PublicKey;
  rwa_amount: BN;
  quote_amount: BN;
  status: number;
}

interface SupplyConfigAccount {
  token_mint: PublicKey;
  vault: PublicKey;
}

function programIdOf(base58: string): PublicKey {
  return new PublicKey(base58);
}

// ---- instruction builders ----------------------------------------------------
// Account order in every `keys` array below matches the IDL's `accounts` list
// (and solana/tests/fullflow.ts) exactly — Solana dispatches accounts
// positionally, not by name.

function meta(pubkey: PublicKey, isSigner: boolean, isWritable: boolean): AccountMeta {
  return { pubkey, isSigner, isWritable };
}

/** compliance.pause() / unpause() — PAUSER_ROLE (single pauser pubkey). */
export function buildSetPausedIx(
  compliance: PublicKey,
  pauser: PublicKey,
  pause: boolean,
): TransactionInstruction {
  const registry = registryPda(compliance);
  const data = complianceCoder.instruction.encode(pause ? "pause" : "unpause", {});
  return new TransactionInstruction({
    programId: compliance,
    keys: [meta(registry, false, true), meta(pauser, true, false)],
    data,
  });
}

/** pricing.set_purchase_price / set_redemption_price — PRICER_ROLE. */
export function buildSetPriceIx(
  pricing: PublicKey,
  pricer: PublicKey,
  side: "purchase" | "redemption",
  newPrice: bigint,
): TransactionInstruction {
  const strategy = strategyPda(pricing);
  const ixName = side === "purchase" ? "set_purchase_price" : "set_redemption_price";
  const data = pricingCoder.instruction.encode(ixName, { new_price: new BN(newPrice.toString()) });
  return new TransactionInstruction({
    programId: pricing,
    keys: [meta(strategy, false, true), meta(pricer, true, false)],
    data,
  });
}

/** vault.withdraw_proceeds(amount) — TREASURER_ROLE. Reads Config on-chain for quote_mint/treasury; resolves quote_mint's owning token program (legacy SPL or Token-2022) from the mint itself rather than assuming legacy SPL. */
export async function buildWithdrawProceedsIx(
  connection: Connection,
  vaultProgram: PublicKey,
  treasurer: PublicKey,
  amount: bigint,
): Promise<TransactionInstruction> {
  const config = vaultConfigPda(vaultProgram);
  const registry = registryPda(programIdOf(requireConfig().programIds.compliance));
  const cfg = await fetchDecoded<VaultConfigAccount>(connection, vaultCoder, "Config", config);
  const quoteTokenProgram = await resolveTokenProgram(connection, cfg.quote_mint);
  const vaultQuote = ata(cfg.quote_mint, config, true, quoteTokenProgram);
  const treasuryQuote = ata(cfg.quote_mint, cfg.treasury, false, quoteTokenProgram);
  const data = vaultCoder.instruction.encode("withdraw_proceeds", { amount: new BN(amount.toString()) });
  return new TransactionInstruction({
    programId: vaultProgram,
    keys: [
      meta(config, false, false),
      meta(registry, false, false),
      meta(cfg.quote_mint, false, false),
      meta(vaultQuote, false, true),
      meta(treasuryQuote, false, true),
      meta(treasurer, true, false),
      meta(quoteTokenProgram, false, false),
    ],
    data,
  });
}

/** redemption.fund_redemption(id) — TREASURER_ROLE. Reads Config + the request account on-chain; resolves quote_mint's owning token program from the mint itself. */
export async function buildFundRedemptionIx(
  connection: Connection,
  redemptionProgram: PublicKey,
  treasurer: PublicKey,
  id: bigint,
): Promise<TransactionInstruction> {
  const config = redemptionConfigPda(redemptionProgram);
  const registry = registryPda(programIdOf(requireConfig().programIds.compliance));
  const cfg = await fetchDecoded<RedemptionConfigAccount>(connection, redemptionCoder, "Config", config);
  const request = requestPda(redemptionProgram, id);
  const req = await fetchDecoded<RedemptionRequestAccount>(
    connection,
    redemptionCoder,
    "RedemptionRequest",
    request,
  );
  const quoteTokenProgram = await resolveTokenProgram(connection, cfg.quote_mint);
  const treasurerQuote = ata(cfg.quote_mint, treasurer, false, quoteTokenProgram);
  const escrowQuote = ata(cfg.quote_mint, config, true, quoteTokenProgram);
  const beneficiaryRecord = recordPda(
    programIdOf(requireConfig().programIds.compliance),
    req.beneficiary,
  );
  const data = redemptionCoder.instruction.encode("fund_redemption", { _id: new BN(id.toString()) });
  return new TransactionInstruction({
    programId: redemptionProgram,
    keys: [
      meta(config, false, false),
      meta(registry, false, false),
      meta(request, false, true),
      meta(cfg.quote_mint, false, false),
      meta(treasurer, true, false),
      meta(treasurerQuote, false, true),
      meta(escrowQuote, false, true),
      meta(beneficiaryRecord, false, false),
      meta(quoteTokenProgram, false, false),
    ],
    data,
  });
}

/**
 * redemption.reject_redemption(id, reason_code) — REDEMPTION_MANAGER_ROLE.
 * Moves the escrowed RWA back to the beneficiary through the transfer hook, so
 * — unlike fund_redemption — this needs the hook's remaining accounts (see
 * fullflow.ts's `hookRemaining`) appended after the strict account list.
 */
export async function buildRejectRedemptionIx(
  connection: Connection,
  redemptionProgram: PublicKey,
  redemptionManager: PublicKey,
  id: bigint,
  reasonCode: Uint8Array,
): Promise<TransactionInstruction> {
  const cfgAddr = requireConfig();
  const compliance = programIdOf(cfgAddr.programIds.compliance);
  const hook = programIdOf(cfgAddr.programIds.transferHook);
  const config = redemptionConfigPda(redemptionProgram);
  const registry = registryPda(compliance);
  const cfg = await fetchDecoded<RedemptionConfigAccount>(connection, redemptionCoder, "Config", config);
  const request = requestPda(redemptionProgram, id);
  const req = await fetchDecoded<RedemptionRequestAccount>(
    connection,
    redemptionCoder,
    "RedemptionRequest",
    request,
  );
  const escrowToken = ata(cfg.rwa_mint, config, true, TOKEN_2022_PROGRAM_ID);
  const beneficiaryToken = ata(cfg.rwa_mint, req.beneficiary, false, TOKEN_2022_PROGRAM_ID);
  const beneficiaryRecord = recordPda(compliance, req.beneficiary);
  const data = redemptionCoder.instruction.encode("reject_redemption", {
    _id: new BN(id.toString()),
    reason_code: Array.from(reasonCode),
  });
  const extraMetas = extraAccountMetaListPda(hook, cfg.rwa_mint);
  const remaining: AccountMeta[] = [
    meta(hook, false, false),
    meta(extraMetas, false, false),
    meta(compliance, false, false),
    meta(registry, false, false),
    meta(recordPda(compliance, config), false, false), // source (escrow) record
    meta(beneficiaryRecord, false, false), // destination (beneficiary) record
  ];
  return new TransactionInstruction({
    programId: redemptionProgram,
    keys: [
      meta(config, false, false),
      meta(registry, false, false),
      meta(request, false, true),
      meta(cfg.rwa_mint, false, false),
      meta(escrowToken, false, true),
      meta(beneficiaryToken, false, true),
      meta(beneficiaryRecord, false, false),
      meta(redemptionManager, true, false),
      meta(TOKEN_2022_PROGRAM_ID, false, false),
      ...remaining,
    ],
    data,
  });
}

/**
 * supply_controller.mint(...) — no on-chain role gate; a valid auditor
 * secp256k1 signature over an unused nonce is the authorization, verified
 * on-chain. `signature` is 64 bytes, `recoveryId` is 0 or 1 — the compact
 * [R||S] + recovery-id form the on-chain `secp256k1_recover` syscall consumes
 * (see signer/internal/output/output.go).
 */
export async function buildMintIx(
  connection: Connection,
  supplyControllerProgram: PublicKey,
  payer: PublicKey,
  recordKey: Uint8Array,
  metadataDigest: Uint8Array,
  amount: bigint,
  nonce: Uint8Array,
  validUntil: bigint,
  signature: Uint8Array,
  recoveryId: number,
): Promise<TransactionInstruction> {
  const config = supplyConfigPda(supplyControllerProgram);
  const registry = registryPda(programIdOf(requireConfig().programIds.compliance));
  const cfg = await fetchDecoded<SupplyConfigAccount>(
    connection,
    supplyCoder,
    "rwa_supply_controller::Config",
    config,
  );
  const vaultToken = ata(cfg.token_mint, cfg.vault, true, TOKEN_2022_PROGRAM_ID);
  const nonceMarker = noncePda(supplyControllerProgram, nonce);
  const recordMarker = recordKeyPda(supplyControllerProgram, recordKey);
  const data = supplyCoder.instruction.encode("mint", {
    record_key: Array.from(recordKey),
    metadata_digest: Array.from(metadataDigest),
    amount: new BN(amount.toString()),
    nonce: Array.from(nonce),
    valid_until: new BN(validUntil.toString()),
    signature: Array.from(signature),
    recovery_id: recoveryId,
  });
  return new TransactionInstruction({
    programId: supplyControllerProgram,
    keys: [
      meta(config, false, false),
      meta(registry, false, false),
      meta(cfg.token_mint, false, true),
      meta(vaultToken, false, true),
      meta(nonceMarker, false, true),
      meta(recordMarker, false, true),
      meta(payer, true, true),
      meta(TOKEN_2022_PROGRAM_ID, false, false),
      meta(SystemProgram.programId, false, false),
    ],
    data,
  });
}

// ---- role management ---------------------------------------------------------
// Role holders are single-address (set_X replaces the holder), unlike
// an EVM AccessControl-style multi-holder grant/revoke — see roles.ts's
// ROLE_TARGET_FIELDS. `program` is whichever program id the caller
// resolved the role's target to (roleTargets() in lib/roles.ts).

export type Role =
  | "PAUSER_ROLE"
  | "PRICER_ROLE"
  | "TREASURER_ROLE"
  | "REDEMPTION_MANAGER_ROLE"
  | "COMPLIANCE_ROLE";

/**
 * Builds the `set_*` instruction that replaces a role's holder on `program`.
 * `program` must be one of the deployment's program ids (the caller passes
 * addresses.compliance/strategy/vault/redemptionEscrow — see roles.ts) — this
 * dispatches on which program it is to pick the right instruction, since the
 * same role can live on more than one program (TREASURER_ROLE: vault +
 * redemption).
 */
export function buildSetRoleHolderIx(
  role: Role,
  program: PublicKey,
  admin: PublicKey,
  newHolder: PublicKey,
  programIds: ProgramIds,
): TransactionInstruction {
  const programBase58 = program.toBase58();
  if (role === "PAUSER_ROLE") {
    if (programBase58 !== programIds.compliance) {
      throw new Error("PAUSER_ROLE is set on the compliance program.");
    }
    const registry = registryPda(program);
    const data = complianceCoder.instruction.encode("set_pauser", { new_pauser: newHolder });
    return new TransactionInstruction({
      programId: program,
      keys: [meta(registry, false, true), meta(admin, true, false)],
      data,
    });
  }
  if (role === "COMPLIANCE_ROLE") {
    if (programBase58 !== programIds.compliance) {
      throw new Error("COMPLIANCE_ROLE is set on the compliance program.");
    }
    const registry = registryPda(program);
    const data = complianceCoder.instruction.encode("set_compliance_authority", {
      new_authority: newHolder,
    });
    return new TransactionInstruction({
      programId: program,
      keys: [meta(registry, false, true), meta(admin, true, false)],
      data,
    });
  }
  if (role === "PRICER_ROLE") {
    if (programBase58 !== programIds.pricing) {
      throw new Error("PRICER_ROLE is set on the pricing program.");
    }
    const strategy = strategyPda(program);
    const data = pricingCoder.instruction.encode("set_pricer", { new_pricer: newHolder });
    return new TransactionInstruction({
      programId: program,
      keys: [meta(strategy, false, true), meta(admin, true, false)],
      data,
    });
  }
  if (role === "TREASURER_ROLE") {
    if (programBase58 === programIds.vault) {
      const config = vaultConfigPda(program);
      const data = vaultCoder.instruction.encode("set_treasurer", { new_treasurer: newHolder });
      return new TransactionInstruction({
        programId: program,
        keys: [meta(config, false, true), meta(admin, true, false)],
        data,
      });
    }
    if (programBase58 === programIds.redemption) {
      const config = redemptionConfigPda(program);
      const data = redemptionCoder.instruction.encode("set_treasurer", { new_treasurer: newHolder });
      return new TransactionInstruction({
        programId: program,
        keys: [meta(config, false, true), meta(admin, true, false)],
        data,
      });
    }
    throw new Error("TREASURER_ROLE is set on the vault and redemption programs.");
  }
  if (role === "REDEMPTION_MANAGER_ROLE") {
    if (programBase58 !== programIds.redemption) {
      throw new Error("REDEMPTION_MANAGER_ROLE is set on the redemption program.");
    }
    const config = redemptionConfigPda(program);
    const data = redemptionCoder.instruction.encode("set_redemption_manager", {
      new_manager: newHolder,
    });
    return new TransactionInstruction({
      programId: program,
      keys: [meta(config, false, true), meta(admin, true, false)],
      data,
    });
  }
  // Exhaustiveness guard — every Role above is handled.
  throw new Error(`Unsupported role: ${String(role)}`);
}

/**
 * Which config-PDA deriver + instruction coder `propose_admin`/`accept_admin`
 * use for each of the five programs with a two-step admin (the RWA
 * mint has no on-chain admin instruction, and rwa-transfer-hook has no
 * two-step admin either — see roles.ts's AdminContractSpec doc comment).
 * Every one of these IDLs defines `propose_admin(new_admin: Pubkey)` /
 * `accept_admin()` with the SAME account shape — `[configPda (writable),
 * signer]` — so this table is the only per-program dispatch needed; the
 * account list itself (buildProposeAdminIx/buildAcceptAdminIx below) is
 * identical across programs.
 */
const ADMIN_PROGRAM_SPECS: Record<
  AdminProgramKey,
  {
    configPda: (programId: PublicKey) => PublicKey;
    coder: BorshCoder;
    /**
     * The account type name as the IDL declares it. Anchor module-qualifies a
     * name that collides across programs, which is why the supply-controller's
     * is "rwa_supply_controller::Config" while the vault's is plain "Config" —
     * decoding with the wrong string throws.
     */
    accountName: string;
  }
> = {
  compliance: {
    configPda: registryPda,
    coder: complianceCoder,
    accountName: "Registry",
  },
  vault: { configPda: vaultConfigPda, coder: vaultCoder, accountName: "Config" },
  pricing: {
    configPda: strategyPda,
    coder: pricingCoder,
    accountName: "Strategy",
  },
  redemption: {
    configPda: redemptionConfigPda,
    coder: redemptionCoder,
    accountName: "Config",
  },
  supplyController: {
    configPda: supplyConfigPda,
    coder: supplyCoder,
    accountName: "rwa_supply_controller::Config",
  },
};

/** The zero pubkey — what `pending_admin` holds when no transfer is pending. */
const ZERO_PUBKEY = "11111111111111111111111111111111";

/**
 * Reads each given program's `pending_admin` straight from its config account.
 *
 * Needed because the server's Project.pendingAdmin is a single AGGREGATE hint
 * (server/internal/project/security.go folds the first program with a pending
 * transfer), so it cannot answer "is this wallet the incoming admin on any
 * program?" — which is what decides whether the accept UI is relevant at all.
 * Reading the accounts is also authoritative and immediate: it does not wait
 * for the indexer, and `accept_admin` is authorized against exactly these
 * bytes on-chain.
 *
 * Per-program failures are swallowed to `null` (a program may not be
 * initialized yet, or the RPC may be flaky for one account): a program whose
 * state cannot be read must not claim a pending transfer, and must not stop the
 * others from reporting theirs.
 */
export async function fetchPendingAdmins(
  targets: { programKey: AdminProgramKey; address: string }[],
): Promise<Record<string, string | null>> {
  const connection = getConnection();
  const entries = await Promise.all(
    targets.map(async ({ programKey, address }) => {
      try {
        const spec = ADMIN_PROGRAM_SPECS[programKey];
        const account = await fetchDecoded<{ pending_admin: PublicKey }>(
          connection,
          spec.coder,
          spec.accountName,
          spec.configPda(programIdOf(address)),
        );
        const pending = account.pending_admin?.toBase58() ?? null;
        return [programKey, pending && pending !== ZERO_PUBKEY ? pending : null];
      } catch {
        return [programKey, null];
      }
    }),
  );
  return Object.fromEntries(entries) as Record<string, string | null>;
}

/**
 * `<program>.propose_admin(new_admin)` — step 1 of the two-step admin
 * transfer, on whichever of the five programs `programKey` selects
 * (roles.ts's adminContractTargets resolves this per admin-owned
 * contract/program). Admins are PER-PROGRAM (5 independent `admin`
 * fields, one per governance program — see each program's lib.rs under
 * solana/programs), unlike EVM's single DEFAULT_ADMIN_ROLE shared by every
 * governance contract, so the UI begins/accepts a transfer on each program
 * independently rather than in one combined action.
 */
export function buildProposeAdminIx(
  program: PublicKey,
  programKey: AdminProgramKey,
  admin: PublicKey,
  newAdmin: PublicKey,
): TransactionInstruction {
  const spec = ADMIN_PROGRAM_SPECS[programKey];
  const config = spec.configPda(program);
  const data = spec.coder.instruction.encode("propose_admin", { new_admin: newAdmin });
  return new TransactionInstruction({
    programId: program,
    keys: [meta(config, false, true), meta(admin, true, false)],
    data,
  });
}

/** `<program>.accept_admin()` — step 2, broadcast by the pending (incoming) admin. See buildProposeAdminIx. */
export function buildAcceptAdminIx(
  program: PublicKey,
  programKey: AdminProgramKey,
  newAdmin: PublicKey,
): TransactionInstruction {
  const spec = ADMIN_PROGRAM_SPECS[programKey];
  const config = spec.configPda(program);
  const data = spec.coder.instruction.encode("accept_admin", {});
  return new TransactionInstruction({
    programId: program,
    keys: [meta(config, false, true), meta(newAdmin, true, false)],
    data,
  });
}

// ---- decimals reads -----------------------------------------------------------

/**
 * Reads a mint's decimals, trying Token-2022 first (the RWA mint) then the
 * legacy Token program (the quote mint) — the caller only has an address, not
 * which mint it is, so this tries both rather than requiring a hint.
 */
export async function fetchMintDecimals(mint: PublicKey): Promise<number> {
  const connection = getConnection();
  try {
    return (await getMint(connection, mint, undefined, TOKEN_2022_PROGRAM_ID)).decimals;
  } catch {
    return (await getMint(connection, mint, undefined, TOKEN_PROGRAM_ID)).decimals;
  }
}

// ---- vault inventory read --------------------------------------------------

export interface VaultInventorySnapshot {
  /** RWA minimal units held in the vault's custody ATA. */
  inventory: string;
  /** Quote-token minimal units held in the vault's quote ATA. */
  quoteBalance: string;
}

/**
 * Reads the vault's live custody balances directly on-chain: there is no
 * server-side inventory read (GET /api/v1/sales/inventory 501s by design —
 * the server does not track live on-chain balances), so the admin console
 * reads the vault's two custody ATAs itself.
 * Both are owned by the vault-config PDA (off-curve — the vault program never
 * holds a private key): the RWA leg always under Token-2022, the quote leg
 * under whichever program the quote mint is actually owned by — legacy Token
 * or Token-2022 (resolved via resolveTokenProgram, not assumed).
 * A not-yet-funded/never-touched ATA (no purchases or mints yet) simply
 * doesn't exist on-chain — getTokenAccountBalance throws for a missing
 * account, treated the same as a zero balance rather than an error.
 */
async function tokenAccountBalance(
  connection: Connection,
  account: PublicKey,
): Promise<string> {
  try {
    return (await connection.getTokenAccountBalance(account)).value.amount;
  } catch {
    return "0";
  }
}

export async function fetchVaultInventory(
  vaultProgram: PublicKey,
  rwaMint: PublicKey,
  quoteMint: PublicKey,
): Promise<VaultInventorySnapshot> {
  const connection = getConnection();
  const config = vaultConfigPda(vaultProgram);
  const quoteTokenProgram = await resolveTokenProgram(connection, quoteMint);
  const vaultRwa = ata(rwaMint, config, true, TOKEN_2022_PROGRAM_ID);
  const vaultQuote = ata(quoteMint, config, true, quoteTokenProgram);
  const [inventory, quoteBalance] = await Promise.all([
    tokenAccountBalance(connection, vaultRwa),
    tokenAccountBalance(connection, vaultQuote),
  ]);
  return { inventory, quoteBalance };
}
