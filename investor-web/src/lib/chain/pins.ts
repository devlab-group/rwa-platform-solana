// Build-time pins for this deployment's program ids and mints.
// investor-web is a self-contained reference SPA that gets forked
// and rebuilt per issuer/deployment, so baking the deployment's own program
// set into the build via Vite env vars is the natural place to defend the
// "a compromised server can't redirect on-chain actions" property that
// client-side instruction building is meant to give: without this, every
// program id and mint the app builds an instruction against comes from the
// same server whose compromise is exactly the threat being defended
// against (GET /config's programIds.*, GET /project's addresses.*).
//
// Set these in the deployment's .env before `npm run build` (see
// .env.example). Unset in local dev is tolerated — an unset program
// id/mint pin falls back to trusting the server, an unset RPC URL pin
// falls back to a hardcoded local-validator default (see
// resolveRpcUrl) — but `pinsConfigured`/`pinsPartiallyConfigured`
// let the UI show a visible warning rather than silently relying on either
// fallback (see Investor.tsx). A production build should always have every
// pin set.
import { PublicKey } from "@solana/web3.js";

function readPin(name: string): string | undefined {
  const raw = (import.meta.env as Record<string, string | undefined>)[name];
  const trimmed = raw?.trim();
  return trimmed ? trimmed : undefined;
}

export interface Pins {
  complianceProgramId?: string;
  vaultProgramId?: string;
  pricingProgramId?: string;
  transferHookProgramId?: string;
  redemptionProgramId?: string;
  /** Not currently consumed by any investor-web instruction (no investor flow
   * touches the supply-controller program) — pinned anyway for BootstrapConfig
   * completeness and so a future call site gets the same protection for free. */
  supplyControllerProgramId?: string;
  rwaMint?: string;
  quoteMint?: string;
  /** The RPC endpoint every read/write in this app goes through.
   * Every other pin in this file is worthless if the node
   * answering questions about the chain is still the attacker's choice — see
   * `resolveRpcUrl`'s doc comment. There is no server value to fall back to
   * here (GET /project does not return one) — an unset pin instead falls
   * back to a local-dev default, same unpinned-dev-fallback shape as the
   * program id/mint pins below; `pinsConfigured` still treats it as
   * required for the "this is a real deployment" check. */
  rpcUrl?: string;
  /** The `Connection`'s WebSocket transport pin — the
   * origin `confirmTransaction`/account subscriptions actually connect to is
   * a DISTINCT origin from the HTTP RPC endpoint (web3.js derives one by
   * swapping scheme and bumping the port when none is given explicitly, e.g.
   * `http://localhost:8899` -> `ws://localhost:8900`, but that derived origin
   * is not necessarily the one baked into the build-time CSP's connect-src —
   * see cspPolicy.ts/vite.config.ts). Passing this explicitly to
   * `getConnection` (provider.ts) guarantees the WS origin the app
   * actually opens is the one the CSP allow-lists. No local-dev fallback
   * (unlike rpcUrl): leaving it unset just lets web3.js derive its own
   * endpoint, which works against a local validator without needing this set. */
  wsUrl?: string;
  /** Optional cluster-identity cross-check (mirrors the equivalent
   * server-side fix): the base58 genesis hash of the cluster
   * `rpcUrl` is expected to serve. Catches a wrong-cluster endpoint that
   * still looks like a plausible URL. See `assertClusterGenesis` in
   * `chain/provider.ts`. */
  clusterGenesis?: string;
}

// Read fresh on every call (cheap — eight env lookups) rather than frozen at
// module load, so tests can flip env vars with vi.stubEnv without needing to
// reset the module registry.
export function getPins(): Pins {
  return {
    complianceProgramId: readPin("VITE_SOLANA_PROGRAM_COMPLIANCE"),
    vaultProgramId: readPin("VITE_SOLANA_PROGRAM_VAULT"),
    pricingProgramId: readPin("VITE_SOLANA_PROGRAM_PRICING"),
    transferHookProgramId: readPin("VITE_SOLANA_PROGRAM_TRANSFER_HOOK"),
    redemptionProgramId: readPin("VITE_SOLANA_PROGRAM_REDEMPTION"),
    supplyControllerProgramId: readPin("VITE_SOLANA_PROGRAM_SUPPLY_CONTROLLER"),
    rwaMint: readPin("VITE_SOLANA_RWA_MINT"),
    quoteMint: readPin("VITE_SOLANA_QUOTE_MINT"),
    rpcUrl: readPin("VITE_SOLANA_RPC_URL"),
    wsUrl: readPin("VITE_SOLANA_WS_URL"),
    clusterGenesis: readPin("VITE_SOLANA_CLUSTER_GENESIS"),
  };
}

/** The pins every instruction-building call site actually consults (excludes
 * supplyControllerProgramId — see Pins' doc comment — and the optional
 * clusterGenesis cross-check). `rpcUrl` is included: every read/write below
 * goes through it, so leaving it unpinned defeats every other pin in this
 * list just as surely as leaving them unset. */
const REQUIRED_FOR_INSTRUCTIONS = [
  "complianceProgramId",
  "vaultProgramId",
  "pricingProgramId",
  "transferHookProgramId",
  "redemptionProgramId",
  "rwaMint",
  "quoteMint",
  "rpcUrl",
] as const satisfies readonly (keyof Pins)[];

/** True once every pin an instruction-building call needs is set — i.e. this
 * is a real per-deployment build, not an unpinned local-dev checkout. */
export function pinsConfigured(): boolean {
  const pins = getPins();
  return REQUIRED_FOR_INSTRUCTIONS.every((key) => pins[key] !== undefined);
}

/** True when at least one (but not all) instruction-relevant pins are set —
 * worth flagging loudly since the unset ones silently fall back to trusting
 * the server, which is easy to miss in a half-finished deployment config. */
export function pinsPartiallyConfigured(): boolean {
  const pins = getPins();
  const set = REQUIRED_FOR_INSTRUCTIONS.filter((key) => pins[key] !== undefined);
  return set.length > 0 && set.length < REQUIRED_FOR_INSTRUCTIONS.length;
}

export class PinMismatchError extends Error {
  constructor(
    public readonly field: string,
    public readonly pinned: string,
    public readonly actual: string,
  ) {
    super(
      `Refusing to build a transaction: the server-supplied ${field} (${actual}) does not match this deployment's pinned value (${pinned}). This can indicate a compromised or misconfigured server. Aborting.`,
    );
    this.name = "PinMismatchError";
  }
}

/** Compares two base58 pubkey strings by decoding rather than by raw string
 * equality — base58 is case-sensitive and a canonical pubkey has exactly one
 * encoding, so this is equivalent to a string compare for well-formed input,
 * but fails closed (throws, via the caller's PublicKey construction) instead
 * of silently passing on a malformed value. */
function pubkeysEqual(a: string, b: string): boolean {
  return new PublicKey(a).equals(new PublicKey(b));
}

/** Throws PinMismatchError if `pinned` is set and disagrees with
 * `actual`. A no-op when `pinned` is undefined (unpinned dev fallback). */
function assertPin(field: string, pinned: string | undefined, actual: string): void {
  if (pinned === undefined) return;
  if (!pubkeysEqual(pinned, actual)) {
    throw new PinMismatchError(field, pinned, actual);
  }
}

/**
 * The server-supplied program ids/mints a buy/redemption/transfer
 * instruction is built from — structurally identical to wallet.ts's
 * ProgramAddresses, kept as an independent type here to avoid a circular
 * import (wallet.ts imports this module).
 */
export interface ProgramSet {
  complianceProgramId: string;
  pricingProgramId: string;
  vaultProgramId: string;
  redemptionProgramId: string;
  rwaMint: string;
  quoteMint: string;
}

/**
 * Hard-asserts every server-supplied program id/mint against this build's
 * pins before any instruction is built from them. Call this
 * first thing in every one of wallet.ts's send-/read- functions
 * that touches an account list, before constructing any PublicKey from the
 * server values. `hookProgramId` is separate from `ProgramSet` because
 * it comes from a different endpoint (GET /config, not GET /project — see
 * ChainContext's doc comment on `hookProgramId`).
 */
export function assertProgramAddressesPinned(
  server: ProgramSet,
  hookProgramId?: string,
): void {
  const pins = getPins();
  assertPin("compliance program id", pins.complianceProgramId, server.complianceProgramId);
  assertPin("pricing program id", pins.pricingProgramId, server.pricingProgramId);
  assertPin("vault program id", pins.vaultProgramId, server.vaultProgramId);
  assertPin("redemption program id", pins.redemptionProgramId, server.redemptionProgramId);
  assertPin("RWA mint", pins.rwaMint, server.rwaMint);
  assertPin("quote mint", pins.quoteMint, server.quoteMint);
  if (hookProgramId !== undefined) {
    assertPin("transfer-hook program id", pins.transferHookProgramId, hookProgramId);
  }
}

/** Asserts a lone server-supplied mint against the pinned RWA mint — for call
 * sites (like sendRwaTransfer) that only ever receive a mint, not the full
 * ProgramSet. */
export function assertPinnedRwaMint(mint: string): void {
  assertPin("RWA mint", getPins().rwaMint, mint);
}

/** Asserts a lone server-supplied quote mint against the pinned quote mint —
 * mirrors assertPinnedRwaMint, for call sites (like decimals.ts's
 * resolveQuoteDecimals) that only ever receive the quote mint address, not
 * the full ProgramSet: the on-chain quote-decimals read
 * this guards is worthless if the address it reads from could itself be
 * server-redirected. */
export function assertPinnedQuoteMint(mint: string): void {
  assertPin("quote mint", getPins().quoteMint, mint);
}

/**
 * Asserts the server-supplied vault program id against the pin.
 * `assertProgramAddressesPinned` already checks
 * `ProgramSet.vaultProgramId`, but wallet.ts's `sendBuy` builds the
 * actual vault `Program`/PDAs from a *separate* positional `vault` argument
 * — today both always come from `project.addresses.vault`, but nothing
 * established that, so this asserts the value instructions are actually
 * built from, not just the one that happens to travel alongside it.
 */
export function assertPinnedVaultProgramId(vault: string): void {
  assertPin("vault program id", getPins().vaultProgramId, vault);
}

/**
 * Same as `assertPinnedVaultProgramId`, for the redemption program's
 * positional `escrow` argument threaded through
 * sendRequestRedemption/sendClaimRedemption/sendCancelRedemption.
 */
export function assertPinnedRedemptionProgramId(escrow: string): void {
  assertPin("redemption program id", getPins().redemptionProgramId, escrow);
}

/** Used by `resolveRpcUrl` when `VITE_SOLANA_RPC_URL` is unset — the default
 * `solana-test-validator` port, so `npm run dev`/`npm test` still work
 * against a local validator without every contributor needing their own
 * `.env.local`. A real deployment should always pin the var (see
 * `pinsConfigured`'s warning banner) — this default exists for
 * developer convenience, not as a safe production fallback. */
const LOCAL_DEV_RPC_URL = "http://127.0.0.1:8899";

/**
 * Resolves the RPC URL this session uses —
 * `VITE_SOLANA_RPC_URL` is the SOLE source; there is no server value to read
 * or compare against — `GET /project` does not return an RPC endpoint at
 * all). Every read AND write in this app goes through whatever this
 * returns — the on-chain price/strategy read, the token-program lookup, the
 * pre-signature simulation, balances, redemption state, next-request-id —
 * so this pin sits underneath every program-id/mint pin above it: an
 * attacker who can no longer redirect *which program* gets called could
 * otherwise still redirect *which node answers every question about the
 * chain*, fabricating UI state and defeating every client-side sanity check
 * layered on top of the other pins.
 *
 * Falls back to `LOCAL_DEV_RPC_URL` when unset — the same
 * unpinned-dev-fallback shape as every other pin in this file. This is why
 * `rpcUrl` stays in `REQUIRED_FOR_INSTRUCTIONS`: `pinsConfigured`'s
 * warning banner, not a thrown error here, is what tells an operator they
 * shipped a build without pinning it.
 */
export function resolveRpcUrl(): string {
  return getPins().rpcUrl ?? LOCAL_DEV_RPC_URL;
}
