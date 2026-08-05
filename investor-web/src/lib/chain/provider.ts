// Wallet + program plumbing: the injected-wallet adapter (Wallet
// Standard / Phantom / Solflare's `window.solana`, deliberately NOT
// @solana/wallet-adapter-react — see the W5 task brief), the
// AnchorProvider it's wrapped in, and the two `Program` instances
// (vault, redemption) the investor screen needs. Kept separate from
// lib/wallet.ts's public send*/read* dispatch so that module stays a thin
// dispatcher and all the wallet/program wiring lives here.
import { AnchorProvider, BN, BorshCoder, Program, type Idl } from "@coral-xyz/anchor";
import {
  Connection,
  PublicKey,
  type Transaction,
  type VersionedTransaction,
} from "@solana/web3.js";
import bs58 from "bs58";
import vaultIdl from "../idl/rwa_vault.json";
import redemptionIdl from "../idl/rwa_redemption.json";
import pricingIdl from "../idl/rwa_pricing.json";
import type { RwaVault } from "../idl/rwa_vault_types";
import type { RwaRedemption } from "../idl/rwa_redemption_types";
import { strategyPda } from "./pda";
import { getPins, PinMismatchError } from "./pins";

/**
 * The subset of the Wallet Standard / Phantom-style injected API this app
 * uses: connect, sign a message (for the X-Wallet-Session ed25519 challenge),
 * and sign transaction(s) (for AnchorProvider). No `sendTransaction` — this
 * app always builds+sends through its own Connection to the build-time
 * pinned `VITE_SOLANA_RPC_URL` (see lib/chain/pins.ts's resolveRpcUrl),
 * never through the wallet's own transport, so which RPC a tx is submitted
 * to is always under this app's control.
 */
export interface InjectedProvider {
  publicKey: PublicKey | null;
  isConnected?: boolean;
  connect: (opts?: { onlyIfTrusted?: boolean }) => Promise<{
    publicKey: PublicKey;
  }>;
  disconnect?: () => Promise<void>;
  signMessage: (
    message: Uint8Array,
  ) => Promise<{ signature: Uint8Array } | Uint8Array>;
  signTransaction: <T extends Transaction>(tx: T) => Promise<T>;
  signAllTransactions: <T extends Transaction>(txs: T[]) => Promise<T[]>;
  on?: (event: string, handler: (...args: unknown[]) => void) => void;
  removeListener?: (
    event: string,
    handler: (...args: unknown[]) => void,
  ) => void;
}

declare global {
  interface Window {
    solana?: InjectedProvider;
  }
}

export function getInjectedProvider(): InjectedProvider | undefined {
  if (typeof window === "undefined") return undefined;
  return window.solana;
}

export interface ConnectedInjectedWallet {
  address: string;
  publicKey: PublicKey;
}

export async function connectInjectedWallet(): Promise<ConnectedInjectedWallet> {
  const provider = getInjectedProvider();
  if (!provider)
    throw new Error(
      "No injected wallet found (e.g. Phantom or Solflare).",
    );
  const { publicKey } = await provider.connect();
  return { address: publicKey.toBase58(), publicKey };
}

/**
 * Signs `message` with the connected wallet (Wallet Standard
 * `signMessage`) and returns the base58-encoded 64-byte ed25519 signature —
 * the exact wire format the frozen wallet-auth contract requires (see
 * server/internal/auth's Verifier: base58-decoded on receipt). The
 * message bytes signed are the UTF-8 encoding of the exact challenge string
 * the server returned, verbatim — no prefixing.
 */
export async function signMessageWithProvider(message: string): Promise<string> {
  const provider = getInjectedProvider();
  if (!provider) throw new Error("No injected wallet found.");
  const result = await provider.signMessage(new TextEncoder().encode(message));
  const signature = result instanceof Uint8Array ? result : result.signature;
  return bs58.encode(signature);
}

// One Connection per RPC URL — cheap to keep around, avoids rebuilding a
// fresh websocket/http client on every read.
const connectionCache = new Map<string, Connection>();

export function getConnection(rpcUrl: string): Connection {
  let conn = connectionCache.get(rpcUrl);
  if (!conn) {
    // Explicit wsEndpoint (when pinned) so the CSP's connect-src, baked from
    // the same VITE_SOLANA_WS_URL at build time, actually covers the origin
    // this Connection opens for confirmTransaction/account subscriptions —
    // mirrors web/src/lib/chain.ts. `undefined` when unset lets web3.js
    // derive its own default (fine for local dev).
    conn = new Connection(rpcUrl, {
      commitment: "confirmed",
      wsEndpoint: getPins().wsUrl,
    });
    connectionCache.set(rpcUrl, conn);
  }
  return conn;
}

// One in-flight/completed genesis check per RPC endpoint per session — a
// cluster's genesis hash is immutable for the life of that cluster, so
// re-checking on every call would be pure overhead. Keyed by
// Connection.rpcEndpoint (not the pin) so a URL that gets pin-rewritten
// mid-session (shouldn't happen, but see resolveRpcUrl) still gets its own
// check.
const genesisChecks = new Map<string, Promise<void>>();

/**
 * Cross-checks the connected cluster's genesis hash against the pinned
 * `VITE_SOLANA_CLUSTER_GENESIS` (optional hardening — mirrors
 * the equivalent server-side fix in server/cmd/platform/main.go). A
 * wrong-cluster RPC endpoint can look entirely plausible — right scheme,
 * right host, right path — while actually serving devnet, a fork, or a
 * malicious validator; the RPC URL pin alone can't catch that if the
 * attacker also controls DNS or the endpoint itself was misconfigured at
 * deploy time.
 *
 * No-op when the pin is unset (same fail-open-to-unpinned-dev behaviour as
 * every other pin in this file). Call before signing/broadcasting anything;
 * `wallet.ts`'s `signAndSend` is the one chokepoint every write
 * passes through, so that's where this is wired in.
 */
export function assertClusterGenesis(connection: Connection): Promise<void> {
  const pinned = getPins().clusterGenesis;
  if (pinned === undefined) return Promise.resolve();
  const key = connection.rpcEndpoint;
  let check = genesisChecks.get(key);
  if (!check) {
    check = connection.getGenesisHash().then((actual) => {
      if (actual !== pinned) {
        throw new PinMismatchError("cluster genesis hash", pinned, actual);
      }
    });
    // Don't cache a failed check indefinitely — a transient RPC error on
    // the first call shouldn't permanently poison this endpoint for the
    // rest of the session; a real cluster mismatch will just fail again on
    // the next call.
    check.catch(() => genesisChecks.delete(key));
    genesisChecks.set(key, check);
  }
  return check;
}

/**
 * Anchor's `AnchorProvider` wallet parameter is a minimal structural
 * interface (publicKey + signTransaction + signAllTransactions, an optional
 * Node-only `payer`) — declared locally rather than imported, since
 * `@coral-xyz/anchor`'s top-level `Wallet` export is the Node keypair-backed
 * class, not that interface. This app only ever builds legacy `Transaction`s
 * (never versioned), so the generic sign methods narrow to that at the call
 * site; the wider `Transaction | VersionedTransaction` signature is kept
 * here only so the shape matches what `AnchorProvider` expects.
 */
interface MinimalAnchorWallet {
  publicKey: PublicKey;
  signTransaction<T extends Transaction | VersionedTransaction>(
    tx: T,
  ): Promise<T>;
  signAllTransactions<T extends Transaction | VersionedTransaction>(
    txs: T[],
  ): Promise<T[]>;
}

/**
 * Adapts the injected provider to Anchor's minimal wallet interface.
 *
 * `.bind(provider)` is required: extracting the methods as
 * plain property values loses `this`, so a caller invoking them through the
 * returned object would call into the injected provider with the returned
 * object as receiver instead — Phantom/Solflare both dereference internal
 * state off `this` and would typically reject that. It's inert today
 * because `signAndSend` (lib/wallet.ts) calls `provider.signTransaction`
 * on the provider directly rather than through this wrapper, but becomes a
 * live bug the moment anything calls `program.methods…rpc()`.
 *
 * The `as unknown as` cast is still needed after the bind fix: this app's
 * injected-provider signature is generic over `Transaction` only (this app
 * never builds a `VersionedTransaction`), while `MinimalAnchorWallet`'s is
 * generic over `Transaction | VersionedTransaction` to match what
 * `AnchorProvider` expects — a real shape mismatch, not just an unbound-`this`
 * one, so narrowing it away isn't possible without either widening
 * InjectedProvider's declared type past what the wallet APIs actually
 * accept or narrowing MinimalAnchorWallet past what AnchorProvider requires.
 */
function toAnchorWallet(provider: InjectedProvider): MinimalAnchorWallet {
  if (!provider.publicKey) {
    throw new Error("Wallet is not connected.");
  }
  return {
    publicKey: provider.publicKey,
    signTransaction: provider.signTransaction.bind(provider),
    signAllTransactions: provider.signAllTransactions.bind(provider),
  } as unknown as MinimalAnchorWallet;
}

export function buildAnchorProvider(rpcUrl: string): AnchorProvider {
  const provider = getInjectedProvider();
  if (!provider) throw new Error("No injected wallet found.");
  const connection = getConnection(rpcUrl);
  return new AnchorProvider(connection, toAnchorWallet(provider), {
    commitment: "confirmed",
  });
}

/**
 * A copied IDL's `address` field is whatever program id was live when
 * `anchor build` generated it — meaningless here, since each deployment of
 * this platform runs its own independently-deployed program set. Every
 * caller must override it with the actual program id from the deployment's
 * Project record (or GET /config for the transfer hook) before constructing
 * a `Program`.
 */
function withAddress(idl: object, programId: string): Idl {
  return { ...idl, address: programId } as Idl;
}

export function vaultProgram(
  rpcUrl: string,
  programId: string,
): Program<RwaVault> {
  const provider = buildAnchorProvider(rpcUrl);
  return new Program(
    withAddress(vaultIdl, programId) as unknown as RwaVault,
    provider,
  );
}

export function redemptionProgram(
  rpcUrl: string,
  programId: string,
): Program<RwaRedemption> {
  const provider = buildAnchorProvider(rpcUrl);
  return new Program(
    withAddress(redemptionIdl, programId) as unknown as RwaRedemption,
    provider,
  );
}

/**
 * The id the NEXT `request_redemption` will be assigned — read off the
 * redemption program's singleton `Config.next_id` (see rwa_redemption's IDL),
 * since the `request` PDA is seeded by that id and must be derived by the
 * client before it can be included as an account in the instruction.
 */
export async function nextRedemptionRequestId(
  program: Program<RwaRedemption>,
  redemptionConfig: PublicKey,
): Promise<bigint> {
  const config = await program.account.config.fetch(redemptionConfig);
  return BigInt(config.nextId.toString());
}

/**
 * The pricing program's on-chain `Strategy` account, decoded via a plain
 * BorshCoder rather than a full `Program<RwaPricing>` — this app only ever
 * reads it (there's no investor-facing pricing instruction), so a typed
 * `Program` wrapper isn't worth the extra generated-types file. Field names
 * are the IDL's literal snake_case (Anchor's coder does not camelCase).
 */
export interface Strategy {
  purchasePrice: bigint;
  redemptionPrice: bigint;
  tokenDecimals: number;
}

const pricingCoder = new BorshCoder(pricingIdl as Idl);

/**
 * Reads the pricing program's Strategy singleton straight off-chain: the
 * on-chain purchase/redemption price and the RWA decimals it was
 * set against — the quote and its slippage bound come from the chain, not
 * from a server-supplied number. `pricingProgramId` must already
 * be pin-verified by the caller (see lib/chain/pins.ts) before this is
 * called.
 */
export async function readStrategyAccount(
  connection: Connection,
  pricingProgramId: PublicKey,
): Promise<Strategy> {
  const strategy = strategyPda(pricingProgramId);
  const info = await connection.getAccountInfo(strategy);
  if (!info) {
    throw new Error(
      `Strategy account not found @ ${strategy.toBase58()} — is the project deployed/finalized?`,
    );
  }
  const decoded = pricingCoder.accounts.decode("Strategy", info.data) as {
    purchase_price: BN;
    redemption_price: BN;
    token_decimals: number;
  };
  return {
    purchasePrice: BigInt(decoded.purchase_price.toString()),
    redemptionPrice: BigInt(decoded.redemption_price.toString()),
    tokenDecimals: decoded.token_decimals,
  };
}
