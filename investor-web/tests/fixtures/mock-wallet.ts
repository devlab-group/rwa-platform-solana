// Installs a Wallet Standard / Phantom-style provider as `window.solana`
// before any page script runs, so the Buy/Redemption/Transfer/Wallet flows
// (src/lib/wallet.ts) work without a real browser extension, and intercepts
// every JSON-RPC call this app's `Connection` makes so those flows
// resolve against realistic account data instead of a live validator.
//
// Account/instruction bytes are built and decoded with the SAME libraries
// (`@coral-xyz/anchor`'s BorshCoder, the pinned IDLs, `@solana/web3.js`) the
// app itself uses, and PDA/ATA addresses are derived with the app's own
// `lib/chain/pda.ts` helpers — so this mock can't disagree with production
// code about a discriminator, field order, or seed. Interception happens
// entirely in this Node-side route handler (the wallet provider itself is
// injected via addInitScript, since that part must run in-page), so decoded
// submissions are just read off a plain array — no page.evaluate() round
// trip needed to retrieve them.
import type { Page, Route } from "@playwright/test";
import bs58 from "bs58";
import { BN, BorshCoder, type Idl } from "@coral-xyz/anchor";
import { PublicKey, Transaction } from "@solana/web3.js";
import { TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID } from "@solana/spl-token";
import vaultIdl from "../../src/lib/idl/rwa_vault.json";
import redemptionIdl from "../../src/lib/idl/rwa_redemption.json";
import pricingIdl from "../../src/lib/idl/rwa_pricing.json";
import {
  redemptionConfigPda,
  requestPda,
  strategyPda,
  walletRwaAta,
} from "../../src/lib/chain/pda";
import {
  MINTS,
  MOCK_WALLET_ADDRESS,
  MOCK_WALLET_KEYPAIR,
  PROGRAM_IDS,
  type MockState,
} from "./mock-api";

export { MOCK_WALLET_ADDRESS };

/**
 * The RPC origin(s) every Connection in this app might talk to. `npm test`
 * (vitest) loads `.env.test`'s `VITE_SOLANA_RPC_URL=http://localhost:8899`,
 * but `npm run build` (what `test:e2e` actually runs the app through) passes
 * no `--mode test`, so unless the environment sets `VITE_SOLANA_RPC_URL`
 * itself, `resolveRpcUrl()`'s unpinned-dev fallback
 * (`http://127.0.0.1:8899` — see lib/chain/pins.ts) is what ends up in the
 * bundle instead. Both are intercepted so this mock doesn't silently miss
 * every request in whichever case applies.
 */
const RPC_ORIGINS = ["http://localhost:8899", "http://127.0.0.1:8899"];

export const MOCK_TOKEN_DECIMALS = 9;
export const MOCK_TOKEN_BALANCE = 1_500_000_000n; // 1.5 whole tokens at 9 decimals
/** Quote-token price of one whole RWA token, as the mock pricing program's Strategy account reports it. */
export const MOCK_PURCHASE_PRICE = 1_000_000n;
export const MOCK_REDEMPTION_PRICE = 950_000n;

const vaultCoder = new BorshCoder(vaultIdl as Idl);
const redemptionCoder = new BorshCoder(redemptionIdl as Idl);
const pricingCoder = new BorshCoder(pricingIdl as Idl);

interface FakeAccount {
  owner: PublicKey;
  data: Buffer;
}

/** Minimal SPL Mint account (82 bytes) — only `decimals`/`isInitialized` are
 * ever read by this app (getMint), so every other field is left at its
 * zero-value default (no mint/freeze authority). */
function mintAccountData(decimals: number): Buffer {
  const buf = Buffer.alloc(82);
  buf.writeUInt8(decimals, 44);
  buf.writeUInt8(1, 45); // isInitialized
  return buf;
}

/** Minimal SPL token account (165 bytes) — only `mint`/`owner`/`amount` are
 * ever read by this app (getAccount); no delegate/native/close-authority. */
function tokenAccountData(mint: PublicKey, owner: PublicKey, amount: bigint): Buffer {
  const buf = Buffer.alloc(165);
  mint.toBuffer().copy(buf, 0);
  owner.toBuffer().copy(buf, 32);
  buf.writeBigUInt64LE(amount, 64);
  buf.writeUInt8(1, 108); // state = Initialized
  return buf;
}

export interface InstallMockWalletOptions {
  /** Overrides MOCK_TOKEN_BALANCE for the wallet's RWA ATA. */
  balance?: bigint;
}

/** A decoded instruction this mock's `sendTransaction` handler observed, targeting the vault or redemption program. */
export interface DecodedInstruction {
  programId: string;
  name: string;
  /** Decoded args, snake_case per the IDL (Anchor's coder does not camelCase). BN fields are stringified. */
  data: Record<string, unknown>;
  accounts: string[];
}

function decodeVaultOrRedemptionInstructions(rawTx: Buffer): DecodedInstruction[] {
  const tx = Transaction.from(rawTx);
  const out: DecodedInstruction[] = [];
  for (const ix of tx.instructions) {
    const programId = ix.programId.toBase58();
    const coder =
      programId === PROGRAM_IDS.vault.toBase58()
        ? vaultCoder
        : programId === PROGRAM_IDS.redemption.toBase58()
          ? redemptionCoder
          : undefined;
    if (!coder) continue;
    const decoded = coder.instruction.decode(ix.data);
    if (!decoded) continue;
    const data = Object.fromEntries(
      Object.entries(decoded.data as Record<string, unknown>).map(([k, v]) => [
        k,
        v instanceof BN ? v.toString() : v,
      ]),
    );
    out.push({
      programId,
      name: decoded.name,
      data,
      accounts: ix.keys.map((k) => k.pubkey.toBase58()),
    });
  }
  return out;
}

/**
 * Installs the fake wallet + RPC mock. `state` is the same MockState
 * `installMockApi` returned — this needs to see redemptions a spec pushes
 * into it after this call, so it derives each `RedemptionRequest` account
 * lazily per-request rather than snapshotting the list once.
 */
export async function installMockWallet(
  page: Page,
  state: MockState,
  options: InstallMockWalletOptions = {},
): Promise<{ getSentTransactions: () => DecodedInstruction[][] }> {
  const balance = options.balance ?? MOCK_TOKEN_BALANCE;
  const walletPubkey = MOCK_WALLET_KEYPAIR.publicKey;

  const rwaAta = walletRwaAta(MINTS.rwa, walletPubkey);
  const strategy = strategyPda(PROGRAM_IDS.pricing);
  const redemptionConfig = redemptionConfigPda(PROGRAM_IDS.redemption);

  const staticAccounts = new Map<string, FakeAccount>();
  staticAccounts.set(MINTS.rwa.toBase58(), {
    owner: TOKEN_2022_PROGRAM_ID,
    data: mintAccountData(MOCK_TOKEN_DECIMALS),
  });
  staticAccounts.set(MINTS.quote.toBase58(), {
    owner: TOKEN_PROGRAM_ID,
    data: mintAccountData(MOCK_TOKEN_DECIMALS),
  });
  staticAccounts.set(rwaAta.toBase58(), {
    owner: TOKEN_2022_PROGRAM_ID,
    data: tokenAccountData(MINTS.rwa, walletPubkey, balance),
  });
  staticAccounts.set(strategy.toBase58(), {
    owner: PROGRAM_IDS.pricing,
    data: pricingCoder.accounts.encode("Strategy", {
      admin: PublicKey.default,
      pending_admin: PublicKey.default,
      pricer: PublicKey.default,
      token_decimals: MOCK_TOKEN_DECIMALS,
      purchase_price: new BN(MOCK_PURCHASE_PRICE.toString()),
      redemption_price: new BN(MOCK_REDEMPTION_PRICE.toString()),
      bump: 255,
    }),
  });
  staticAccounts.set(redemptionConfig.toBase58(), {
    owner: PROGRAM_IDS.redemption,
    data: redemptionCoder.accounts.encode("Config", {
      admin: PublicKey.default,
      pending_admin: PublicKey.default,
      treasurer: PublicKey.default,
      redemption_manager: PublicKey.default,
      vault: PROGRAM_IDS.vault,
      rwa_mint: MINTS.rwa,
      quote_mint: MINTS.quote,
      quote_decimals: MOCK_TOKEN_DECIMALS,
      strategy: PROGRAM_IDS.pricing,
      registry: PublicKey.default,
      redemption_timeout: new BN(3600),
      next_id: new BN(0),
      bump: 255,
    }),
  });

  /** Every `state.redemptions` entry, as the RedemptionRequest account its
   * requestPda would hold — computed lazily (not just at install time) so a
   * spec that pushes a redemption AFTER installMockWallet runs still gets a
   * fetchable account. */
  function redemptionRequestAccount(pubkey: string): FakeAccount | undefined {
    for (const r of state.redemptions) {
      if (!r.id || !r.beneficiary) continue;
      let id: bigint;
      try {
        id = BigInt(r.id);
      } catch {
        continue;
      }
      if (requestPda(PROGRAM_IDS.redemption, id).toBase58() !== pubkey) continue;
      return {
        owner: PROGRAM_IDS.redemption,
        data: redemptionCoder.accounts.encode("RedemptionRequest", {
          id: new BN(id.toString()),
          beneficiary: new PublicKey(r.beneficiary),
          rwa_amount: new BN(r.rwaAmount ?? "0"),
          quote_amount: new BN(r.quoteAmount ?? "0"),
          created_at: new BN(r.createdAt ?? 0),
          status: 0,
          bump: 255,
        }),
      };
    }
    return undefined;
  }

  function lookupAccount(pubkey: string): FakeAccount | undefined {
    return staticAccounts.get(pubkey) ?? redemptionRequestAccount(pubkey);
  }

  const sentTransactions: DecodedInstruction[][] = [];
  let signatureCounter = 0;

  const handleRpcRoute = async (route: Route) => {
    const req = route.request();
    let body: { jsonrpc: string; id: number; method: string; params?: unknown[] };
    try {
      body = req.postDataJSON();
    } catch {
      return route.continue();
    }
    const respond = (result: unknown) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ jsonrpc: "2.0", id: body.id, result }),
      });

    switch (body.method) {
      case "getAccountInfo": {
        const pubkey = body.params?.[0] as string;
        const account = lookupAccount(pubkey);
        return respond({
          context: { slot: 1 },
          value: account
            ? {
                data: [account.data.toString("base64"), "base64"],
                executable: false,
                lamports: 1_000_000,
                owner: account.owner.toBase58(),
                rentEpoch: 0,
              }
            : null,
        });
      }
      case "getLatestBlockhash":
        return respond({
          context: { slot: 1 },
          value: {
            blockhash: "11111111111111111111111111111111111111111111",
            lastValidBlockHeight: 1_000_000,
          },
        });
      case "simulateTransaction":
        return respond({
          context: { slot: 1 },
          value: { err: null, logs: [], accounts: null, unitsConsumed: 0 },
        });
      case "sendTransaction": {
        const rawTx = Buffer.from(body.params?.[0] as string, "base64");
        sentTransactions.push(decodeVaultOrRedemptionInstructions(rawTx));
        signatureCounter += 1;
        const sig = Buffer.alloc(64, 0);
        sig.writeUInt32LE(signatureCounter, 0);
        return respond(bs58.encode(sig));
      }
      case "getGenesisHash":
        // VITE_SOLANA_CLUSTER_GENESIS is unset in the test build (see
        // .env.test) so assertClusterGenesis never actually calls this, but
        // answer harmlessly if it ever does.
        return respond("11111111111111111111111111111111111111111111");
      default:
        return respond(null);
    }
  };

  for (const origin of RPC_ORIGINS) {
    await page.route(`${origin}/**`, handleRpcRoute);
  }

  // The injected window.solana provider itself has to run in-page — it
  // can't import @solana/web3.js/bs58 (no bundling happens for
  // addInitScript). `tx` passed to signTransaction is nonetheless a REAL
  // `Transaction` instance (built by this app's own bundled web3.js in
  // wallet.ts's signAndSend), and `signAndSend` calls
  // `signed.serialize()` afterwards, which cryptographically verifies every
  // signature — so a dummy/unsigned return would make every write flow fail.
  // It signs for real via the Web Crypto API's native Ed25519 support (no
  // bundled crypto library available here either), importing the fixed test
  // keypair's raw seed wrapped in the constant RFC 8410 PKCS8 DER prefix for
  // Ed25519 private keys, and reuses
  // `tx.feePayer` (already a real PublicKey from the same bundle) as the
  // signer identity for `tx.addSignature` rather than trying to construct
  // one of its own.
  await page.addInitScript(
    ({
      publicKeyBase58,
      seed,
    }: {
      publicKeyBase58: string;
      seed: number[];
    }) => {
      // RFC 8410 PKCS8 wrapping for a raw 32-byte Ed25519 private key seed —
      // a fixed 16-byte ASN.1 prefix, not computed.
      const PKCS8_ED25519_PREFIX = new Uint8Array([
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
        0x04, 0x22, 0x04, 0x20,
      ]);
      const pkcs8 = new Uint8Array(48);
      pkcs8.set(PKCS8_ED25519_PREFIX, 0);
      pkcs8.set(seed, 16);
      const signingKeyPromise = crypto.subtle.importKey(
        "pkcs8",
        pkcs8,
        { name: "Ed25519" },
        false,
        ["sign"],
      );

      const listeners = new Map<string, Set<(...args: unknown[]) => void>>();
      const fakePublicKey = {
        toBase58: () => publicKeyBase58,
        equals: (other: { toBase58: () => string }) =>
          other.toBase58() === publicKeyBase58,
      };
      (window as unknown as { solana: unknown }).solana = {
        publicKey: fakePublicKey,
        isConnected: true,
        async connect() {
          return { publicKey: fakePublicKey };
        },
        async signMessage(message: Uint8Array) {
          const key = await signingKeyPromise;
          const sig = await crypto.subtle.sign({ name: "Ed25519" }, key, message);
          return { signature: new Uint8Array(sig) };
        },
        async signTransaction(tx: {
          serializeMessage(): Uint8Array;
          feePayer: unknown;
          addSignature(pubkey: unknown, signature: Uint8Array): void;
        }) {
          const key = await signingKeyPromise;
          const message = tx.serializeMessage();
          const sig = await crypto.subtle.sign({ name: "Ed25519" }, key, message);
          tx.addSignature(tx.feePayer, new Uint8Array(sig));
          return tx;
        },
        async signAllTransactions(
          txs: Array<{
            serializeMessage(): Uint8Array;
            feePayer: unknown;
            addSignature(pubkey: unknown, signature: Uint8Array): void;
          }>,
        ) {
          const key = await signingKeyPromise;
          for (const tx of txs) {
            const sig = await crypto.subtle.sign(
              { name: "Ed25519" },
              key,
              tx.serializeMessage(),
            );
            tx.addSignature(tx.feePayer, new Uint8Array(sig));
          }
          return txs;
        },
        on(event: string, handler: (...args: unknown[]) => void) {
          if (!listeners.has(event)) listeners.set(event, new Set());
          listeners.get(event)!.add(handler);
        },
        removeListener(event: string, handler: (...args: unknown[]) => void) {
          listeners.get(event)?.delete(handler);
        },
      };
    },
    {
      publicKeyBase58: walletPubkey.toBase58(),
      seed: Array.from(MOCK_WALLET_KEYPAIR.secretKey.slice(0, 32)),
    },
  );

  return { getSentTransactions: () => sentTransactions };
}
