// Injects a minimal Wallet-Standard-shaped wallet provider as `window.solana`
// before any page script runs, so the admin flows (src/lib/wallet.ts /
// src/lib/chain.ts) work without a real browser extension. Every
// instruction the mock wallet is asked to sign is recorded (program id +
// base64-encoded instruction data) and exposed for specs to assert against —
// see getMockSentTransactions. Specs decode the data themselves against
// whichever checked-in Anchor IDL (src/lib/idl/*.json) matches the program
// under test, the same way src/lib/chain.test.ts does — there is no generic
// program-id -> IDL lookup here, since the deployment's actual program ids
// (GET /api/v1/config's programIds) are arbitrary per-deployment addresses,
// not the placeholder `address` field baked into the IDL JSON at build time.
//
// NOTE: this only mocks the WALLET (signing). It does not mock the RPC
// endpoint lib/chain.ts's `Connection` reads/broadcasts against
// (VITE_SOLANA_RPC_URL) — that still needs a real, reachable RPC endpoint
// (e.g. a local `solana-test-validator`) at Playwright's build time for any
// spec that exercises a wallet.ts function backed by an on-chain read
// (readMintDecimals, readVaultInventory, sendFundRedemption, etc.). See this
// worker's report for the cross-scope flag on wiring that up.
import type { Page } from "@playwright/test";

export const MOCK_WALLET_ADDRESS = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";

export interface InstallMockWalletOptions {
  address?: string;
}

export async function installMockWallet(
  page: Page,
  options: InstallMockWalletOptions = {},
): Promise<void> {
  await page.addInitScript((address: string) => {
    let sigCounter = 0;
    const sentTransactions: { programId: string; data: string }[] = [];

    const provider = {
      isMockWallet: true,
      publicKey: {
        toBase58: () => address,
        toBytes: () => new Uint8Array(32),
      },
      _listeners: new Map<string, Set<(...a: unknown[]) => void>>(),
      on(event: string, handler: (...a: unknown[]) => void) {
        if (!this._listeners.has(event)) this._listeners.set(event, new Set());
        this._listeners.get(event)!.add(handler);
      },
      removeListener(event: string, handler: (...a: unknown[]) => void) {
        this._listeners.get(event)?.delete(handler);
      },
      async connect() {
        return { publicKey: this.publicKey };
      },
      async disconnect() {},
      async signMessage(message: Uint8Array) {
        // A fixed, deterministic 64-byte "signature" — specs assert wallet
        // interaction happened, not the exact bytes of an unauthenticated
        // ed25519 signature.
        void message;
        return { signature: new Uint8Array(64).fill(7) };
      },
      // Test-only hook (not part of Wallet Standard): specs call this via
      // page.evaluate to read every instruction submitted so far.
      __getSentTransactions() {
        return sentTransactions;
      },
      async signAndSendTransaction(tx: {
        instructions: { programId: { toBase58(): string }; data: Uint8Array }[];
      }) {
        for (const ix of tx.instructions) {
          sentTransactions.push({
            programId: ix.programId.toBase58(),
            data: Buffer.from(ix.data).toString("base64"),
          });
        }
        sigCounter += 1;
        return { signature: `mocksig${sigCounter}` };
      },
      async signTransaction<T>(tx: T) {
        return tx;
      },
    };

    (window as unknown as { solana: unknown }).solana = provider;
  }, options.address ?? MOCK_WALLET_ADDRESS);
}

export interface MockSentTransaction {
  /** base58 program id the instruction was addressed to. */
  programId: string;
  /** Base64-encoded raw instruction data — decode with the matching program's BorshCoder (see src/lib/chain.test.ts's pattern). */
  data: string;
}

/** Returns every instruction submitted so far, as sent (undecoded) — decode against the expected program's Anchor IDL in the spec itself. */
export async function getMockSentTransactions(page: Page): Promise<MockSentTransaction[]> {
  return page.evaluate(() =>
    (
      window as unknown as {
        solana: { __getSentTransactions: () => MockSentTransaction[] };
      }
    ).solana.__getSentTransactions(),
  );
}
