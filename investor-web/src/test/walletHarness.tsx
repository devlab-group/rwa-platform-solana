// Test-only helper (never in the app bundle), so react-refresh's
// "only export components" constraint — which exists purely for dev HMR —
// doesn't apply here; it intentionally exports render/install helpers too.
/* eslint-disable react-refresh/only-export-components */
import { render, type RenderResult } from "@testing-library/react";
import { useEffect, type ReactElement } from "react";
import { vi } from "vitest";
import { Keypair, PublicKey, Transaction } from "@solana/web3.js";
import { WalletProvider } from "../context/WalletContext";
import { useWalletContext } from "../context/walletContextValue";
import type { InjectedProvider } from "../lib/chain/provider";

export interface FakeWalletOptions {
  /** Base58 pubkey the fake wallet connects with; defaults to a fixed test keypair. */
  account?: string;
  /** Fixed 64-byte signature (as bytes) returned by signMessage; defaults to a fixed pattern. */
  signature?: Uint8Array;
  /** When set, signMessage rejects with this (e.g. a user-rejection error). */
  signRejection?: unknown;
}

const DEFAULT_KEYPAIR = Keypair.generate();
const DEFAULT_ACCOUNT = DEFAULT_KEYPAIR.publicKey.toBase58();
const DEFAULT_SIGNATURE = new Uint8Array(64).fill(7);

/**
 * Installs a fake Wallet Standard / Phantom-style provider on `window.solana`
 * that lib/chain/provider.ts can drive: connect(), signMessage(), and a
 * signTransaction() that just returns the transaction unmodified (this
 * harness doesn't exercise a real broadcast — see wallet.test.ts and
 * wallet.instructions.test.ts for that). Returned handle exposes spies and
 * lets a test fire an accountChanged/disconnect event so WalletProvider's
 * listeners can be exercised.
 */
export function installFakeWallet(opts: FakeWalletOptions = {}) {
  const account = opts.account ?? DEFAULT_ACCOUNT;
  const publicKey = new PublicKey(account);
  const signature = opts.signature ?? DEFAULT_SIGNATURE;
  const listeners = new Map<string, Array<(...args: unknown[]) => void>>();

  const emit = (event: string, payload: unknown) => {
    for (const h of listeners.get(event) ?? []) h(payload);
  };

  const connect = vi.fn(async () => ({ publicKey }));
  const signMessage = vi.fn(async (_message: Uint8Array) => {
    if (opts.signRejection) throw opts.signRejection;
    return { signature };
  });
  // Wallet Standard's signTransaction/signAllTransactions are generic in the
  // transaction type (`<T extends Transaction>(tx: T) => Promise<T>`) — a
  // vi.fn() typed against the concrete Transaction loses that genericity, so
  // these are plain generic functions instead (no mock assertions currently
  // depend on them; add a vi.fn() wrapper inside the body if a test needs
  // one later).
  function signTransaction<T extends Transaction>(tx: T): Promise<T> {
    return Promise.resolve(tx);
  }
  function signAllTransactions<T extends Transaction>(txs: T[]): Promise<T[]> {
    return Promise.resolve(txs);
  }

  const provider: InjectedProvider = {
    publicKey,
    isConnected: true,
    connect,
    signMessage,
    signTransaction,
    signAllTransactions,
    on: (event, handler) => {
      const arr = listeners.get(event) ?? [];
      arr.push(handler);
      listeners.set(event, arr);
    },
    removeListener: (event, handler) => {
      const arr = listeners.get(event);
      if (arr)
        listeners.set(
          event,
          arr.filter((h) => h !== handler),
        );
    },
  };

  window.solana = provider;

  return {
    account,
    signature,
    connect,
    signMessage,
    signTransaction,
    /** Fire an accountChanged event to every registered handler. */
    emitAccountChanged(newPublicKey: PublicKey | null) {
      emit("accountChanged", newPublicKey);
    },
    /** Simulate the wallet disconnecting on its own (e.g. the user locks it). */
    emitDisconnect() {
      emit("disconnect", undefined);
    },
    uninstall() {
      delete window.solana;
    },
  };
}

/**
 * Fires the context's connect() once on mount so a test starts with a
 * connected wallet, which is the state every investor action assumes.
 * Renders nothing.
 */
function ConnectOnMount() {
  const { connect } = useWalletContext();
  useEffect(() => {
    void connect();
  }, [connect]);
  return null;
}

/**
 * Renders `ui` inside a real <WalletProvider> so context-reading components
 * work. Pass `{ connected: true }` to auto-connect the (fake) wallet on mount;
 * requires installFakeWallet() to have been called first.
 */
export function renderWithWallet(
  ui: ReactElement,
  { connected = false }: { connected?: boolean } = {},
): RenderResult {
  return render(
    <WalletProvider>
      {connected && <ConnectOnMount />}
      {ui}
    </WalletProvider>,
  );
}
