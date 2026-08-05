// Test-only helper (never in the app bundle), so react-refresh's
// "only export components" constraint — which exists purely for dev HMR —
// doesn't apply here; it intentionally exports render/install helpers too.
/* eslint-disable react-refresh/only-export-components */
import { render, type RenderResult } from "@testing-library/react";
import { useEffect, type ReactElement } from "react";
import bs58 from "bs58";
import { vi } from "vitest";
import { WalletProvider } from "../context/WalletContext";
import { useWalletContext } from "../context/walletContextValue";
import type { InjectedProvider } from "../lib/chain";

export interface FakeWalletOptions {
  account?: string;
  /** Fixed signature (base58) returned by signMessage; defaults to a valid-length 64-byte signature, base58-encoded. */
  signature?: string;
  /** When set, signMessage rejects with this (e.g. a user-rejection error). */
  signRejection?: unknown;
}

const DEFAULT_ACCOUNT = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
// A syntactically valid base58 string standing in for a 64-byte signature —
// tests only assert it round-trips through wallet.signMessage, never decode it.
const DEFAULT_SIGNATURE =
  "3v1VbGV8DzGVoRUpUgcnpDVLXFCmvvCyzq5w4RYqNQhVE3RVKMuLW3wf4V1SoJKrFnQxvE6d1XPjM8Q1AC9sNKcJ";

/**
 * Installs a fake injected wallet provider on `window.solana` that
 * WalletContext.tsx / lib/wallet.ts can drive: it answers connect() and
 * signMessage(). Returned handle exposes the account and lets a test flip the
 * connected account (accountChanged) so WalletProvider's listener can be
 * exercised.
 */
export function installFakeWallet(opts: FakeWalletOptions = {}) {
  const account = opts.account ?? DEFAULT_ACCOUNT;
  const signature = opts.signature ?? DEFAULT_SIGNATURE;
  const listeners = new Map<string, Array<(...args: unknown[]) => void>>();

  const emit = (event: string, payload: unknown) => {
    for (const h of listeners.get(event) ?? []) h(payload);
  };

  // lib/chain.ts's signInjectedMessage base58-encodes whatever byte signature
  // comes back from the provider — decode the desired base58 `signature`
  // once here so the round trip reproduces it exactly.
  const signatureBytes = bs58.decode(signature);
  const signMessage = vi.fn(async () => {
    if (opts.signRejection) throw opts.signRejection;
    return { signature: signatureBytes };
  });

  const provider: InjectedProvider = {
    publicKey: { toBase58: () => account, toBytes: () => new Uint8Array() },
    async connect() {
      return { publicKey: { toBase58: () => account } };
    },
    signMessage,
    signTransaction: async (tx) => tx,
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
    signMessage,
    /** Fire an accountChanged event to every registered handler. */
    emitAccountChanged(pk: { toBase58(): string } | null) {
      emit("accountChanged", pk);
    },
    uninstall() {
      delete window.solana;
    },
  };
}

/**
 * Fires the context's connect() once on mount so a test starts with a
 * connected wallet — mirroring the real app, where the admin connects during
 * login before reaching a screen like Setup. Renders nothing.
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
