import { createContext, useContext } from "react";

export type WalletStatus = "disconnected" | "connecting" | "connected";

/**
 * App-wide connected-wallet state (see WalletContext.tsx for the provider).
 * Kept in its own module so WalletContext.tsx exports only the component,
 * which keeps react-refresh happy.
 *
 * `address` is a base58 pubkey; `chainId` is informational only
 * (BootstrapConfig.solanaChainId) — no wallet call is gated on it.
 */
export interface WalletContextValue {
  address: string | null;
  chainId: number | null;
  /**
   * Set when GET /api/v1/config reports a chain configuration lib/wallet.ts
   * cannot act on safely — currently: no programIds configured (a
   * misconfigured deployment). AppLayout renders this in place of the routed
   * screen rather than letting a screen reach a state it can't act on.
   */
  chainConfigError: string | null;
  status: WalletStatus;
  connecting: boolean;
  error: string | null;
  /** Prompts the wallet for account access (the wallet's connect()). */
  connect: () => Promise<void>;
  /** Client-side disconnect: injected wallets have no programmatic revoke, so this just forgets the account locally. */
  disconnect: () => void;
  /**
   * Signs `message` with the connected account: the injected wallet's
   * ed25519 signMessage, base58-encoded — see lib/wallet.ts's signMessage.
   * Throws if no wallet is connected.
   */
  signMessage: (message: string) => Promise<string>;
}

export const WalletContext = createContext<WalletContextValue | undefined>(
  undefined,
);

/** Reads the app-wide wallet context. Throws if used outside <WalletProvider>. */
export function useWalletContext(): WalletContextValue {
  const ctx = useContext(WalletContext);
  if (!ctx)
    throw new Error("useWalletContext must be used within a <WalletProvider>.");
  return ctx;
}
