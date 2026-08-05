import { createContext, useContext } from "react";

export type WalletStatus = "disconnected" | "connecting" | "connected";

/**
 * App-wide connected-wallet state (see WalletContext.tsx for the provider).
 * Kept in its own module so WalletContext.tsx exports only the component,
 * which keeps react-refresh happy.
 */
export interface WalletContextValue {
  /** Base58 pubkey. */
  address: string | null;
  status: WalletStatus;
  connecting: boolean;
  error: string | null;
  /** Prompts the wallet for account access (Wallet Standard connect()). */
  connect: () => Promise<void>;
  /** Client-side disconnect: injected wallets have no programmatic revoke, so this just forgets the account locally. */
  disconnect: () => void;
  /** Signs the given message with the connected account (Wallet Standard signMessage, base58 ed25519 signature). Throws if no wallet is connected. */
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
