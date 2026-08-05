import { useWalletContext } from "../context/walletContextValue";

export interface WalletState {
  address: string | null;
  connecting: boolean;
  error: string | null;
  connect: () => Promise<void>;
}

/**
 * Per-page binding over the app-wide WalletProvider. The connection itself
 * (address/connect/events) lives in the context so it's shared across every
 * screen; this hook is a thin pass-through kept so call sites don't reach
 * into the context directly.
 */
export function useWallet(): WalletState {
  const wallet = useWalletContext();
  return {
    address: wallet.address,
    connecting: wallet.connecting,
    error: wallet.error,
    connect: wallet.connect,
  };
}
