import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import {
  connectWallet,
  signMessage as signMessageWithWallet,
} from "../lib/wallet";
import { getInjectedProvider } from "../lib/chain/provider";
import {
  WalletContext,
  type WalletContextValue,
  type WalletStatus,
} from "./walletContextValue";

/**
 * App-wide connected-wallet state, built on lib/wallet's Wallet
 * Standard stack. A single provider is mounted at the app root so the header
 * Connect button and every section that reads or writes on-chain share one
 * wallet connection and one set of `accountChanged`/`disconnect`
 * subscriptions, rather than each hook opening its own. The context
 * value/type/hook live in ./walletContextValue so this file only exports the
 * component (react-refresh).
 */
export function WalletProvider({ children }: { children: ReactNode }) {
  const [address, setAddress] = useState<string | null>(null);
  const [connecting, setConnecting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const connect = useCallback(async () => {
    setConnecting(true);
    setError(null);
    try {
      const wallet = await connectWallet();
      setAddress(wallet.address);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to connect wallet.",
      );
    } finally {
      setConnecting(false);
    }
  }, []);

  const disconnect = useCallback(() => {
    // Phantom/Solflare expose no "disconnect this dApp" RPC, so connection is
    // a purely client-side notion: forget the account and the app falls back
    // to the Connect affordance. The stored wallet session is dropped
    // alongside it by the caller (see components/WalletConnectButton.tsx).
    setAddress(null);
    setError(null);
  }, []);

  const signMessage = useCallback(
    (message: string): Promise<string> => {
      if (!address) throw new Error("No wallet connected.");
      return signMessageWithWallet(message);
    },
    [address],
  );

  // React to the wallet's own account/disconnect changes rather than only
  // reading them at connect time — an account swap after connect must be
  // reflected immediately, not just at the next reload. Connection is only
  // ever established by an explicit connect() (the header Connect button),
  // never silently — the app always starts disconnected until the user acts.
  useEffect(() => {
    const provider = getInjectedProvider();
    if (!provider?.on) return;

    const handleAccountChanged = (...args: unknown[]) => {
      const newPublicKey = args[0] as { toBase58?: () => string } | undefined;
      if (!newPublicKey) {
        setAddress(null);
      } else if (typeof newPublicKey.toBase58 === "function") {
        setAddress(newPublicKey.toBase58());
      }
    };
    const handleDisconnect = () => {
      setAddress(null);
    };

    provider.on("accountChanged", handleAccountChanged);
    provider.on("disconnect", handleDisconnect);
    return () => {
      provider.removeListener?.("accountChanged", handleAccountChanged);
      provider.removeListener?.("disconnect", handleDisconnect);
    };
  }, []);

  const status: WalletStatus = connecting
    ? "connecting"
    : address
      ? "connected"
      : "disconnected";

  const value = useMemo<WalletContextValue>(
    () => ({
      address,
      status,
      connecting,
      error,
      connect,
      disconnect,
      signMessage,
    }),
    [address, status, connecting, error, connect, disconnect, signMessage],
  );

  return (
    <WalletContext.Provider value={value}>{children}</WalletContext.Provider>
  );
}
