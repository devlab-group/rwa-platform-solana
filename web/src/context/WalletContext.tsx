import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { api } from "../lib/client";
import { connectWallet, signMessage as signMessageWithWallet } from "../lib/wallet";
import { configure, getInjectedProvider } from "../lib/chain";
import {
  WalletContext,
  type WalletContextValue,
  type WalletStatus,
} from "./walletContextValue";

/**
 * App-wide connected-wallet state, built on lib/wallet's chain-access stack
 * (lib/chain.ts + the injected wallet provider — no
 * @solana/wallet-adapter-react). A single provider is mounted at the app root
 * so every screen — the admin login, the always-present header Connect
 * button, and Setup's on-chain decimals read — shares one wallet connection
 * and one `accountChanged` subscription, rather than each hook opening its
 * own. The context value/type/hook live in ./walletContextValue so this file
 * only exports the component (react-refresh).
 */
export function WalletProvider({ children }: { children: ReactNode }) {
  const [address, setAddress] = useState<string | null>(null);
  const [chainId, setChainId] = useState<number | null>(null);
  const [chainConfigError, setChainConfigError] = useState<string | null>(
    null,
  );
  const [connecting, setConnecting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // GET /api/v1/config is public and available even pre-deploy — read once at
  // startup for the program ids/RPC endpoint lib/wallet.ts's send*/
  // read* functions need. This single-tenant deployment's config is fixed for
  // its whole lifetime, so this is set once and never changes. A server
  // response with no programIds configured is a misconfigured deployment —
  // every wallet action is blocked (chainConfigError) rather than silently
  // proceeding with an unconfigured chain layer.
  useEffect(() => {
    let cancelled = false;
    api
      .getConfig()
      .then((cfg) => {
        if (cancelled) return;
        if (!cfg.programIds) {
          setChainConfigError(
            "Server has no program ids configured. This deployment is misconfigured — wallet actions are disabled until it is fixed.",
          );
          return;
        }
        configure({
          solanaChainId: cfg.solanaChainId,
          programIds: {
            compliance: cfg.programIds.compliance ?? "",
            vault: cfg.programIds.vault ?? "",
            pricing: cfg.programIds.pricing ?? "",
            transferHook: cfg.programIds.transferHook ?? "",
            redemption: cfg.programIds.redemption ?? "",
            supplyController: cfg.programIds.supplyController ?? "",
          },
        });
      })
      .catch(() => {
        // Bootstrap config is unreachable (server down, network error) — every
        // screen's own AsyncSection already surfaces the underlying fetch
        // failure independently.
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const connect = useCallback(async () => {
    setConnecting(true);
    setError(null);
    try {
      const wallet = await connectWallet();
      setAddress(wallet.address);
      setChainId(wallet.chainId);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to connect wallet.",
      );
    } finally {
      setConnecting(false);
    }
  }, []);

  const disconnect = useCallback(() => {
    // The injected wallets have no programmatic "disconnect this
    // dApp" RPC that's universally implemented (Phantom's disconnect() is
    // opt-in), so connection is a purely client-side notion here: forget the
    // account and the app falls back to the Connect affordance. The admin JWT
    // is dropped separately on logout.
    setAddress(null);
    setChainId(null);
    setError(null);
  }, []);

  const signMessage = useCallback((message: string): Promise<string> => {
    if (!address) throw new Error("No wallet connected.");
    return signMessageWithWallet(message);
  }, [address]);

  // React to the wallet's own account changes rather than only reading them
  // at connect time — an account swap after connect must be reflected
  // immediately, not just at the next reload. Connection is only ever
  // established by an explicit connect() (the header Connect button / admin
  // login), never silently, so the admin flow starts disconnected until the
  // user acts. Phantom/Solflare emit "accountChanged" (singular) with the new
  // PublicKey, or no argument on disconnect.
  useEffect(() => {
    const provider = getInjectedProvider();
    if (!provider?.on) return;

    const handleAccountChanged = (...args: unknown[]) => {
      const pk = args[0] as { toBase58?(): string } | null | undefined;
      setAddress(pk?.toBase58 ? pk.toBase58() : null);
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
      chainId,
      chainConfigError,
      status,
      connecting,
      error,
      connect,
      disconnect,
      signMessage,
    }),
    [
      address,
      chainId,
      chainConfigError,
      status,
      connecting,
      error,
      connect,
      disconnect,
      signMessage,
    ],
  );

  return (
    <WalletContext.Provider value={value}>{children}</WalletContext.Provider>
  );
}
