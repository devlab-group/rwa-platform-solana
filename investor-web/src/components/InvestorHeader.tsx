import { WalletConnectButton } from "./WalletConnectButton";

/**
 * The app's only chrome: a brand label plus the wallet affordance, which
 * reads the connected account straight from WalletProvider, so there is
 * nothing to thread through.
 *
 * The page's own <h1> lives in the Investor route, so this stays a plain
 * banner with no heading of its own.
 */
export function InvestorHeader() {
  return (
    <nav className="app-nav" aria-label="Primary">
      <div className="app-nav__brand">RWA Investor</div>
      <WalletConnectButton />
    </nav>
  );
}
