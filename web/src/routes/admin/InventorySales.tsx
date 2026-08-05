import { useState } from "react";
import { AsyncSection } from "../../components/AsyncSection";
import { PaginationFooter } from "../../components/PaginationFooter";
import { RoleGate } from "../../components/RoleGate";
import { useWalletContext } from "../../context/walletContextValue";
import { useAsync } from "../../hooks/useAsync";
import { usePaginatedList } from "../../hooks/usePaginatedList";
import { api } from "../../lib/client";
import type { components } from "../../lib/api-types";
import { resolveQuoteDecimals } from "../../lib/decimals";
import { ROLES } from "../../lib/roles";
import {
  formatTokenAmount,
  shortenAddress,
  toMinimalUnits,
} from "../../lib/format";
import {
  readPreviewBuy,
  readVaultInventory,
  sendWithdrawProceeds,
  waitForTxReceipt,
} from "../../lib/wallet";

type Inventory = components["schemas"]["Inventory"];
type Project = components["schemas"]["Project"];
type Purchase = components["schemas"]["Purchase"];

/** A purchase quote read straight off the vault; both amounts are minimal units. */
interface BuyQuote {
  tokenAmount: string;
  quoteAmount: string;
}

/**
 * Inventory & Sales: vault inventory, quote balance, purchase price, custom
 * strategy address, purchase quote preview, purchase history, and treasury
 * withdrawal (Vault.withdrawProceeds broadcast from the connected wallet).
 * Off-chain distribution was removed — only on-chain payment via Vault `buy`
 * remains.
 */
export function InventorySales() {
  // project loads first — the vault inventory read needs its vault/token/
  // quoteToken addresses (see readVaultInventory), and the rest of the
  // screen's display waits on it for decimals too, so there's no benefit to
  // racing them.
  const project = useAsync<Project>((signal) => api.getProject({ signal }), []);
  const proj = project.status === "success" ? project.data : undefined;

  // GET /api/v1/sales/inventory 501s by design (the server does not track
  // live on-chain balances) — read the vault's custody ATAs directly on-chain
  // instead, folded into the same Inventory shape the API would otherwise
  // return so the rest of this screen doesn't need a separate read path.
  const inventory = useAsync<Inventory>(
    async () => {
      if (!proj?.addresses?.vault || !proj.addresses.token || !proj.addresses.quoteToken) {
        throw new Error("Project not loaded yet — try again in a moment.");
      }
      const { inventory: rwaBalance, quoteBalance } = await readVaultInventory(
        proj.addresses.vault,
        proj.addresses.token,
        proj.addresses.quoteToken,
      );
      return {
        inventory: rwaBalance,
        quoteBalance,
        purchasePrice: proj.purchasePricePerWholeToken,
        redemptionPrice: proj.redemptionPricePerWholeToken,
      };
    },
    [
      proj?.addresses?.vault,
      proj?.addresses?.token,
      proj?.addresses?.quoteToken,
      proj?.purchasePricePerWholeToken,
      proj?.redemptionPricePerWholeToken,
    ],
  );
  const purchases = usePaginatedList<Purchase>(
    (cursor, signal) => api.listPurchases({ signal, cursor }),
    [],
  );

  // RWA decimals come straight from the project (authoritative). Quote-token
  // decimals have no field in the HTTP contract, so they're read on-chain
  // best-effort for DISPLAY — a missing wallet/RPC just falls back to the
  // grouped raw integer rather than mis-scaling. The withdrawal form resolves
  // them itself at submit time and errors instead of guessing (input safety).
  const rwaDecimals = proj?.decimals;
  const quoteDecimalsState = useAsync<number | null>(async () => {
    if (!proj) return null;
    try {
      return await resolveQuoteDecimals(proj);
    } catch {
      return null;
    }
  }, [proj?.addresses?.quoteToken]);
  const quoteDecimals =
    quoteDecimalsState.status === "success"
      ? (quoteDecimalsState.data ?? undefined)
      : undefined;

  return (
    <div>
      <header className="app-main__header">
        <h1>Inventory &amp; Sales</h1>
        <p>Vault inventory, pricing, purchases, and treasury withdrawal.</p>
      </header>

      <section className="card">
        <h2>Inventory</h2>
        <AsyncSection state={inventory} onRetry={inventory.reload}>
          {(data) => (
            <dl className="tx-preview__grid">
              <div className="tx-preview__row">
                <dt>Vault inventory</dt>
                <dd>{formatTokenAmount(data.inventory ?? "", rwaDecimals)}</dd>
              </div>
              <div className="tx-preview__row">
                <dt>Quote balance</dt>
                <dd>
                  {formatTokenAmount(data.quoteBalance ?? "", quoteDecimals)}
                </dd>
              </div>
              <div className="tx-preview__row">
                <dt>Purchase price</dt>
                <dd>
                  {formatTokenAmount(data.purchasePrice ?? "", quoteDecimals)}
                </dd>
              </div>
              <div className="tx-preview__row">
                <dt>Redemption price</dt>
                <dd>
                  {formatTokenAmount(data.redemptionPrice ?? "", quoteDecimals)}
                </dd>
              </div>
              {project.status === "success" &&
                project.data.addresses?.strategy && (
                  <div className="tx-preview__row">
                    <dt>Strategy address</dt>
                    <dd title={project.data.addresses.strategy}>
                      {shortenAddress(project.data.addresses.strategy)}
                    </dd>
                  </div>
                )}
            </dl>
          )}
        </AsyncSection>
      </section>

      <section className="card">
        <h2>Purchase quote preview</h2>
        <BuyQuotePreview
          vault={proj?.addresses?.vault}
          rwaDecimals={rwaDecimals}
          quoteDecimals={quoteDecimals}
          purchasePricePerWholeToken={proj?.purchasePricePerWholeToken}
        />
      </section>

      <section className="card">
        <h2>Treasury withdrawal</h2>
        <RoleGate
          roles={proj?.roles}
          role={ROLES.treasurer}
          action="withdraw treasury proceeds"
        >
          <WithdrawForm
            project={proj}
            availableQuote={
              inventory.status === "success"
                ? inventory.data.quoteBalance
                : undefined
            }
            quoteDecimals={quoteDecimals}
            onWithdrawn={inventory.reload}
          />
        </RoleGate>
      </section>

      <section className="card">
        <h2>Purchase history</h2>
        <AsyncSection
          state={purchases}
          onRetry={purchases.reload}
          empty={(d) => d.length === 0}
          emptyLabel="No purchases recorded yet."
        >
          {(data) => (
            <>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Tx hash</th>
                      <th>Buyer</th>
                      <th>Recipient</th>
                      <th>Token amount</th>
                      <th>Quote amount</th>
                      <th>Confirmations</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.map((p) => (
                      <tr key={p.txHash}>
                        <td className="mono">{p.txHash}</td>
                        <td className="mono" title={p.buyer}>
                          {shortenAddress(p.buyer)}
                        </td>
                        <td className="mono" title={p.recipient}>
                          {shortenAddress(p.recipient)}
                        </td>
                        <td>
                          {formatTokenAmount(p.tokenAmount ?? "", rwaDecimals)}
                        </td>
                        <td>
                          {formatTokenAmount(
                            p.quoteAmount ?? "",
                            quoteDecimals,
                          )}
                        </td>
                        <td>{p.confirmations ?? 0}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <PaginationFooter
                loadedCount={data.length}
                totalCount={purchases.totalCount}
                hasMore={purchases.hasMore}
                loadingMore={purchases.loadingMore}
                loadMoreError={purchases.loadMoreError}
                onLoadMore={purchases.loadMore}
              />
            </>
          )}
        </AsyncSection>
      </section>
    </div>
  );
}

function BuyQuotePreview({
  vault,
  rwaDecimals,
  quoteDecimals,
  purchasePricePerWholeToken,
}: {
  /** Presence gates the preview: readPreviewBuy itself doesn't need the vault address (see below), but requiring it here keeps the form hidden until the project is deployed. */
  vault: string | undefined;
  rwaDecimals: number | undefined;
  quoteDecimals: number | undefined;
  /** Current on-chain purchase price (GET /project) — there is no on-chain preview instruction, so readPreviewBuy computes the quote client-side from this instead. */
  purchasePricePerWholeToken: string | undefined;
}) {
  const [tokenAmount, setTokenAmount] = useState("");
  const [quote, setQuote] = useState<BuyQuote | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handlePreview() {
    if (rwaDecimals === undefined) {
      setError("Token decimals not available yet — project still loading.");
      return;
    }
    if (!vault) {
      setError("Missing vault address — project not deployed?");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      // Human whole units -> the RWA token's minimal units. There is no
      // on-chain preview instruction, so readPreviewBuy computes the quote
      // from purchasePricePerWholeToken client-side.
      // Only pass the 2nd (priceHint) argument when there is one — an
      // explicit `undefined` 2nd argument is a distinct call shape from a
      // 1-argument call to a mocked spy in tests.
      const minimal = toMinimalUnits(tokenAmount, rwaDecimals);
      const quoteAmount = purchasePricePerWholeToken
        ? await readPreviewBuy(BigInt(minimal), {
            purchasePricePerWholeToken,
            rwaDecimals,
          })
        : await readPreviewBuy(BigInt(minimal));
      setQuote({ tokenAmount: minimal, quoteAmount: quoteAmount.toString() });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Quote request failed.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <div className="field">
        <label htmlFor="buy-amount">RWA token amount (whole units)</label>
        <input
          id="buy-amount"
          value={tokenAmount}
          onChange={(e) => setTokenAmount(e.target.value)}
        />
      </div>
      <button
        type="button"
        className="button button--secondary"
        onClick={handlePreview}
        disabled={loading || !tokenAmount}
      >
        {loading ? "Fetching…" : "Preview quote"}
      </button>
      {error && (
        <p className="async-state--error" role="alert">
          {error}
        </p>
      )}
      {quote && (
        <dl className="tx-preview__grid u-mt-4">
          <div className="tx-preview__row">
            <dt>Token amount</dt>
            <dd>{formatTokenAmount(quote.tokenAmount, rwaDecimals)}</dd>
          </div>
          <div className="tx-preview__row">
            <dt>Quote amount</dt>
            <dd>{formatTokenAmount(quote.quoteAmount, quoteDecimals)}</dd>
          </div>
          <div className="tx-preview__row">
            {/* This preview only ever quotes the purchase side. */}
            <dt>Side</dt>
            <dd>purchase</dd>
          </div>
        </dl>
      )}
    </div>
  );
}

function WithdrawForm({
  project,
  availableQuote,
  quoteDecimals,
  onWithdrawn,
}: {
  project: Project | undefined;
  /** The vault's withdrawable quote-token balance, in minimal units (from inventory). */
  availableQuote: string | undefined;
  /** Quote-token decimals for display + the live over-balance check (best-effort). */
  quoteDecimals: number | undefined;
  onWithdrawn: () => void;
}) {
  const from = useWalletContext().address;
  const [amount, setAmount] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Live, best-effort check that the entered amount doesn't exceed the vault's
  // available quote balance — for immediate feedback + to disable the button.
  // It needs the quote decimals (to scale) client-side; when those aren't
  // available the button stays enabled and the authoritative check at submit
  // (which resolves decimals on-chain) still blocks an over-withdrawal.
  const overBalance =
    availableQuote !== undefined &&
    quoteDecimals !== undefined &&
    amount !== "" &&
    (() => {
      try {
        return BigInt(toMinimalUnits(amount, quoteDecimals)) > BigInt(availableQuote);
      } catch {
        return false; // malformed input — let submit-time validation report it
      }
    })();

  async function handleWithdraw() {
    setError(null);
    setDone(null);
    setProgress(null);
    if (!from) {
      setError("Wallet not connected.");
      return;
    }
    const vault = project?.addresses?.vault;
    if (!vault) {
      setError("Missing vault address — project not deployed?");
      return;
    }
    // withdrawProceeds pays out the QUOTE token, so the entered whole-unit
    // amount is scaled by the quote token's decimals — never the RWA token's.
    // There's no quote-decimals field in the HTTP contract, so it's read
    // on-chain; if that read fails (no wallet/RPC) we error rather than guess
    // and mis-scale the withdrawal.
    let minimal: string;
    try {
      const decimals = await resolveQuoteDecimals(project);
      minimal = toMinimalUnits(amount, decimals);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Invalid amount.");
      return;
    }
    // Authoritative guard: never broadcast a withdrawal larger than the vault's
    // available quote balance — it would revert on-chain. Compared in minimal
    // units against the inventory's reported quoteBalance.
    if (availableQuote !== undefined && BigInt(minimal) > BigInt(availableQuote)) {
      setError(
        `Amount exceeds the vault's available quote balance (${formatTokenAmount(
          availableQuote,
          quoteDecimals,
        )}).`,
      );
      return;
    }
    setBusy(true);
    try {
      setProgress("Submitting withdrawal…");
      const hash = await sendWithdrawProceeds(from, vault, BigInt(minimal));
      await waitForTxReceipt(hash);
      setDone("Withdrawal submitted.");
      onWithdrawn();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Withdrawal failed.");
    } finally {
      setBusy(false);
      setProgress(null);
    }
  }

  return (
    <div>
      <div className="field">
        <label htmlFor="withdraw-amount">
          Amount (whole quote-token units)
        </label>
        <input
          id="withdraw-amount"
          value={amount}
          onChange={(e) => setAmount(e.target.value)}
          aria-describedby="withdraw-amount-hint"
        />
        <span className="field__hint" id="withdraw-amount-hint">
          Available in vault:{" "}
          {availableQuote !== undefined
            ? formatTokenAmount(availableQuote, quoteDecimals)
            : "—"}
          . Cannot exceed this.
        </span>
        {overBalance && (
          <span className="async-state--error" role="alert">
            Amount exceeds the vault&apos;s available quote balance.
          </span>
        )}
      </div>
      <button
        type="button"
        className="button button--primary"
        onClick={handleWithdraw}
        disabled={busy || !amount || overBalance}
      >
        {busy ? "Submitting…" : "Withdraw"}
      </button>
      {progress && (
        <p role="status" className="u-mt-4">
          {progress}
        </p>
      )}
      {error && (
        <p className="async-state--error" role="alert">
          {error}
        </p>
      )}
      {done && (
        <p role="status" className="u-mt-4">
          {done}
        </p>
      )}
    </div>
  );
}
