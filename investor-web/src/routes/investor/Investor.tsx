import { useCallback, useMemo, useState } from "react";
import { AsyncSection } from "../../components/AsyncSection";
import { PaginationFooter } from "../../components/PaginationFooter";
import {
  RedemptionStatusBadge,
  TransactionStatusBadge,
} from "../../components/StatusBadge";
import {
  TransactionPreview,
  type ConfirmationState,
} from "../../components/TransactionPreview";
import { useAsync } from "../../hooks/useAsync";
import { usePaginatedList } from "../../hooks/usePaginatedList";
import { useWallet } from "../../hooks/useWallet";
import { useHookProgramId } from "../../hooks/useHookProgramId";
import { KycVerificationSection } from "./KycVerification";
import { api, ApiError } from "../../lib/client";
import type { components } from "../../lib/api-types";
import { resolveQuoteDecimals, resolveRwaDecimals } from "../../lib/decimals";
import {
  formatTokenAmount,
  formatUnixSeconds,
  isWellFormedAddress,
  shortenAddress,
  toMinimalUnits,
} from "../../lib/format";
import {
  applySlippageCeil,
  applySlippageFloor,
  deadlineInMinutes,
  MAX_SLIPPAGE_BPS,
} from "../../lib/slippage";
import {
  formatWithDecimals,
  readPreviewBuy,
  readPreviewRedeem,
  readTokenBalance,
  readTokenDecimals,
  sendBuy,
  sendCancelRedemption,
  sendClaimRedemption,
  sendRequestRedemption,
  sendRwaTransfer,
  signMessage,
  type ChainContext,
  type ProgramAddresses,
} from "../../lib/wallet";
import {
  clearWalletSession,
  getWalletSession,
  setWalletSession,
} from "../../lib/walletSession";
import { pinsConfigured, pinsPartiallyConfigured } from "../../lib/chain/pins";
import {
  investorActionBlocker,
  type InvestorChainState,
} from "../../lib/status";

type Project = components["schemas"]["Project"];

/** project.addresses -> the extra program ids/mints send*() needs beyond `vault`/`escrow` (see ProgramAddresses). undefined before every field is known. */
function toProgramAddresses(
  addresses: Project["addresses"] | undefined,
): ProgramAddresses | undefined {
  if (!addresses) return undefined;
  const { compliance, strategy, vault, redemptionEscrow, token, quoteToken } =
    addresses;
  if (
    !compliance ||
    !strategy ||
    !vault ||
    !redemptionEscrow ||
    !token ||
    !quoteToken
  ) {
    return undefined;
  }
  return {
    complianceProgramId: compliance,
    pricingProgramId: strategy,
    vaultProgramId: vault,
    redemptionProgramId: redemptionEscrow,
    rwaMint: token,
    quoteMint: quoteToken,
  };
}
type WalletStatus = components["schemas"]["WalletStatus"];
type VerifyChallengeResult = components["schemas"]["VerifyChallengeResult"];
type Redemption = components["schemas"]["Redemption"];
type Transaction = components["schemas"]["Transaction"];
type Challenge = components["schemas"]["Challenge"];

/**
 * A price preview read from the chain — the vault/pricing program's
 * on-chain Strategy account — with the amount it was quoted for. Both
 * figures are minimal units: `tokenAmount` in RWA decimals, `quoteAmount` in
 * quote-token decimals. The slippage bound is derived from `quoteAmount`.
 */
interface Quote {
  tokenAmount: string;
  quoteAmount: string;
  side: "purchase" | "redemption";
}

/** A wallet-submitted transaction this browser session has seen (see HistorySection). */
interface SubmittedTx {
  txHash: string;
  kind: string;
  submittedAt: number;
}

/**
 * Investor: wallet connect + ownership challenge, KYC status, balance &
 * compliance, purchase, redemption (request/cancel/funded/claim), transfer,
 * and transaction history.
 *
 * Buy/request/claim/cancel are encoded here in the browser from the pinned
 * Anchor IDLs (lib/idl/) and broadcast from the connected wallet
 * (lib/wallet.ts), and the buy/redeem quotes come from the same programs'
 * on-chain Strategy account. The server supplies indexed lists and
 * compliance state only — it never hands the browser calldata or a price,
 * so the target of every transaction is the project address this page
 * already knows and there is nothing to check a server-picked target or
 * quote against.
 */
export function Investor() {
  const project = useAsync<Project>((signal) => api.getProject({ signal }), []);
  const projectData = project.status === "success" ? project.data : undefined;
  const wallet = useWallet();
  const finalityConfirmations = projectData?.finalityConfirmations;

  // The transfer-hook program id and the rest of the deployment's
  // program ids/mints (from Project.addresses), bundled once for every
  // section below.
  const hookProgramId = useHookProgramId();
  const addresses = projectData?.addresses;
  const programAddresses = useMemo(
    () => toProgramAddresses(addresses),
    [addresses],
  );
  // No publicRpcUrl here: GET /project no longer returns one — see
  // ChainContext's doc comment in lib/wallet.ts.
  const ctx: ChainContext = useMemo(() => ({ hookProgramId }), [hookProgramId]);

  // The investor's own KYC status comes from a subject-scoped session minted
  // at challenge-verify (X-Wallet-Session), never from the operator-only global
  // wallet list.
  const ownWalletStatus = useOwnWalletStatus(wallet.address);
  const submitted = useSubmittedTransactions();

  // Everything `investorActionBlocker` needs, assembled once from data the
  // page already loads: the project's pause flag and the investor's own
  // compliance record. No extra RPC or API call. `nowSeconds` is sampled per
  // render so an expiry that lapses while the page is open takes effect on
  // the next render rather than being frozen at mount.
  const own =
    ownWalletStatus.status === "success" ? ownWalletStatus.data : null;
  const chainState: InvestorChainState = {
    paused: projectData?.paused,
    ownStatus: own?.status,
    ownValidUntil: own?.validUntil,
    nowSeconds: Math.floor(Date.now() / 1000),
  };

  return (
    <div>
      <header className="app-main__header">
        <h1>Investor</h1>
        <p>
          Connect a wallet to view balance, compliance status, and submit
          transactions.
        </p>
      </header>

      {!pinsConfigured() && (
        <p className="async-state--error" role="alert">
          {pinsPartiallyConfigured()
            ? "This build has only SOME of its program ids/mints/RPC endpoint pinned (VITE_SOLANA_* env vars)."
            : "This build has no pinned program ids/mints/RPC endpoint (VITE_SOLANA_* env vars)."}{" "}
          An unset program id/mint pin is trusted unverified from GET /config
          and GET /project, and a compromised server could redirect a
          buy/redemption/transfer to an attacker-controlled program. An unset{" "}
          <code>VITE_SOLANA_RPC_URL</code> silently falls back to a local
          validator address instead — harmless for local development, but this
          app will not be talking to the right network in production. Set the
          pins before deploying to production — see investor-web/README.md.
        </p>
      )}

      <WalletSection
        wallet={wallet}
        onSessionEstablished={ownWalletStatus.reload}
      />

      <KycSection
        ownWalletStatus={ownWalletStatus}
        connected={Boolean(wallet.address)}
      />

      <KycVerificationSection
        walletAddress={wallet.address}
        ownWalletStatus={ownWalletStatus}
      />

      <BalanceSection project={projectData} address={wallet.address} />

      <BuySection
        ctx={ctx}
        project={projectData}
        walletAddress={wallet.address}
        programAddresses={programAddresses}
        chainState={chainState}
        onSubmitted={submitted.record}
      />

      <RedemptionSection
        ctx={ctx}
        project={projectData}
        walletAddress={wallet.address}
        finalityConfirmations={finalityConfirmations}
        programAddresses={programAddresses}
        chainState={chainState}
        onSubmitted={submitted.record}
      />

      <TransferSection
        project={projectData}
        walletAddress={wallet.address}
        chainState={chainState}
        onSubmitted={submitted.record}
      />

      <HistorySection
        entries={submitted.entries}
        walletAddress={wallet.address}
      />
    </div>
  );
}

/**
 * The connected wallet's own compliance status, read via the subject-scoped
 * session minted at challenge-verify (X-Wallet-Session) — never the
 * operator-only global wallet list. `data` is `null` (a successful
 * "no status" result, not an error) whenever there is no
 * unexpired session for `address` yet, i.e. the investor hasn't completed
 * (or has outlived) an ownership challenge.
 */
function useOwnWalletStatus(address: string | null) {
  return useAsync<WalletStatus | null>(
    async (signal) => {
      if (!address) return null;
      const session = getWalletSession(address);
      if (!session) return null;
      try {
        return await api.getMyWalletStatus(session.token, { signal });
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) {
          // Expired/invalid on the server even though our local copy looked
          // live — drop it so the UI prompts a fresh challenge instead of
          // retrying the same dead token forever.
          clearWalletSession(address);
          return null;
        }
        throw err;
      }
    },
    [address],
  );
}

/**
 * Locally-tracked record of every transaction this browser session has
 * submitted from the connected wallet. The server's transaction index is
 * operator-only and doesn't contain investor wallet-submitted transactions
 * anyway — this is deliberately not a replacement for that index, just an
 * honest "what you just sent" list.
 */
function useSubmittedTransactions() {
  const [entries, setEntries] = useState<SubmittedTx[]>([]);
  const record = useCallback((txHash: string, kind: string) => {
    setEntries((prev) => [{ txHash, kind, submittedAt: Date.now() }, ...prev]);
  }, []);
  return { entries, record };
}

function WalletSection({
  wallet,
  onSessionEstablished,
}: {
  wallet: ReturnType<typeof useWallet>;
  onSessionEstablished: () => void;
}) {
  const [challenge, setChallenge] = useState<Challenge | null>(null);
  const [signature, setSignature] = useState<string | null>(null);
  const [verified, setVerified] = useState<VerifyChallengeResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function handleChallenge() {
    if (!wallet.address) return;
    setError(null);
    setSignature(null);
    setVerified(null);
    setBusy(true);
    try {
      setChallenge(await api.createChallenge({ address: wallet.address }));
    } catch (err) {
      setError(
        err instanceof ApiError ? err.message : "Failed to create challenge.",
      );
    } finally {
      setBusy(false);
    }
  }

  async function handleSign() {
    if (!wallet.address || !challenge?.message) return;
    setError(null);
    setBusy(true);
    try {
      setSignature(await signMessage(challenge.message));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Signing failed.");
    } finally {
      setBusy(false);
    }
  }

  async function handleVerify() {
    if (!wallet.address || !challenge?.nonce || !signature) return;
    setError(null);
    setBusy(true);
    try {
      const result = await api.verifyChallenge({
        address: wallet.address,
        nonce: challenge.nonce,
        signature,
      });
      setVerified(result);
      // Store the subject-scoped session and have the KYC section re-read its
      // own status through it — never an operator key.
      if (result.sessionToken && result.sessionExpiresAt) {
        setWalletSession(wallet.address, {
          token: result.sessionToken,
          expiresAt: result.sessionExpiresAt,
        });
        onSessionEstablished();
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Verification failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card">
      <h2>Wallet</h2>
      {!wallet.address ? (
        <button
          type="button"
          className="button button--primary"
          onClick={wallet.connect}
          disabled={wallet.connecting}
        >
          {wallet.connecting ? "Connecting…" : "Connect wallet"}
        </button>
      ) : (
        <dl className="tx-preview__grid">
          <div className="tx-preview__row">
            <dt>Address</dt>
            <dd title={wallet.address}>{shortenAddress(wallet.address)}</dd>
          </div>
        </dl>
      )}
      {wallet.error && (
        <p className="async-state--error" role="alert">
          {wallet.error}
        </p>
      )}

      {wallet.address && (
        <div className="u-mt-4">
          <button
            type="button"
            className="button button--secondary"
            onClick={handleChallenge}
            disabled={busy}
          >
            Generate ownership challenge
          </button>
          {challenge?.message && (
            <>
              <p className="mono">{challenge.message}</p>
              <button
                type="button"
                className="button button--secondary"
                onClick={handleSign}
                disabled={busy}
              >
                Sign with wallet
              </button>
            </>
          )}
          {signature && (
            <>
              <p className="field__hint" role="status">
                Signed: <span className="mono">{signature}</span>
              </p>
              <button
                type="button"
                className="button button--primary"
                onClick={handleVerify}
                disabled={busy}
              >
                Submit signature for verification
              </button>
            </>
          )}
          {verified && (
            <p className="field__hint" role="status">
              Ownership verified: {verified.ownershipVerified ? "Yes" : "No"}.
              Compliance status: {verified.status ?? "Unknown"}.
            </p>
          )}
          {error && (
            <p className="async-state--error" role="alert">
              {error}
            </p>
          )}
        </div>
      )}
    </section>
  );
}

function KycSection({
  ownWalletStatus,
  connected,
}: {
  ownWalletStatus: ReturnType<typeof useOwnWalletStatus>;
  connected: boolean;
}) {
  const status =
    ownWalletStatus.status === "success" ? ownWalletStatus.data : undefined;

  return (
    <section className="card">
      <h2>KYC status</h2>
      {!connected ? (
        <p className="field__hint">
          Connect a wallet to view your compliance status.
        </p>
      ) : ownWalletStatus.status === "loading" ? (
        <p className="field__hint">Loading…</p>
      ) : ownWalletStatus.status === "error" ? (
        <p className="async-state--error" role="alert">
          {ownWalletStatus.error}
        </p>
      ) : status ? (
        <dl className="tx-preview__grid">
          <div className="tx-preview__row">
            <dt>Status</dt>
            <dd>{status.status}</dd>
          </div>
          <div className="tx-preview__row">
            <dt>Valid until</dt>
            <dd>{formatUnixSeconds(status.validUntil)}</dd>
          </div>
          <div className="tx-preview__row">
            <dt>Ownership verified</dt>
            <dd>{status.ownershipVerified ? "Yes" : "No"}</dd>
          </div>
        </dl>
      ) : (
        <p className="field__hint">
          Generate and sign an ownership challenge below (Wallet section) to
          view your compliance status — it&apos;s read through your own verified
          session, not a shared list.
        </p>
      )}
    </section>
  );
}

function BalanceSection({
  project,
  address,
}: {
  project: Project | undefined;
  address: string | null | undefined;
}) {
  const [balance, setBalance] = useState<{
    raw: string;
    decimals: number;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const token = project?.addresses?.token;
  const unit = project?.tokenUnit ?? "RWA";

  async function handleLoad() {
    if (!token || !address) return;
    setLoading(true);
    setError(null);
    try {
      // Project.decimals is never trustworthy for the RWA mint (see
      // resolveRwaDecimals' doc comment) — always read it directly off the
      // mint.
      const decimals = await readTokenDecimals(token, "rwa");
      const raw = await readTokenBalance(token, address, "rwa");
      setBalance({ raw, decimals });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to read balance.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="card">
      <h2>Balance</h2>
      {!address ? (
        <p className="field__hint">
          Connect a wallet to view your RWA token balance.
        </p>
      ) : !token ? (
        <p className="field__hint">
          Token address not yet available from the project.
        </p>
      ) : (
        <div>
          <button
            type="button"
            className="button button--secondary"
            onClick={handleLoad}
            disabled={loading}
          >
            {loading ? "Reading…" : "Read balance"}
          </button>
          {balance !== null && (
            <p>
              {formatWithDecimals(balance.raw, balance.decimals)} {unit}
            </p>
          )}
          {error && (
            <p className="async-state--error" role="alert">
              {error}
            </p>
          )}
        </div>
      )}
    </section>
  );
}

function BuySection({
  ctx,
  project,
  walletAddress,
  programAddresses,
  chainState,
  onSubmitted,
}: {
  ctx: ChainContext;
  project: Project | undefined;
  walletAddress: string | null | undefined;
  programAddresses: ProgramAddresses | undefined;
  chainState: InvestorChainState;
  onSubmitted: (txHash: string, kind: string) => void;
}) {
  const [tokenAmount, setTokenAmount] = useState("");
  const [slippageBps, setSlippageBps] = useState(50);
  const [quote, setQuote] = useState<Quote | null>(null);
  // Decimals captured at preview time so the preview renders the (already
  // minimal-unit) quote back as whole units: RWA decimals for the token
  // amount, quote-token decimals for the quote/payment amounts.
  const [decimals, setDecimals] = useState<number | null>(null);
  const [quoteDecimals, setQuoteDecimals] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [txState, setTxState] = useState<ConfirmationState>("draft");
  const [buyTx, setBuyTx] = useState<string | null>(null);

  const maxQuoteAmount = quote?.quoteAmount
    ? applySlippageCeil(quote.quoteAmount, slippageBps)
    : null;
  const vault = project?.addresses?.vault;

  async function handlePreview() {
    setError(null);
    setBuyTx(null);
    try {
      if (!vault) throw new Error("Project addresses not loaded.");
      // Human whole units -> the RWA token's minimal units before the amount
      // reaches the vault. toMinimalUnits throws a friendly AmountFormatError
      // on bad/over-precise input.
      const rwaDecimals = await resolveRwaDecimals(project);
      const minimalTokenAmount = toMinimalUnits(tokenAmount, rwaDecimals);
      // Read straight off the pricing program's on-chain Strategy account
      // (see readPreviewBuy's doc comment — never the server-supplied
      // project.purchasePricePerWholeToken).
      const quoteAmount = await readPreviewBuy(
        BigInt(minimalTokenAmount),
        programAddresses,
      );
      setDecimals(rwaDecimals);
      // Quote-token decimals are display-only and best-effort — a failed read
      // must not block the (already-correct) quote; fall back to the grouped
      // raw integer.
      try {
        setQuoteDecimals(await resolveQuoteDecimals(project));
      } catch {
        setQuoteDecimals(null);
      }
      setQuote({
        tokenAmount: minimalTokenAmount,
        quoteAmount: quoteAmount.toString(),
        side: "purchase",
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Quote request failed.");
    }
  }

  // Buy re-checks the buyer's own compliance record on-chain
  // (`CallerNotAllowed`) and refuses while paused, so both are surfaced on
  // the approval step rather than as a post-signature revert.
  const blocker = investorActionBlocker("buy", chainState);

  async function handleBuy() {
    if (!walletAddress || !quote?.tokenAmount || !maxQuoteAmount || !vault)
      return;
    if (blocker) return;
    setTxState("awaiting-signature");
    setError(null);
    try {
      // Encoded here and sent to this project's Vault — the buyer receives the
      // tokens themselves, bounded by the slippage ceiling they approved.
      const tx = await sendBuy(ctx, walletAddress, vault, {
        tokenAmount: BigInt(quote.tokenAmount),
        maxQuoteAmount: BigInt(maxQuoteAmount),
        recipient: walletAddress,
        deadline: BigInt(deadlineInMinutes(10)),
        programAddresses,
      });
      setBuyTx(tx);
      onSubmitted(tx, "buy");
      setTxState("submitted");
    } catch (err) {
      setTxState("draft");
      setError(err instanceof Error ? err.message : "Buy failed.");
    }
  }

  return (
    <section className="card">
      <h2>Buy</h2>
      <div className="field">
        <label htmlFor="buy-token-amount">RWA token amount (whole units)</label>
        <input
          id="buy-token-amount"
          value={tokenAmount}
          onChange={(e) => setTokenAmount(e.target.value)}
        />
      </div>
      <div className="field field--slim">
        <label htmlFor="buy-slippage">Slippage (bps)</label>
        <input
          id="buy-slippage"
          type="number"
          min={0}
          max={MAX_SLIPPAGE_BPS}
          value={slippageBps}
          onChange={(e) => setSlippageBps(Number(e.target.value))}
          aria-describedby="buy-slippage-hint"
        />
        <span className="field__hint" id="buy-slippage-hint">
          Capped at {MAX_SLIPPAGE_BPS / 100}% — the approved spend amount never
          exceeds this.
        </span>
      </div>
      <button
        type="button"
        className="button button--secondary"
        onClick={handlePreview}
        disabled={!tokenAmount}
      >
        Preview quote
      </button>
      {error && (
        <p className="async-state--error" role="alert">
          {error}
        </p>
      )}

      {quote && project && maxQuoteAmount && (
        <TransactionPreview
          title="Purchase preview"
          addresses={[
            {
              label: "Vault (transaction target)",
              address: project.addresses?.vault ?? "",
            },
            { label: "RWA token", address: project.addresses?.token ?? "" },
            // Backstop: show the CPI-authority-bearing program ids
            // too, not just the transaction target — a buy grants these
            // programs (not only the vault) authority over the buyer's
            // token accounts.
            ...(programAddresses
              ? [
                  {
                    label: "Compliance program",
                    address: programAddresses.complianceProgramId,
                  },
                  {
                    label: "Transfer-hook program",
                    address: ctx.hookProgramId ?? "",
                  },
                ]
              : []),
          ]}
          amounts={[
            {
              label: "RWA amount",
              raw: quote.tokenAmount ?? "0",
              decimals: decimals ?? undefined,
              symbol: project.tokenUnit ?? "RWA",
            },
            {
              label: "Quote amount",
              raw: quote.quoteAmount ?? "0",
              decimals: quoteDecimals ?? undefined,
              symbol: "quote token",
            },
            {
              label: "Max quote amount (slippage bound)",
              raw: maxQuoteAmount,
              decimals: quoteDecimals ?? undefined,
              symbol: "quote token",
            },
          ]}
          priceSide="purchase"
          quoteTokenSymbol={
            project.addresses?.quoteToken
              ? shortenAddress(project.addresses.quoteToken)
              : undefined
          }
          slippageBps={slippageBps}
          confirmationState={txState}
        >
          <button
            type="button"
            className="button button--primary"
            onClick={handleBuy}
            disabled={
              !walletAddress ||
              txState === "awaiting-signature" ||
              blocker !== null
            }
            title={blocker ?? undefined}
          >
            Buy
          </button>
          {blocker && (
            <p className="async-state--error" role="alert">
              {blocker}
            </p>
          )}
        </TransactionPreview>
      )}
      {buyTx && (
        <p role="status">
          Buy submitted: <span className="mono">{buyTx}</span>
        </p>
      )}
    </section>
  );
}

function RedemptionSection({
  ctx,
  project,
  walletAddress,
  finalityConfirmations,
  programAddresses,
  chainState,
  onSubmitted,
}: {
  ctx: ChainContext;
  project: Project | undefined;
  walletAddress: string | null | undefined;
  finalityConfirmations: number | undefined;
  programAddresses: ProgramAddresses | undefined;
  chainState: InvestorChainState;
  onSubmitted: (txHash: string, kind: string) => void;
}) {
  const [rwaAmount, setRwaAmount] = useState("");
  const [slippageBps, setSlippageBps] = useState(50);
  const [quote, setQuote] = useState<Quote | null>(null);
  // The entered RWA amount converted to minimal units at preview time — reused
  // by request so both see the same value the quote was built from.
  const [minimalRwaAmount, setMinimalRwaAmount] = useState<string | null>(null);
  const [decimals, setDecimals] = useState<number | null>(null);
  const [quoteDecimals, setQuoteDecimals] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [txState, setTxState] = useState<ConfirmationState>("draft");
  const [requestTx, setRequestTx] = useState<string | null>(null);
  const [claimTx, setClaimTx] = useState<string | null>(null);
  const [cancelTx, setCancelTx] = useState<string | null>(null);
  // Request, claim and cancel are all redemption-program calls — `escrow` is
  // the program id there.
  const escrow = project?.addresses?.redemptionEscrow;

  // The connected wallet's own redemption requests, server-fetched and
  // paginated (the public listRedemptions filtered by beneficiary). Only
  // queried when a wallet is connected — disconnected shows a connect hint and
  // never hits the API.
  const myRedemptions = usePaginatedList<Redemption>(
    (cursor, signal) =>
      walletAddress
        ? api.listRedemptions({ address: walletAddress, cursor, signal })
        : Promise.resolve({ items: [] }),
    [walletAddress],
  );

  // Display decimals for the list rows: RWA from the project (authoritative);
  // the quote token has no HTTP-contract field, so it's read on-chain
  // best-effort and falls back to the grouped raw integer rather than
  // mis-scaling.
  const rwaDisplayDecimals = project?.decimals;
  const listQuoteDecimalsState = useAsync<number | null>(async () => {
    if (!project) return null;
    try {
      return await resolveQuoteDecimals(project);
    } catch {
      return null;
    }
  }, [project]);
  const listQuoteDecimals =
    listQuoteDecimalsState.status === "success"
      ? (listQuoteDecimalsState.data ?? undefined)
      : undefined;

  const minQuoteOut = quote?.quoteAmount
    ? applySlippageFloor(quote.quoteAmount, slippageBps)
    : null;

  async function handlePreview() {
    setError(null);
    setRequestTx(null);
    try {
      if (!escrow) throw new Error("Project addresses not loaded.");
      // Human whole units -> the RWA token's minimal units before the amount
      // reaches the request call.
      const rwaDecimals = await resolveRwaDecimals(project);
      const minimal = toMinimalUnits(rwaAmount, rwaDecimals);
      // Read straight off the pricing program's on-chain Strategy account
      // (never the server-supplied project.redemptionPricePerWholeToken).
      const quoteAmount = await readPreviewRedeem(
        BigInt(minimal),
        programAddresses,
      );
      setDecimals(rwaDecimals);
      setMinimalRwaAmount(minimal);
      try {
        setQuoteDecimals(await resolveQuoteDecimals(project));
      } catch {
        setQuoteDecimals(null);
      }
      setQuote({
        tokenAmount: minimal,
        quoteAmount: quoteAmount.toString(),
        side: "redemption",
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Quote request failed.");
    }
  }

  async function handleRequest() {
    if (!walletAddress || !minimalRwaAmount || !minQuoteOut || !escrow) return;
    if (requestBlocker) return;
    setTxState("awaiting-signature");
    setError(null);
    try {
      const tx = await sendRequestRedemption(ctx, walletAddress, escrow, {
        rwaAmount: BigInt(minimalRwaAmount),
        minQuoteOut: BigInt(minQuoteOut),
        deadline: BigInt(deadlineInMinutes(10)),
        programAddresses,
      });
      setRequestTx(tx);
      onSubmitted(tx, "redemption request");
      setTxState("submitted");
    } catch (err) {
      setTxState("draft");
      setError(
        err instanceof Error ? err.message : "Redemption request failed.",
      );
    }
  }

  // The three redemption calls do NOT share one guard set, so each gets its
  // own: request re-checks the caller's compliance and refuses while paused;
  // claim refuses while paused but deliberately never re-checks compliance (a
  // funded quote is already committed); cancel re-checks compliance but has
  // NO pause guard at all — it is the escape hatch and must survive a pause.
  const requestBlocker = investorActionBlocker("requestRedemption", chainState);
  const claimBlocker = investorActionBlocker("claim", chainState);
  const cancelBlocker = investorActionBlocker("cancel", chainState);

  async function handleClaim(id: string) {
    if (!walletAddress || !escrow) return;
    if (claimBlocker) return;
    setError(null);
    try {
      const tx = await sendClaimRedemption(
        ctx,
        walletAddress,
        escrow,
        BigInt(id),
        programAddresses,
      );
      setClaimTx(tx);
      onSubmitted(tx, "redemption claim");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Claim failed.");
    }
  }

  async function handleCancel(id: string) {
    if (!walletAddress || !escrow) return;
    if (cancelBlocker) return;
    setError(null);
    try {
      const tx = await sendCancelRedemption(
        ctx,
        walletAddress,
        escrow,
        BigInt(id),
        programAddresses,
      );
      setCancelTx(tx);
      onSubmitted(tx, "redemption cancel");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Cancel failed.");
    }
  }

  return (
    <section className="card">
      <h2>Redemption</h2>

      <div className="field">
        <label htmlFor="redeem-amount">
          RWA amount to redeem (whole units)
        </label>
        <input
          id="redeem-amount"
          value={rwaAmount}
          onChange={(e) => setRwaAmount(e.target.value)}
        />
      </div>
      <div className="field field--slim">
        <label htmlFor="redeem-slippage">Slippage (bps)</label>
        <input
          id="redeem-slippage"
          type="number"
          min={0}
          max={10_000}
          value={slippageBps}
          onChange={(e) => setSlippageBps(Number(e.target.value))}
        />
      </div>
      <button
        type="button"
        className="button button--secondary"
        onClick={handlePreview}
        disabled={!rwaAmount}
      >
        Preview quote
      </button>
      {error && (
        <p className="async-state--error" role="alert">
          {error}
        </p>
      )}

      {quote && project && minQuoteOut && (
        <TransactionPreview
          title="Redemption request preview"
          addresses={[
            {
              label: "Redemption escrow (transaction target)",
              address: project.addresses?.redemptionEscrow ?? "",
            },
            { label: "RWA token", address: project.addresses?.token ?? "" },
            ...(programAddresses
              ? [
                  {
                    label: "Compliance program",
                    address: programAddresses.complianceProgramId,
                  },
                  {
                    label: "Transfer-hook program",
                    address: ctx.hookProgramId ?? "",
                  },
                ]
              : []),
          ]}
          amounts={[
            {
              label: "RWA amount",
              raw: quote.tokenAmount ?? minimalRwaAmount ?? "0",
              decimals: decimals ?? undefined,
              symbol: project.tokenUnit ?? "RWA",
            },
            {
              label: "Snapshotted quote",
              raw: quote.quoteAmount ?? "0",
              decimals: quoteDecimals ?? undefined,
              symbol: "quote token",
            },
            {
              label: "Min quote out (slippage bound)",
              raw: minQuoteOut,
              decimals: quoteDecimals ?? undefined,
              symbol: "quote token",
            },
          ]}
          priceSide="redemption"
          quoteTokenSymbol={
            project.addresses?.quoteToken
              ? shortenAddress(project.addresses.quoteToken)
              : undefined
          }
          slippageBps={slippageBps}
          confirmationState={txState}
        >
          <button
            type="button"
            className="button button--primary"
            onClick={handleRequest}
            disabled={
              !walletAddress ||
              txState === "awaiting-signature" ||
              requestBlocker !== null
            }
            title={requestBlocker ?? undefined}
          >
            Request redemption
          </button>
          {requestBlocker && (
            <p className="async-state--error" role="alert">
              {requestBlocker}
            </p>
          )}
        </TransactionPreview>
      )}
      {requestTx && (
        <p role="status">
          Request submitted: <span className="mono">{requestTx}</span>
        </p>
      )}

      <h3 className="u-mt-5">Your redemption requests</h3>
      {/* A disabled row button on its own doesn't say why; state the reason
          once for the table. Claim and cancel are listed separately because
          they can be blocked independently — during a pause, claim is
          blocked and cancel deliberately is not. */}
      {claimBlocker && (
        <p className="async-state--error" role="alert">
          Claim unavailable — {claimBlocker}
        </p>
      )}
      {cancelBlocker && (
        <p className="async-state--error" role="alert">
          Cancel unavailable — {cancelBlocker}
        </p>
      )}
      {!walletAddress ? (
        <p className="field__hint">
          Connect a wallet to view your redemption requests.
        </p>
      ) : (
        <AsyncSection
          state={myRedemptions}
          onRetry={myRedemptions.reload}
          empty={(d) => d.length === 0}
          emptyLabel="No redemption requests for this wallet yet."
        >
          {(data) => (
            <>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>ID</th>
                      <th>Status</th>
                      <th>RWA amount</th>
                      <th>Quote amount</th>
                      <th>Timeout</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.map((r) => {
                      // Claim: server-derived `claimable` (Funded AND
                      // confirmations>=finality). Cancel: a Pending request
                      // whose timeout has elapsed (the beneficiary's escape
                      // hatch). Neither shows for Completed/Rejected/Cancelled
                      // or a Funded-but-not-yet-claimable request.
                      const cancellable =
                        r.status === "Pending" &&
                        !!r.timeoutAt &&
                        r.timeoutAt <= Math.floor(Date.now() / 1000);
                      return (
                        <tr key={r.id}>
                          <td className="mono">{r.id}</td>
                          <td>
                            <RedemptionStatusBadge
                              status={r.status}
                              claimable={r.claimable}
                              confirmations={r.confirmations}
                              finalityConfirmations={finalityConfirmations}
                            />
                          </td>
                          <td>
                            {formatTokenAmount(
                              r.rwaAmount ?? "",
                              rwaDisplayDecimals,
                            )}
                          </td>
                          <td>
                            {formatTokenAmount(
                              r.quoteAmount ?? "",
                              listQuoteDecimals,
                            )}
                          </td>
                          <td>{formatUnixSeconds(r.timeoutAt)}</td>
                          <td>
                            <span className="badge-row">
                              {r.claimable && r.id && (
                                <button
                                  type="button"
                                  className="button button--primary"
                                  onClick={() => handleClaim(r.id!)}
                                  disabled={
                                    !walletAddress || claimBlocker !== null
                                  }
                                  title={claimBlocker ?? undefined}
                                >
                                  Claim (permissionless)
                                </button>
                              )}
                              {cancellable && r.id && (
                                <button
                                  type="button"
                                  className="button button--danger"
                                  onClick={() => handleCancel(r.id!)}
                                  disabled={
                                    !walletAddress || cancelBlocker !== null
                                  }
                                  title={cancelBlocker ?? undefined}
                                >
                                  Cancel (timeout elapsed)
                                </button>
                              )}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              <PaginationFooter
                loadedCount={data.length}
                totalCount={myRedemptions.totalCount}
                hasMore={myRedemptions.hasMore}
                loadingMore={myRedemptions.loadingMore}
                loadMoreError={myRedemptions.loadMoreError}
                onLoadMore={myRedemptions.loadMore}
              />
            </>
          )}
        </AsyncSection>
      )}
      {claimTx && (
        <p role="status">
          Claim submitted: <span className="mono">{claimTx}</span>
        </p>
      )}
      {cancelTx && (
        <p role="status">
          Cancel submitted: <span className="mono">{cancelTx}</span>
        </p>
      )}
    </section>
  );
}

function TransferSection({
  project,
  walletAddress,
  chainState,
  onSubmitted,
}: {
  project: Project | undefined;
  walletAddress: string | null | undefined;
  chainState: InvestorChainState;
  onSubmitted: (txHash: string, kind: string) => void;
}) {
  const [recipient, setRecipient] = useState("");
  const [amount, setAmount] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [tx, setTx] = useState<string | null>(null);
  const [sending, setSending] = useState(false);

  // Public, unauthenticated eligibility preflight — replaces the operator-only
  // global wallet list, which an investor session can never call. Deliberately
  // less detailed than before: AllowedResult is
  // just a boolean, not the recipient's full status/validUntil/ownership,
  // so an investor can't enumerate a third party's exact compliance record.
  const recipientWellFormed = isWellFormedAddress(recipient);
  const eligibility = useAsync<{ allowed?: boolean } | null>(
    (signal) =>
      recipientWellFormed
        ? api.isAddressAllowed(recipient, { signal })
        : Promise.resolve(null),
    [recipient, recipientWellFormed],
  );
  const recipientAllowed =
    eligibility.status === "success" && eligibility.data?.allowed === true;

  // The hook checks BOTH sides of a transfer (`SenderNotAllowed` /
  // `RecipientNotAllowed`) and rejects any wallet-to-wallet move while paused
  // — only the pinned RedemptionEscrow is exempt. The recipient preflight
  // above covers one side; this covers the sender's own record and the pause.
  const senderBlocker = investorActionBlocker("transfer", chainState);

  async function handleTransfer() {
    if (
      !walletAddress ||
      !project?.addresses?.token ||
      !recipient ||
      !amount ||
      !recipientAllowed ||
      senderBlocker
    )
      return;
    setSending(true);
    setError(null);
    try {
      // Human whole units -> the RWA token's minimal units before building the
      // transfer instruction.
      const decimals = await resolveRwaDecimals(project);
      const minimal = toMinimalUnits(amount, decimals);
      const hash = await sendRwaTransfer(
        walletAddress,
        project.addresses.token,
        recipient,
        BigInt(minimal),
      );
      setTx(hash);
      onSubmitted(hash, "transfer");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Transfer failed.");
    } finally {
      setSending(false);
    }
  }

  return (
    <section className="card">
      <h2>Transfer</h2>
      <div className="field">
        <label htmlFor="transfer-recipient">Recipient address</label>
        <input
          id="transfer-recipient"
          className="mono"
          value={recipient}
          onChange={(e) => setRecipient(e.target.value)}
        />
      </div>
      {recipient && recipientWellFormed && eligibility.status !== "loading" && (
        <p
          className={recipientAllowed ? "field__hint" : "async-state--error"}
          role={recipientAllowed ? undefined : "alert"}
        >
          {recipientAllowed
            ? "Recipient is eligible to receive tokens."
            : "Recipient is not eligible to receive tokens — transfer disabled."}
        </p>
      )}
      {recipient && !recipientWellFormed && (
        <p className="field__hint">
          Enter a complete address to check eligibility.
        </p>
      )}
      <div className="field">
        <label htmlFor="transfer-amount">Amount (whole units)</label>
        <input
          id="transfer-amount"
          value={amount}
          onChange={(e) => setAmount(e.target.value)}
        />
      </div>
      <button
        type="button"
        className="button button--primary"
        onClick={handleTransfer}
        disabled={
          sending ||
          !walletAddress ||
          !recipient ||
          !amount ||
          !recipientAllowed ||
          senderBlocker !== null
        }
        title={senderBlocker ?? undefined}
      >
        {sending ? "Submitting…" : "Transfer"}
      </button>
      {senderBlocker && (
        <p className="async-state--error" role="alert">
          {senderBlocker}
        </p>
      )}
      {error && (
        <p className="async-state--error" role="alert">
          {error}
        </p>
      )}
      {tx && (
        <p role="status">
          Submitted: <span className="mono">{tx}</span>
        </p>
      )}
    </section>
  );
}

/**
 * Two complementary views of this wallet's activity:
 *
 * - "On-chain transactions": the server's now-public, address-filtered
 *   transaction index (`GET /api/v1/transactions?address=`), which carries the
 *   authoritative confirmation status the server observes. Only the
 *   connected wallet's own txs are queried.
 * - "Submitted this session": a local record of what this browser session sent
 *   from the wallet. The server index may not have indexed a just-submitted tx
 *   yet (or ever, for a pure wallet transfer), so this stays useful; it
 *   deliberately carries no confirmation status — this page can't observe it.
 */
function HistorySection({
  entries,
  walletAddress,
}: {
  entries: SubmittedTx[];
  walletAddress: string | null | undefined;
}) {
  // Server-indexed txs involving this wallet (public, paginated). Only queried
  // when connected — disconnected shows a connect hint and never hits the API.
  const onchain = usePaginatedList<Transaction>(
    (cursor, signal) =>
      walletAddress
        ? api.listTransactions({ address: walletAddress, cursor, signal })
        : Promise.resolve({ items: [] }),
    [walletAddress],
  );

  return (
    <section className="card">
      <h2>Transaction history</h2>

      <h3>On-chain transactions</h3>
      {!walletAddress ? (
        <p className="field__hint">
          Connect a wallet to view its transactions from the server&apos;s
          on-chain index.
        </p>
      ) : (
        <AsyncSection
          state={onchain}
          onRetry={onchain.reload}
          empty={(d) => d.length === 0}
          emptyLabel="No on-chain transactions indexed for this wallet yet."
        >
          {(data) => (
            <>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Tx hash</th>
                      <th>Kind</th>
                      <th>Status</th>
                      <th>Block</th>
                      <th>Explorer</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.map((tx) => (
                      <tr key={tx.txHash}>
                        <td className="mono">{tx.txHash}</td>
                        <td>{tx.kind ?? "—"}</td>
                        <td>
                          {tx.status && (
                            <TransactionStatusBadge status={tx.status} />
                          )}
                        </td>
                        <td>{tx.blockNumber ?? "—"}</td>
                        <td>
                          {tx.explorerUrl && (
                            <a
                              href={tx.explorerUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                            >
                              View
                            </a>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <PaginationFooter
                loadedCount={data.length}
                totalCount={onchain.totalCount}
                hasMore={onchain.hasMore}
                loadingMore={onchain.loadingMore}
                loadMoreError={onchain.loadMoreError}
                onLoadMore={onchain.loadMore}
              />
            </>
          )}
        </AsyncSection>
      )}

      <h3 className="u-mt-5">Submitted this session</h3>
      {entries.length === 0 ? (
        <p className="field__hint">
          Nothing submitted from this wallet yet this session. Connect and
          submit a transaction above to see it listed here.
        </p>
      ) : (
        <>
          <p className="field__hint">
            Submitted directly from your wallet this session — not the
            server&apos;s transaction index above; a just-sent transaction may
            not be indexed yet.
          </p>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Tx hash</th>
                  <th>Kind</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((entry) => (
                  <tr key={entry.txHash}>
                    <td className="mono">{entry.txHash}</td>
                    <td>{entry.kind}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </section>
  );
}
