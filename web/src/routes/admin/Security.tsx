import { useState } from "react";
import { AsyncSection } from "../../components/AsyncSection";
import { RoleGate } from "../../components/RoleGate";
import { useAsync } from "../../hooks/useAsync";
import { useWalletContext } from "../../context/walletContextValue";
import { api } from "../../lib/client";
import type { components } from "../../lib/api-types";
import { resolveQuoteDecimals } from "../../lib/decimals";
import {
  formatTokenAmount,
  shortenAddress,
  toMinimalUnits,
} from "../../lib/format";
import {
  adminContractTargets,
  GRANTABLE_ROLES,
  ROLES,
  roleTargets,
  type AdminContractTarget,
} from "../../lib/roles";
import {
  readPendingAdminTargets,
  sendAcceptAdminTransfer,
  sendBeginAdminTransfer,
  sendRoleChange,
  sendSetPaused,
  sendSetStrategyPrice,
  waitForTxReceipt,
} from "../../lib/wallet";

type Addresses = components["schemas"]["Addresses"];

type Project = components["schemas"]["Project"];

/**
 * `securityAsOfBlock` (number), `securityAsOfTime` (ISO string), and
 * `securityStale` (boolean) aren't in api/openapi.yaml yet, so we extend the
 * generated `Project` type locally rather than hand-editing api-types.ts.
 * Every read below is optional-chained, so an older server that hasn't shipped
 * these fields still renders — just without the staleness banner.
 */
type ProjectWithSecurityStaleness = Project & {
  securityAsOfBlock?: number;
  securityAsOfTime?: string;
  securityStale?: boolean;
};

/** "as of 3m ago" / "as of 2h ago" / "as of just now" — no external date lib needed for this granularity. */
function formatRelativeAge(isoTime: string): string | undefined {
  const then = new Date(isoTime).getTime();
  if (Number.isNaN(then)) return undefined;
  const seconds = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (seconds < 60) return "just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  return `${days}d ago`;
}

function SecurityStalenessNotice({
  data,
}: {
  data: ProjectWithSecurityStaleness;
}) {
  const { securityAsOfBlock, securityAsOfTime, securityStale } = data;
  // Older server: none of these fields are present. Say nothing rather than
  // imply a guarantee we can't back up either way.
  if (
    securityAsOfBlock === undefined &&
    securityAsOfTime === undefined &&
    securityStale === undefined
  ) {
    return null;
  }

  const age = securityAsOfTime
    ? formatRelativeAge(securityAsOfTime)
    : undefined;

  return (
    <p
      className={`security-staleness ${securityStale ? "security-staleness--stale" : ""}`}
      role={securityStale ? "alert" : "status"}
    >
      {securityStale ? "Possibly stale — " : ""}
      as of
      {securityAsOfBlock !== undefined ? ` block ${securityAsOfBlock}` : ""}
      {age ? ` (${age})` : ""}
      {securityAsOfBlock === undefined && !age ? " an unknown point" : ""}. Not
      guaranteed current — reload to refresh.
    </p>
  );
}

/**
 * Security: pause status, role holders, auditor, treasury, redemption
 * manager, strategy, deployment bytecode/version.
 *
 * This data is a point-in-time snapshot from the last indexer read, not a
 * live chain read — it must never be presented as guaranteed current. See
 * SecurityStalenessNotice above.
 */
export function Security() {
  const project = useAsync<ProjectWithSecurityStaleness>(
    (signal) =>
      api.getProject({ signal }) as Promise<ProjectWithSecurityStaleness>,
    [],
  );

  // The live prices are quote-token minimal units, so they scale by the QUOTE
  // token's decimals (never the RWA token's). Prefer the server-provided
  // Project.quoteDecimals; fall back to an on-chain read only when it's absent.
  // A failed resolve leaves quoteDecimals undefined and formatTokenAmount shows
  // the grouped raw integer rather than mis-scaling.
  const proj = project.status === "success" ? project.data : undefined;
  const quoteDecimalsState = useAsync<number | null>(async () => {
    if (!proj) return null;
    try {
      return await resolveQuoteDecimals(proj);
    } catch {
      return null;
    }
  }, [proj?.quoteDecimals, proj?.addresses?.quoteToken]);
  const quoteDecimals =
    quoteDecimalsState.status === "success"
      ? (quoteDecimalsState.data ?? undefined)
      : undefined;

  return (
    <div>
      <header className="app-main__header">
        <h1>Security</h1>
        <p>Pause status, roles, and deployment identity.</p>
      </header>

      <section className="card">
        <h2>Status</h2>
        <AsyncSection state={project} onRetry={project.reload}>
          {(data) => (
            <>
              <SecurityStalenessNotice data={data} />
              <dl className="tx-preview__grid">
                <div className="tx-preview__row">
                  <dt>Paused</dt>
                  <dd>
                    <span
                      className={`badge ${data.paused ? "badge--danger" : "badge--success"}`}
                    >
                      {data.paused ? "Paused" : "Active"}
                    </span>
                  </dd>
                </div>
                <div className="tx-preview__row">
                  <dt>Version</dt>
                  <dd>{data.version ?? "—"}</dd>
                </div>
                <div className="tx-preview__row">
                  <dt>Bytecode verified</dt>
                  <dd>
                    <span
                      className={`badge ${data.bytecodeVerified ? "badge--success" : "badge--warning"}`}
                    >
                      {data.bytecodeVerified ? "Verified" : "Unverified"}
                    </span>
                  </dd>
                </div>
                <div className="tx-preview__row">
                  <dt>Decimals</dt>
                  <dd>{data.decimals ?? "—"}</dd>
                </div>
                <div className="tx-preview__row">
                  <dt>Token unit</dt>
                  <dd>{data.tokenUnit ?? "—"}</dd>
                </div>
                <div className="tx-preview__row">
                  <dt>Finality confirmations</dt>
                  <dd>{data.finalityConfirmations ?? "—"}</dd>
                </div>
                <div className="tx-preview__row">
                  <dt>Auditor</dt>
                  <dd title={data.auditor}>{data.auditor}</dd>
                </div>
                <div className="tx-preview__row">
                  <dt>Treasury</dt>
                  <dd title={data.treasury}>{data.treasury}</dd>
                </div>
                <div className="tx-preview__row">
                  <dt>Redemption manager</dt>
                  <dd title={data.redemptionManager}>
                    {data.redemptionManager}
                  </dd>
                </div>
                {data.addresses &&
                  Object.entries(data.addresses).map(([key, value]) => (
                    <div className="tx-preview__row" key={key}>
                      <dt>{key}</dt>
                      <dd title={value}>{value}</dd>
                    </div>
                  ))}
              </dl>
            </>
          )}
        </AsyncSection>
      </section>

      <section className="card">
        <h2>Pause / unpause trading</h2>
        <RoleGate
          roles={proj?.roles}
          role={ROLES.pauser}
          action="pause or unpause trading"
        >
          <PauseControls project={proj} onChanged={project.reload} />
        </RoleGate>
      </section>

      <section className="card">
        <h2>Current prices</h2>
        <AsyncSection state={project} onRetry={project.reload}>
          {(data) =>
            data.purchasePricePerWholeToken === undefined &&
            data.redemptionPricePerWholeToken === undefined ? (
              <p className="field__hint">
                No on-chain prices reported yet (project not deployed or price
                not projected).
              </p>
            ) : (
              <dl className="tx-preview__grid">
                {data.purchasePricePerWholeToken !== undefined && (
                  <div className="tx-preview__row">
                    <dt>Current purchase price (per whole token)</dt>
                    <dd>
                      {formatTokenAmount(
                        data.purchasePricePerWholeToken,
                        quoteDecimals,
                      )}
                    </dd>
                  </div>
                )}
                {data.redemptionPricePerWholeToken !== undefined && (
                  <div className="tx-preview__row">
                    <dt>Current redemption price (per whole token)</dt>
                    <dd>
                      {formatTokenAmount(
                        data.redemptionPricePerWholeToken,
                        quoteDecimals,
                      )}
                    </dd>
                  </div>
                )}
              </dl>
            )
          }
        </AsyncSection>
      </section>

      <section className="card">
        <h2>Update prices</h2>
        <RoleGate roles={proj?.roles} role={ROLES.pricer} action="set prices">
          <PriceControls
            project={proj}
            quoteDecimals={quoteDecimals}
            onChanged={project.reload}
          />
        </RoleGate>
      </section>

      <section className="card">
        <h2>Role holders</h2>
        <AsyncSection
          state={project}
          onRetry={project.reload}
          empty={(d) => !d.roles || Object.keys(d.roles).length === 0}
          emptyLabel="No role holders reported."
        >
          {(data) => (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Role</th>
                    <th>Holders</th>
                  </tr>
                </thead>
                <tbody>
                  {data.roles &&
                    Object.entries(data.roles).map(([role, holders]) => (
                      <tr key={role}>
                        <td className="mono">{role}</td>
                        <td>
                          {holders.map((h) => (
                            <div key={h} className="mono" title={h}>
                              {shortenAddress(h)}
                            </div>
                          ))}
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          )}
        </AsyncSection>
      </section>

      <section className="card">
        <h2>Manage roles &amp; admin</h2>
        <RoleGate
          roles={proj?.roles}
          role={ROLES.admin}
          action="change role holders or transfer admin"
        >
          <RoleAdminControls project={proj} onChanged={project.reload} />
        </RoleGate>
      </section>

      {/*
        Not RoleGate-gated: the incoming admin is NOT DEFAULT_ADMIN yet (that's
        the whole point of accepting), so it never appears in proj.roles.
        Shown ONLY when the connected wallet is the pending admin on at least
        one program, read per-program from the config accounts — see
        useIsPendingAdmin. For everyone else the section is irrelevant: every
        button in it would revert on-chain, and the outgoing admin in
        particular has no use for it at all.
      */}
      <AcceptAdminSection project={proj} onChanged={project.reload} />
    </div>
  );
}

/** The connected wallet address, or null. All admin actions require it. */
function useSender(): string | null {
  return useWalletContext().address;
}

function PauseControls({
  project,
  onChanged,
}: {
  project: Project | undefined;
  onChanged: () => void;
}) {
  const from = useSender();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);
  // Pause/unpause lives on the compliance program's Registry, not the RWA
  // mint — there is no pause instruction on the mint itself.
  const compliance = project?.addresses?.compliance;
  const paused = Boolean(project?.paused);

  async function handle(pause: boolean) {
    setError(null);
    setDone(null);
    if (!from || !compliance) {
      setError("Wallet not connected or compliance address unavailable.");
      return;
    }
    setBusy(true);
    try {
      const hash = await sendSetPaused(from, compliance, pause);
      await waitForTxReceipt(hash);
      setDone(pause ? "Trading paused." : "Trading unpaused.");
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Transaction failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <p className="field__hint">
        Current status:{" "}
        <span
          className={`badge ${paused ? "badge--danger" : "badge--success"}`}
        >
          {paused ? "Paused" : "Active"}
        </span>
        . Pausing halts all token transfers (buys, redemptions, and wallet
        transfers) until unpaused.
      </p>
      <div className="tx-preview__actions">
        <button
          type="button"
          className="button button--danger"
          onClick={() => handle(true)}
          disabled={busy || paused}
        >
          {busy ? "Submitting…" : "Pause trading"}
        </button>
        <button
          type="button"
          className="button button--primary"
          onClick={() => handle(false)}
          disabled={busy || !paused}
        >
          {busy ? "Submitting…" : "Unpause trading"}
        </button>
      </div>
      {error && (
        <p className="async-state--error" role="alert">
          {error}
        </p>
      )}
      {done && <p role="status">{done}</p>}
    </div>
  );
}

function PriceControls({
  project,
  quoteDecimals,
  onChanged,
}: {
  project: Project | undefined;
  quoteDecimals: number | undefined;
  onChanged: () => void;
}) {
  const from = useSender();
  const [purchase, setPurchase] = useState("");
  const [redemption, setRedemption] = useState("");
  const [busy, setBusy] = useState<"purchase" | "redemption" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const strategy = project?.addresses?.strategy;

  async function handle(side: "purchase" | "redemption", value: string) {
    setError(null);
    setDone(null);
    if (!from || !strategy) {
      setError("Wallet not connected or strategy address unavailable.");
      return;
    }
    // Prices are entered in whole quote-token units and scaled to the quote
    // token's minimal units (per whole RWA token) before going on-chain. The
    // decimals come from the server (Project.quoteDecimals) or an on-chain
    // read; a failed resolve blocks the tx rather than mis-scaling.
    let decimals = quoteDecimals;
    if (decimals === undefined) {
      try {
        decimals = await resolveQuoteDecimals(project);
      } catch {
        setError(
          "Couldn't determine the quote token's decimals — connect your wallet and try again.",
        );
        return;
      }
    }
    let minimal: string;
    try {
      minimal = toMinimalUnits(value, decimals);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Invalid price.");
      return;
    }
    setBusy(side);
    try {
      const hash = await sendSetStrategyPrice(
        from,
        strategy,
        side,
        BigInt(minimal),
      );
      await waitForTxReceipt(hash);
      setDone(
        side === "purchase"
          ? "Purchase price updated."
          : "Redemption price updated.",
      );
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Transaction failed.");
    } finally {
      setBusy(null);
    }
  }

  return (
    <div>
      <p className="field__hint">
        Prices are per whole token, in whole quote-token units. Each is set on
        the fixed-price strategy independently.
      </p>
      <div className="field">
        <label htmlFor="new-purchase-price">
          Purchase price (whole quote-token units)
        </label>
        <input
          id="new-purchase-price"
          value={purchase}
          onChange={(e) => setPurchase(e.target.value)}
        />
      </div>
      <button
        type="button"
        className="button button--secondary"
        onClick={() => handle("purchase", purchase)}
        disabled={busy !== null || !purchase}
      >
        {busy === "purchase" ? "Submitting…" : "Set purchase price"}
      </button>
      <div className="field u-mt-4">
        <label htmlFor="new-redemption-price">
          Redemption price (whole quote-token units)
        </label>
        <input
          id="new-redemption-price"
          value={redemption}
          onChange={(e) => setRedemption(e.target.value)}
        />
      </div>
      <button
        type="button"
        className="button button--secondary"
        onClick={() => handle("redemption", redemption)}
        disabled={busy !== null || !redemption}
      >
        {busy === "redemption" ? "Submitting…" : "Set redemption price"}
      </button>
      {error && (
        <p className="async-state--error" role="alert">
          {error}
        </p>
      )}
      {done && <p role="status">{done}</p>}
    </div>
  );
}

/**
 * Sends `send` to each target contract in turn (a role may live on more than
 * one contract), waiting for each receipt. Returns a per-contract error message
 * if any submission fails, naming how many succeeded so the operator knows the
 * partial state.
 */
async function runSequential(
  targets: string[],
  send: (target: string) => Promise<string>,
  onProgress: (done: number, total: number) => void,
): Promise<string | null> {
  for (let i = 0; i < targets.length; i++) {
    onProgress(i, targets.length);
    try {
      const hash = await send(targets[i]);
      await waitForTxReceipt(hash);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Transaction failed.";
      return `Stopped after ${i} of ${targets.length} transaction(s): ${msg}`;
    }
  }
  onProgress(targets.length, targets.length);
  return null;
}

function RoleAdminControls({
  project,
  onChanged,
}: {
  project: Project | undefined;
  onChanged: () => void;
}) {
  const from = useSender();
  const addresses = project?.addresses as Addresses | undefined;
  const [role, setRole] = useState<string>(GRANTABLE_ROLES[0]);
  const [account, setAccount] = useState("");
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  async function handleRoleChange() {
    setError(null);
    setDone(null);
    setProgress(null);
    if (!from) {
      setError("Wallet not connected.");
      return;
    }
    const targets = roleTargets(role, addresses);
    if (targets.length === 0) {
      setError("No target programs for this role — project not deployed?");
      return;
    }
    setBusy(true);
    const failure = await runSequential(
      targets,
      (target) => sendRoleChange(from, target, role, account),
      (d, t) => setProgress(`Submitting ${Math.min(d + 1, t)} of ${t}…`),
    );
    setBusy(false);
    setProgress(null);
    if (failure) setError(failure);
    else {
      setDone(
        `Replaced ${role}'s holder with ${account} on ${targets.length} program(s).`,
      );
      onChanged();
    }
  }

  return (
    <div>
      <h3>Replace role holder</h3>
      <p className="field__hint">
        Roles are single-holder: setting a new holder REPLACES the current one
        on every target program below. There is no separate revoke — to
        remove a holder, replace it with a different account.
      </p>
      <div className="field">
        <label htmlFor="role-select">Role</label>
        <select
          id="role-select"
          value={role}
          onChange={(e) => setRole(e.target.value)}
        >
          {GRANTABLE_ROLES.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
        <span className="field__hint">
          Applied to every program the role is held on (
          {roleTargets(role, addresses).length} for this role).
        </span>
      </div>
      <div className="field">
        <label htmlFor="role-account">Account address</label>
        <input
          id="role-account"
          className="mono"
          value={account}
          onChange={(e) => setAccount(e.target.value)}
        />
      </div>
      <div className="tx-preview__actions">
        <button
          type="button"
          className="button button--primary"
          onClick={handleRoleChange}
          disabled={busy || !account}
        >
          Replace role holder
        </button>
      </div>

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

      <h3 className="u-mt-5">Transfer admin</h3>
      <p className="field__hint">
        Every admin-owned program below has its OWN independent two-step
        admin. Begin a transfer on the one(s) you intend to rotate — the
        incoming admin must separately accept on each one to complete it;
        until then, you remain admin on that program.
      </p>
      <AdminTransferForms
        targets={adminContractTargets(addresses)}
        onChanged={onChanged}
      />
    </div>
  );
}

/** One "Begin admin transfer" form per admin-owned program, each labeled with its name and on-chain address. */
function AdminTransferForms({
  targets,
  onChanged,
}: {
  targets: AdminContractTarget[];
  onChanged: () => void;
}) {
  if (targets.length === 0) {
    return (
      <p className="field__hint">
        No admin-owned programs found — project not deployed?
      </p>
    );
  }
  return (
    <div className="admin-transfer-list">
      {targets.map((target) => (
        <AdminTransferForm
          key={target.programKey}
          target={target}
          onChanged={onChanged}
        />
      ))}
    </div>
  );
}

function AdminTransferForm({
  target,
  onChanged,
}: {
  target: AdminContractTarget;
  onChanged: () => void;
}) {
  const from = useSender();
  const [newAdmin, setNewAdmin] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const inputId = `new-admin-${target.programKey}`;

  async function handle() {
    setError(null);
    setDone(null);
    if (!from) {
      setError("Wallet not connected.");
      return;
    }
    setBusy(true);
    try {
      const hash = await sendBeginAdminTransfer(
        from,
        target.address,
        newAdmin,
        target.programKey,
      );
      await waitForTxReceipt(hash);
      setDone(`Admin transfer to ${newAdmin} begun on ${target.name}.`);
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Transaction failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="admin-transfer-list__item">
      <h4>{target.name}</h4>
      <p className="field__hint mono" title={target.address}>
        {shortenAddress(target.address)}
      </p>
      <div className="field">
        <label htmlFor={inputId}>New admin address</label>
        <input
          id={inputId}
          className="mono"
          value={newAdmin}
          onChange={(e) => setNewAdmin(e.target.value)}
        />
      </div>
      <button
        type="button"
        className="button button--danger"
        onClick={handle}
        disabled={busy || !newAdmin}
      >
        {busy ? "Submitting…" : "Begin admin transfer"}
      </button>
      {error && (
        <p className="async-state--error" role="alert">
          {error}
        </p>
      )}
      {done && <p role="status">{done}</p>}
    </div>
  );
}

/**
 * Renders the "Accept admin transfer" card only when the connected wallet is
 * actually the pending (incoming) admin on at least one program.
 *
 * Why this needs an on-chain read rather than GET /project: `pendingAdmin`
 * there is a single AGGREGATE value — the server's fold reports the first
 * program it finds a pending transfer on — so it can say "some transfer is
 * pending somewhere" but not which programs, and not whether the connected
 * wallet is the target. Admins are per-program on Solana (five independent
 * `admin` fields), so only a per-program read can answer this.
 *
 * While the read is in flight, and on failure, the card stays HIDDEN. Hiding
 * is the safe default: a spuriously-shown card offers buttons that can only
 * revert, whereas a genuine pending admin who briefly sees nothing gets the
 * card as soon as the read lands. Nothing here is a security control — the
 * program authorizes `accept_admin` against its own `pending_admin` field
 * regardless of what the UI chooses to render.
 */
function AcceptAdminSection({
  project,
  onChanged,
}: {
  project: Project | undefined;
  onChanged: () => void;
}) {
  const sender = useSender();
  const addresses = project?.addresses as Addresses | undefined;
  const targets = adminContractTargets(addresses);

  const pending = useAsync<AdminContractTarget[]>(async () => {
    if (!sender || targets.length === 0) return [];
    const matches = await readPendingAdminTargets(
      sender,
      targets.map((t) => ({ programKey: t.programKey, address: t.address })),
    );
    const matched = new Set(matches.map((m) => m.programKey));
    return targets.filter((t) => matched.has(t.programKey));
  }, [sender, targets.map((t) => t.address).join(",")]);

  if (pending.status !== "success" || pending.data.length === 0) return null;

  // Accepting clears that program's `pending_admin` on-chain, so the card must
  // re-read: otherwise the just-accepted program keeps offering a button that
  // now reverts, and the card lingers after the last one is accepted.
  function handleAccepted() {
    onChanged();
    pending.reload();
  }

  return (
    <section className="card">
      <h2>Accept admin transfer</h2>
      <p className="field__hint">
        This wallet is the pending admin on{" "}
        {pending.data.length === 1
          ? "one program"
          : `${pending.data.length} programs`}
        . Accept each one independently — admins are per-program.
      </p>
      <AcceptAdminControls targets={pending.data} onChanged={handleAccepted} />
    </section>
  );
}

/**
 * Step 2 of the two-step admin transfer, for the INCOMING admin: one
 * independent "Accept admin transfer" control per admin-owned program, each
 * labeled with its name and on-chain address. Broadcasts with no args (the
 * program already recorded the pending admin) — reverts on-chain if nothing
 * is pending to the connected wallet on that particular one, so this is
 * intentionally not gated on the connected wallet matching anything
 * client-side.
 */
function AcceptAdminControls({
  targets,
  onChanged,
}: {
  /** Only the programs where the connected wallet IS the pending admin. */
  targets: AdminContractTarget[];
  onChanged: () => void;
}) {
  return (
    <div className="admin-transfer-list">
      {targets.map((target) => (
        <AcceptAdminForm
          key={target.programKey}
          target={target}
          onChanged={onChanged}
        />
      ))}
    </div>
  );
}

function AcceptAdminForm({
  target,
  onChanged,
}: {
  target: AdminContractTarget;
  onChanged: () => void;
}) {
  const from = useSender();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  async function handle() {
    setError(null);
    setDone(null);
    if (!from) {
      setError("Wallet not connected.");
      return;
    }
    setBusy(true);
    try {
      const hash = await sendAcceptAdminTransfer(
        from,
        target.address,
        target.programKey,
      );
      await waitForTxReceipt(hash);
      setDone(`Accepted the admin role on ${target.name}.`);
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Transaction failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="admin-transfer-list__item">
      <h4>{target.name}</h4>
      <p className="field__hint mono" title={target.address}>
        {shortenAddress(target.address)}
      </p>
      <button
        type="button"
        className="button button--primary"
        onClick={handle}
        disabled={busy || !from}
      >
        {busy ? "Submitting…" : "Accept admin transfer"}
      </button>
      {error && (
        <p className="async-state--error" role="alert">
          {error}
        </p>
      )}
      {done && <p role="status">{done}</p>}
    </div>
  );
}
