// UI-level status derivation. Chain state (from api-types) is the source of
// truth; this module only adds display labels and the Funded -> Claimable
// split, so the UI can distinguish Pending, Funded, and Claimable clearly.
import type { components } from "./api-types";

export type RedemptionChainStatus = NonNullable<
  components["schemas"]["Redemption"]["status"]
>;
export type TransactionChainStatus = NonNullable<
  components["schemas"]["Transaction"]["status"]
>;

/**
 * Fallback confirmations threshold, only used when a Redemption predates the
 * server's `claimable`/Project's `finalityConfirmations` fields (defensive;
 * both are always present as of the current contract).
 */
export const FALLBACK_FINALITY_CONFIRMATIONS = 12;

export type RedemptionDisplayStatus =
  | "Pending"
  | "Funded"
  | "Claimable"
  | "Completed"
  | "Rejected"
  | "Cancelled"
  | "Unknown";

/**
 * A `Funded` redemption is technically claimable the instant it is funded,
 * but the indexer's view of that funding tx is only safe to act on past the
 * finality threshold — treat indexer results as unconfirmed until the
 * configured number of confirmations. The server now computes this directly
 * as `Redemption.claimable` (status==Funded AND
 * confirmations>=Project.finalityConfirmations) — prefer that. The
 * confirmations/threshold fallback below only covers callers that haven't
 * loaded a claimable flag yet.
 */
export function redemptionDisplayStatus(
  status: RedemptionChainStatus | undefined,
  opts: {
    claimable?: boolean;
    confirmations?: number;
    finalityConfirmations?: number;
  } = {},
): RedemptionDisplayStatus {
  switch (status) {
    case "Pending":
      return "Pending";
    case "Funded": {
      const claimable =
        opts.claimable ??
        (opts.confirmations ?? 0) >=
          (opts.finalityConfirmations ?? FALLBACK_FINALITY_CONFIRMATIONS);
      return claimable ? "Claimable" : "Funded";
    }
    case "Completed":
      return "Completed";
    case "Rejected":
      return "Rejected";
    case "Cancelled":
      return "Cancelled";
    default:
      return "Unknown";
  }
}

export const REDEMPTION_STATUS_LABEL: Record<RedemptionDisplayStatus, string> =
  {
    Pending: "Pending",
    Funded: "Funded (confirming)",
    Claimable: "Claimable",
    Completed: "Completed",
    Rejected: "Rejected",
    Cancelled: "Cancelled",
    Unknown: "Unknown",
  };

/**
 * Human-readable label for every `domain.TxStatus` the server can emit.
 * Keyed by the generated `TransactionChainStatus` union,
 * so widening the OpenAPI enum forces this map (and `TRANSACTION_TONE`) to be
 * updated — an incomplete map fails typecheck. For a value that is *not* in
 * the union (a forward-compat status a newer server added), use
 * `transactionStatusLabel`, which falls back to "Unknown".
 */
export const TRANSACTION_STATUS_LABEL: Record<TransactionChainStatus, string> =
  {
    pending: "Unconfirmed",
    confirmed: "Confirmed",
    failed: "Failed — did not take effect",
  };

/** Label shown for any status the client doesn't recognize (forward-compat). */
export const TRANSACTION_STATUS_UNKNOWN_LABEL = "Unknown";

/**
 * Transaction states in which automated progress is stopped, so an operator
 * must look: `failed` means the attempt did not take effect (submission
 * errored, or the cluster reported an execution error). The self-progressing
 * states — `pending` and the terminal `confirmed` — are excluded.
 */
const TRANSACTION_ATTENTION: ReadonlySet<TransactionChainStatus> = new Set([
  "failed",
]);

/** Narrowing guard: is `status` one of the statuses this client knows about? */
export function isKnownTransactionStatus(
  status: string,
): status is TransactionChainStatus {
  return Object.prototype.hasOwnProperty.call(TRANSACTION_STATUS_LABEL, status);
}

/**
 * Display label for any status string, including a forward-compat value a
 * newer server sends that isn't in the generated enum — that renders a clear
 * "Unknown" rather than an empty/undefined label.
 */
export function transactionStatusLabel(status: string): string {
  return isKnownTransactionStatus(status)
    ? TRANSACTION_STATUS_LABEL[status]
    : TRANSACTION_STATUS_UNKNOWN_LABEL;
}

/**
 * True for states where the indexer's record of a transaction is no longer
 * trustworthy as-is and automated progress has stopped or become unsafe (see
 * `TRANSACTION_ATTENTION`). An *unrecognized* forward-compat status is also
 * flagged: the client can't prove it is safe, so it fails closed toward
 * operator visibility. Screens showing a transaction list use this to surface
 * a page-level warning rather than relying on the reader to notice a single
 * row's badge color.
 */
export function needsAttention(status: string): boolean {
  return !isKnownTransactionStatus(status) || TRANSACTION_ATTENTION.has(status);
}

/**
 * True when a redemption still has an admin action available. Both admin
 * transitions — `fundRedemption` (treasurer) and `rejectRedemption`
 * (redemption manager) — require `Pending` on-chain (`ensure_pending`), so a
 * request that has left `Pending` can only move via the permissionless
 * investor claim. Offering "Manage" on those rows would open a panel whose
 * every button reverts.
 */
export function redemptionHasAdminAction(
  status: RedemptionChainStatus | undefined,
): boolean {
  return status === "Pending";
}

/**
 * True when a Pending redemption's `fundRedemption` call would revert
 * because the recorded beneficiary is not currently Allowed. Surfacing this
 * lets the admin panel show clearly that the request is blocked by the
 * current compliance status, which guards against front-running / issuer
 * abuse. Once a request reaches Funded, a later compliance change no longer
 * matters — the quote is already committed and stays claimable, so a later
 * status change must not prevent payment of the already-committed amount.
 * That's why this only applies to Pending requests.
 *
 * `beneficiaryAllowed` is optional on the wire; when it's absent this
 * degrades to `false` (no blocked indicator) rather than guessing.
 */
export function redemptionBlockedByCompliance(
  status: RedemptionChainStatus | undefined,
  beneficiaryAllowed: boolean | undefined,
): boolean {
  return status === "Pending" && beneficiaryAllowed === false;
}
