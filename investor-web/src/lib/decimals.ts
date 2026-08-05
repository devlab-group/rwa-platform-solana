// Resolves the decimals to use when converting a human-entered amount to
// minimal units (or rendering a minimal-unit amount back as whole units) for a
// given token — the second half of the req_changes Web 1 boundary, alongside
// lib/format.ts's toMinimalUnits/formatTokenAmount.
import type { components } from "./api-types";
import { readTokenDecimals } from "./wallet";
import { assertPinnedQuoteMint, assertPinnedRwaMint } from "./chain/pins";

type Project = components["schemas"]["Project"];

/**
 * RWA token decimals: always read from the RWA mint on-chain, even though
 * server/internal/project/seed.go DOES populate Project.decimals
 * (`p.TokenDecimals = params.RWADecimals`, required at config load via
 * `solana.rwa_decimals`) — this isn't working around a missing value, it's a
 * deliberate choice to trust the mint over a server-cached number: the
 * on-chain read is cheap, always correct even if the config value is ever
 * wrong or stale, and mirrors resolveQuoteDecimals' on-chain-only behavior
 * below. The mint address is pin-checked first so a compromised server
 * can't redirect the read itself, not just the value it returns.
 */
export async function resolveRwaDecimals(
  project: Project | undefined,
): Promise<number> {
  const token = project?.addresses?.token;
  if (!token) {
    throw new Error("Token decimals unavailable — project not fully loaded.");
  }
  assertPinnedRwaMint(token);
  return readTokenDecimals(token, "rwa");
}

/**
 * Quote-token decimals. project.quoteDecimals is IGNORED entirely and always
 * replaced with an on-chain mint read — mirroring resolveRwaDecimals above.
 * This value renders the buy cost and redemption payout the investor
 * approves; unlike every address/program-id pin, it's a
 * plain integer with no pin of its own, so a compromised or misconfigured
 * server could scale the displayed price by 10^(reported-actual) without
 * redirecting any on-chain value — defeating informed consent even though
 * nothing the investor signs is affected. `assertPinnedQuoteMint` pin-checks
 * the mint address before reading it, so the read itself can't be
 * redirected either.
 */
export async function resolveQuoteDecimals(
  project: Project | undefined,
): Promise<number> {
  const quoteToken = project?.addresses?.quoteToken;
  if (!quoteToken) {
    throw new Error(
      "Quote token decimals unavailable — project not fully loaded.",
    );
  }
  assertPinnedQuoteMint(quoteToken);
  return readTokenDecimals(quoteToken, "quote");
}
