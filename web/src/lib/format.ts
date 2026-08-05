// Amount/address/time formatting helpers shared across admin and investor screens.
// All on-chain amounts arrive from the API as decimal strings of smallest units
// (they must be strings, never JSON floats — see api/openapi.yaml).
//
// This module owns both sides of the human<->minimal boundary:
// amounts DISPLAYED to a user are scaled to whole units for reading
// (formatTokenAmount / formatUnits), and amounts a user ENTERS are converted
// back to the token's minimal integer units with `toMinimalUnits` before they
// go to the server or into on-chain calldata. Never route an amount through a
// JS number/float — strings and BigInt only.
/**
 * Formats a smallest-units bigint as a decimal string scaled down by
 * `decimals`, trimming trailing fractional zeros (and the decimal point
 * entirely when nothing but zeros remain) — e.g. formatUnits(1500000000000000000n, 18) -> "1.5".
 * Negative values are supported for symmetry with toMinimalUnits/parseUnits
 * even though no caller here produces one.
 */
function formatUnits(value: bigint, decimals: number): string {
  const negative = value < 0n;
  const abs = negative ? -value : value;
  const digits = abs.toString().padStart(decimals + 1, "0");
  const whole = decimals === 0 ? digits : digits.slice(0, -decimals);
  const frac = decimals === 0 ? "" : digits.slice(-decimals).replace(/0+$/, "");
  const result = frac ? `${whole}.${frac}` : whole;
  return negative ? `-${result}` : result;
}

/**
 * Parses a decimal string (already validated by toMinimalUnits — non-negative,
 * at most `decimals` fractional digits) into its smallest-units bigint by
 * padding the fractional part out to `decimals` places and concatenating.
 */
function parseUnits(value: string, decimals: number): bigint {
  const [wholeRaw, fracRaw = ""] = value.split(".");
  const whole = wholeRaw === "" ? "0" : wholeRaw;
  const frac = fracRaw.padEnd(decimals, "0").slice(0, decimals);
  return BigInt(whole + frac);
}

/**
 * Render a smallest-units amount string for display.
 * When `decimals` is known (e.g. from Project.decimals for RWA amounts), the
 * value is scaled to whole units. Otherwise the raw integer is grouped as-is
 * and callers must label the unit explicitly.
 */
export function formatTokenAmount(raw: string, decimals?: number): string {
  if (raw === "" || raw === undefined) return "—";
  try {
    if (decimals === undefined) {
      return groupDigits(raw);
    }
    const value = formatUnits(BigInt(raw), decimals);
    return groupDecimal(value);
  } catch {
    return raw;
  }
}

/**
 * Thrown by `toMinimalUnits` when the entered value isn't a valid non-negative
 * amount for a token with `decimals` fractional places. Callers surface
 * `.message` directly, which echoes the value the user typed so they get a
 * friendly, specific error.
 */
export class AmountFormatError extends Error {
  constructor(
    public readonly value: string,
    public readonly decimals: number,
  ) {
    const precision =
      decimals > 0
        ? ` Enter a whole number or a decimal with up to ${decimals} fractional digit${decimals === 1 ? "" : "s"}.`
        : " Enter a whole number (this token has no fractional units).";
    super(`"${value}" is not a valid amount.${precision}`);
    this.name = "AmountFormatError";
  }
}

/**
 * Convert a human-entered, whole-unit amount (e.g. "1.5") into the token's
 * smallest integer units as a decimal string, using the local `parseUnits`
 * above.
 *
 * `parseUnits` alone is unsafe as an input guard here: naively it would
 * silently coerce "" -> 0, accept a leading "-", and ROUND over-precise input
 * (e.g. "1.2345678" at 6 decimals -> "1234568"), any of which would quietly
 * mis-scale money. This wrapper rejects all of those up front so a bad amount
 * surfaces as an error to the user rather than a wrong on-chain value.
 */
export function toMinimalUnits(human: string, decimals: number): string {
  const value = human.trim();
  // Non-negative decimal only: "5", "5.", "5.5", ".5", "00.50". Rejects "",
  // ".", "-1", "1e3", "1,000", "abc", "1.5.5".
  if (!/^(\d+\.?\d*|\.\d+)$/.test(value)) {
    throw new AmountFormatError(human, decimals);
  }
  const frac = value.includes(".") ? value.slice(value.indexOf(".") + 1) : "";
  if (frac.length > decimals) {
    // More fractional digits than the token supports — parseUnits would round
    // and silently change the amount, so reject instead.
    throw new AmountFormatError(human, decimals);
  }
  return parseUnits(value, decimals).toString();
}

function groupDigits(raw: string): string {
  const negative = raw.startsWith("-");
  const digits = negative ? raw.slice(1) : raw;
  if (!/^\d+$/.test(digits)) return raw;
  const grouped = digits.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  return negative ? `-${grouped}` : grouped;
}

function groupDecimal(value: string): string {
  const [whole, frac] = value.split(".");
  const groupedWhole = groupDigits(whole);
  return frac ? `${groupedWhole}.${frac}` : groupedWhole;
}

export function shortenAddress(
  address: string | undefined | null,
  chars = 4,
): string {
  if (!address) return "—";
  if (address.length <= chars * 2 + 2) return address;
  return `${address.slice(0, chars + 2)}…${address.slice(-chars)}`;
}

export function formatUnixSeconds(seconds: number | undefined | null): string {
  if (!seconds) return "—";
  return new Date(seconds * 1000).toLocaleString();
}

export function formatIsoTimestamp(iso: string | undefined | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}
