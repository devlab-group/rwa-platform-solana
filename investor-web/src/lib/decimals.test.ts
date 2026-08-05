import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resolveQuoteDecimals } from "./decimals";
import { readTokenDecimals } from "./wallet";
import type { components } from "./api-types";

type Project = components["schemas"]["Project"];

// project.quoteDecimals must be ignored entirely — it's what
// the *server* reports, unverified, and unlike every address/program-id pin
// it has no pin of its own, so a compromised/misconfigured server could
// otherwise scale the price the investor reads by 10^(reported-actual)
// without redirecting any on-chain value. readTokenDecimals is the on-chain
// path, so a strict "called with the mint" assertion proves the value always
// comes from the chain, never the server.
vi.mock("./wallet", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./wallet")>();
  return { ...actual, readTokenDecimals: vi.fn().mockResolvedValue(6) };
});

// Two real, distinct, well-known base58 pubkeys (rather than
// vi.mocked/made-up strings, or Keypair.generate() — PublicKey construction
// misbehaves under this suite's default jsdom environment's crypto shim, see
// chain/pins.test.ts) so assertPinnedQuoteMint's PublicKey-decode path below
// runs for real.
const QUOTE = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const QUOTE_REDIRECTED = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

describe("resolveQuoteDecimals", () => {
  beforeEach(() => {
    vi.mocked(readTokenDecimals).mockClear().mockResolvedValue(6);
  });
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("ignores a WRONG Project.quoteDecimals and always reads the mint on-chain", async () => {
    const project: Project = {
      // A server misreporting 18 for a real 6-decimal mint — the wrong value
      // that used to render a 1,000,000-unit cost as 0.000001. This must
      // never reach the caller.
      quoteDecimals: 18,
      addresses: { quoteToken: QUOTE },
    };

    await expect(resolveQuoteDecimals(project)).resolves.toBe(6);
    expect(readTokenDecimals).toHaveBeenCalledWith(QUOTE, "quote");
  });

  it("reads on-chain even when Project.quoteDecimals is absent", async () => {
    const project: Project = { addresses: { quoteToken: QUOTE } };

    await expect(resolveQuoteDecimals(project)).resolves.toBe(6);
  });

  it("throws when the project isn't fully loaded yet (no quote token address)", async () => {
    await expect(resolveQuoteDecimals(undefined)).rejects.toThrow(
      /not fully loaded/,
    );
    expect(readTokenDecimals).not.toHaveBeenCalled();
  });

  it("does not throw when the quote mint is unpinned (dev fallback)", async () => {
    const project: Project = {
      quoteDecimals: 18,
      addresses: { quoteToken: QUOTE },
    };

    await expect(resolveQuoteDecimals(project)).resolves.toBe(6);
  });

  it("throws PinMismatchError rather than reading a server-redirected quote mint", async () => {
    vi.stubEnv("VITE_SOLANA_QUOTE_MINT", QUOTE);
    const project: Project = { addresses: { quoteToken: QUOTE_REDIRECTED } };

    await expect(resolveQuoteDecimals(project)).rejects.toThrow(/quote mint/i);
    expect(readTokenDecimals).not.toHaveBeenCalled();
  });
});
