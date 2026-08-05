import { beforeEach, describe, expect, it, vi } from "vitest";
import { resolveQuoteDecimals } from "./decimals";
import { readMintDecimals } from "./wallet";
import type { components } from "./api-types";

type Project = components["schemas"]["Project"];

// Post-deploy screens already fetch the project; when the server supplies
// Project.quoteDecimals they must scale quote amounts from it instead of an
// on-chain round trip, falling back to the mint read only when it's absent
// (older server builds). readMintDecimals is the on-chain path, so a strict
// "not called" assertion proves the server value was preferred.
vi.mock("./wallet", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./wallet")>();
  return { ...actual, readMintDecimals: vi.fn().mockResolvedValue(18) };
});

const QUOTE = "Quote1111111111111111111111111111111111111";

describe("resolveQuoteDecimals", () => {
  beforeEach(() => {
    vi.mocked(readMintDecimals).mockClear().mockResolvedValue(18);
  });

  it("prefers Project.quoteDecimals and does not read on-chain", async () => {
    const project: Project = {
      quoteDecimals: 6,
      addresses: { quoteToken: QUOTE },
    };

    await expect(resolveQuoteDecimals(project)).resolves.toBe(6);
    expect(readMintDecimals).not.toHaveBeenCalled();
  });

  it("falls back to the on-chain read when quoteDecimals is absent", async () => {
    const project: Project = {
      addresses: { quoteToken: QUOTE },
    };

    await expect(resolveQuoteDecimals(project)).resolves.toBe(18);
    expect(readMintDecimals).toHaveBeenCalledWith(QUOTE);
  });

  it("uses quoteDecimals even when it is 0 (a real, valid value)", async () => {
    const project: Project = {
      quoteDecimals: 0,
      addresses: { quoteToken: QUOTE },
    };

    await expect(resolveQuoteDecimals(project)).resolves.toBe(0);
    expect(readMintDecimals).not.toHaveBeenCalled();
  });
});
