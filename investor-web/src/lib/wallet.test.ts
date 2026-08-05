// Coverage for lib/wallet.ts and lib/chain/provider.ts.
// Deliberately no live validator/RPC here — these exercise pure math and the
// injected-wallet message-signing contract with a fake `window.solana`.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import bs58 from "bs58";
import { Keypair } from "@solana/web3.js";
import {
  readPreviewBuy,
  readPreviewRedeem,
  type ProgramAddresses,
} from "./wallet";
import {
  getInjectedProvider,
  getConnection,
  readStrategyAccount,
  signMessageWithProvider,
  type InjectedProvider,
} from "./chain/provider";

vi.mock("./chain/provider", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./chain/provider")>();
  return {
    ...actual,
    readStrategyAccount: vi.fn(),
    getConnection: vi.fn(),
  };
});

const PROGRAM_ADDRESSES: ProgramAddresses = {
  complianceProgramId: Keypair.generate().publicKey.toBase58(),
  pricingProgramId: Keypair.generate().publicKey.toBase58(),
  vaultProgramId: Keypair.generate().publicKey.toBase58(),
  redemptionProgramId: Keypair.generate().publicKey.toBase58(),
  rwaMint: Keypair.generate().publicKey.toBase58(),
  quoteMint: Keypair.generate().publicKey.toBase58(),
};

// VITE_SOLANA_RPC_URL is the SOLE source of the
// RPC endpoint now. Stubbed globally so every requireRpcUrl() call
// below resolves without each test having to set it itself.
beforeEach(() => {
  vi.stubEnv("VITE_SOLANA_RPC_URL", "http://localhost:8899");
});

afterEach(() => {
  delete window.solana;
  vi.unstubAllEnvs();
  vi.resetAllMocks();
});

describe("readPreviewBuy / readPreviewRedeem", () => {
  // The quote is read from the pricing program's on-chain
  // Strategy account (via lib/chain/provider.ts's readStrategyAccount), not
  // from a server-supplied price — mirrors solana/crates/pricing-math:
  // purchase rounds up, redemption rounds down, quote = tokenAmount * price
  // / 10**decimals.
  it("computes the purchase quote from the on-chain Strategy account, rounding up", async () => {
    vi.mocked(getConnection).mockReturnValue(
      {} as unknown as ReturnType<typeof getConnection>,
    );
    vi.mocked(readStrategyAccount).mockResolvedValue({
      purchasePrice: 1n,
      redemptionPrice: 1n,
      tokenDecimals: 18,
    });
    // 0.5 whole token (10**17 at 18 decimals) at price 1 -> 0.5 units, ceiled to 1.
    const half = 5n * 10n ** 17n;
    const quote = await readPreviewBuy(half, PROGRAM_ADDRESSES);
    expect(quote).toBe(1n);
    expect(readStrategyAccount).toHaveBeenCalledTimes(1);
  });

  it("computes the redemption quote from the on-chain Strategy account, rounding down", async () => {
    vi.mocked(getConnection).mockReturnValue(
      {} as unknown as ReturnType<typeof getConnection>,
    );
    vi.mocked(readStrategyAccount).mockResolvedValue({
      purchasePrice: 1n,
      redemptionPrice: 1n,
      tokenDecimals: 18,
    });
    const half = 5n * 10n ** 17n;
    const quote = await readPreviewRedeem(half, PROGRAM_ADDRESSES);
    expect(quote).toBe(0n);
  });

  it("throws a clear error when the program addresses are missing", async () => {
    await expect(readPreviewBuy(1_000_000n)).rejects.toThrow(
      /Program addresses are required/,
    );
  });
});

describe("signMessageWithProvider", () => {
  it("signs the exact UTF-8 bytes of the message and returns a base58 signature", async () => {
    const fakeSignatureBytes = new Uint8Array(64).fill(7);
    const signMessage = vi.fn().mockImplementation(async (msg: Uint8Array) => {
      // The wallet sees exactly the UTF-8 encoding of the challenge string —
      // no prefixing.
      expect(Array.from(msg)).toEqual(
        Array.from(new TextEncoder().encode("challenge-message-123")),
      );
      return { signature: fakeSignatureBytes };
    });
    window.solana = {
      publicKey: null,
      connect: vi.fn(),
      signMessage,
      signTransaction: vi.fn(),
      signAllTransactions: vi.fn(),
    } as unknown as InjectedProvider;

    const signature = await signMessageWithProvider("challenge-message-123");
    expect(signature).toBe(bs58.encode(fakeSignatureBytes));
    expect(signMessage).toHaveBeenCalledTimes(1);
  });

  it("also accepts a wallet that returns the raw Uint8Array (not {signature})", async () => {
    const fakeSignatureBytes = new Uint8Array(64).fill(9);
    window.solana = {
      publicKey: null,
      connect: vi.fn(),
      signMessage: vi.fn().mockResolvedValue(fakeSignatureBytes),
      signTransaction: vi.fn(),
      signAllTransactions: vi.fn(),
    } as unknown as InjectedProvider;

    const signature = await signMessageWithProvider("another-message");
    expect(signature).toBe(bs58.encode(fakeSignatureBytes));
  });

  it("throws when no injected wallet is present", async () => {
    expect(getInjectedProvider()).toBeUndefined();
    await expect(signMessageWithProvider("x")).rejects.toThrow(
      /No injected wallet found/,
    );
  });
});
