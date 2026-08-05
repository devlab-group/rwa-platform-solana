// @vitest-environment node
//
// Exercises lib/wallet.ts's send*/read* functions reaching
// lib/chain.ts without needing any component-level mocking. Runs under the
// Node environment (not the default jsdom) — see chain.test.ts's doc
// comment for why: @solana/web3.js's PDA derivation needs the real Node
// Uint8Array realm, which some of the branches below reach (e.g.
// sendSetPaused builds a real instruction, including a real PDA, before
// failing on the absent injected wallet).
import { PublicKey } from "@solana/web3.js";
import { afterEach, describe, expect, it } from "vitest";
import { configure } from "./chain";
import { readPreviewBuy, sendRoleChange, sendSetPaused, signMessage } from "./wallet";

const PROGRAM_IDS = {
  compliance: PublicKey.unique().toBase58(),
  vault: PublicKey.unique().toBase58(),
  pricing: PublicKey.unique().toBase58(),
  transferHook: PublicKey.unique().toBase58(),
  redemption: PublicKey.unique().toBase58(),
  supplyController: PublicKey.unique().toBase58(),
};
const FAKE_WALLET = PublicKey.unique().toBase58();

describe("lib/wallet.ts — chain dispatch", () => {
  afterEach(() => {
    // lib/chain.ts's active config is process-global — reset it after each
    // test so other test files sharing this module aren't affected by
    // leftover state.
    configure(null);
  });

  it("signMessage reaches the injected-wallet path (fails on the absent window.solana)", async () => {
    await expect(signMessage("hello")).rejects.toThrow(
      /No injected wallet found/,
    );
  });

  it("sendRoleChange reaches the instruction-build path (real PDA derivation, fails only on the absent injected wallet)", async () => {
    configure({ programIds: PROGRAM_IDS });
    const newHolder = PublicKey.unique().toBase58();
    await expect(
      sendRoleChange(FAKE_WALLET, PROGRAM_IDS.compliance, "PAUSER_ROLE", newHolder),
    ).rejects.toThrow(/No injected wallet found/);
  });

  it("sendSetPaused reaches the instruction-build path (real PDA derivation, fails only on the absent injected wallet)", async () => {
    configure({ programIds: PROGRAM_IDS });
    await expect(
      sendSetPaused(FAKE_WALLET, PROGRAM_IDS.compliance, true),
    ).rejects.toThrow(/No injected wallet found/);
  });

  it("readPreviewBuy's priceHint math rounds the purchase quote UP, matching on-chain quote_purchase", async () => {
    // 0.5 whole token (10**17 at 18 decimals) at price 1 -> 0.5 units, ceiled to 1
    // (this used to floor to 0 — see the regression this guards against).
    const half = 5n * 10n ** 17n;
    await expect(
      readPreviewBuy(half, { purchasePricePerWholeToken: "1", rwaDecimals: 18 }),
    ).resolves.toBe(1n);
    // An exact (non-fractional) quote is unaffected by rounding.
    await expect(
      readPreviewBuy(10n ** 18n, {
        purchasePricePerWholeToken: "2",
        rwaDecimals: 18,
      }),
    ).resolves.toBe(2n);
    // Zero amount stays zero (no off-by-one from the ceil formula).
    await expect(
      readPreviewBuy(0n, { purchasePricePerWholeToken: "1", rwaDecimals: 18 }),
    ).resolves.toBe(0n);
  });

  it("readPreviewBuy rejects when no priceHint is given — there is no on-chain preview instruction to fall back to", async () => {
    await expect(readPreviewBuy(1n)).rejects.toThrow(/Missing price context/);
  });
});
