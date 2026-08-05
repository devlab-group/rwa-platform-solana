import { BorshCoder, type Idl } from "@coral-xyz/anchor";
import { expect, mockOnly, test } from "../fixtures/fixtures";
import { AdminRedemptionsPage } from "../pages/AdminRedemptionsPage";
import { ADDRESSES } from "../fixtures/mock-api";
import { getMockSentTransactions } from "../fixtures/mock-wallet";
import redemptionIdl from "../../src/lib/idl/rwa_redemption.json";

const redemptionCoder = new BorshCoder(redemptionIdl as Idl);

test.describe("Redemption — admin funding", () => {
  mockOnly();

  test("admin funds a pending redemption directly from the connected wallet (no approve step)", async ({
    page,
    api,
  }) => {
    // Numeric id: the web does BigInt(id) to build the redemption's u64 id arg.
    api.redemptions.push({
      id: "1",
      beneficiary: "7dCuDA1NoP3tsZBFiXdzyKZP8kqNw5vkxveGVQLc9QzN",
      rwaAmount: "500000000000000000",
      quoteAmount: "475000",
      status: "Pending",
      claimable: false,
      createdAt: Math.floor(Date.now() / 1000),
      timeoutAt: Math.floor(Date.now() / 1000) + 3600,
      beneficiaryAllowed: true,
      confirmations: 3,
    });

    const redemptions = new AdminRedemptionsPage(page);
    await redemptions.goto();
    await expect(redemptions.row("1")).toBeVisible();

    await redemptions.connectWallet();
    await redemptions.manage("1");
    await redemptions.fundRedemption("1");

    // Broadcast directly from the wallet: a single fund_redemption
    // instruction on the redemption escrow program — no approve leg exists on
    // this path (funding transfers directly from the treasurer's own token
    // account).
    await expect(redemptions.detailSection.getByText("Redemption funded.")).toBeVisible();
    const sent = await getMockSentTransactions(page);
    const fundTx = sent.find((t) => t.programId === ADDRESSES.redemptionEscrow);
    expect(fundTx, "a fund_redemption instruction was broadcast").toBeTruthy();
    expect(sent).toHaveLength(1); // no separate approval instruction

    const decoded = redemptionCoder.instruction.decode(Buffer.from(fundTx!.data, "base64"));
    expect(decoded?.name).toBe("fund_redemption");
  });
});
