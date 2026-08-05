import { expect, mockOnly, test } from "../fixtures/fixtures";
import { ADDRESSES } from "../fixtures/mock-api";
import { MOCK_WALLET_ADDRESS } from "../fixtures/mock-wallet";
import { InvestorPage } from "../pages/InvestorPage";

test.describe("Investor — wallet, balance, and buy", () => {
  mockOnly();

  test("connects a wallet and verifies ownership", async ({ page }) => {
    const investor = new InvestorPage(page);
    await investor.goto();

    await investor.connectWallet();
    await expect(investor.walletSection).toContainText(
      `${MOCK_WALLET_ADDRESS.slice(0, 6)}…${MOCK_WALLET_ADDRESS.slice(-4)}`,
    );

    await investor.verifyOwnership();
    await expect(page.getByText(/Ownership verified: Yes/)).toBeVisible();
  });

  test("reads the RWA token balance once a wallet is connected", async ({ page }) => {
    const investor = new InvestorPage(page);
    await investor.goto();
    await investor.connectWallet();

    await investor.readBalance();
    await expect(investor.balanceSection).toContainText("1.5 gram");
  });

  test("previews a purchase and buys — no approval step needed", async ({ page, wallet }) => {
    const investor = new InvestorPage(page);
    await investor.goto();
    await investor.connectWallet();

    // "1" whole RWA token at the mint's 9 decimals -> 1_000_000_000 minimal units.
    await investor.previewBuy("1");
    await expect(page.getByRole("region", { name: "Purchase preview" })).toBeVisible();

    // There is no approve step to click first — Buy is enabled the instant
    // there's a quote.
    const buyButton = investor.buySection.getByRole("button", { name: "Buy", exact: true });
    await expect(buyButton).toBeEnabled();

    await investor.submitBuy();
    await expect(page.getByText(/Buy submitted:/)).toBeVisible();

    // The buy is encoded in the browser (the pinned Anchor IDL) and targets
    // this project's vault program — nothing here comes from the server.
    const buy = wallet
      .getSentTransactions()
      .flat()
      .find((ix) => ix.programId === ADDRESSES.vault && ix.name === "buy");
    expect(buy).toBeTruthy();
    // 1e9 minimal units at price 1_000_000 -> 1_000_000 quote, ceiled by the
    // default 50 bps slippage tolerance to 1_005_000.
    expect(buy?.data).toMatchObject({
      token_amount: "1000000000",
      max_quote_amount: "1005000",
    });
    expect(buy?.accounts).toContain(MOCK_WALLET_ADDRESS);
  });
});
