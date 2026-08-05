import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { installFakeWallet, renderWithWallet } from "../../test/walletHarness";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Keypair } from "@solana/web3.js";
import { Investor } from "./Investor";
import { api } from "../../lib/client";
import {
  readPreviewBuy,
  readPreviewRedeem,
  sendBuy,
  sendCancelRedemption,
  sendClaimRedemption,
  sendRequestRedemption,
  type ChainContext,
} from "../../lib/wallet";

// The investor forms take human whole-unit amounts and must convert them to the
// token's minimal units before anything reaches a program.
// A 6-decimal token is used throughout so "1" must become "1000000".
vi.mock("../../lib/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/client")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      getProject: vi.fn(),
      getConfig: vi.fn().mockResolvedValue({ programIds: {} }),
      // The connected-wallet redemptions/history lists + claim/cancel flow.
      listRedemptions: vi.fn(),
      listTransactions: vi.fn(),
    },
  };
});

// resolveQuoteDecimals reads the quote token on-chain; stub the wallet read so
// the (display-only) quote-decimals lookup doesn't need a live RPC. The two
// price previews are on-chain reads as well and are stubbed with the raw
// bigint the pricing program's Strategy account would return. The
// buy/claim/cancel senders are spied so the flows can be asserted without a
// chain.
vi.mock("../../lib/wallet", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/wallet")>();
  return {
    ...actual,
    readTokenDecimals: vi.fn().mockResolvedValue(6),
    readPreviewBuy: vi.fn().mockResolvedValue(2000000n),
    readPreviewRedeem: vi.fn().mockResolvedValue(5000000n),
    sendBuy: vi.fn().mockResolvedValue("sig-buy"),
    sendRequestRedemption: vi.fn().mockResolvedValue("sig-request"),
    sendClaimRedemption: vi.fn().mockResolvedValue("sig-claim"),
    sendCancelRedemption: vi.fn().mockResolvedValue("sig-cancel"),
  };
});

const COMPLIANCE = Keypair.generate().publicKey.toBase58();
const STRATEGY = Keypair.generate().publicKey.toBase58();
const VAULT = Keypair.generate().publicKey.toBase58();
const REDEMPTION_ESCROW = Keypair.generate().publicKey.toBase58();
const TOKEN = Keypair.generate().publicKey.toBase58();
const QUOTE_TOKEN = Keypair.generate().publicKey.toBase58();

const PROJECT = {
  decimals: 6,
  tokenUnit: "RWA",
  addresses: {
    token: TOKEN,
    quoteToken: QUOTE_TOKEN,
    vault: VAULT,
    redemptionEscrow: REDEMPTION_ESCROW,
    compliance: COMPLIANCE,
    strategy: STRATEGY,
  },
};

// Investor.tsx builds this once from the project + GET /config's
// programIds.transferHook (stubbed to undefined here since none of these
// tests reach a real pin-check).
const CTX: ChainContext = { hookProgramId: undefined };

const PROGRAM_ADDRESSES = {
  complianceProgramId: COMPLIANCE,
  pricingProgramId: STRATEGY,
  vaultProgramId: VAULT,
  redemptionProgramId: REDEMPTION_ESCROW,
  rwaMint: TOKEN,
  quoteMint: QUOTE_TOKEN,
};

// lib/chain/pins.ts hard-asserts every server-supplied program id/mint
// against this build's VITE_SOLANA_* pins before an instruction is built, and
// getPins() reads import.meta.env on every call. Vitest loads `.env.local`
// for its default "test" mode, so a contributor whose `.env.local` pins a
// real deployment would otherwise see every buy/redeem test in this file
// abort with PinMismatchError against the randomly-generated fixtures above.
// Stub the pins TO the fixtures instead of clearing them: the suite becomes
// independent of the developer's env either way, but this keeps the pin
// assertions live on the path under test rather than skipping them.
beforeEach(() => {
  vi.stubEnv("VITE_SOLANA_PROGRAM_COMPLIANCE", COMPLIANCE);
  vi.stubEnv("VITE_SOLANA_PROGRAM_PRICING", STRATEGY);
  vi.stubEnv("VITE_SOLANA_PROGRAM_VAULT", VAULT);
  vi.stubEnv("VITE_SOLANA_PROGRAM_REDEMPTION", REDEMPTION_ESCROW);
  vi.stubEnv("VITE_SOLANA_RWA_MINT", TOKEN);
  vi.stubEnv("VITE_SOLANA_QUOTE_MINT", QUOTE_TOKEN);
  // CTX.hookProgramId is undefined here, so the transfer-hook pin is never
  // asserted — left unstubbed deliberately rather than given a bogus value.
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("Investor amount conversion", () => {
  beforeEach(() => {
    vi.mocked(api.getProject).mockReset().mockResolvedValue(PROJECT);
    vi.mocked(readPreviewBuy).mockClear().mockResolvedValue(2000000n);
    vi.mocked(readPreviewRedeem).mockClear().mockResolvedValue(5000000n);
    window.localStorage.clear();
  });

  it("prices the buy token amount in minimal units for the token's decimals", async () => {
    renderWithWallet(<Investor />);
    await waitFor(() => expect(api.getProject).toHaveBeenCalled());

    fireEvent.change(screen.getByLabelText("RWA token amount (whole units)"), {
      target: { value: "1" },
    });
    fireEvent.click(
      screen.getAllByRole("button", { name: "Preview quote" })[0],
    );

    // "1" whole unit at 6 decimals -> 1000000n minimal units, priced by the
    // project's own pricing program.
    await waitFor(() =>
      expect(readPreviewBuy).toHaveBeenCalledWith(1000000n, PROGRAM_ADDRESSES),
    );
  });

  it("prices the redemption amount in minimal units, including fractions", async () => {
    renderWithWallet(<Investor />);
    await waitFor(() => expect(api.getProject).toHaveBeenCalled());

    fireEvent.change(
      screen.getByLabelText("RWA amount to redeem (whole units)"),
      { target: { value: "2.5" } },
    );
    fireEvent.click(
      screen.getAllByRole("button", { name: "Preview quote" })[1],
    );

    await waitFor(() =>
      expect(readPreviewRedeem).toHaveBeenCalledWith(
        2500000n,
        PROGRAM_ADDRESSES,
      ),
    );
  });

  it("rejects an over-precise amount with a friendly error and sends nothing", async () => {
    renderWithWallet(<Investor />);
    await waitFor(() => expect(api.getProject).toHaveBeenCalled());

    fireEvent.change(screen.getByLabelText("RWA token amount (whole units)"), {
      target: { value: "1.2345678" },
    });
    fireEvent.click(
      screen.getAllByRole("button", { name: "Preview quote" })[0],
    );

    // Target the amount error specifically rather than "the only alert": the
    // page also renders the unrelated partial-pins warning banner
    // (VITE_SOLANA_* are not fully set under test), so role=alert is no longer
    // unique here.
    await waitFor(() =>
      expect(screen.getByText(/is not a valid amount/)).toHaveTextContent(
        '"1.2345678"',
      ),
    );
    expect(readPreviewBuy).not.toHaveBeenCalled();
  });
});

const CONNECTED_KEYPAIR = Keypair.generate();
const CONNECTED = CONNECTED_KEYPAIR.publicKey.toBase58();

function makeRedemption(over: Record<string, unknown>) {
  const now = Math.floor(Date.now() / 1000);
  return {
    beneficiary: CONNECTED,
    rwaAmount: "1000000",
    quoteAmount: "2000000",
    createdAt: now,
    timeoutAt: now + 3600,
    beneficiaryAllowed: true,
    confirmations: 3,
    claimable: false,
    ...over,
  };
}

/** The <tr> containing a redemption row's id cell. */
function rowById(id: string): HTMLElement {
  return screen.getByText(id).closest("tr") as HTMLElement;
}

describe("Investor redemptions list (connected wallet)", () => {
  let wallet: ReturnType<typeof installFakeWallet>;

  beforeEach(() => {
    wallet = installFakeWallet({ account: CONNECTED });
    vi.mocked(api.getProject).mockReset().mockResolvedValue(PROJECT);
    vi.mocked(api.listTransactions)
      .mockReset()
      .mockResolvedValue({ items: [] });
    vi.mocked(sendClaimRedemption).mockClear().mockResolvedValue("sig-claim");
    vi.mocked(sendCancelRedemption).mockClear().mockResolvedValue("sig-cancel");
  });

  afterEach(() => {
    wallet.uninstall();
  });

  it("shows Claim on a claimable request and Cancel on a timed-out Pending one, not vice-versa", async () => {
    const now = Math.floor(Date.now() / 1000);
    vi.mocked(api.listRedemptions)
      .mockReset()
      .mockResolvedValue({
        items: [
          makeRedemption({ id: "10", status: "Funded", claimable: true }),
          makeRedemption({
            id: "11",
            status: "Pending",
            timeoutAt: now - 3600,
          }),
        ],
      });

    renderWithWallet(<Investor />, { connected: true });

    // The list is address-filtered to the connected wallet.
    await waitFor(() =>
      expect(api.listRedemptions).toHaveBeenCalledWith(
        expect.objectContaining({ address: CONNECTED }),
      ),
    );
    await screen.findByText("10");

    const claimable = rowById("10");
    expect(
      within(claimable).getByRole("button", { name: "Claim (permissionless)" }),
    ).toBeInTheDocument();
    expect(
      within(claimable).queryByRole("button", {
        name: "Cancel (timeout elapsed)",
      }),
    ).toBeNull();

    const timedOut = rowById("11");
    expect(
      within(timedOut).getByRole("button", {
        name: "Cancel (timeout elapsed)",
      }),
    ).toBeInTheDocument();
    expect(
      within(timedOut).queryByRole("button", {
        name: "Claim (permissionless)",
      }),
    ).toBeNull();
  });

  it("offers no Claim/Cancel on a Funded-but-not-yet-claimable request", async () => {
    vi.mocked(api.listRedemptions)
      .mockReset()
      .mockResolvedValue({
        items: [
          makeRedemption({ id: "12", status: "Funded", claimable: false }),
        ],
      });

    renderWithWallet(<Investor />, { connected: true });
    await screen.findByText("12");

    const row = rowById("12");
    expect(
      within(row).queryByRole("button", { name: "Claim (permissionless)" }),
    ).toBeNull();
    expect(
      within(row).queryByRole("button", { name: "Cancel (timeout elapsed)" }),
    ).toBeNull();
  });

  it("claims a claimable request by encoding claimRedemption(id) for the escrow", async () => {
    vi.mocked(api.listRedemptions)
      .mockReset()
      .mockResolvedValue({
        items: [
          makeRedemption({ id: "10", status: "Funded", claimable: true }),
        ],
      });

    renderWithWallet(<Investor />, { connected: true });
    await screen.findByText("10");

    fireEvent.click(
      within(rowById("10")).getByRole("button", {
        name: "Claim (permissionless)",
      }),
    );

    await waitFor(() =>
      expect(sendClaimRedemption).toHaveBeenCalledWith(
        CTX,
        CONNECTED,
        PROJECT.addresses.redemptionEscrow,
        10n,
        PROGRAM_ADDRESSES,
      ),
    );
    await screen.findByText(/Claim submitted:/);
  });

  it("cancels a timed-out Pending request by encoding cancelRedemption(id) for the escrow", async () => {
    const now = Math.floor(Date.now() / 1000);
    vi.mocked(api.listRedemptions)
      .mockReset()
      .mockResolvedValue({
        items: [
          makeRedemption({
            id: "11",
            status: "Pending",
            timeoutAt: now - 3600,
          }),
        ],
      });

    renderWithWallet(<Investor />, { connected: true });
    await screen.findByText("11");

    fireEvent.click(
      within(rowById("11")).getByRole("button", {
        name: "Cancel (timeout elapsed)",
      }),
    );

    await waitFor(() =>
      expect(sendCancelRedemption).toHaveBeenCalledWith(
        CTX,
        CONNECTED,
        PROJECT.addresses.redemptionEscrow,
        11n,
        PROGRAM_ADDRESSES,
      ),
    );
    await screen.findByText(/Cancel submitted:/);
  });
});

// Buy and redemption-request are encoded in the browser and broadcast from the
// connected wallet: the target is the project's own vault/redemption program,
// and the on-chain arguments must carry the amounts, the slippage bound, the
// connected recipient and a future deadline the page derived itself.
describe("Investor buy and redemption request (client-encoded)", () => {
  let wallet: ReturnType<typeof installFakeWallet>;

  beforeEach(() => {
    wallet = installFakeWallet({ account: CONNECTED });
    vi.mocked(api.getProject).mockReset().mockResolvedValue(PROJECT);
    vi.mocked(readPreviewBuy).mockClear().mockResolvedValue(2000000n);
    vi.mocked(readPreviewRedeem).mockClear().mockResolvedValue(5000000n);
    vi.mocked(api.listRedemptions).mockReset().mockResolvedValue({ items: [] });
    vi.mocked(api.listTransactions)
      .mockReset()
      .mockResolvedValue({ items: [] });
    vi.mocked(sendBuy).mockClear().mockResolvedValue("sig-buy");
    vi.mocked(sendRequestRedemption)
      .mockClear()
      .mockResolvedValue("sig-request");
  });

  afterEach(() => {
    wallet.uninstall();
  });

  it("buys with the quoted amount, the slippage-ceiled max spend and the connected recipient", async () => {
    renderWithWallet(<Investor />, { connected: true });
    await waitFor(() => expect(api.getProject).toHaveBeenCalled());

    fireEvent.change(screen.getByLabelText("RWA token amount (whole units)"), {
      target: { value: "1" },
    });
    fireEvent.click(
      screen.getAllByRole("button", { name: "Preview quote" })[0],
    );

    const buy = await screen.findByRole("button", { name: "Buy" });
    await waitFor(() => expect(buy).toBeEnabled());
    fireEvent.click(buy);

    await waitFor(() => expect(sendBuy).toHaveBeenCalled());
    const [ctx, from, to, args] = vi.mocked(sendBuy).mock.calls[0];
    expect([ctx, from, to]).toEqual([CTX, CONNECTED, PROJECT.addresses.vault]);
    expect(args).toMatchObject({
      tokenAmount: 1000000n,
      // 2000000 quote + the default 50 bps.
      maxQuoteAmount: 2010000n,
      recipient: CONNECTED,
      programAddresses: PROGRAM_ADDRESSES,
    });
    expect(args.deadline).toBeGreaterThan(
      BigInt(Math.floor(Date.now() / 1000)),
    );

    await screen.findByText(/Buy submitted:/);
  });

  it("requests a redemption with the minimal-unit amount and the slippage-floored min quote out", async () => {
    renderWithWallet(<Investor />, { connected: true });
    await waitFor(() => expect(api.getProject).toHaveBeenCalled());

    fireEvent.change(
      screen.getByLabelText("RWA amount to redeem (whole units)"),
      { target: { value: "2.5" } },
    );
    fireEvent.click(
      screen.getAllByRole("button", { name: "Preview quote" })[1],
    );

    const request = await screen.findByRole("button", {
      name: "Request redemption",
    });
    await waitFor(() => expect(request).toBeEnabled());
    fireEvent.click(request);

    await waitFor(() => expect(sendRequestRedemption).toHaveBeenCalled());
    const [ctx, from, to, args] = vi.mocked(sendRequestRedemption).mock
      .calls[0];
    expect([ctx, from, to]).toEqual([
      CTX,
      CONNECTED,
      PROJECT.addresses.redemptionEscrow,
    ]);
    expect(args).toMatchObject({
      rwaAmount: 2500000n,
      // 5000000 quote less the default 50 bps.
      minQuoteOut: 4975000n,
      programAddresses: PROGRAM_ADDRESSES,
    });
    expect(args.deadline).toBeGreaterThan(
      BigInt(Math.floor(Date.now() / 1000)),
    );

    await screen.findByText(/Request submitted:/);
  });
});

describe("Investor pause gating", () => {
  let wallet: ReturnType<typeof installFakeWallet>;

  beforeEach(() => {
    wallet = installFakeWallet({ account: CONNECTED });
    vi.mocked(api.getProject)
      .mockReset()
      .mockResolvedValue({ ...PROJECT, paused: true });
    vi.mocked(api.listTransactions)
      .mockReset()
      .mockResolvedValue({ items: [] });
    vi.mocked(sendClaimRedemption).mockClear().mockResolvedValue("sig-claim");
    vi.mocked(sendCancelRedemption).mockClear().mockResolvedValue("sig-cancel");
  });

  afterEach(() => {
    wallet.uninstall();
  });

  // claim_redemption keeps its !paused guard; cancel_redemption deliberately
  // has none, because it is the beneficiary's escape hatch for recovering
  // escrowed tokens and rides the transfer hook's escrow-only pause bypass.
  // Disabling cancel during a pause would strand exactly the investor the
  // escape hatch exists for, so this asymmetry is asserted on the rendered
  // buttons, not only on the predicate.
  it("disables Claim but leaves Cancel usable while the project is paused", async () => {
    const now = Math.floor(Date.now() / 1000);
    vi.mocked(api.listRedemptions)
      .mockReset()
      .mockResolvedValue({
        items: [
          makeRedemption({ id: "20", status: "Funded", claimable: true }),
          makeRedemption({
            id: "21",
            status: "Pending",
            timeoutAt: now - 3600,
          }),
        ],
      });

    renderWithWallet(<Investor />, { connected: true });
    await screen.findByText("20");

    expect(
      within(rowById("20")).getByRole("button", {
        name: "Claim (permissionless)",
      }),
    ).toBeDisabled();
    expect(
      within(rowById("21")).getByRole("button", {
        name: "Cancel (timeout elapsed)",
      }),
    ).toBeEnabled();
  });

  it("refuses to broadcast a claim while paused even if the click lands", async () => {
    // Belt and braces: `disabled` is a UI affordance, so the handler carries
    // its own guard. fireEvent bypasses the disabled attribute in jsdom for a
    // programmatic click, which is exactly the case this covers.
    vi.mocked(api.listRedemptions)
      .mockReset()
      .mockResolvedValue({
        items: [
          makeRedemption({ id: "22", status: "Funded", claimable: true }),
        ],
      });

    renderWithWallet(<Investor />, { connected: true });
    await screen.findByText("22");

    fireEvent.click(
      within(rowById("22")).getByRole("button", {
        name: "Claim (permissionless)",
      }),
    );
    await new Promise((r) => setTimeout(r, 0));
    expect(sendClaimRedemption).not.toHaveBeenCalled();
  });

  it("disables Buy while the project is paused", async () => {
    vi.mocked(api.listRedemptions).mockReset().mockResolvedValue({ items: [] });
    vi.mocked(readPreviewBuy).mockClear().mockResolvedValue(2000000n);

    renderWithWallet(<Investor />, { connected: true });
    await waitFor(() => expect(api.getProject).toHaveBeenCalled());

    fireEvent.change(screen.getByLabelText("RWA token amount (whole units)"), {
      target: { value: "1" },
    });
    fireEvent.click(
      screen.getAllByRole("button", { name: "Preview quote" })[0],
    );

    const buy = await screen.findByRole("button", { name: "Buy" });
    expect(buy).toBeDisabled();
  });
});
