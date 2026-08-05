import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Redemptions } from "./Redemptions";
import { api } from "../../lib/client";
import { installFakeWallet, renderWithWallet } from "../../test/walletHarness";
import type { RedemptionChainStatus } from "../../lib/status";

// Both admin transitions on a redemption — fundRedemption (treasurer) and
// rejectRedemption (redemption manager) — are guarded on-chain by
// `ensure_pending`. Once a request leaves Pending it can only move via the
// permissionless investor claim, so the console must not offer an admin an
// entry point whose every button would revert.
const CONNECTED = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";

vi.mock("../../lib/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/client")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      getProject: vi.fn(),
      listRedemptions: vi.fn(),
      getRedemption: vi.fn(),
    },
  };
});

// Quote-token decimals are read on-chain purely for display; stub it so these
// tests never touch a cluster.
vi.mock("../../lib/decimals", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/decimals")>();
  return { ...actual, resolveQuoteDecimals: vi.fn().mockResolvedValue(6) };
});

const PROJECT = {
  decimals: 6,
  finalityConfirmations: 12,
  addresses: {
    quoteToken: "Quot1111111111111111111111111111111111111",
    redemptionEscrow: "Escr1111111111111111111111111111111111111",
  },
  roles: {
    TREASURER_ROLE: [CONNECTED],
    REDEMPTION_MANAGER_ROLE: [CONNECTED],
  },
};

function redemption(id: string, status: RedemptionChainStatus) {
  return {
    id,
    beneficiary: CONNECTED,
    rwaAmount: "1000000",
    quoteAmount: "2000000",
    status,
    claimable: status === "Funded",
    createdAt: 1700000000,
    timeoutAt: 1700086400,
    beneficiaryAllowed: true,
    confirmations: 32,
  };
}

describe("Redemptions admin actions", () => {
  let wallet: ReturnType<typeof installFakeWallet>;

  beforeEach(() => {
    wallet = installFakeWallet({ account: CONNECTED });
    vi.mocked(api.getProject).mockReset().mockResolvedValue(PROJECT);
    vi.mocked(api.getRedemption).mockReset();
    vi.mocked(api.listRedemptions).mockReset();
  });

  afterEach(() => {
    wallet.uninstall();
  });

  it("offers Manage only on Pending rows", async () => {
    vi.mocked(api.listRedemptions).mockResolvedValue({
      items: [
        redemption("1", "Pending"),
        redemption("2", "Funded"),
        redemption("3", "Completed"),
        redemption("4", "Rejected"),
        redemption("5", "Cancelled"),
      ],
    });
    renderWithWallet(<Redemptions />, { connected: true });

    // All five rows render; exactly one — the Pending one — carries a Manage
    // button. A count assertion (rather than a per-row query) is what catches
    // the regression of showing it on every row.
    await waitFor(() => expect(screen.getByText("5")).toBeTruthy());
    expect(screen.getAllByRole("button", { name: "Manage" })).toHaveLength(1);
  });

  it("shows fund and reject for a Pending request", async () => {
    vi.mocked(api.listRedemptions).mockResolvedValue({
      items: [redemption("1", "Pending")],
    });
    vi.mocked(api.getRedemption).mockResolvedValue(redemption("1", "Pending"));
    renderWithWallet(<Redemptions />, { connected: true });

    fireEvent.click(await screen.findByRole("button", { name: "Manage" }));

    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Fund redemption" }),
      ).toBeTruthy(),
    );
    expect(
      screen.getByRole("button", { name: "Reject redemption" }),
    ).toBeTruthy();
  });

  it("withdraws both actions when the request leaves Pending while open", async () => {
    vi.mocked(api.listRedemptions).mockResolvedValue({
      items: [redemption("1", "Pending")],
    });
    // Opened from a Pending row, but the detail fetch comes back Funded —
    // the same race as another operator funding it, and the same state the
    // panel lands in after this admin funds it and the detail reloads.
    vi.mocked(api.getRedemption).mockResolvedValue(redemption("1", "Funded"));
    renderWithWallet(<Redemptions />, { connected: true });

    fireEvent.click(await screen.findByRole("button", { name: "Manage" }));

    await waitFor(() =>
      expect(screen.getByText(/No administrator action remains/)).toBeTruthy(),
    );
    expect(
      screen.queryByRole("button", { name: "Fund redemption" }),
    ).toBeNull();
    expect(
      screen.queryByRole("button", { name: "Reject redemption" }),
    ).toBeNull();
  });
});
