import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Security } from "./Security";
import { api } from "../../lib/client";
import {
  readMintDecimals,
  readPendingAdminTargets,
  sendAcceptAdminTransfer,
  sendBeginAdminTransfer,
  sendRoleChange,
  sendSetPaused,
  sendSetStrategyPrice,
} from "../../lib/wallet";
import { ROLES } from "../../lib/roles";
import { installFakeWallet, renderWithWallet } from "../../test/walletHarness";

// The live prices are quote-token MINIMAL units and must render as HUMAN whole
// units scaled by the QUOTE token's decimals (6 here). "2000000" -> "2".
vi.mock("../../lib/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/client")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      getProject: vi.fn(),
      getConfig: vi.fn().mockResolvedValue({ projectId: "proj-1" }),
    },
  };
});

// readMintDecimals is stubbed; the admin write helpers are spied so the
// role-gated action tests can assert the exact broadcast without a chain.
vi.mock("../../lib/wallet", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/wallet")>();
  return {
    ...actual,
    readMintDecimals: vi.fn().mockResolvedValue(6),
    sendSetPaused: vi.fn().mockResolvedValue("sig"),
    sendSetStrategyPrice: vi.fn().mockResolvedValue("sig"),
    sendRoleChange: vi.fn().mockResolvedValue("sig"),
    sendBeginAdminTransfer: vi.fn().mockResolvedValue("sig"),
    sendAcceptAdminTransfer: vi.fn().mockResolvedValue("sig"),
    // Default: this wallet is the pending admin nowhere, so the accept card is
    // hidden. Tests that need it opt in explicitly — which keeps every OTHER
    // Security test honest about the card not being universally present.
    readPendingAdminTargets: vi.fn().mockResolvedValue([]),
    waitForTxReceipt: vi.fn().mockResolvedValue(undefined),
  };
});

const QUOTE_TOKEN = "Quot1111111111111111111111111111111111111";
/** A wallet that is NOT the connected one — the pending admin someone else is. */
const OTHER_WALLET = "OtherAdmin111111111111111111111111111111111";

const BASE = {
  addresses: { quoteToken: QUOTE_TOKEN },
  purchasePricePerWholeToken: "2000000",
  redemptionPricePerWholeToken: "5500000",
};

/** The <dd> value of the row whose <dt> matches `label`. */
function priceValue(label: RegExp): string {
  const dt = screen.getByText(label);
  const dd = dt.parentElement?.querySelector("dd");
  return dd?.textContent ?? "";
}

describe("Security current prices", () => {
  beforeEach(() => {
    vi.mocked(readMintDecimals).mockClear().mockResolvedValue(6);
  });

  it("renders prices in human units using Project.quoteDecimals (no on-chain read)", async () => {
    vi.mocked(api.getProject)
      .mockReset()
      .mockResolvedValue({ ...BASE, quoteDecimals: 6 });

    renderWithWallet(<Security />);
    await waitFor(() =>
      expect(screen.getByText(/current purchase price/i)).toBeTruthy(),
    );

    // 2000000 / 5500000 minimal at 6 decimals -> "2" / "5.5" whole units.
    await waitFor(() =>
      expect(priceValue(/current purchase price/i)).toBe("2"),
    );
    expect(priceValue(/current redemption price/i)).toBe("5.5");
    // Server supplied quoteDecimals, so no on-chain round trip.
    expect(readMintDecimals).not.toHaveBeenCalled();
  });

  it("falls back to the on-chain quote decimals when quoteDecimals is absent", async () => {
    vi.mocked(api.getProject).mockReset().mockResolvedValue(BASE);

    renderWithWallet(<Security />);
    await waitFor(() =>
      expect(priceValue(/current purchase price/i)).toBe("2"),
    );
    expect(readMintDecimals).toHaveBeenCalledWith(QUOTE_TOKEN);
  });

  it("shows a hint when no on-chain prices are reported", async () => {
    vi.mocked(api.getProject).mockReset().mockResolvedValue({ quoteDecimals: 6 });

    renderWithWallet(<Security />);
    const card = await screen.findByRole("heading", {
      name: "Current prices",
    });
    await waitFor(() =>
      expect(
        within(card.parentElement as HTMLElement).getByText(
          /no on-chain prices reported/i,
        ),
      ).toBeTruthy(),
    );
  });
});

const ADMIN = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"; // fake wallet's account
const PROGRAM_IDS = {
  token: "Token111111111111111111111111111111111111",
  compliance: "Comp1111111111111111111111111111111111111",
  supplyController: "Supp1111111111111111111111111111111111111",
  vault: "Vau11111111111111111111111111111111111111",
  redemptionEscrow: "Rede1111111111111111111111111111111111111",
  strategy: "Pric1111111111111111111111111111111111111",
  quoteToken: "Quot1111111111111111111111111111111111111",
};
const DEPLOYED = {
  paused: false,
  quoteDecimals: 6,
  addresses: { ...PROGRAM_IDS },
};

describe("Security admin actions (role-gated, connected wallet broadcasts)", () => {
  let wallet: ReturnType<typeof installFakeWallet>;

  beforeEach(() => {
    wallet = installFakeWallet({ account: ADMIN });
    vi.mocked(sendSetPaused).mockClear().mockResolvedValue("sig");
    vi.mocked(sendSetStrategyPrice).mockClear().mockResolvedValue("sig");
    vi.mocked(sendRoleChange).mockClear().mockResolvedValue("sig");
    vi.mocked(sendBeginAdminTransfer).mockClear().mockResolvedValue("sig");
    vi.mocked(sendAcceptAdminTransfer).mockClear().mockResolvedValue("sig");
  });

  afterEach(() => {
    wallet.uninstall();
  });

  it("hides an action behind a notice when the connected wallet lacks the role", async () => {
    // Connected wallet holds no roles → the pause action is gated out.
    vi.mocked(api.getProject).mockReset().mockResolvedValue({
      ...DEPLOYED,
      roles: {},
    });
    renderWithWallet(<Security />, { connected: true });

    const heading = await screen.findByRole("heading", {
      name: "Pause / unpause trading",
    });
    const section = heading.closest("section") as HTMLElement;
    // The gate renders a notice naming the required role instead of the button.
    expect(within(section).getByText("PAUSER_ROLE")).toBeInTheDocument();
    expect(
      within(section).queryByRole("button", { name: "Pause trading" }),
    ).toBeNull();
  });

  it("broadcasts compliance pause() when the wallet holds PAUSER_ROLE", async () => {
    vi.mocked(api.getProject)
      .mockReset()
      .mockResolvedValue({ ...DEPLOYED, roles: { PAUSER_ROLE: [ADMIN] } });
    renderWithWallet(<Security />, { connected: true });

    const pauseBtn = await screen.findByRole("button", {
      name: "Pause trading",
    });
    fireEvent.click(pauseBtn);

    await waitFor(() =>
      expect(sendSetPaused).toHaveBeenCalledWith(
        ADMIN,
        DEPLOYED.addresses.compliance,
        true,
      ),
    );
  });

  it("scales and broadcasts a purchase price to the strategy when the wallet holds PRICER_ROLE", async () => {
    vi.mocked(api.getProject)
      .mockReset()
      .mockResolvedValue({ ...DEPLOYED, roles: { PRICER_ROLE: [ADMIN] } });
    renderWithWallet(<Security />, { connected: true });

    const input = await screen.findByLabelText(
      /Purchase price \(whole quote-token units\)/,
    );
    fireEvent.change(input, { target: { value: "3" } });
    fireEvent.click(screen.getByRole("button", { name: "Set purchase price" }));

    await waitFor(() =>
      // 3 whole quote-token units at 6 decimals -> 3000000n.
      expect(sendSetStrategyPrice).toHaveBeenCalledWith(
        ADMIN,
        DEPLOYED.addresses.strategy,
        "purchase",
        3000000n,
      ),
    );
  });

  it("replaces a role's holder on its target program when the wallet holds DEFAULT_ADMIN_ROLE", async () => {
    vi.mocked(api.getProject)
      .mockReset()
      .mockResolvedValue({
        ...DEPLOYED,
        roles: { DEFAULT_ADMIN_ROLE: [ADMIN] },
      });
    renderWithWallet(<Security />, { connected: true });

    const account = await screen.findByLabelText("Account address");
    const newHolder = "NewHolder1111111111111111111111111111111111";
    fireEvent.change(account, { target: { value: newHolder } });
    // Default role selection is PAUSER_ROLE, held only on the compliance program.
    fireEvent.click(screen.getByRole("button", { name: "Replace role holder" }));

    await waitFor(() =>
      expect(sendRoleChange).toHaveBeenCalledWith(
        ADMIN,
        DEPLOYED.addresses.compliance,
        ROLES.pauser,
        newHolder,
      ),
    );
  });

  it('relabels the operation "Replace role holder" and never shows a Revoke button', async () => {
    vi.mocked(api.getProject)
      .mockReset()
      .mockResolvedValue({
        ...DEPLOYED,
        roles: { DEFAULT_ADMIN_ROLE: [ADMIN] },
      });
    renderWithWallet(<Security />, { connected: true });
    const heading = await screen.findByRole("heading", {
      name: "Replace role holder",
    });
    const section = heading.closest("section") as HTMLElement;

    expect(
      within(section).getByRole("button", { name: "Replace role holder" }),
    ).toBeInTheDocument();
    expect(
      within(section).queryByRole("button", { name: "Revoke role" }),
    ).toBeNull();
    expect(within(section).getByText(/single-holder/i)).toBeTruthy();
  });
});

// The five governance programs with a two-step admin, each with its own
// independent admin — adminContractTargets() resolves them from
// DEPLOYED.addresses in this order (see roles.ts's ADMIN_CONTRACTS). The RWA
// mint has no on-chain admin instruction, so it never gets a form.
const GOVERNANCE_PROGRAMS: { name: string; address: string }[] = [
  { name: "Compliance Registry", address: DEPLOYED.addresses.compliance },
  { name: "Supply Controller", address: DEPLOYED.addresses.supplyController },
  { name: "Vault", address: DEPLOYED.addresses.vault },
  { name: "Redemption Escrow", address: DEPLOYED.addresses.redemptionEscrow },
  { name: "Fixed-Price Strategy", address: DEPLOYED.addresses.strategy },
];

/**
 * The admin-transfer-list__item box for the named program WITHIN `container`
 * (every program now gets its own form, and the Begin-transfer
 * and Accept-transfer lists both render a heading per program, so a
 * page-wide lookup would find two "Vault" headings at once — this scopes the
 * search to whichever section's list is under test).
 */
function contractBox(container: HTMLElement, name: string): HTMLElement {
  const heading = within(container).getByRole("heading", { name, level: 4 });
  return heading.closest(".admin-transfer-list__item") as HTMLElement;
}

describe("Security transfer admin (role-gated, one form per program)", () => {
  let wallet: ReturnType<typeof installFakeWallet>;

  beforeEach(() => {
    wallet = installFakeWallet({ account: ADMIN });
    vi.mocked(sendBeginAdminTransfer).mockClear().mockResolvedValue("sig");
    vi.mocked(api.getProject)
      .mockReset()
      .mockResolvedValue({
        ...DEPLOYED,
        roles: { DEFAULT_ADMIN_ROLE: [ADMIN] },
      });
  });

  afterEach(() => {
    wallet.uninstall();
  });

  it("does not render a form for the RWA Token — it has no on-chain admin instruction", async () => {
    renderWithWallet(<Security />, { connected: true });

    await screen.findByRole("heading", { name: "Transfer admin" });
    expect(
      screen.queryByRole("heading", { name: "RWA Token", level: 4 }),
    ).toBeNull();
  });

  it("renders one Begin admin transfer form per governance program, each labeled with its name and address", async () => {
    renderWithWallet(<Security />, { connected: true });
    const transferHeading = await screen.findByRole("heading", { name: "Transfer admin" });
    const section = transferHeading.closest("section") as HTMLElement;

    for (const { name, address } of GOVERNANCE_PROGRAMS) {
      const box = contractBox(section, name);
      expect(within(box).getByTitle(address)).toBeTruthy();
      expect(
        within(box).getByRole("button", { name: "Begin admin transfer" }),
      ).toBeInTheDocument();
    }
  });

  it("broadcasts a begin-transfer only for the program whose form was submitted, passing its program key", async () => {
    renderWithWallet(<Security />, { connected: true });
    const transferHeading = await screen.findByRole("heading", { name: "Transfer admin" });
    const section = transferHeading.closest("section") as HTMLElement;

    const box = contractBox(section, "Vault");
    const newAdmin = "NewAdmin11111111111111111111111111111111";
    fireEvent.change(within(box).getByLabelText("New admin address"), {
      target: { value: newAdmin },
    });
    fireEvent.click(within(box).getByRole("button", { name: "Begin admin transfer" }));

    await waitFor(() =>
      expect(sendBeginAdminTransfer).toHaveBeenCalledWith(
        ADMIN,
        DEPLOYED.addresses.vault,
        newAdmin,
        "vault",
      ),
    );
    // Only the Vault form submitted — no other program's transfer begun.
    expect(sendBeginAdminTransfer).toHaveBeenCalledTimes(1);
  });
});

describe("Security accept admin transfer (incoming admin, not role-gated)", () => {
  let wallet: ReturnType<typeof installFakeWallet>;

  beforeEach(() => {
    wallet = installFakeWallet({ account: ADMIN });
    vi.mocked(sendAcceptAdminTransfer).mockClear().mockResolvedValue("sig");
    // Call counts accumulate across tests otherwise — the refresh-after-accept
    // assertion below counts calls, so this must be reset per test too.
    vi.mocked(readPendingAdminTargets).mockClear().mockResolvedValue([]);
  });

  afterEach(() => {
    wallet.uninstall();
  });

  it("is hidden entirely when the connected wallet is not a pending admin anywhere", async () => {
    // The whole point of the gate: for the outgoing admin, or any other
    // wallet, every button in this card could only ever revert on-chain.
    vi.mocked(readPendingAdminTargets).mockResolvedValue([]);
    vi.mocked(api.getProject)
      .mockReset()
      .mockResolvedValue({ ...DEPLOYED, roles: {}, pendingAdmin: OTHER_WALLET });
    renderWithWallet(<Security />, { connected: true });

    // Wait for the page to settle on something else before asserting absence,
    // so this cannot pass merely because the render hadn't happened yet.
    await screen.findByRole("heading", { name: "Manage roles & admin" });
    expect(
      screen.queryByRole("heading", { name: "Accept admin transfer" }),
    ).toBeNull();
  });

  it("stays hidden even when a transfer IS pending, if it is pending to someone else", async () => {
    // Project.pendingAdmin being populated is NOT sufficient — it is a single
    // aggregate hint that says nothing about which wallet is the target.
    vi.mocked(readPendingAdminTargets).mockResolvedValue([]);
    vi.mocked(api.getProject)
      .mockReset()
      .mockResolvedValue({ ...DEPLOYED, roles: {}, pendingAdmin: OTHER_WALLET });
    renderWithWallet(<Security />, { connected: true });

    await screen.findByRole("heading", { name: "Manage roles & admin" });
    expect(
      screen.queryByRole("heading", { name: "Accept admin transfer" }),
    ).toBeNull();
  });

  it("shows only the programs where the connected wallet is the pending admin", async () => {
    // Pending on two of the five: the card appears, and lists exactly those.
    vi.mocked(readPendingAdminTargets).mockResolvedValue([
      { programKey: "redemption", address: DEPLOYED.addresses.redemptionEscrow },
      { programKey: "vault", address: DEPLOYED.addresses.vault },
    ]);
    vi.mocked(api.getProject)
      .mockReset()
      .mockResolvedValue({ ...DEPLOYED, roles: {} });
    renderWithWallet(<Security />, { connected: true });

    const acceptHeading = await screen.findByRole("heading", {
      name: "Accept admin transfer",
    });
    const section = acceptHeading.closest("section") as HTMLElement;

    expect(
      within(section).getAllByRole("button", { name: "Accept admin transfer" }),
    ).toHaveLength(2);
    for (const name of ["Redemption Escrow", "Vault"]) {
      const box = contractBox(section, name);
      expect(
        within(box).getByRole("button", { name: "Accept admin transfer" }),
      ).toBeInTheDocument();
    }
    // The three the wallet is NOT pending on must not be offered.
    for (const name of [
      "Compliance Registry",
      "Supply Controller",
      "Fixed-Price Strategy",
    ]) {
      expect(within(section).queryByText(name)).toBeNull();
    }
  });

  it("accepts only on the program whose control was clicked, passing its program key", async () => {
    vi.mocked(readPendingAdminTargets).mockResolvedValue([
      { programKey: "redemption", address: DEPLOYED.addresses.redemptionEscrow },
      { programKey: "vault", address: DEPLOYED.addresses.vault },
    ]);
    vi.mocked(api.getProject)
      .mockReset()
      .mockResolvedValue({ ...DEPLOYED, roles: {}, pendingAdmin: ADMIN });
    renderWithWallet(<Security />, { connected: true });
    const acceptHeading = await screen.findByRole("heading", {
      name: "Accept admin transfer",
    });
    const section = acceptHeading.closest("section") as HTMLElement;

    const box = contractBox(section, "Redemption Escrow");
    fireEvent.click(
      within(box).getByRole("button", { name: "Accept admin transfer" }),
    );

    await waitFor(() =>
      expect(sendAcceptAdminTransfer).toHaveBeenCalledWith(
        ADMIN,
        DEPLOYED.addresses.redemptionEscrow,
        "redemption",
      ),
    );
    expect(sendAcceptAdminTransfer).toHaveBeenCalledTimes(1);
    // Accepting clears pending_admin on that program, so the card must re-read
    // rather than keep offering a button that now reverts.
    await waitFor(() =>
      expect(readPendingAdminTargets).toHaveBeenCalledTimes(2),
    );
  });

  it("is not rendered without a connected wallet", async () => {
    // No wallet → nobody to be the pending admin, and readPendingAdminTargets
    // is never even called.
    vi.mocked(readPendingAdminTargets).mockClear().mockResolvedValue([]);
    vi.mocked(api.getProject)
      .mockReset()
      .mockResolvedValue({ ...DEPLOYED, roles: {} });
    renderWithWallet(<Security />, { connected: false });

    await screen.findByRole("heading", { name: "Manage roles & admin" });
    expect(
      screen.queryByRole("heading", { name: "Accept admin transfer" }),
    ).toBeNull();
    expect(readPendingAdminTargets).not.toHaveBeenCalled();
  });

});

describe("Security role management — target count", () => {
  let wallet: ReturnType<typeof installFakeWallet>;

  beforeEach(() => {
    wallet = installFakeWallet({ account: ADMIN });
    vi.mocked(sendRoleChange).mockClear().mockResolvedValue("sig");
    vi.mocked(api.getProject)
      .mockReset()
      .mockResolvedValue({ ...DEPLOYED, roles: { DEFAULT_ADMIN_ROLE: [ADMIN] } });
  });

  afterEach(() => {
    wallet.uninstall();
  });

  it("shows the target count for the selected role", async () => {
    renderWithWallet(<Security />, { connected: true });
    const heading = await screen.findByRole("heading", {
      name: "Replace role holder",
    });
    const section = heading.closest("section") as HTMLElement;

    // PRICER_ROLE targets only ["strategy"] (1) — no vault set_pricer.
    const select = within(section).getByLabelText("Role") as HTMLSelectElement;
    fireEvent.change(select, { target: { value: ROLES.pricer } });

    await waitFor(() =>
      expect(within(section).getByText(/\(1 for this role\)/)).toBeTruthy(),
    );
  });
});
