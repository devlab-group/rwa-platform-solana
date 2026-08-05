import { screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "../lib/client";
import { useWalletContext } from "./walletContextValue";
import { renderWithWallet } from "../test/walletHarness";

// WalletProvider reads GET /api/v1/config once at mount to configure
// lib/chain.ts's program ids — mocked per test below.
vi.mock("../lib/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/client")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      getConfig: vi.fn(),
    },
  };
});

const PROGRAM_IDS = {
  compliance: "Comp11111111111111111111111111111111111111",
  vault: "Vau1111111111111111111111111111111111111111",
  pricing: "Pric1111111111111111111111111111111111111111",
  transferHook: "Hook1111111111111111111111111111111111111111",
  redemption: "Rede1111111111111111111111111111111111111111",
  supplyController: "Supp1111111111111111111111111111111111111111",
};

function Probe() {
  const { chainConfigError } = useWalletContext();
  return (
    <span data-testid="chain-config-error">{chainConfigError ?? ""}</span>
  );
}

describe("WalletProvider config resolution", () => {
  afterEach(() => {
    vi.mocked(api.getConfig).mockReset();
  });

  it("a config WITH programIds configures the chain layer with no error", async () => {
    vi.mocked(api.getConfig).mockResolvedValue({
      projectId: "proj-1",
      solanaChainId: 103,
      programIds: PROGRAM_IDS,
    });

    renderWithWallet(<Probe />);

    await waitFor(() =>
      expect(screen.getByTestId("chain-config-error").textContent).toBe(""),
    );
  });

  it("a config WITHOUT programIds surfaces chainConfigError — a misconfigured deployment is blocked rather than silently proceeding", async () => {
    vi.mocked(api.getConfig).mockResolvedValue({
      projectId: "proj-1",
      // programIds intentionally omitted — a misconfigured deployment.
    });

    renderWithWallet(<Probe />);

    await waitFor(() =>
      expect(
        screen.getByTestId("chain-config-error").textContent,
      ).not.toBe(""),
    );
  });
});
