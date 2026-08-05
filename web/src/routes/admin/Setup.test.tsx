import { act, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Setup } from "./Setup";
import { api, ApiError } from "../../lib/client";
import { installFakeWallet, renderWithWallet } from "../../test/walletHarness";

// Deployment is an operator CLI/bootstrap step, not something this console
// broadcasts — Setup only edits the Asset Profile and reports deploy status
// polled from GET /project.
vi.mock("../../lib/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/client")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      getProject: vi.fn(),
      getProfile: vi.fn(),
      getConfig: vi.fn(),
      validateProfile: vi.fn(),
      createProfile: vi.fn(),
    },
  };
});

describe("Setup load-existing-profile on mount", () => {
  let wallet: ReturnType<typeof installFakeWallet>;

  afterEach(() => {
    wallet?.uninstall();
  });

  it("prefills a persisted profile and shows the deploy runbook hint without re-creating", async () => {
    vi.mocked(api.getProject).mockReset().mockRejectedValue(new Error("404"));
    vi.mocked(api.getProfile).mockReset().mockResolvedValue({
      // The raw profile is an untyped object in the OpenAPI schema
      // (Record<string, never> once generated), so cast the concrete document.
      profile: {
        profileVersion: "1.0",
        projectId: "proj-1",
        assetType: "gold",
        tokenUnit: "OZ",
        tokenDecimals: 6,
      } as unknown as Record<string, never>,
      projectId: "proj-1",
      profileDigest: "0xstoreddigest",
      cid: "cid-stored",
      decimals: 6,
      tokenUnit: "OZ",
    });
    vi.mocked(api.createProfile).mockReset();
    vi.mocked(api.getConfig)
      .mockReset()
      .mockResolvedValue({ projectId: "proj-1" });
    wallet = installFakeWallet();

    renderWithWallet(<Setup />, { connected: true });

    // The persisted profile view (not the empty create form) is shown, and the
    // raw JSON is visible read-only.
    await screen.findByText(
      /Persisted — immutable for the life of this deployment/i,
    );
    const storedJson = screen.getByLabelText(
      "Stored Asset Profile JSON",
    ) as HTMLTextAreaElement;
    expect(storedJson.value).toContain("proj-1");
    expect(storedJson).toHaveAttribute("readonly");
    expect(api.createProfile).not.toHaveBeenCalled();

    // The deploy runbook hint is shown (not-yet-deployed) — there is no deploy
    // form on this console.
    await screen.findByText(/operator CLI step/i);
  });

  it("shows the empty create form when no profile is stored yet (404)", async () => {
    vi.mocked(api.getProject).mockReset().mockRejectedValue(new Error("404"));
    vi.mocked(api.getProfile)
      .mockReset()
      .mockRejectedValue(
        new ApiError(404, { code: "not_found", message: "no profile" }),
      );
    vi.mocked(api.getConfig)
      .mockReset()
      .mockResolvedValue({ projectId: "proj-1" });
    wallet = installFakeWallet();

    renderWithWallet(<Setup />, { connected: true });

    // The create flow is shown.
    await screen.findByRole("button", { name: "Validate profile" });
    expect(
      screen.queryByText(/Persisted — immutable/i),
    ).not.toBeInTheDocument();
  });
});

/** A stored profile so the deploy status section has something to render alongside. */
function storedProfileResponse() {
  return {
    profile: {
      profileVersion: "1.0",
      projectId: "proj-1",
      tokenUnit: "OZ",
      tokenDecimals: 6,
    } as unknown as Record<string, never>,
    projectId: "proj-1",
    profileDigest: "0xdig",
    cid: "cid",
    decimals: 6,
    tokenUnit: "OZ",
  };
}

const DEPLOY_POLL_MS = 3000; // must match Setup.tsx

describe("Setup deployment status gating", () => {
  function seed() {
    vi.mocked(api.getProject).mockReset();
    vi.mocked(api.getProfile).mockReset().mockResolvedValue(storedProfileResponse());
    vi.mocked(api.getConfig).mockReset().mockResolvedValue({ projectId: "proj-1" });
  }

  it("shows the operator-runbook hint when the project is not yet deployed (Undeployed)", async () => {
    seed();
    vi.mocked(api.getProject).mockResolvedValue({
      projectId: "proj-1",
      status: "Undeployed",
    });

    renderWithWallet(<Setup />);

    await screen.findByText(/operator CLI step/i);
    expect(screen.queryByText(/Deployment in progress/i)).toBeNull();
  });

  it("shows an in-progress indicator while Deploying/Verifying", async () => {
    seed();
    vi.mocked(api.getProject).mockResolvedValue({
      projectId: "proj-1",
      status: "Verifying",
    });

    renderWithWallet(<Setup />);

    await screen.findByText(/Deployment in progress — Verifying/i);
    expect(screen.queryByText(/operator CLI step/i)).toBeNull();
  });

  it("shows a deployed confirmation when Active", async () => {
    seed();
    vi.mocked(api.getProject).mockResolvedValue({
      projectId: "proj-1",
      status: "Active",
    });

    renderWithWallet(<Setup />);

    await screen.findByText(/Deployed —/i);
    expect(screen.queryByText(/operator CLI step/i)).toBeNull();
  });

  it("shows the failure with its note and the runbook hint when Failed", async () => {
    seed();
    vi.mocked(api.getProject).mockResolvedValue({
      projectId: "proj-1",
      status: "Failed",
      verificationNote: "bytecode mismatch",
    });

    renderWithWallet(<Setup />);

    await screen.findByText(/Deployment failed: bytecode mismatch/i);
    await screen.findByText(/operator CLI step/i);
  });

  it("polls GET /project while Deploying and flips to the deployed state on Active", async () => {
    seed();
    vi.useFakeTimers();
    try {
      vi.mocked(api.getProject)
        .mockResolvedValueOnce({
          projectId: "proj-1",
          status: "Deploying",
        })
        .mockResolvedValue({
          projectId: "proj-1",
          status: "Active",
        });

      renderWithWallet(<Setup />);

      // Flush the initial loads → Deploying (runbook hint hidden, indicator shown).
      await act(async () => {
        await vi.advanceTimersByTimeAsync(0);
      });
      expect(
        screen.getByText(/Deployment in progress — Deploying/i),
      ).toBeInTheDocument();
      expect(api.getProject).toHaveBeenCalledTimes(1);

      // One poll interval later, GET /project reports Active → UI flips.
      await act(async () => {
        await vi.advanceTimersByTimeAsync(DEPLOY_POLL_MS);
      });
      expect(api.getProject).toHaveBeenCalledTimes(2);
      expect(screen.getByText(/Deployed —/i)).toBeInTheDocument();
      expect(screen.queryByText(/Deployment in progress/i)).toBeNull();

      // Terminal state → polling stops (no further GET /project calls).
      await act(async () => {
        await vi.advanceTimersByTimeAsync(DEPLOY_POLL_MS * 3);
      });
      expect(api.getProject).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });
});
