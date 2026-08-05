import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Assets, parseSignedResult } from "./Assets";
import { buildSignerPolicy } from "../../lib/signerPolicy";
import { api, ApiError } from "../../lib/client";
import { sendMint, waitForTxReceipt } from "../../lib/wallet";
import { installFakeWallet, renderWithWallet } from "../../test/walletHarness";

// The mint is broadcast from the admin's wallet (supply_controller.mint), not
// relayed by the server. The signed-result.json supplies only the auditor
// signature (bound into the on-chain MintAttestation) + auditor address
// (cross-checked); every other attestation field comes from the record and
// project.
vi.mock("../../lib/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/client")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      listRecords: vi.fn(),
      getProject: vi.fn(),
      getProfile: vi.fn(),
      createRecord: vi.fn(),
      // Inline literal, not the BOOTSTRAP const: vi.mock factories are hoisted
      // above every top-level declaration. Tests that assert on the policy
      // block re-mock this with BOOTSTRAP explicitly.
      getConfig: vi.fn().mockResolvedValue({ projectId: "proj-1" }),
    },
  };
});

// sendMint/waitForTxReceipt are spied so the mint test can assert the exact
// broadcast (supplyController, MintAttestation, signature) without a chain.
vi.mock("../../lib/wallet", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../lib/wallet")>();
  return {
    ...actual,
    sendMint: vi.fn().mockResolvedValue("mintsig"),
    waitForTxReceipt: vi.fn().mockResolvedValue(undefined),
  };
});

const ADMIN = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"; // fake wallet account
const AUDITOR = "0x9999999999999999999999999999999999999999"; // secp256k1 auditor identity rendered as a 20-byte address — not base58
const SUPPLY_CONTROLLER = "Supp1111111111111111111111111111111111111";
const VAULT = "Vau11111111111111111111111111111111111111";

const RECORD = {
  recordId: "record-001",
  status: "Signed" as const,
  metadataDigest: `0x${"aa".repeat(32)}`,
  cid: "bafyrecord",
  amount: "1000000000000000000",
  createdAt: "2026-01-01T00:00:00Z",
  recordKey: `0x${"bb".repeat(32)}`,
  nonce: "7",
  validUntil: 4102444800,
};

const PROJECT = {
  decimals: 18,
  auditor: AUDITOR,
  profileDigest: `0x${"cc".repeat(32)}`,
  addresses: { supplyController: SUPPLY_CONTROLLER, vault: VAULT },
};

// The attestation domain inputs, which live on GET /api/v1/config rather than
// on the project. VAULT_CONFIG is deliberately a DIFFERENT value from the
// project's `addresses.vault` (the vault PROGRAM id): the policy's `vault` must
// be the vault Config PDA, and a test that reused one value for both could not
// tell the two apart — which is exactly the mix-up that produces signatures the
// on-chain program rejects.
const CLUSTER_GENESIS = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";
const SUPPLY_CONFIG = "8sN3xz2XSXo7oJ6VfBJKF4G8VZ7pJZcFmqjWpZBAeZZ5";
const VAULT_CONFIG = "3n1LDeUZm2q7NwiWWY6VkFpBEsWc3d2SNAhK6vAj9Fyc";

const BOOTSTRAP = {
  projectId: "proj-1",
  programIds: { supplyController: SUPPLY_CONTROLLER, vault: VAULT },
  clusterGenesis: CLUSTER_GENESIS,
  supplyConfig: SUPPLY_CONFIG,
  vaultConfig: VAULT_CONFIG,
};

function signedResultRecord(overrides: Record<string, unknown> = {}) {
  return {
    formatVersion: "solana-1.0",
    chain: "solana",
    auditor: AUDITOR,
    primaryType: "MintAttestation",
    cluster: "devnet",
    program: SUPPLY_CONTROLLER,
    config: "Cfg111111111111111111111111111111111111111",
    attestationDigest: `0x${"dd".repeat(32)}`,
    signature: `0x${"ab".repeat(64)}`,
    recoveryId: 0,
    signedAt: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

// jsdom's File has no .text(); the form reads the upload via file.text(), so a
// File-like object with a text() method is enough to drive handleFile.
function signedResultFile(overrides: Record<string, unknown> = {}): File {
  const content = JSON.stringify(signedResultRecord(overrides));
  return {
    name: "signed-result.json",
    text: () => Promise.resolve(content),
  } as unknown as File;
}

describe("Assets signature upload → wallet mint", () => {
  let wallet: ReturnType<typeof installFakeWallet>;

  beforeEach(() => {
    wallet = installFakeWallet({ account: ADMIN });
    vi.mocked(api.listRecords)
      .mockReset()
      .mockResolvedValue({ items: [RECORD] });
    vi.mocked(api.getProject).mockReset().mockResolvedValue(PROJECT);
    // No stored profile → empty metadata skeleton; irrelevant to the mint path.
    vi.mocked(api.getProfile)
      .mockReset()
      .mockRejectedValue(
        new ApiError(404, { code: "not_found", message: "no profile" }),
      );
    vi.mocked(sendMint).mockClear().mockResolvedValue("mintsig");
    vi.mocked(waitForTxReceipt).mockClear().mockResolvedValue(undefined);
  });

  afterEach(() => {
    wallet.uninstall();
  });

  it("assembles the MintAttestation from the record + project and broadcasts supply_controller.mint", async () => {
    renderWithWallet(<Assets />, { connected: true });

    // Wait for the record to load (so the form can find it by ID).
    await screen.findByText("record-001");

    fireEvent.change(
      await screen.findByLabelText("Record ID", { selector: "#sigRecordId" }),
      {
        target: { value: "record-001" },
      },
    );
    fireEvent.change(screen.getByLabelText("Signed result"), {
      target: { files: [signedResultFile()] },
    });
    // The parsed-file summary confirms the file was read before we mint.
    await screen.findByText(AUDITOR);

    fireEvent.click(
      screen.getByRole("button", { name: "Upload signature & mint" }),
    );

    await waitFor(() => expect(sendMint).toHaveBeenCalled());
    const [from, supplyController, attestation, signature] =
      vi.mocked(sendMint).mock.calls[0];
    expect(from).toBe(ADMIN);
    expect(supplyController).toBe(SUPPLY_CONTROLLER);
    expect(signature).toBe(`${signedResultRecord().signature}00`);
    expect(attestation).toEqual({
      auditor: AUDITOR,
      profileDigest: PROJECT.profileDigest,
      recordKey: RECORD.recordKey,
      metadataDigest: RECORD.metadataDigest,
      amount: 1000000000000000000n,
      nonce: 7n,
      validUntil: 4102444800n,
    });
  });

  it("blocks the mint when the signed-result auditor is not the project's auditor", async () => {
    renderWithWallet(<Assets />, { connected: true });
    await screen.findByText("record-001");

    fireEvent.change(
      await screen.findByLabelText("Record ID", { selector: "#sigRecordId" }),
      {
        target: { value: "record-001" },
      },
    );
    fireEvent.change(screen.getByLabelText("Signed result"), {
      target: {
        files: [
          signedResultFile({
            auditor: "0x1234567890123456789012345678901234567890",
          }),
        ],
      },
    });
    await screen.findByText("0x1234567890123456789012345678901234567890");

    fireEvent.click(
      screen.getByRole("button", { name: "Upload signature & mint" }),
    );

    await screen.findByText(/this project's auditor is/i);
    expect(sendMint).not.toHaveBeenCalled();
  });

  it("blocks the mint when no loaded record matches the entered ID", async () => {
    renderWithWallet(<Assets />, { connected: true });
    await screen.findByText("record-001");

    fireEvent.change(
      await screen.findByLabelText("Record ID", { selector: "#sigRecordId" }),
      {
        target: { value: "does-not-exist" },
      },
    );
    fireEvent.change(screen.getByLabelText("Signed result"), {
      target: { files: [signedResultFile()] },
    });
    await screen.findByText(AUDITOR);

    fireEvent.click(
      screen.getByRole("button", { name: "Upload signature & mint" }),
    );

    await screen.findByText(/no loaded record matches that id/i);
    expect(sendMint).not.toHaveBeenCalled();
  });

  it("rejects a file that is not a signed-result.json before relaying", async () => {
    renderWithWallet(<Assets />, { connected: true });
    await screen.findByText("record-001");

    fireEvent.change(
      await screen.findByLabelText("Record ID", { selector: "#sigRecordId" }),
      {
        target: { value: "record-001" },
      },
    );
    // A JSON object missing the signature fields must be rejected client-side.
    fireEvent.change(screen.getByLabelText("Signed result"), {
      target: {
        files: [
          {
            name: "wrong.json",
            text: () => Promise.resolve(JSON.stringify({ hello: "world" })),
          } as unknown as File,
        ],
      },
    });
    await screen.findByText(/missing field\(s\)/i);
    expect(
      screen.getByRole("button", { name: "Upload signature & mint" }),
    ).toBeDisabled();
  });
});

const POLICY_UUID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

describe("Assets signer policy (offline signing trust root)", () => {
  it("buildSignerPolicy emits exactly the seven Solana keys the signer accepts", () => {
    const policy = buildSignerPolicy(
      { ...PROJECT, chainId: 31337 },
      POLICY_UUID,
      BOOTSTRAP,
    );
    expect(policy).not.toBeNull();
    // Exactly the keys signer/internal/policy's DisallowUnknownFields loader
    // accepts — no more (an extra key is a hard parse failure) and no fewer
    // (every one of these is required and non-empty). `chainId` in particular
    // must be GONE: it was the EVM field, and leaving it in made the signer
    // reject the file outright.
    expect(Object.keys(policy!).sort()).toEqual([
      "auditor",
      "cluster",
      "config",
      "profileDigest",
      "program",
      "projectId",
      "vault",
    ]);
    // The domain inputs come from the bootstrap config...
    expect(policy!.cluster).toBe(CLUSTER_GENESIS);
    expect(policy!.program).toBe(SUPPLY_CONTROLLER);
    expect(policy!.config).toBe(SUPPLY_CONFIG);
    // ...and `vault` is the vault CONFIG PDA, never the vault program id.
    expect(policy!.vault).toBe(VAULT_CONFIG);
    expect(policy!.vault).not.toBe(VAULT);
    // projectId is the UUID string, NOT the bytes32 profileDigest/hash.
    expect(policy!.projectId).toBe(POLICY_UUID);
    expect(policy!.projectId).not.toBe(PROJECT.profileDigest);
    expect(policy!.auditor).toBe(AUDITOR);
    expect(policy!.profileDigest).toBe(PROJECT.profileDigest);
    // maxAttestationLifetimeHours is intentionally absent: the signer applies
    // its own 30-day default, and the console must not widen it.
    expect(policy).not.toHaveProperty("maxAttestationLifetimeHours");
  });

  it("returns null rather than a partial file when anything is missing", () => {
    const project = { ...PROJECT, chainId: 31337 };
    expect(buildSignerPolicy(undefined, POLICY_UUID, BOOTSTRAP)).toBeNull();
    expect(buildSignerPolicy(project, undefined, BOOTSTRAP)).toBeNull();
    expect(buildSignerPolicy(project, POLICY_UUID, undefined)).toBeNull();
    // Pre-bootstrap: the domain inputs are unset in the server config, so no
    // policy can be built — each one individually blocks the download.
    for (const missing of [
      "clusterGenesis",
      "supplyConfig",
      "vaultConfig",
    ] as const) {
      expect(
        buildSignerPolicy(project, POLICY_UUID, {
          ...BOOTSTRAP,
          [missing]: undefined,
        }),
      ).toBeNull();
    }
    expect(
      buildSignerPolicy(project, POLICY_UUID, { ...BOOTSTRAP, programIds: {} }),
    ).toBeNull();
    // No auditor yet (nothing reconciled) → no partial file.
    expect(
      buildSignerPolicy({ ...project, auditor: "" }, POLICY_UUID, BOOTSTRAP),
    ).toBeNull();
  });

  it("renders the policy block before Records with a download button when deployed", async () => {
    vi.mocked(api.listRecords).mockReset().mockResolvedValue({ items: [] });
    vi.mocked(api.getProject)
      .mockReset()
      .mockResolvedValue({ ...PROJECT, chainId: 31337 });
    vi.mocked(api.getConfig).mockReset().mockResolvedValue(BOOTSTRAP);
    vi.mocked(api.getProfile)
      .mockReset()
      .mockResolvedValue({
        profile: {
          profileVersion: "1.0",
          projectId: POLICY_UUID,
          assetType: "gold",
          tokenUnit: "gram",
          tokenDecimals: 18,
        } as unknown as Record<string, never>,
        projectId: POLICY_UUID,
        profileDigest: PROJECT.profileDigest,
        cid: "cid",
        decimals: 18,
        tokenUnit: "gram",
      });

    renderWithWallet(<Assets />);

    const policyHeading = await screen.findByRole("heading", {
      name: /Signer policy/,
    });
    await screen.findByRole("button", { name: "Download policy.json" });
    // The UUID (not the digest) is shown in the block.
    expect(screen.getByText(POLICY_UUID)).toBeInTheDocument();

    // The policy block precedes the Records block in the DOM.
    const recordsHeading = screen.getByRole("heading", { name: "Records" });
    expect(
      policyHeading.compareDocumentPosition(recordsHeading) &
        Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
  });

  it("hides the record form and policy behind a not-ready notice when the project has no auditor yet", async () => {
    // The state a server started BEFORE the chain was bootstrapped sits in:
    // the project loads, but no auditor has been read off the supply-controller
    // config account. Any .rwa package built now would carry a zero auditor and
    // could be neither signed nor minted, so the actions that lead there must
    // not be offered — and the reason must be visible, not just an absence.
    vi.mocked(api.listRecords).mockReset().mockResolvedValue({ items: [] });
    vi.mocked(api.getProject)
      .mockReset()
      .mockResolvedValue({ ...PROJECT, auditor: "", chainId: 31337 });
    vi.mocked(api.getConfig).mockReset().mockResolvedValue(BOOTSTRAP);

    renderWithWallet(<Assets />);

    await screen.findByRole("heading", { name: "Deployment not ready" });
    expect(screen.queryByRole("heading", { name: "Create record" })).toBeNull();
    expect(screen.queryByRole("heading", { name: /Signer policy/ })).toBeNull();
  });

  it("shows a muted note (no download) when the project isn't deployed / no profile", async () => {
    vi.mocked(api.listRecords).mockReset().mockResolvedValue({ items: [] });
    vi.mocked(api.getProject).mockReset().mockRejectedValue(new Error("404"));
    vi.mocked(api.getProfile)
      .mockReset()
      .mockRejectedValue(
        new ApiError(404, { code: "not_found", message: "no profile" }),
      );

    renderWithWallet(<Assets />);

    await screen.findByText(
      /Bootstrap the deployment and create the asset profile first/i,
    );
    expect(
      screen.queryByRole("button", { name: "Download policy.json" }),
    ).toBeNull();
  });
});

describe("parseSignedResult", () => {
  it("packs the 64-byte signature + recoveryId 0 into a 65-byte hex", () => {
    const parsed = parseSignedResult(JSON.stringify(signedResultRecord()));
    expect(parsed.signature).toBe(`0x${"ab".repeat(64)}00`);
    expect(parsed.auditor).toBe(AUDITOR);
    expect(parsed.primaryType).toBe("MintAttestation");
    expect(parsed.signedAt).toBe("2026-01-01T00:00:00Z");
  });

  it("packs the 64-byte signature + recoveryId 1 into a 65-byte hex", () => {
    const parsed = parseSignedResult(
      JSON.stringify(signedResultRecord({ recoveryId: 1 })),
    );
    expect(parsed.signature).toBe(`0x${"ab".repeat(64)}01`);
  });

  it("rejects text that isn't valid JSON", () => {
    expect(() => parseSignedResult("{not json")).toThrow(/not valid JSON/);
  });

  it("rejects a JSON array or primitive (not an object)", () => {
    expect(() => parseSignedResult("[]")).toThrow(/must be a JSON object/);
    expect(() => parseSignedResult("42")).toThrow(/must be a JSON object/);
  });

  it("rejects a missing required string field", () => {
    const rec: Record<string, unknown> = signedResultRecord();
    delete rec.auditor;
    expect(() => parseSignedResult(JSON.stringify(rec))).toThrow(
      /missing field.*auditor/,
    );
  });

  it("rejects the wrong formatVersion", () => {
    expect(() =>
      parseSignedResult(
        JSON.stringify(signedResultRecord({ formatVersion: "1.0" })),
      ),
    ).toThrow(/solana-1\.0/);
  });

  it("rejects the wrong chain", () => {
    expect(() =>
      parseSignedResult(JSON.stringify(signedResultRecord({ chain: "evm" }))),
    ).toThrow(/solana-1\.0/);
  });

  it("rejects a signature that isn't exactly 64 bytes (0x + 128 hex chars)", () => {
    expect(() =>
      parseSignedResult(
        JSON.stringify(
          signedResultRecord({ signature: `0x${"11".repeat(63)}` }),
        ),
      ),
    ).toThrow(/64-byte compact form/);
    expect(() =>
      parseSignedResult(
        JSON.stringify(
          signedResultRecord({ signature: `0x${"11".repeat(65)}` }),
        ),
      ),
    ).toThrow(/64-byte compact form/);
  });

  it("rejects recoveryId 2 (out of range)", () => {
    expect(() =>
      parseSignedResult(JSON.stringify(signedResultRecord({ recoveryId: 2 }))),
    ).toThrow(/must be 0 or 1/);
  });

  it("rejects a string recoveryId (must be numeric)", () => {
    expect(() =>
      parseSignedResult(
        JSON.stringify(signedResultRecord({ recoveryId: "0" })),
      ),
    ).toThrow(/must be 0 or 1/);
  });
});
