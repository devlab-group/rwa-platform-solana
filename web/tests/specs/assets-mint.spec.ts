import { BorshCoder, type Idl } from "@coral-xyz/anchor";
import { expect, mockOnly, test } from "../fixtures/fixtures";
import { AdminAssetsPage } from "../pages/AdminAssetsPage";
import { ADDRESSES } from "../fixtures/mock-api";
import { getMockSentTransactions } from "../fixtures/mock-wallet";
import supplyControllerIdl from "../../src/lib/idl/rwa_supply_controller.json";

const supplyCoder = new BorshCoder(supplyControllerIdl as Idl);

// Matches the default mock project's auditor (mock-api's Project.auditor) —
// the auditor identity is a secp256k1 key rendered as a 20-byte address,
// so it stays 0x-hex even on Solana.
const AUDITOR = "0x9999999999999999999999999999999999999999";
// A valid-hex 64-byte compact secp256k1 signature — the form packs this with
// a recoveryId into the 65-byte hex lib/wallet.ts's sendMint takes.
const SIGNATURE = `0x${"ab".repeat(64)}`;

test.describe("Assets — create record and mint via auditor signature", () => {
  mockOnly();

  test("uploading the auditor signature broadcasts supply_controller.mint from the wallet", async ({ page }) => {
    const assets = new AdminAssetsPage(page);
    await assets.goto();

    // "1" whole token → 1e18 minimal units (project decimals = 18); the record
    // is stored in minimal units, which is what the MintAttestation carries.
    await assets.createRecord({ recordId: "record-001", amount: "1" });
    await expect(assets.recordRow("record-001")).toBeVisible();
    // The record starts Pending; it flips to Minted only once the server
    // observes the on-chain Minted event (not simulated by the mock).
    await expect(assets.recordRow("record-001").locator(".badge")).toHaveText("Pending");

    await assets.uploadSignature({
      recordId: "record-001",
      auditor: AUDITOR,
      primaryType: "MintAttestation",
      program: ADDRESSES.supplyController,
      signature: SIGNATURE,
      recoveryId: 1,
    });

    await expect(page.getByText(/Mint broadcast\. Transaction:/)).toBeVisible();

    // The mint was broadcast to the SupplyController program from the
    // connected wallet, carrying the record's attestation fields and the
    // auditor's signature.
    const sent = await getMockSentTransactions(page);
    const mintTx = sent.find((t) => t.programId === ADDRESSES.supplyController);
    expect(mintTx, "a mint instruction to the supply controller was broadcast").toBeTruthy();

    const decoded = supplyCoder.instruction.decode(Buffer.from(mintTx!.data, "base64"));
    expect(decoded?.name).toBe("mint");
    const args = decoded!.data as {
      amount: { toString(): string };
      signature: number[];
      recovery_id: number;
    };
    expect(args.amount.toString()).toBe("1000000000000000000");
    // The 64-byte compact signature + recovery id round-trip exactly.
    expect(Buffer.from(args.signature).toString("hex")).toBe("ab".repeat(64));
    expect(args.recovery_id).toBe(1);
  });

  test("rejects a file that is not a signed-result.json before relaying", async ({ page }) => {
    const assets = new AdminAssetsPage(page);
    await assets.goto();
    await assets.createRecord({ recordId: "record-003", amount: "1000000000000000000" });

    await page.locator("#sigRecordId").fill("record-003");
    // A JSON object missing the signature fields must be rejected client-side.
    await assets.uploadSignedResultFile(
      "wrong.json",
      JSON.stringify({ hello: "world" }),
    );
    await expect(page.getByText(/missing field\(s\)/i)).toBeVisible();
    // The mint button stays disabled with no valid parsed result.
    await expect(
      page.getByRole("button", { name: "Upload signature & mint" }),
    ).toBeDisabled();
  });

  test("prefills the Metadata editor from the profile's assetSchema", async ({ page, api }) => {
    // Seed a persisted profile whose assetSchema declares two fields; the
    // Create-record Metadata editor should open pre-filled with a skeleton
    // built from that schema instead of an empty object.
    api.createdProfiles.set("proj-schema", {
      profileDigest: "0xdig",
      tokenDecimals: 18,
      tokenUnit: "gram",
      profile: {
        profileVersion: "1.0",
        projectId: "proj-schema",
        assetType: "gold",
        tokenUnit: "gram",
        tokenDecimals: 18,
        recordIdLabel: "Serial number",
        assetSchema: {
          type: "object",
          properties: {
            serial: { type: "string" },
            weightGrams: { type: "number" },
          },
          required: ["serial"],
        },
      },
    });

    const assets = new AdminAssetsPage(page);
    await assets.goto();

    const metadata = page.locator("#assetJson");
    // Skeleton derived from the schema: both properties present, typed defaults.
    await expect(metadata).toHaveValue(/"serial":\s*""/);
    await expect(metadata).toHaveValue(/"weightGrams":\s*0/);
    // The Record ID hint is made concrete from the profile's recordIdLabel.
    await expect(page.getByText(/the serial number/i)).toBeVisible();
  });

  test("package download is available and fetches authenticated", async ({ page }) => {
    // The operator's bearer session (see src/lib/authSession.ts) is already
    // seeded in memory by the `api` fixture — the download has to attach it,
    // which a plain <a href> can't do.
    const assets = new AdminAssetsPage(page);
    await assets.goto();

    await assets.createRecord({ recordId: "record-002", amount: "500000000000000000" });
    const downloadButton = assets.recordRow("record-002").getByRole("button", { name: "Download .rwa" });
    await expect(downloadButton).toBeVisible();

    // A plain <a href> can't attach an Authorization header, so the download
    // goes through an authenticated fetch instead — the package endpoint is
    // operator-only and would 403 without it.
    const [request, download] = await Promise.all([
      page.waitForRequest((r) => r.url().includes("/package") && r.method() === "GET"),
      page.waitForEvent("download"),
      downloadButton.click(),
    ]);
    expect(request.headers()["authorization"]).toMatch(/^Bearer /);
    expect(request.headers()["x-api-key"]).toBeFalsy();
    expect(download.suggestedFilename()).toBe("record-002.rwa");
  });

  test("Signer policy block downloads a valid policy.json for the auditor", async ({ page, api }) => {
    // Seed a persisted profile whose raw doc carries the project UUID — the
    // signer policy pins that UUID (not a hash). The default project is already
    // deployed (supplyController/vault/auditor/profileDigest present).
    const uuid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    api.createdProfiles.set(uuid, {
      profileDigest: `0x${"ce".repeat(32)}`,
      tokenDecimals: 18,
      tokenUnit: "gram",
      profile: {
        profileVersion: "1.0",
        projectId: uuid,
        assetType: "gold",
        tokenUnit: "gram",
        tokenDecimals: 18,
      },
    });

    const assets = new AdminAssetsPage(page);
    await assets.goto();

    await expect(
      page.getByRole("heading", { name: /Signer policy/ }),
    ).toBeVisible();
    await expect(page.getByText(uuid)).toBeVisible();

    const [download] = await Promise.all([
      page.waitForEvent("download"),
      page.getByRole("button", { name: "Download policy.json" }).click(),
    ]);
    expect(download.suggestedFilename()).toBe("policy.json");

    const stream = await download.createReadStream();
    const content = await new Promise<string>((resolve, reject) => {
      const chunks: Buffer[] = [];
      stream.on("data", (c: Buffer) => chunks.push(Buffer.from(c)));
      stream.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
      stream.on("error", reject);
    });

    const policy = JSON.parse(content) as Record<string, unknown>;
    // Exactly the six keys the signer's DisallowUnknownFields loader accepts.
    expect(Object.keys(policy).sort()).toEqual([
      "auditor",
      "chainId",
      "controller",
      "profileDigest",
      "projectId",
      "vault",
    ]);
    // chainId is a decimal string, projectId is the UUID (not a hash).
    expect(typeof policy.chainId).toBe("string");
    expect(policy.projectId).toBe(uuid);
    expect(policy.controller).toBe(ADDRESSES.supplyController);
    expect(policy.vault).toBe(ADDRESSES.vault);
  });
});
