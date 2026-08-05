import type { Page } from "@playwright/test";
import { sectionByHeading } from "../fixtures/helpers";

export class AdminAssetsPage {
  constructor(private readonly page: Page) {}

  async goto(): Promise<void> {
    await this.page.goto("/admin/assets");
  }

  private get createSection() {
    return sectionByHeading(this.page, "Create record");
  }

  private get signatureSection() {
    return sectionByHeading(this.page, "Auditor signature upload & mint");
  }

  private get recordsSection() {
    return sectionByHeading(this.page, "Records");
  }

  async createRecord(fields: { recordId: string; amount: string }): Promise<void> {
    await this.page.locator("#recordId").fill(fields.recordId);
    await this.page.locator("#amount").fill(fields.amount);
    await this.createSection.getByRole("button", { name: "Create record" }).click();
  }

  /**
   * Uploads the auditor's signed-result.json (built from the given fields) and
   * relays. The form doesn't take the signature fields individually — they
   * are read from the uploaded file (signer/internal/output/output.go's
   * SolanaSignedResult; formatVersion "solana-1.0"). `signature` here is the
   * 64-byte compact form (0x + 128 hex chars); `recoveryId` (0 or 1) is packed
   * into it by the form to make the 65-byte hex lib/wallet.ts's sendMint takes.
   */
  async uploadSignature(fields: {
    recordId: string;
    auditor: string;
    primaryType: string;
    program: string;
    signature: string;
    recoveryId?: 0 | 1;
    signedAt?: string;
  }): Promise<void> {
    await this.page.locator("#sigRecordId").fill(fields.recordId);
    const signedResult = {
      formatVersion: "solana-1.0",
      chain: "solana",
      auditor: fields.auditor,
      primaryType: fields.primaryType,
      cluster: "devnet",
      program: fields.program,
      config: fields.program,
      attestationDigest: `0x${"dd".repeat(32)}`,
      signature: fields.signature,
      recoveryId: fields.recoveryId ?? 0,
      signedAt: fields.signedAt ?? "2026-01-01T00:00:00Z",
    };
    await this.page.locator("#signedResultFile").setInputFiles({
      name: "signed-result.json",
      mimeType: "application/json",
      buffer: Buffer.from(JSON.stringify(signedResult)),
    });
    await this.signatureSection.getByRole("button", { name: "Upload signature & mint" }).click();
  }

  /** Uploads a raw file body to the signed-result input (for malformed-file specs). */
  async uploadSignedResultFile(name: string, contents: string): Promise<void> {
    await this.page.locator("#signedResultFile").setInputFiles({
      name,
      mimeType: "application/json",
      buffer: Buffer.from(contents),
    });
  }

  recordRow(recordId: string) {
    return this.recordsSection.locator("tr", { hasText: recordId });
  }
}
