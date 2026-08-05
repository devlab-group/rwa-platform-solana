import type { Page } from "@playwright/test";
import { sectionByHeading } from "../fixtures/helpers";

export class AdminSetupPage {
  constructor(private readonly page: Page) {}

  async goto(): Promise<void> {
    await this.page.goto("/admin/setup");
  }

  private get profileSection() {
    return sectionByHeading(this.page, "Asset Profile");
  }

  private get deploySection() {
    return sectionByHeading(this.page, "Deployment");
  }

  async validateProfile(): Promise<void> {
    await this.profileSection.getByRole("button", { name: "Validate profile" }).click();
  }

  async createProfile(): Promise<void> {
    await this.profileSection.getByRole("button", { name: "Create & persist profile" }).click();
  }

  /**
   * Fills the discrete profile fields then validates + creates in one call —
   * the common path for deploy-focused specs. projectId (from the server config)
   * and profileVersion (pinned 1.0) aren't entered here; read the projectId back
   * with `generatedProjectId()`.
   */
  async createProfileFor(fields: {
    tokenUnit: string;
    tokenDecimals: number;
    assetType?: string;
    recordIdLabel?: string;
    assetSchema?: object;
  }): Promise<void> {
    await this.page.locator("#assetType").fill(fields.assetType ?? "commodity");
    await this.page.locator("#tokenUnit").fill(fields.tokenUnit);
    await this.page.locator("#tokenDecimals").fill(String(fields.tokenDecimals));
    await this.page.locator("#recordIdLabel").fill(fields.recordIdLabel ?? "Serial number");
    await this.page
      .locator("#assetSchema")
      .fill(JSON.stringify(fields.assetSchema ?? {}, null, 2));
    await this.validateProfile();
    await this.createProfile();
  }

  createdProfileStatus() {
    return this.profileSection.getByRole("status");
  }

  /** The deployment's project ID (from the server config), read from the create
   * form (before create) or the persisted-profile summary (after create) — both
   * show a "Project ID" row. */
  async generatedProjectId(): Promise<string> {
    const row = this.profileSection
      .locator(".tx-preview__row")
      .filter({ hasText: "Project ID" });
    return ((await row.locator("dd").first().textContent()) ?? "").trim();
  }

  /** The operator-CLI runbook hint shown in place of a deploy form — there is no wallet-broadcast deploy action on this console. */
  deployRunbookHint() {
    return this.deploySection.getByText(/operator CLI step/i);
  }

  currentProjectSection() {
    return sectionByHeading(this.page, "Current project");
  }
}
