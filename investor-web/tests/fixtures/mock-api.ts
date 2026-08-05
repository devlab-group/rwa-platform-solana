// Stateful mock of the investor-facing slice of api/openapi.yaml, via
// Playwright route interception. Each spec gets a fresh in-memory store
// (installMockApi returns it) so it can both drive the UI and mutate
// server-side state directly — e.g. simulate the issuer funding a redemption
// that the investor then sees as Claimable after a reload.
//
// Only the endpoints this app calls are mocked; anything else 501s loudly so
// an un-mocked route can never silently pass a spec.
import type { Page, Route } from "@playwright/test";
import { Keypair } from "@solana/web3.js";
import type { components } from "../../src/lib/api-types";

type Project = components["schemas"]["Project"];
type WalletStatus = components["schemas"]["WalletStatus"];
type Challenge = components["schemas"]["Challenge"];
type Redemption = components["schemas"]["Redemption"];
type Transaction = components["schemas"]["Transaction"];

/** Deterministic pubkeys for this test run — fixed seeds, not
 * randomly generated, so every spec (and mock-wallet.ts's account-data
 * builder) sees the exact same addresses without needing to thread them
 * through a fixture. */
function fixedPubkey(seed: number): Keypair {
  return Keypair.fromSeed(Buffer.alloc(32, seed));
}

export const PROGRAM_IDS = {
  compliance: fixedPubkey(10).publicKey,
  vault: fixedPubkey(11).publicKey,
  pricing: fixedPubkey(12).publicKey,
  transferHook: fixedPubkey(13).publicKey,
  redemption: fixedPubkey(14).publicKey,
  supplyController: fixedPubkey(15).publicKey,
};

export const MINTS = {
  rwa: fixedPubkey(20).publicKey,
  quote: fixedPubkey(21).publicKey,
};

export const MOCK_WALLET_KEYPAIR = fixedPubkey(1);
export const MOCK_WALLET_ADDRESS = MOCK_WALLET_KEYPAIR.publicKey.toBase58();

export const ADDRESSES = {
  token: MINTS.rwa.toBase58(),
  compliance: PROGRAM_IDS.compliance.toBase58(),
  supplyController: PROGRAM_IDS.supplyController.toBase58(),
  vault: PROGRAM_IDS.vault.toBase58(),
  redemptionEscrow: PROGRAM_IDS.redemption.toBase58(),
  strategy: PROGRAM_IDS.pricing.toBase58(),
  quoteToken: MINTS.quote.toBase58(),
};

// Buy/redemption prices are not part of this store: the app quotes them from
// the pricing program's on-chain Strategy account, which the mock RPC
// answers (mock-wallet.ts).
export interface MockState {
  project: Project;
  wallets: WalletStatus[];
  redemptions: Redemption[];
  transactions: Transaction[];
  challenges: Record<string, Challenge>;
}

export function defaultState(): MockState {
  return {
    project: {
      projectId: "demo-project",
      version: "1.0.0",
      decimals: 9,
      tokenUnit: "gram",
      profileDigest: `0x${"de".repeat(32)}`,
      addresses: { ...ADDRESSES },
      paused: false,
      finalityConfirmations: 12,
      bytecodeVerified: true,
    },
    wallets: [
      {
        address: fixedPubkey(99).publicKey.toBase58(),
        status: "Allowed",
        validUntil: 4102444800,
        ownershipVerified: true,
      },
    ],
    redemptions: [],
    transactions: [],
    challenges: {},
  };
}

let idCounter = 0;
function nextId(prefix: string): string {
  idCounter += 1;
  return `${prefix}-${idCounter}`;
}

/** Installs route interception for every `/api/v1/**` call and returns the mutable backing store. */
export async function installMockApi(
  page: Page,
  overrides: Partial<MockState> = {},
): Promise<MockState> {
  const state: MockState = { ...defaultState(), ...overrides };

  await page.route("**/api/v1/**", async (route: Route) => {
    const req = route.request();
    const url = new URL(req.url());
    const path = url.pathname;
    const method = req.method();

    const json = (data: unknown, status = 200) =>
      route.fulfill({
        status,
        contentType: "application/json",
        body: JSON.stringify(data),
      });
    // --- project -----------------------------------------------------
    if (path === "/api/v1/project" && method === "GET")
      return json(state.project);
    // --- config (bootstrap, incl. the transfer-hook program id) --------
    if (path === "/api/v1/config" && method === "GET")
      return json({
        projectId: state.project.projectId ?? "",
        programIds: {
          compliance: PROGRAM_IDS.compliance.toBase58(),
          vault: PROGRAM_IDS.vault.toBase58(),
          pricing: PROGRAM_IDS.pricing.toBase58(),
          transferHook: PROGRAM_IDS.transferHook.toBase58(),
          redemption: PROGRAM_IDS.redemption.toBase58(),
          supplyController: PROGRAM_IDS.supplyController.toBase58(),
        },
        rwaMint: MINTS.rwa.toBase58(),
        quoteMint: MINTS.quote.toBase58(),
      });
    // --- compliance ----------------------------------------------------
    if (path === "/api/v1/compliance/challenge" && method === "POST") {
      const body = req.postDataJSON() as { address: string };
      const nonce = nextId("nonce");
      const challenge: Challenge = {
        address: body.address,
        nonce,
        message: `Sign to verify ownership of ${body.address} (nonce ${nonce})`,
        expiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
      };
      state.challenges[nonce] = challenge;
      return json(challenge);
    }
    if (path === "/api/v1/compliance/challenge/verify" && method === "POST") {
      const body = req.postDataJSON() as {
        address: string;
        nonce: string;
        signature: string;
      };
      let wallet = state.wallets.find((w) => w.address === body.address);
      if (!wallet) {
        wallet = {
          address: body.address,
          status: "Unknown",
          ownershipVerified: false,
        };
        state.wallets.push(wallet);
      }
      wallet.ownershipVerified = true;
      // Session token deliberately encodes the address so the mock's
      // GET /api/v1/me/wallet-status handler below can resolve it without a
      // real server-side session store.
      return json({
        ...wallet,
        sessionToken: `mock-session:${wallet.address}`,
        sessionExpiresAt: new Date(Date.now() + 15 * 60_000).toISOString(),
      });
    }
    if (path === "/api/v1/me/wallet-status" && method === "GET") {
      const session = await req.headerValue("x-wallet-session");
      const address = session?.startsWith("mock-session:")
        ? session.slice("mock-session:".length)
        : undefined;
      const wallet = address && state.wallets.find((w) => w.address === address);
      if (!wallet)
        return json(
          {
            code: "unauthorized",
            message: "missing or expired wallet session",
          },
          401,
        );
      return json(wallet);
    }
    const allowedMatch = path.match(
      /^\/api\/v1\/compliance\/allowed\/([^/]+)$/,
    );
    if (allowedMatch && method === "GET") {
      const address = decodeURIComponent(allowedMatch[1]);
      const wallet = state.wallets.find((w) => w.address === address);
      return json({ allowed: wallet?.status === "Allowed" });
    }
    // --- redemptions (specific routes before the generic /{id}) --------
    if (path === "/api/v1/redemptions" && method === "GET") {
      const status = url.searchParams.get("status");
      // Public list: filter by status and/or by beneficiary address (the
      // investor page passes its connected wallet).
      const address = url.searchParams.get("address");
      const list = state.redemptions.filter(
        (r) =>
          (!status || r.status === status) &&
          (!address || r.beneficiary === address),
      );
      return json(list);
    }
    // No redemption call is a server calldata endpoint — request, claim,
    // cancel, fund and reject are all encoded in the browser and broadcast
    // from the connected wallet.
    const idMatch = path.match(/^\/api\/v1\/redemptions\/([^/]+)$/);
    if (idMatch && method === "GET") {
      const redemption = state.redemptions.find(
        (r) => r.id === decodeURIComponent(idMatch[1]),
      );
      if (!redemption)
        return json(
          { code: "not_found", message: "redemption not found" },
          404,
        );
      return json(redemption);
    }

    // --- transactions --------------------------------------------------
    if (path === "/api/v1/transactions" && method === "GET") {
      const address = url.searchParams.get("address");
      const list = address
        ? state.transactions.filter((t) => JSON.stringify(t).includes(address))
        : state.transactions;
      return json(list);
    }

    // Fail loudly rather than let an un-mocked route silently pass a spec.
    return route.fulfill({
      status: 501,
      contentType: "application/json",
      body: JSON.stringify({
        code: "unmocked_route",
        message: `${method} ${path} not mocked`,
      }),
    });
  });

  return state;
}
