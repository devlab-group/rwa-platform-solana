import "@testing-library/jest-dom/vitest";
import { afterEach } from "vitest";

// Vitest's default mode is "test", so Vite loads `.env.local` — which a
// contributor running this app against their own deployment will have filled
// in with real program ids and mints. lib/chain/pins.ts reads those on every
// getPins() call and hard-asserts them against the server-supplied addresses,
// so those pins would make every test using a generated fixture address abort
// with PinMismatchError. That turns the suite red purely because someone
// configured a deployment, which is why the baseline is cleared here.
//
// Cleared by direct assignment rather than vi.stubEnv so that a test's own
// `vi.unstubAllEnvs()` restores THIS baseline instead of resurrecting
// `.env.local`. A test that wants pins set (pins.test.ts,
// Investor.test.tsx) still stubs them explicitly, which continues to win.
//
// Deliberately NOT cleared: VITE_SOLANA_RPC_URL / VITE_SOLANA_WS_URL. Those
// are what `.env.test` exists to provide — the unit tests use them to
// exercise the real getConnection() path, and cspPolicy.test.ts builds a
// bundle that must carry both origins. Tests needing the genuinely-unset RPC
// case override it to "" themselves.
for (const pin of [
  "VITE_SOLANA_PROGRAM_COMPLIANCE",
  "VITE_SOLANA_PROGRAM_VAULT",
  "VITE_SOLANA_PROGRAM_PRICING",
  "VITE_SOLANA_PROGRAM_TRANSFER_HOOK",
  "VITE_SOLANA_PROGRAM_REDEMPTION",
  "VITE_SOLANA_PROGRAM_SUPPLY_CONTROLLER",
  "VITE_SOLANA_RWA_MINT",
  "VITE_SOLANA_QUOTE_MINT",
  "VITE_SOLANA_CLUSTER_GENESIS",
]) {
  (import.meta.env as Record<string, string | undefined>)[pin] = "";
}

afterEach(() => {
  // The only client-side persistence is the per-address X-Wallet-Session in
  // localStorage; clear it so a session never leaks between tests. Guarded
  // for the odd `// @vitest-environment node` file (e.g. lib/chain/pda.test.ts,
  // which sidesteps a jsdom `crypto` quirk unrelated to the DOM) where there
  // is no `window` at all.
  if (typeof window !== "undefined") window.localStorage.clear();
});
