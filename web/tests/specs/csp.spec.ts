// Regression check for the CSP meta tag injected at build time (see
// vite.config.ts's injectCsp plugin) — catches someone accidentally dropping
// the plugin or loosening a directive. Runs in both modes: it's checking
// shipped markup, not seeded state, and the live server embeds the same
// dist/index.html.
//
// This suite's build (npm run preview, no VITE_SOLANA_RPC_URL set — see
// playwright.config.ts) has no RPC endpoint configured, so connect-src
// here is 'self' only; the RPC-origin-appended connect-src is covered by
// src/lib/cspPolicy.test.ts's unit tests instead, which exercise the same
// buildCsp() this plugin calls directly against a fake VITE_SOLANA_RPC_URL —
// there is no second, RPC-configured build wired into this pipeline to load a
// real page against.
import { expect, test } from "../fixtures/fixtures";

test("ships a restrictive CSP with no unsafe-inline/unsafe-eval", async ({ page }) => {
  await page.goto("/admin/setup");

  const csp = await page
    .locator('meta[http-equiv="Content-Security-Policy"]')
    .getAttribute("content");

  expect(csp).not.toBeNull();
  expect(csp).toContain("default-src 'self'");
  expect(csp).toContain("object-src 'none'");
  expect(csp).not.toMatch(/unsafe-inline/);
  expect(csp).not.toMatch(/unsafe-eval/);
  // frame-ancestors is intentionally NOT in the meta tag — browsers ignore it
  // there entirely (only a real HTTP response header is protective); the Go
  // server sends it as a header on SPA routes instead. Asserting its absence
  // here guards against someone re-adding a decorative copy that looks
  // protective but isn't.
  expect(csp).not.toMatch(/frame-ancestors/);
  // Regression guard: connect-src must be an EXPLICIT directive
  // in the EFFECTIVE policy, not merely implied by default-src's CSP Level 3
  // fallback (an absent connect-src falls back to default-src, which is
  // exactly the bug this replaces — it silently capped fetch/XHR/WebSocket at
  // 'self' even though the server's header, since removed, claimed to allow
  // more). This build has no RPC endpoint configured, so 'self' is the whole
  // story here; see cspPolicy.test.ts for the RPC-origin-appended case.
  expect(csp).toContain("connect-src 'self';");
});
