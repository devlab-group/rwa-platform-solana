// This file's "build-level CSP injection" describe block below calls Vite's
// own build() (which runs esbuild) directly. jsdom's TextEncoder polyfill
// breaks an esbuild environment invariant it relies on
// ("new TextEncoder().encode("") instanceof Uint8Array"), so the whole file
// (not just that block — vitest environments are per-file) runs under node
// instead of the suite's default jsdom. Mirrors web/src/lib/cspPolicy.test.ts.
// @vitest-environment node
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { build, loadEnv } from "vite";
import { buildCsp, originOf } from "./cspPolicy";

// investor-web/ (this file is investor-web/src/lib/cspPolicy.test.ts).
const appRoot = fileURLToPath(new URL("../../", import.meta.url));
const viteConfigFile = join(appRoot, "vite.config.ts");

describe("originOf", () => {
  it("extracts scheme+host+port, dropping any path", () => {
    expect(originOf("https://rpc.example.com/v1/abc123")).toBe(
      "https://rpc.example.com",
    );
    expect(originOf("http://localhost:8899")).toBe("http://localhost:8899");
  });

  it("returns empty string for an unparseable URL", () => {
    expect(originOf("not-a-url")).toBe("");
    expect(originOf("")).toBe("");
  });
});

describe("buildCsp — base policy / KYC widening", () => {
  it("ships a strict connect-src 'self' with no KYC provider and no pins", () => {
    const csp = buildCsp(undefined);
    expect(csp).toContain("connect-src 'self'");
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).not.toMatch(/unsafe-inline/);
    expect(csp).not.toMatch(/unsafe-eval/);
  });

  it("throws for an unrecognized VITE_KYC_PROVIDER", () => {
    expect(() => buildCsp("not-a-real-provider")).toThrow(/not a provider/);
  });

  it("widens frame-src/connect-src for sumsub without touching unrelated directives", () => {
    const csp = buildCsp("sumsub");
    expect(csp).toContain("frame-src https://*.sumsub.com");
    expect(csp).toContain("connect-src 'self' https://*.sumsub.com");
    expect(csp).toContain("object-src 'none'");
  });

  it("includes frame-ancestors 'none' (documentation only — meta tags can't enforce it)", () => {
    expect(buildCsp(undefined)).toContain("frame-ancestors 'none'");
  });
});

describe("buildCsp — RPC/WS pinning", () => {
  it("leaves connect-src at 'self' when no RPC URL is configured", () => {
    const csp = buildCsp(undefined, "");
    expect(csp).toContain("connect-src 'self';");
  });

  it("bakes the RPC origin into connect-src alongside 'self' when VITE_SOLANA_RPC_URL is set", () => {
    const csp = buildCsp(undefined, "https://rpc.example.com/some/path");
    expect(csp).toContain("connect-src 'self' https://rpc.example.com;");
  });

  it("also bakes the WS origin into connect-src when VITE_SOLANA_WS_URL is set — the WebSocket transport confirmTransaction opens is a distinct origin from the HTTP RPC", () => {
    const csp = buildCsp(
      undefined,
      "https://rpc.example.com",
      "wss://rpc.example.com/some/path",
    );
    expect(csp).toContain(
      "connect-src 'self' https://rpc.example.com wss://rpc.example.com;",
    );
  });

  it("throws rather than silently omitting the RPC origin when VITE_SOLANA_RPC_URL is set but malformed", () => {
    expect(() => buildCsp(undefined, "not-a-url")).toThrow(
      /VITE_SOLANA_RPC_URL/,
    );
  });

  it("throws rather than silently omitting the WS origin when VITE_SOLANA_WS_URL is set but malformed", () => {
    expect(() =>
      buildCsp(undefined, "https://rpc.example.com", "not-a-url"),
    ).toThrow(/VITE_SOLANA_WS_URL/);
  });

  it("composes with a KYC provider's own connect-src widening", () => {
    const csp = buildCsp("sumsub", "https://rpc.example.com");
    expect(csp).toContain(
      "connect-src 'self' https://*.sumsub.com https://rpc.example.com;",
    );
  });
});

describe("buildCsp — non-loopback plain http/ws rejected", () => {
  it("throws for a non-loopback plain-http RPC URL — upgrade-insecure-requests would silently rewrite it to https and break the connection", () => {
    expect(() => buildCsp(undefined, "http://rpc.example.com")).toThrow(
      /non-loopback/,
    );
  });

  it("throws for a non-loopback plain-ws WS URL", () => {
    expect(() =>
      buildCsp(undefined, "https://rpc.example.com", "ws://rpc.example.com"),
    ).toThrow(/non-loopback/);
  });

  it("allows plain http/ws on loopback hosts (localhost, 127.0.0.1) — the only case the upgrade doesn't break", () => {
    expect(() =>
      buildCsp(undefined, "http://localhost:8899", "ws://localhost:8900"),
    ).not.toThrow();
    expect(() =>
      buildCsp(undefined, "http://127.0.0.1:8899", "ws://127.0.0.1:8900"),
    ).not.toThrow();
  });

  it("allows https/wss on any host, loopback or not", () => {
    expect(() =>
      buildCsp(
        undefined,
        "https://rpc.example.com",
        "wss://rpc.example.com",
      ),
    ).not.toThrow();
  });

  it("still appends upgrade-insecure-requests unconditionally", () => {
    expect(buildCsp(undefined, "http://localhost:8899")).toMatch(
      /upgrade-insecure-requests$/,
    );
  });
});

// Regression coverage: the bug wasn't in a pure string builder
// (there wasn't one) — it was that vite.config.ts read VITE_KYC_PROVIDER only
// and never consulted VITE_SOLANA_RPC_URL/VITE_SOLANA_WS_URL at all, so a
// build's meta tag stayed connect-src 'self' while the bundle
// embedded a real RPC URL. These two describe blocks exercise the actual
// vite.config.ts handoff, not just buildCsp() in isolation.
describe("vite config env-loading handoff", () => {
  it("loadEnv(mode, cwd, 'VITE_') — the exact call vite.config.ts's defineConfig callback makes — resolves .env.test's VITE_SOLANA_RPC_URL/VITE_SOLANA_WS_URL", () => {
    const env = loadEnv("test", appRoot, "VITE_");
    expect(env.VITE_SOLANA_RPC_URL).toBe("http://localhost:8899");
    expect(env.VITE_SOLANA_WS_URL).toBe("ws://localhost:8900");

    const csp = buildCsp(
      env.VITE_KYC_PROVIDER || undefined,
      env.VITE_SOLANA_RPC_URL,
      env.VITE_SOLANA_WS_URL,
    );
    expect(csp).toContain(
      "connect-src 'self' http://localhost:8899 ws://localhost:8900;",
    );
  });
});

describe("build-level CSP injection — real vite build, mode=test", () => {
  it("dist/index.html's CSP meta tag actually contains both the RPC and WS origins baked into the JS bundle, not just 'self'", async () => {
    const outDir = mkdtempSync(join(tmpdir(), "iw-csp-build-test-"));
    try {
      await build({
        configFile: viteConfigFile,
        root: appRoot,
        mode: "test",
        logLevel: "silent",
        build: { outDir, emptyOutDir: true, write: true },
      });
      const html = readFileSync(join(outDir, "index.html"), "utf8");
      const match = html.match(
        /<meta http-equiv="Content-Security-Policy" content="([^"]+)"/,
      );
      expect(match).not.toBeNull();
      const csp = match![1];
      expect(csp).toContain(
        "connect-src 'self' http://localhost:8899 ws://localhost:8900;",
      );
      // And the RPC URL really is embedded in the shipped JS — confirming
      // this is the same bundle the CSP above must actually unblock.
      const assetFiles = readdirSync(join(outDir, "assets")).filter((f) =>
        f.endsWith(".js"),
      );
      const bundleText = assetFiles
        .map((f) => readFileSync(join(outDir, "assets", f), "utf8"))
        .join("\n");
      expect(bundleText).toContain("http://localhost:8899");
    } finally {
      rmSync(outDir, { recursive: true, force: true });
    }
  }, 60_000);
});
