// This file's "build-level CSP injection" describe block below calls Vite's
// own build() (which runs esbuild) directly. jsdom's TextEncoder polyfill
// breaks an esbuild environment invariant it relies on
// ("new TextEncoder().encode("") instanceof Uint8Array"), so the whole file
// (not just that block — vitest environments are per-file) runs under node
// instead of the suite's default jsdom.
// @vitest-environment node
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { build, loadEnv } from "vite";
import { buildCsp, originOf } from "./cspPolicy";

// web/ (this file is web/src/lib/cspPolicy.test.ts).
const webRoot = fileURLToPath(new URL("../../", import.meta.url));
const viteConfigFile = join(webRoot, "vite.config.ts");

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

describe("buildCsp", () => {
  it("emits connect-src 'self' only when no RPC URL is configured", () => {
    const csp = buildCsp("");
    expect(csp).toContain("connect-src 'self';");
    // Regression guard: connect-src must be an EXPLICIT
    // directive in this string, never merely implied by default-src's
    // fallback — CSP Level 3 falls back connect-src to default-src when the
    // directive is absent, which is exactly the bug this replaces.
    expect(csp).toMatch(/connect-src '/);
  });

  it("bakes the RPC origin into connect-src alongside 'self' when VITE_SOLANA_RPC_URL is set", () => {
    const csp = buildCsp("https://rpc.example.com/some/path");
    expect(csp).toContain("connect-src 'self' https://rpc.example.com;");
  });

  it("also bakes the WS origin into connect-src when VITE_SOLANA_WS_URL is set — the WebSocket transport confirmTransaction opens is a distinct origin from the HTTP RPC", () => {
    const csp = buildCsp(
      "http://localhost:8899",
      "ws://localhost:8900/some/path",
    );
    expect(csp).toContain(
      "connect-src 'self' http://localhost:8899 ws://localhost:8900;",
    );
  });

  it("throws rather than silently omitting the WS origin when VITE_SOLANA_WS_URL is set but malformed", () => {
    expect(() => buildCsp("http://localhost:8899", "not-a-url")).toThrow(
      /VITE_SOLANA_WS_URL/,
    );
  });

  it("still restricts default-src/script-src/style-src/object-src as before", () => {
    const csp = buildCsp("");
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("style-src 'self'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).not.toMatch(/unsafe-inline/);
    expect(csp).not.toMatch(/unsafe-eval/);
  });

  it("omits frame-ancestors — that directive is browser-header-only and stays server-side", () => {
    expect(buildCsp("")).not.toMatch(/frame-ancestors/);
  });

  it("throws rather than silently shipping connect-src 'self' when VITE_SOLANA_RPC_URL is set but malformed", () => {
    expect(() => buildCsp("not-a-url")).toThrow(/VITE_SOLANA_RPC_URL/);
  });

  // upgrade-insecure-requests silently rewrites a plain
  // http:/ws: connect-src origin to https:/wss: in the browser — fine for a
  // loopback RPC node (browsers exempt loopback from the rewrite), but a
  // self-defeating, opaque-network-error trap for any real deployment.
  describe("plain http:/ws: origins vs upgrade-insecure-requests", () => {
    it("throws for a NON-loopback plain-http VITE_SOLANA_RPC_URL", () => {
      expect(() => buildCsp("http://rpc.example.com")).toThrow(
        /VITE_SOLANA_RPC_URL/,
      );
    });

    it("throws for a NON-loopback plain-ws VITE_SOLANA_WS_URL", () => {
      expect(() =>
        buildCsp("https://rpc.example.com", "ws://rpc.example.com"),
      ).toThrow(/VITE_SOLANA_WS_URL/);
    });

    it("accepts a loopback plain-http RPC URL and drops upgrade-insecure-requests so the policy doesn't contradict it", () => {
      const csp = buildCsp("http://localhost:8899");
      expect(csp).toContain("connect-src 'self' http://localhost:8899");
      expect(csp).not.toMatch(/upgrade-insecure-requests/);
    });

    it("accepts a loopback plain-ws WS URL alongside a loopback RPC URL, also dropping upgrade-insecure-requests", () => {
      const csp = buildCsp("http://127.0.0.1:8899", "ws://127.0.0.1:8900");
      expect(csp).toContain(
        "connect-src 'self' http://127.0.0.1:8899 ws://127.0.0.1:8900",
      );
      expect(csp).not.toMatch(/upgrade-insecure-requests/);
    });

    it("keeps upgrade-insecure-requests when the RPC/WS origins are https/wss (the normal, non-loopback case)", () => {
      const csp = buildCsp(
        "https://rpc.example.com",
        "wss://rpc.example.com",
      );
      expect(csp).toMatch(/upgrade-insecure-requests/);
    });

    it("keeps upgrade-insecure-requests when no RPC/WS URL is configured", () => {
      expect(buildCsp("")).toMatch(/upgrade-insecure-requests/);
    });
  });
});

// Regression coverage: the bug wasn't in buildCsp() itself (the
// suite above already covered the pure string builder) — it was in HOW
// vite.config.ts got values into buildCsp(). It read `process.env`, which
// Vite never populates from `.env*` files at config-evaluation time, so the
// generated CSP silently stayed `connect-src 'self'` while the bundle
// embedded a real RPC URL via `import.meta.env`. These two describe blocks
// exercise that handoff instead of just the string builder.
describe("vite config env-loading handoff", () => {
  it("loadEnv(mode, cwd, '') — the exact call vite.config.ts's defineConfig callback now makes — resolves .env.test's VITE_SOLANA_RPC_URL/VITE_SOLANA_WS_URL", () => {
    const env = loadEnv("test", webRoot, "");
    expect(env.VITE_SOLANA_RPC_URL).toBe("http://localhost:8899");
    expect(env.VITE_SOLANA_WS_URL).toBe("ws://localhost:8900");

    const csp = buildCsp(env.VITE_SOLANA_RPC_URL, env.VITE_SOLANA_WS_URL);
    expect(csp).toContain(
      "connect-src 'self' http://localhost:8899 ws://localhost:8900;",
    );
  });
});

describe("build-level CSP injection — real vite build, mode=test", () => {
  it("dist/index.html's CSP meta tag actually contains both the RPC and WS origins baked into the JS bundle, not just 'self'", async () => {
    const outDir = mkdtempSync(join(tmpdir(), "csp-build-test-"));
    try {
      await build({
        configFile: viteConfigFile,
        root: webRoot,
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
      // this is the same bundle the CSP above must actually unblock, exactly
      // reproducing the failure mode being guarded against (RPC URL in the
      // JS, but 'self' only in the CSP).
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
