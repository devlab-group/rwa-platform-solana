import { defineConfig, loadEnv, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import { buildCsp } from "./src/lib/cspPolicy";

// Everything this SPA loads is same-origin (self-hosted, embedded in the Go
// binary): no CDN scripts/fonts, no external stylesheets, no images. The
// RPC endpoint (lib/chain.ts's `Connection`, ordinary same-page
// fetch() calls — unlike EVM wallet RPC, which goes through window.ethereum's
// own out-of-page channel and is outside CSP entirely) is now BUILD-TIME only
// (`VITE_SOLANA_RPC_URL`/`VITE_SOLANA_WS_URL`), so this meta tag can — and
// must — carry the COMPLETE fetch-directive policy, including `connect-src`,
// itself: the server no longer supplies `publicRpcUrl` or emits `connect-src`
// in its own header (see CSP-AUDIT.md and src/lib/cspPolicy.ts, which builds
// the string and is unit-tested directly since vitest doesn't load this
// config module).
// `frame-ancestors` stays server-only — browsers only honor it via an HTTP
// response header, never a <meta> tag, so putting it here would be decorative
// at best and the server already sends it.

/**
 * Injects the CSP as a <meta> tag into the BUILT index.html only — never in
 * `vite dev`, whose HMR client needs a WebSocket connection and injects its
 * own inline bootstrap script that a strict CSP would break. `vite preview`
 * (and the server, which embeds `dist/`) serves the built file, so the tag
 * still applies there. See CSP-AUDIT.md for the full writeup.
 */
function injectCsp(rpcUrl: string, wsUrl: string): Plugin {
  return {
    name: "inject-csp",
    apply: "build",
    transformIndexHtml(html) {
      const csp = buildCsp(rpcUrl, wsUrl);
      return html.replace(
        "<head>",
        `<head>\n    <meta http-equiv="Content-Security-Policy" content="${csp}" />`,
      );
    },
  };
}

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  // Vite does NOT populate config-time `process.env` from mode-specific
  // `.env*` files — that resolution only happens for client-bundle
  // `import.meta.env` access. `loadEnv` reproduces the exact same
  // file-resolution Vite itself uses for `import.meta.env`, so the CSP baked
  // into the meta tag here is guaranteed to match what actually ends up in
  // the bundle (reading `process.env` directly silently baked
  // in `connect-src 'self'` while the bundle embedded a real RPC URL, so the
  // browser blocked every RPC call).
  const env = loadEnv(mode, process.cwd(), "");
  return {
    plugins: [
      react(),
      injectCsp(env.VITE_SOLANA_RPC_URL ?? "", env.VITE_SOLANA_WS_URL ?? ""),
    ],
    // Sass preprocessing needs no options: Vite 7 dropped the legacy Sass API
    // entirely and always uses the modern compiler API now, so the previous
    // `css.preprocessorOptions.scss.api: "modern-compiler"` opt-in is gone.
    build: {
      outDir: "dist",
      emptyOutDir: true,
    },
  };
});
