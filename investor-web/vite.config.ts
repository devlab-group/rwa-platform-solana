import { defineConfig, loadEnv, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import { buildCsp } from "./src/lib/cspPolicy";

// The complete fetch-directive CSP string (KYC-provider widening + the
// Solana RPC/WS origin pins) is built by src/lib/cspPolicy.ts, importable
// from a normal test file since Vite config modules aren't loaded by vitest
// (see cspPolicy.test.ts). `injectCsp` below only wires the resulting string
// into the built HTML.

/**
 * Injects the CSP as a <meta> tag into the BUILT index.html only — never in
 * `vite dev`, whose HMR client needs a WebSocket connection and injects its
 * own inline bootstrap script that a strict CSP would break. `vite preview`
 * (and whatever static host serves the built `dist/`) serves the built file, so
 * the tag still applies there. That host should additionally set the CSP as a
 * real response header (frame-ancestors is only honored as a header, not a tag).
 */
function injectCsp(csp: string): Plugin {
  return {
    name: "inject-csp",
    apply: "build",
    transformIndexHtml(html) {
      return html.replace(
        "<head>",
        `<head>\n    <meta http-equiv="Content-Security-Policy" content="${csp}" />`,
      );
    },
  };
}

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  // loadEnv reproduces the exact same file-resolution Vite itself uses for
  // client-bundle `import.meta.env` access — config-time `process.env` is NOT
  // populated from `.env*` files, so reading it directly here would silently
  // desync the CSP from what's actually in the bundle (the same defect found
  // in web/, and found here too: this file used to call loadEnv but only
  // ever read env.VITE_KYC_PROVIDER, never the Solana RPC/WS vars, so a
  // Solana build's connect-src stayed 'self' while the bundle embedded a
  // real RPC URL).
  const env = loadEnv(mode, process.cwd(), "VITE_");
  return {
    plugins: [
      react(),
      injectCsp(
        buildCsp(
          env.VITE_KYC_PROVIDER || undefined,
          env.VITE_SOLANA_RPC_URL || undefined,
          env.VITE_SOLANA_WS_URL || undefined,
        ),
      ),
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
