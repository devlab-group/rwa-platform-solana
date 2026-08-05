// Pure CSP-string builder shared by vite.config.ts's `injectCsp` build plugin
// and its own vitest coverage (src/lib/cspPolicy.test.ts). Kept out of
// vite.config.ts itself so it's importable from a normal test file — Vite
// config modules aren't loaded by vitest. Mirrors web/src/lib/cspPolicy.ts's
// `originOf` export and RPC/WS-pinning shape, extended with this app's
// own KYC-provider connect-src/frame-src widening (this SPA embeds a KYC
// vendor's web SDK; the admin console never does) and a non-loopback
// plain-http/ws guard.
//
// This is the SOLE source of the fetch-directive policy the built index.html
// ships (a <meta> tag, injected only for `apply: "build"` — see
// vite.config.ts): every RPC call (`@solana/web3.js`'s `Connection`,
// an ordinary same-page `fetch()`/WebSocket) is blocked unless its origin is
// baked into `connect-src` here at build time.

/** Extracts scheme+host+port from a URL, dropping any path — a CSP source
 * expression matches a path literally, so a `/v1/rpc`-suffixed URL would
 * otherwise narrow connect-src to that exact path. Returns "" on an
 * unparseable URL so the caller can fail loudly rather than silently permit
 * nothing. */
export function originOf(url: string): string {
  try {
    return new URL(url).origin;
  } catch {
    return "";
  }
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);

/**
 * True when `url` is plain `http:`/`ws:` on a NON-loopback host — the one
 * combination `upgrade-insecure-requests` (appended to every build of this
 * policy, see buildCsp below) silently breaks: browsers exempt loopback from
 * the http->https/ws->wss rewrite, so `http://localhost:8899` still connects,
 * but any other plain-http origin gets rewritten to a scheme the RPC node
 * doesn't serve and fails with an opaque network error rather than a CSP
 * violation. Returns false (not our problem — let originOf's
 * caller report it) on an unparseable URL.
 */
function isNonLoopbackInsecure(url: string): boolean {
  try {
    const u = new URL(url);
    if (u.protocol !== "http:" && u.protocol !== "ws:") return false;
    return !LOOPBACK_HOSTS.has(u.hostname);
  } catch {
    return false;
  }
}

/**
 * The app's own content is entirely same-origin: no CDN scripts/fonts, no
 * external stylesheets, no images. This is the standalone investor example — a
 * client forks it and serves the built `dist/` from their own static host;
 * unlike the admin console it is NOT embedded in the platform's Go binary.
 * `frame-ancestors` is included for documentation but browsers only honor it
 * via an HTTP header, never a <meta> tag — whatever host serves this should
 * also set it (recommend 'none').
 */
const BASE_CSP: Record<string, string[]> = {
  "default-src": ["'self'"],
  "script-src": ["'self'"],
  "style-src": ["'self'"],
  "img-src": ["'self'"],
  "font-src": ["'self'"],
  "connect-src": ["'self'"],
  "frame-src": ["'none'"],
  "object-src": ["'none'"],
  "base-uri": ["'self'"],
  "form-action": ["'self'"],
  "frame-ancestors": ["'none'"],
};

/**
 * The one exception to "same-origin only": a KYC provider's web SDK, which
 * necessarily loads code from and streams captures to the provider. Widening
 * the policy for a provider a deployment doesn't use would be pure attack
 * surface, so it is opt-in per build via `VITE_KYC_PROVIDER` — leave it unset
 * (the default, and the right setting for a deployment with no KYC provider)
 * and the policy stays exactly as strict as it was.
 *
 * The entries below are what each SDK, as shipped in node_modules, actually
 * reaches for:
 *
 * - Sumsub is an iframe and nothing else: `@sumsub/websdk` creates an
 *   `<iframe>` at `<baseUrl>/websdk/websdk.html` (default baseUrl
 *   `https://in.sumsub.com`) and talks to it over postMessage. No script, no
 *   fetch, no worker runs in this origin, so `frame-src` carries the load.
 *   That iframe requests camera/microphone/geolocation through its `allow`
 *   attribute, so the serving host must NOT send a Permissions-Policy denying
 *   them — Sumsub's docs call for
 *   `camera=(self "https://api.sumsub.com"), microphone=(self "https://api.sumsub.com")`.
 * - Onfido runs *in this origin*: `onfido-sdk-ui` is a thin loader that
 *   dynamically imports `https://sdk.onfido.com/<version>/Onfido.js`, and the
 *   real SDK it pulls in does its own API calls, camera capture and
 *   cross-device handoff. Because that bundle is fetched at runtime, its hosts
 *   can't be read off node_modules — the entries below are Onfido's own
 *   published CSP guide (documentation.onfido.com/sdk/sdk-csp-guide/), which
 *   lists the regional API hosts explicitly. The four regional `connect-src`
 *   hosts cover every account region; drop the ones your account doesn't use.
 *
 * The `img-src`/`media-src`/`worker-src` blob: entries are NOT in Onfido's
 * guide — they're the usual needs of in-browser camera capture and are included
 * so a document/selfie step doesn't fail closed. Onfido also warns that the
 * guide omits some hosts, so run a real capture flow behind
 * Content-Security-Policy-Report-Only before trusting this in enforcing mode.
 */
const KYC_CSP: Record<string, Record<string, string[]>> = {
  sumsub: {
    // Sumsub publishes no CSP guide and no domain allowlist, and the iframe
    // origin varies by account region (in./api./api.uae. …), so this stays a
    // wildcard rather than a guess at one host.
    "frame-src": ["https://*.sumsub.com"],
    "connect-src": ["https://*.sumsub.com"],
  },
  onfido: {
    "script-src": ["https://sdk.onfido.com", "https://assets.onfido.com"],
    "style-src": ["https://sdk.onfido.com"],
    "font-src": ["https://sdk.onfido.com"],
    "connect-src": [
      "https://api.onfido.com",
      "https://api.eu.onfido.com",
      "https://api.us.onfido.com",
      "https://api.ca.onfido.com",
      "wss://*.onfido.com",
    ],
    "frame-src": ["https://sdk.onfido.com"],
    "img-src": ["data:", "blob:"],
    "media-src": ["blob:"],
    "worker-src": ["'self'", "blob:"],
  },
};

/**
 * Builds the complete fetch-directive CSP string baked into the built
 * index.html's meta tag.
 *
 * `kycProvider` is `VITE_KYC_PROVIDER` — widens the policy for that vendor's
 * SDK, or throws for an unrecognized value (see KYC_CSP).
 *
 * `rpcUrl`/`wsUrl` are `VITE_SOLANA_RPC_URL`/`VITE_SOLANA_WS_URL`
 * — when either is unset, `connect-src` is simply not widened for it.
 * `wsUrl` matters because the `Connection`'s WebSocket
 * transport (used by `confirmTransaction`/account subscriptions) is a
 * DISTINCT origin from the HTTP RPC endpoint (e.g. `http://localhost:8899` ->
 * `ws://localhost:8900`), so it needs its own `connect-src` entry or the
 * browser blocks confirmation. Throws if either URL is set but not a valid
 * URL, or is a non-loopback plain `http:`/`ws:` origin —
 * rather than silently shipping a `connect-src` that would block, or that
 * `upgrade-insecure-requests` would silently rewrite into, a broken
 * connection.
 */
export function buildCsp(
  kycProvider: string | undefined,
  rpcUrl?: string,
  wsUrl?: string,
): string {
  const extra = kycProvider ? KYC_CSP[kycProvider] : undefined;
  if (kycProvider && !extra) {
    throw new Error(
      `VITE_KYC_PROVIDER=${kycProvider} is not a provider this build knows how to allow ` +
        `(expected one of: ${Object.keys(KYC_CSP).join(", ")}).`,
    );
  }

  const merged: Record<string, string[]> = { ...BASE_CSP };
  for (const [directive, sources] of Object.entries(extra ?? {})) {
    const base = (merged[directive] ?? []).filter((s) => s !== "'none'");
    merged[directive] = [...new Set([...base, ...sources])];
  }

  const rpcOrigins: string[] = [];
  for (const [envVar, url] of [
    ["VITE_SOLANA_RPC_URL", rpcUrl],
    ["VITE_SOLANA_WS_URL", wsUrl],
  ] as const) {
    if (!url) continue;
    const origin = originOf(url);
    if (!origin) {
      throw new Error(`${envVar} is set but not a valid URL: "${url}"`);
    }
    if (isNonLoopbackInsecure(url)) {
      throw new Error(
        `${envVar} ("${url}") is a non-loopback plain http/ws endpoint. This CSP ` +
          `also sends upgrade-insecure-requests, which browsers apply to ANY ` +
          `http:/ws: source: the connection is silently rewritten to https/wss and ` +
          `fails, since the RPC node serves no TLS on that port. ` +
          `Use an https/wss endpoint, or serve the RPC over loopback (localhost/127.0.0.1).`,
      );
    }
    rpcOrigins.push(origin);
  }
  if (rpcOrigins.length > 0) {
    merged["connect-src"] = [
      ...new Set([...(merged["connect-src"] ?? []), ...rpcOrigins]),
    ];
  }

  return [
    ...Object.entries(merged).map(
      ([directive, sources]) => `${directive} ${sources.join(" ")}`,
    ),
    "upgrade-insecure-requests",
  ].join("; ");
}
