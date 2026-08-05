// Pure CSP-string builder shared by vite.config.ts's `injectCsp` build plugin
// and its own vitest coverage (src/lib/cspPolicy.test.ts). Kept out of
// vite.config.ts itself so it's importable from a normal test file — Vite
// config modules aren't loaded by vitest.
//
// See CSP-AUDIT.md: the meta tag is now the SOLE source of the fetch-directive
// policy (the server no longer emits connect-src on SPA responses), so this
// builder is what makes RPC calls (an ordinary same-page fetch()) work
// at all — it bakes VITE_SOLANA_RPC_URL's origin into connect-src at build
// time, since a browser CSP can only allow-list an origin it's told about
// then, not one a server config could supply later.

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

/** Loopback hosts browsers exempt from upgrade-insecure-requests — a plain
 * http/ws endpoint here is genuinely reachable as-is, unlike anywhere else. */
function isLoopbackHost(hostname: string): boolean {
  return (
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "::1" ||
    hostname.endsWith(".localhost")
  );
}

/**
 * Guards against a self-defeating CSP: `upgrade-insecure-requests` (below)
 * silently rewrites any plain http:/ws: connect-src origin to https:/wss: in
 * the browser. Loopback hosts are exempt from that rewrite (per the Fetch
 * spec's "potentially trustworthy origin" rules), so a local dev RPC node
 * still works; anywhere else, the browser upgrades the request to a scheme
 * the endpoint doesn't serve, and the connection fails with an opaque network
 * error rather than a CSP violation. Throws for a non-loopback
 * plain endpoint — there's no legitimate reason to run a public
 * RPC/WS endpoint over plain http/ws — and returns whether the origin is a
 * plain-scheme loopback one, so the caller can drop the contradictory
 * directive in that case instead of shipping both.
 */
function checkUpgradeSafety(url: string, envVarName: string): boolean {
  const { protocol, hostname } = new URL(url);
  const isPlain = protocol === "http:" || protocol === "ws:";
  if (!isPlain) return false;
  if (!isLoopbackHost(hostname)) {
    const secureScheme = protocol === "http:" ? "https:" : "wss:";
    throw new Error(
      `${envVarName} is a non-loopback plain-${protocol} origin, but the CSP's ` +
        `upgrade-insecure-requests directive silently rewrites it to ${secureScheme} ` +
        "in the browser — a scheme this endpoint doesn't serve, so the connection " +
        "would fail with an opaque network error. Use an https/wss URL, or a " +
        "loopback host (localhost/127.0.0.1) for a local dev RPC node.",
    );
  }
  return true;
}

/**
 * Builds the complete fetch-directive CSP string baked into the built
 * index.html's meta tag. `rpcUrl` is `VITE_SOLANA_RPC_URL` — empty when
 * no RPC endpoint is configured, in which case connect-src is just
 * `'self'`. `wsUrl` is
 * `VITE_SOLANA_WS_URL` — the `Connection`'s WebSocket transport (used
 * by `confirmTransaction`/account subscriptions) is a DISTINCT origin from
 * the HTTP RPC endpoint (e.g. `http://localhost:8899` -> `ws://localhost:8900`),
 * so it needs its own `connect-src` entry or the browser blocks confirmation.
 * Throws if either URL is set but not a valid URL, rather
 * than silently shipping a `connect-src` that would block the corresponding
 * calls; also throws for a non-loopback plain http:/ws: URL (see
 * checkUpgradeSafety) rather than shipping a CSP that's self-defeating for it.
 */
export function buildCsp(rpcUrl: string, wsUrl?: string): string {
  const rpcOrigin = rpcUrl ? originOf(rpcUrl) : "";
  if (rpcUrl && !rpcOrigin) {
    throw new Error(
      `VITE_SOLANA_RPC_URL is set but not a valid URL: "${rpcUrl}"`,
    );
  }
  const wsOrigin = wsUrl ? originOf(wsUrl) : "";
  if (wsUrl && !wsOrigin) {
    throw new Error(
      `VITE_SOLANA_WS_URL is set but not a valid URL: "${wsUrl}"`,
    );
  }

  const rpcIsPlainLoopback = rpcUrl
    ? checkUpgradeSafety(rpcUrl, "VITE_SOLANA_RPC_URL")
    : false;
  const wsIsPlainLoopback = wsUrl
    ? checkUpgradeSafety(wsUrl, "VITE_SOLANA_WS_URL")
    : false;

  const connectSrc = ["'self'", rpcOrigin, wsOrigin].filter(Boolean).join(" ");
  const directives = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self'",
    "font-src 'self'",
    `connect-src ${connectSrc}`,
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ];
  // Dropped when a configured endpoint is deliberately plain-http(s)
  // on a loopback host — otherwise this directive would silently contradict
  // the pinned endpoint (see checkUpgradeSafety) even though loopback's
  // upgrade-exemption means nothing was actually broken; keeping the two
  // directives from ever contradicting each other is simpler than relying on
  // every reader to know the loopback exemption exists.
  if (!rpcIsPlainLoopback && !wsIsPlainLoopback) {
    directives.push("upgrade-insecure-requests");
  }
  return directives.join("; ");
}
