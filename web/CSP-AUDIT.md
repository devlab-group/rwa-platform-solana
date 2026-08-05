# CSP & no-secret-in-browser audit

## Content-Security-Policy

Shipped as a `<meta http-equiv="Content-Security-Policy">` tag, injected into
`dist/index.html` at build time only (`vite.config.ts`'s `injectCsp` plugin —
`apply: "build"`, so `npm run dev`'s HMR client, which needs an inline
bootstrap script and a WebSocket, is unaffected; `npm run preview` and the Go
server, which embeds `dist/`, both serve the tagged file).

```
default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self';
font-src 'self'; connect-src 'self' <VITE_SOLANA_RPC_URL origin, if set>;
object-src 'none'; base-uri 'self'; form-action 'self';
upgrade-insecure-requests
```

No `'unsafe-inline'` or `'unsafe-eval'` anywhere. This was reachable because:

- **No inline `style` attributes.** The 10 pre-existing `style={{...}}` React
  props were replaced with plain CSS utility classes (`u-mt-4`, `u-mt-5`,
  `field--narrow`, `field--slim` in `src/styles/_base.scss`) — otherwise
  `style-src` would have needed `'unsafe-inline'`, which defeats most of the
  point of a style CSP.
- **No `dangerouslySetInnerHTML`, `eval`, or `new Function`** anywhere in
  `src/` (grepped, confirmed clean) — React's default JSX text rendering
  escapes everything, so `style-src`/`script-src` never need inline
  allowances for that either.
- All CSS is Vite-built into one external stylesheet; all JS into
  same-origin chunks (see route-code-splitting below). No CDN scripts,
  fonts, or images — `public/` is empty, no `<img>` tags exist.

**The meta tag now carries the FULL fetch-directive policy, `connect-src`
included — the server's response header no longer sets it at all.** This is
a deliberate reversal from the earlier design (server-header-only
`connect-src`, meta tag silent on it), which turned out to be broken in
practice: the meta tag still had `default-src 'self'`, and per
CSP Level 3 an absent `connect-src` **falls back to `default-src`** — so the
meta policy was silently capping `fetch`/XHR/WebSocket at `'self'` regardless
of anything the server's header allowed, since a browser enforces the
*intersection* of the two policies. The Solana RPC endpoint is now
BUILD-TIME only (`VITE_SOLANA_RPC_URL`, read at build in `vite.config.ts` and
at runtime in `lib/chain.ts` via `import.meta.env`, not from
`GET /config`/`GET /project` — the server no longer supplies a `publicRpcUrl`
field at all), which is exactly what makes emitting a correct `connect-src`
here possible: the build knows the RPC origin, so it can bake
`connect-src 'self' <that origin>` directly into the one policy source that
actually governs same-page fetches.

- `lib/chain.ts`'s `Connection` (`@solana/web3.js`) makes
  ordinary same-page `fetch()` calls straight to `VITE_SOLANA_RPC_URL` — the
  injected `window.solana` provider only signs; it doesn't proxy RPC
  reads/sends, so there is no out-of-page channel that could bypass the
  page's CSP the way a browser extension's own channel would. `injectCsp`
  parses the env var's origin (scheme+host+port,
  dropping any path) and emits `connect-src 'self' <that origin>`; an
  invalid `VITE_SOLANA_RPC_URL` fails the build outright rather than
  silently shipping a `connect-src 'self'` that would block every RPC call.

Note this build-time pin is a CSP-mechanics fix for the ADMIN console, not a
trust-boundary claim the way `investor-web`'s RPC pin is: the
Go server serves this very bundle, so the RPC endpoint baked into it is
already server-trusted either way. It matters here purely because a browser
CSP has to allow-list an origin it can be told about, and only a build-time
value can be baked into the one policy source (the meta tag) that now
carries `connect-src` at all.

**What's left to the server: `frame-ancestors` only.** Browsers ignore
`frame-ancestors` (and `report-uri`/`report-to`) in a `<meta>` tag; it only
takes effect via a real `Content-Security-Policy` **response header**, so it
is deliberately NOT in the meta tag above (an omission there would look like
an oversight if it were still being documented as intent-only — it isn't
carried here at all now). The Go server sends `frame-ancestors 'none'` as a
response header on SPA routes; `web/` has no way to set it itself. Also
recommend the server set `X-Content-Type-Options: nosniff` and
`Referrer-Policy: no-referrer` while it's at it — standard hardening, outside
`web/`'s reach to set itself.

**Verified**: full Playwright suite (44 specs, wallet-interaction flows
included — buy/approve, redemption request/claim/cancel, transfer) passes
against the CSP'd **production** build (`npm run build`, which now forces
`NODE_ENV=production` — see below) via `vite preview`, so the policy
doesn't break any real flow. Regression-guarded by `tests/specs/csp.spec.ts`.

**Unrelated but adjacent build-hygiene fix that turned up while writing this**: this
sandbox's shell environment exports `NODE_ENV=development` globally. `vite
build` was inheriting it, silently producing a *development*-mode bundle
under the `build` command — visible as unstripped dev-only warnings/checks
in the output and, concretely, as React's Strict Mode double-invoking a
`useEffect` in a way that broke a focus-management test. `package.json`'s
`build` script now explicitly runs `NODE_ENV=production vite build` so this
can't happen regardless of the ambient shell (this also shrank every real
chunk — e.g. the main chunk from 371KB to 171KB — since dev-only code now
actually gets dead-code-eliminated). Worth checking whether the CI runner's
environment has the same leak.

## No-secret-in-browser

**Not secrets** (safe to be fully visible in the browser, network tab, and
DOM — this is the whole point of a self-custody design):
wallet addresses, quote amounts, instruction data (program id + accounts +
args for mint/pause/price/role-replace/fund/reject/withdraw, all of it built
locally against the checked-in Anchor IDLs in `lib/idl/*.json` — see
`lib/chain.ts`), auditor signatures (meant to be publicly verifiable),
profile digests/CIDs, transaction signatures.

**Real secret**: the admin session JWT. Admin auth is wallet-signature →
JWT, single-admin — the only account that can sign in is the project admin
address the server is configured with (the deployer).

**The flow** (`components/Login.tsx`): connect the admin wallet →
`POST /auth/challenge` with the connected address → the server returns a
single-use, time-limited challenge message → the wallet signs it with its
ed25519 signMessage (`lib/wallet.ts`'s `signMessage`, over the injected Solana
provider) → `POST /auth/session` carries address + signature → the server
verifies the signature against the configured admin address, and on a match
mints a stateless HMAC-signed JWT (`{token, expiresAt, role, address}`).
`lib/client.ts` attaches that token to every admin request as
`Authorization: Bearer <token>`.

**What the browser does and doesn't hold**:

- The **admin's signing key never touches the SPA**. It lives in the wallet
  extension; the page only ever asks for a signature over a message it
  displays first, and that's equally true of the login challenge and of
  every state-changing chain call. Compromising the browser does not
  compromise the key.
- The **JWT is the one real bearer credential in the page**, and it *is*
  persisted: `lib/authSession.ts` writes it through to IndexedDB
  (`lib/idb.ts` — database `rwa`, store `kv`, key `authSession`) behind an
  in-memory mirror that serves the synchronous read path, and `main.tsx`
  rehydrates it at startup so a reload doesn't bounce the admin back to the
  sign-in screen. This is a deliberate, accepted deviation from the earlier
  in-memory-only session, bought for exactly that: surviving a reload.
  Choosing IndexedDB over `localStorage` is a mild preference (async, not
  enumerable as plain strings off `window`), not a security boundary — it is
  still same-origin readable.
- The token is short-lived and dropped eagerly. `getSession()` discards it
  once the server-set `expiresAt` passes, `lib/client.ts` clears it on any
  `401` response, and **Log out** (`SessionControls.tsx`) clears it on
  demand; `AppLayout.tsx` renders `Login.tsx` in place of the admin
  `<Outlet/>` whenever there is no live session. Logout is purely
  client-side — the JWT is stateless, so there is no server-side revocation
  endpoint to call, and its TTL is what bounds a leaked token.
- Investor access uses a separate, narrower credential (`X-Wallet-Session`,
  scoped to a single address) and lives in the standalone `investor-web/`
  app. `web/` is admin-only and never handles it.

**Where that leaves XSS**: a bug that achieves same-origin script execution
can read the JWT out of IndexedDB, and — unlike the in-memory-only design —
can do so without the admin being actively signed in in that tab. What it
still cannot reach is the admin's private key, so it cannot sign anything
on-chain: the JWT authorizes the server's admin API surface, while every
privileged *chain* action needs a fresh wallet signature the operator sees
and approves in the extension. The blast radius is capped at the API side
for the token's remaining TTL, and that's the accepted cost of a session
that survives a reload. `script-src 'self'` with no
`'unsafe-inline'`/`'unsafe-eval'`, plus a confirmed absence of
`dangerouslySetInnerHTML`, remains the first line of defense against getting
script execution in the first place.

No chain private keys are ever handled in the browser (unchanged from the
original build) — every state-changing chain call is encoded client-side
from the pinned ABIs and signed by the connected wallet, the private key
never leaving the extension.
