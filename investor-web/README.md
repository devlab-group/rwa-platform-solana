# investor-web — example investor SPA

A standalone, investor-facing single-page app for the self-hosted RWA
tokenization platform. It is a **reference example**: fork it, restyle it, and
build your own investor UI on top.

Vite + React + TypeScript, SCSS, `@solana/web3.js` + Anchor over a Wallet
Standard / Phantom-style injected `window.solana` provider. No wallet SDK
beyond that and no CDN assets of its own; the only third-party code it will
load is the KYC provider's web SDK, and only on a deployment that has one
configured (see [Identity verification](#identity-verification-kyc)).

## What it does

Everything an investor needs against one deployed project:

- **Connect a wallet** and prove ownership of the address — request a
  challenge, sign it with the wallet's Wallet Standard `signMessage`, submit
  the signature. The server returns a short-lived, address-scoped session
  token.
- **KYC / compliance status** for the connected address, read back through
  that session.
- **Identity verification (KYC)** — start a verification for the address you
  proved you own and complete it in the provider's own web SDK, embedded in the
  page. Approval lands on-chain by itself; see below.
- **Balance and compliance** — RWA balance read straight from the Token-2022
  mint's associated token account.
- **Buy**: preview a quote read from the pricing program's on-chain `Strategy`
  account, then broadcast the vault program's `buy` instruction with a
  slippage-bounded spend ceiling and a deadline. There is no approve step —
  the buyer signs the transfer directly.
- **Redemption**: preview a quote, request the redemption, then either claim
  it once the issuer funds it (permissionless) or cancel it once the on-chain
  timeout has elapsed.
- **Transfer** with a recipient-eligibility preflight (RWA transfers require
  both parties to be Allowed on-chain, so the UI checks before letting you
  submit).
- **Transaction history** from the server's on-chain index.

Every on-chain action is broadcast from the connected wallet. The instruction
is encoded **in the browser** from the pinned Anchor IDLs in `src/lib/idl/` —
the server never builds a transaction, so a compromised server cannot
redirect a call by itself. The buy/redemption quote is also read on-chain
rather than trusted from the server: the pricing program's `Strategy` account
directly, so the price a slippage bound is derived from comes from the chain
that will honour it. "A compromised server cannot redirect a call" further
depends on pinning the deployment's own program ids/mints at build time — see
[Pin the deployment's program ids and mints](#pin-the-deployments-program-ids-and-mints).
The app holds no private key and never asks for one.

## How it talks to the server

Only two kinds of endpoint, both from the platform's public HTTP contract
(`api/openapi.yaml`):

- **Public, unauthenticated**: `GET /api/v1/project`, `GET /api/v1/config`,
  `GET /api/v1/redemptions`, `GET /api/v1/transactions`,
  `GET /api/v1/compliance/allowed/{address}`,
  `POST /api/v1/compliance/challenge`, `POST /api/v1/compliance/challenge/verify`.
- **`X-Wallet-Session`**: `GET /api/v1/me/wallet-status` and
  `POST /api/v1/compliance/kyc/start`. The token is minted by challenge-verify,
  scoped to the one address that proved ownership, and stored in `localStorage`
  keyed by that address. Disconnecting the wallet drops it.

There is **no admin JWT** and no `Authorization: Bearer` header anywhere in
this app. `src/lib/client.ts` wraps only the calls listed above;
`src/lib/api-types.ts` is generated from the platform's OpenAPI document and
shipped here as-is (do not hand-edit it).

## Identity verification (KYC)

`POST /api/v1/compliance/kyc/start` opens a verification with whichever provider
the server is configured for and returns the token its official web SDK needs.
The subject wallet is taken from the session server-side — the browser never
names an address — and the response says which SDK to mount:

| `provider` | What the page does                                                                                       |
| ---------- | -------------------------------------------------------------------------------------------------------- |
| `sumsub`   | Mounts `@sumsub/websdk-react` with `token`; re-calls `/kyc/start` when Sumsub reports the token expired. |
| `onfido`   | Mounts `onfido-sdk-ui` in Studio workflow mode with `token` and `ref` as the `workflowRunId`.            |
| `generic`  | Shows "verification is arranged directly with the issuer" — same as a `501`, which means no provider.    |

The browser decides nothing about the outcome. Documents go straight to the
provider, the provider calls the server's signed webhook, and the server flips
the wallet to Allowed **on-chain**. So once the SDK signals it's done, the page
just polls `GET /api/v1/me/wallet-status` every 5s (giving up after 3 minutes
and offering a manual re-check — provider review can take hours and a browser
tab is a poor place to wait for one). There is nothing for the investor to sign
or submit.

Both SDKs load code and stream captures from their vendor's own origins, which
the SPA's default `'self'`-only CSP forbids. Set `VITE_KYC_PROVIDER` at build
time to widen it for exactly the provider you use — see the table below. Leave
it unset on a deployment with no KYC provider and the CSP stays as tight as it
was.

Two caveats before you enable one in production. Onfido's published CSP guide
warns it isn't exhaustive, and Sumsub publishes no allowlist at all — do a pass
with `Content-Security-Policy-Report-Only` through a real document-capture flow
and fix up `vite.config.ts` from what it reports. Separately, both SDKs need
camera and microphone: whatever serves `dist/` must not send a
`Permissions-Policy` that denies them.

## Configuration

| Variable            | Default            | Meaning                                                                                                                                                                                                                                                                        |
| ------------------- | ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `VITE_API_BASE_URL` | `""` (same origin) | Base URL of the platform API. Set it when the SPA is served from a different origin than the server, e.g. `VITE_API_BASE_URL=https://rwa.example.com`.                                                                                                                         |
| `VITE_KYC_PROVIDER` | unset              | `sumsub` or `onfido`. Build-time only, and only affects the CSP: it widens the injected policy for that provider's SDK. Leave unset when the deployment has no KYC provider. An unrecognised value fails the build rather than shipping a policy that silently blocks the SDK. |

### Cross-origin access (CORS)

Whenever `VITE_API_BASE_URL` points at a different origin than the one serving
this SPA — which is the normal case in development, and the whole point of this
app being a separate deployable — **the server must allowlist this app's
origin** or the browser blocks every request:

```yaml
# server config.yaml
http:
  cors_allowed_origins: ["http://localhost:5173"]
```

The match is exact (scheme + host + port), so use whatever origin the dev
server actually prints on startup — Vite defaults to `5173` unless you pass
`--port`. A near-miss silently never matches, and it presents as a plain CORS
failure with nothing in the server log explaining why. The server refuses `*`,
a trailing slash, or a missing scheme at startup rather than accepting a value
that could not work (or, for `*`, must not).

The embedded admin console needs none of this: it is served same-origin from
the platform binary itself.

The project addresses, token decimals, and finality threshold are not
configured here — they come from `GET /api/v1/project` at runtime. The
deployment's program ids/mints and RPC endpoint are pinned at build
time instead — see the next two sections — since there is no wallet-reported
"current chain" to check against.

### Pin the deployment's program ids and mints

A `buy`/`request`/`claim`/`cancel` instruction grants the invoked program CPI
authority over the signer's **entire** token account for that transaction, so
if the program id itself came from a compromised server, client-side
instruction building stops protecting you.

Set these at build time (see `.env.example`) to the deployment's actual
program ids/mints:

| Variable                                | Meaning                                          |
| ---------------------------------------- | ------------------------------------------------ |
| `VITE_SOLANA_PROGRAM_COMPLIANCE`         | rwa-compliance program id                        |
| `VITE_SOLANA_PROGRAM_VAULT`              | rwa-vault program id                              |
| `VITE_SOLANA_PROGRAM_PRICING`            | rwa-pricing program id                            |
| `VITE_SOLANA_PROGRAM_TRANSFER_HOOK`      | rwa-transfer-hook program id                      |
| `VITE_SOLANA_PROGRAM_REDEMPTION`         | rwa-redemption program id                         |
| `VITE_SOLANA_PROGRAM_SUPPLY_CONTROLLER`  | rwa-supply-controller program id (not yet used by any investor-web instruction; pinned for completeness) |
| `VITE_SOLANA_RWA_MINT`                   | the RWA Token-2022 mint                           |
| `VITE_SOLANA_QUOTE_MINT`                 | the quote/collateral mint                         |

Every buy/redemption/transfer call hard-asserts the equivalent value it gets
at runtime from `GET /api/v1/config` and `GET /api/v1/project` against these
pins **before** building any instruction, and refuses (throws) on a mismatch.
If a pin is left unset, that value falls back to trusting the server, and the
app shows a visible warning banner — a production build should have every one
of them set. Pins bind the program identity itself, not just which RPC
endpoint or cluster the app talks to (see the next section).

The quote-token program (legacy SPL Token vs. Token-2022) is never assumed —
it's resolved from the quote mint's own on-chain owner at call time (mirrors
the on-chain `validate_quote_mint` check), so a Token-2022 quote mint works
without any extra configuration.

Buy/redemption quotes and their slippage bounds are read directly from the
pricing program's on-chain `Strategy` account (via the pinned
`VITE_SOLANA_PROGRAM_PRICING`), never from the server's cached price.

### Pin the RPC endpoint too

`VITE_SOLANA_RPC_URL` (see `.env.example`) is part of the same trust
boundary as the program id/mint pins above. Every read and write in
this app (`getConnection(...)`) goes through whichever RPC node
`lib/chain/pins.ts`'s `resolveRpcUrl()` returns, and that function's *only*
source is this build-time variable: `GET /api/v1/project` does not return an
RPC endpoint at all — there is no server value left to read or compare
against.

This wasn't always true: an earlier version shipped with the RPC URL sourced
from `Project.publicRpcUrl`, and a later pass pinned it while still falling
back to that server value when unpinned. The server field is
gone now (removed from the API entirely, not just left unread) and so is the
fallback to it — a compromised server could otherwise still redirect *which
node answers every question about the chain* (the on-chain price/`Strategy`
read, the quote mint's token-program lookup, the pre-signature simulation,
balances, redemption state, next-request-id) even though the program-id/mint
pins above stop it from redirecting *which program* gets called.

Leaving `VITE_SOLANA_RPC_URL` unset does **not** throw: `resolveRpcUrl()`
falls back to a hardcoded local-validator default
(`http://127.0.0.1:8899`), the same unpinned-dev-fallback shape as every
other pin in this file — useful for `npm run dev`/`npm test` against a local
validator, useless (and silently wrong) for a real deployment. It's included
in the same required-pins check as the program ids/mints above precisely so
that case is caught: an unpinned deployment shows the visible warning
banner, which is what actually enforces this in practice rather than a
thrown error.

`VITE_SOLANA_CLUSTER_GENESIS` is an optional further check: once per
session, the app compares the connected RPC's `getGenesisHash()` against it,
catching a wrong-cluster endpoint that still looks like a plausible URL
(mirrors the equivalent server-side fix).

## Commands

```bash
npm install
npm run dev         # dev server
npm run build       # typecheck + production build to dist/
npm run preview     # serve the production build
npm test            # vitest unit/component tests
npm run typecheck   # tsc, no emit
npm run lint        # eslint
npm run test:e2e    # build + Playwright critical-flow suite (tests/)
```

`dist/` is a plain static bundle — serve it from any static host, or from the
platform server itself if you point it at this build output.

`package.json` pins `overrides: { "utf-8-validate": "5.0.10" }` — keep it if you
fork this app. Inside the `@solana/web3.js` tree, `jayson`'s nested `ws@7`
peer-depends on `^5.0.2` of that optional native accelerator while
`rpc-websockets` lists `^6.0.0`, and no single hoisted version satisfies both.
The tree still installs, but the invalid edge makes `npm sbom` fail outright and
makes npm 10 and npm 11 disagree on the lockfile, so `npm ci` breaks on whichever
major did not write it. `5.0.10` satisfies every consumer at once. It never
reaches the browser bundle — this only affects Node-side tooling.

## Layout

```
src/
  main.tsx                  entry: WalletProvider + router
  App.tsx                   shell + the single route
  components/               header, wallet connect, the shared
                            async/pagination/status/tx-preview pieces, and
                            the Sumsub/Onfido SDK wrappers
  context/                  WalletProvider — connected account
  hooks/                    useAsync, usePaginatedList, useWallet,
                            useHookProgramId
  lib/
    idl/                    pinned Anchor IDLs (vault, redemption, pricing)
    wallet.ts               senders + reads over window.solana
    chain/                  Wallet Standard provider, PDA derivation,
                            build-time program id/mint/RPC pins
    client.ts               typed fetch wrapper for the endpoints above
    api-types.ts            generated from api/openapi.yaml — do not edit
    walletSession.ts        X-Wallet-Session storage, keyed by address
    slippage.ts decimals.ts format.ts status.ts
  routes/investor/          the whole UI, plus KycVerification.tsx (start a
                            verification, mount the provider SDK, poll for
                            approval)
  styles/                   SCSS tokens + layout
tests/                      Playwright specs, mocked API and mocked wallet
```

## Building your own

The pieces worth keeping when you restyle: `lib/idl/` and `lib/wallet.ts`
(instructions must stay client-side), `lib/slippage.ts` (the bounds shown to
the user must be the bounds sent on-chain), and the transaction-preview
component — before any submission, show the target program/accounts, amounts
and units, price side, quote token, slippage bounds, and confirmation state.
Treat indexed data as unconfirmed until the project's finality threshold, and
never present a pending redemption as guaranteed. Keep `lib/chain/pins.ts`
and fill in its `VITE_SOLANA_*` build vars — that's what makes "the server
can't redirect a call" true (see Configuration above); don't ship a build
with them unset.
