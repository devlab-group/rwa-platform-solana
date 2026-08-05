# investor-web/ — standalone example investor SPA

Vite + React + TypeScript + `@solana/web3.js`/Anchor. A **self-contained reference** a client
forks to build their own investor-facing UI for the self-hosted RWA platform. It is NOT part of
the admin console (`web/`) and is NOT embedded by the Go server — it's a separate app
deployed/hosted by whoever runs the platform, talking to the same server over HTTP.

## What it is / isn't

- One screen: `src/routes/investor/Investor.tsx` (wallet connect + ownership challenge, KYC
  status, balance/compliance, buy quote→buy, redemption quote→request→timeout-cancel→claim,
  transfer, tx history), mounted by a minimal `App.tsx` + `InvestorHeader`.
- Talks ONLY to the server's public and `X-Wallet-Session` endpoints — never the admin JWT.
- Every on-chain action is encoded client-side from pinned Anchor IDLs (`lib/idl/`) and broadcast
  from the connected wallet (`lib/wallet.ts`); the server builds no transaction.

## Rules

- Keep it self-contained: it deliberately does NOT import from `web/`. Shared logic was copied
  in and trimmed to the investor subset. If you improve a shared file here, that's fine — this is
  a fork, not a package dependency.
- `src/lib/api-types.ts` is the generated OpenAPI types, committed as-is (no `gen:api` here).
  If the server's `api/openapi.yaml` changes, regenerate it manually and copy it in.
- Configure the server URL via `VITE_API_BASE_URL` (defaults to same-origin `""`).
- No private keys in the browser; wallet via a Wallet Standard / Phantom-style injected
  `window.solana` provider. Every deployment's own Solana program ids/mints/RPC endpoint must be
  pinned at build time via `VITE_SOLANA_*` (see `lib/chain/pins.ts`, README.md).

## Commands

`npm install`, `npm run dev`, `npm run typecheck`, `npm test`, `npm run build`. Playwright under
`tests/`. From root: `make investor-web-test`.
