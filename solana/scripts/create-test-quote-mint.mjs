#!/usr/bin/env node
// create-test-quote-mint.mjs — create a throwaway stand-in for USDC on a test
// cluster, and fund some accounts with it.
//
// The bootstrap does NOT create the quote mint: `bootstrap.mjs` requires one to
// already exist and only checks that its decimals match the config. On mainnet
// that is real USDC. On devnet/testnet/localnet there is nothing to point at,
// so this script makes one.
//
//   node scripts/create-test-quote-mint.mjs --url https://api.devnet.solana.com \
//     --mint-to <PUBKEY>,<PUBKEY> --amount 1000000
//
// It creates a LEGACY SPL Token mint (not Token-2022), which is what real USDC
// is and what `validate_quote_mint` accepts unconditionally — a Token-2022
// quote mint is also supported by the programs, but only with a narrow set of
// transfer-neutral extensions, so the legacy program is the closer and duller
// match for a test double. Freeze authority is deliberately null: a freeze
// authority on the quote mint is a real counterparty risk the deployment
// manifest is supposed to record (solana/README.md step 10), and a test token
// should not quietly introduce one.
//
// Idempotent when given --mint-keypair: an existing mint at that address is
// reused rather than recreated, so re-running only tops accounts up. Without
// it, a fresh mint keypair is generated AND SAVED (see --keypair-out) — losing
// it means losing mint authority over the token.
//
// REFUSES TO RUN ON MAINNET-BETA. This mints an unbacked token to arbitrary
// accounts from a key on your laptop; it has no place on mainnet.

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { createRequire } from "node:module";
import { homedir } from "node:os";

const require = createRequire(import.meta.url);
const web3 = require("@solana/web3.js");
const spl = require("@solana/spl-token");
const { Connection, Keypair, PublicKey, LAMPORTS_PER_SOL } = web3;
const {
  TOKEN_PROGRAM_ID,
  createMint,
  mintTo,
  getMint,
  getOrCreateAssociatedTokenAccount,
} = spl;

const arg = (name, fallback = null) => {
  const i = process.argv.indexOf(name);
  return i > -1 ? process.argv[i + 1] : fallback;
};
const has = (name) => process.argv.includes(name);
const die = (m) => {
  console.error("ERROR:", m);
  process.exit(1);
};
const expand = (p) => (p?.startsWith("~") ? p.replace("~", homedir()) : p);
const loadKp = (p) =>
  Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(readFileSync(expand(p), "utf8"))),
  );

if (has("--help") || has("-h")) {
  console.log(`usage: node scripts/create-test-quote-mint.mjs [options]

  --url <RPC_URL>          default https://api.devnet.solana.com
  --payer <KEYPAIR>        fee payer + mint authority (default ~/.config/solana/id.json)
  --decimals <N>           default 6 (USDC's)
  --mint-keypair <PATH>    reuse/persist the mint address; created if absent
  --keypair-out <PATH>     where to save a generated mint keypair
                           (default ./test-quote-mint.json)
  --mint-to <PUBKEY,...>   recipients (default: the payer)
  --amount <UI_AMOUNT>     whole tokens per recipient, default 1000000
  --out <PATH>             write a small JSON summary here
`);
  process.exit(0);
}

const url = arg("--url", "https://api.devnet.solana.com");
const decimals = Number(arg("--decimals", "6"));
if (!Number.isInteger(decimals) || decimals < 0 || decimals > 9) {
  die(`--decimals must be an integer in [0,9], got ${arg("--decimals")}`);
}
// Parsed as a decimal string, never a float: 1e6 tokens at 9 decimals exceeds
// what a double can hold exactly, and silently minting the wrong supply is the
// kind of bug a "just a test token" script is most likely to get away with.
const amountUI = arg("--amount", "1000000");
if (!/^\d+$/.test(amountUI))
  die(`--amount must be a whole number of tokens, got ${amountUI}`);
const amountBase = BigInt(amountUI) * 10n ** BigInt(decimals);

const conn = new Connection(url, "confirmed");
const payer = loadKp(arg("--payer", "~/.config/solana/id.json"));

// genesis hash -> cluster label (same table verify-cluster.mjs uses).
const CLUSTERS = {
  "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d": "mainnet-beta",
  EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG: "devnet",
  "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY": "testnet",
};

const genesis = await conn.getGenesisHash();
const cluster = CLUSTERS[genesis] ?? "custom/local";
if (cluster === "mainnet-beta") {
  die(
    "refusing to create a test token on mainnet-beta — use the real quote mint (USDC) there",
  );
}
console.log(`cluster: ${cluster} (genesis ${genesis})`);
console.log(`payer:   ${payer.publicKey.toBase58()}`);

// Creating a mint plus one ATA per recipient is a few thousandths of a SOL, but
// an unfunded devnet key is the single most common way this fails, so say so
// up front with the fix rather than after a confusing simulation error.
const balance = await conn.getBalance(payer.publicKey);
if (balance < 0.05 * LAMPORTS_PER_SOL) {
  die(
    `payer has ${(balance / LAMPORTS_PER_SOL).toFixed(4)} SOL, need ~0.05\n` +
      `  fix: solana airdrop 2 ${payer.publicKey.toBase58()} --url ${url}`,
  );
}

// --- the mint --------------------------------------------------------------
const mintKeypairPath = arg("--mint-keypair");
let mintKp;
if (mintKeypairPath && existsSync(expand(mintKeypairPath))) {
  mintKp = loadKp(mintKeypairPath);
} else {
  mintKp = Keypair.generate();
}

let mint = mintKp.publicKey;
const existing = await conn.getAccountInfo(mint);
if (existing) {
  const info = await getMint(conn, mint, undefined, TOKEN_PROGRAM_ID);
  if (info.decimals !== decimals) {
    die(
      `mint ${mint.toBase58()} already exists with ${info.decimals} decimals, but --decimals says ${decimals}\n` +
        `  decimals are fixed at creation; pass --decimals ${info.decimals} or use a different --mint-keypair`,
    );
  }
  if (!info.mintAuthority?.equals(payer.publicKey)) {
    die(
      `mint ${mint.toBase58()} exists but its mint authority is ${info.mintAuthority?.toBase58() ?? "null"}, not the payer — cannot mint`,
    );
  }
  console.log(`mint:    ${mint.toBase58()} (already exists — reusing)`);
} else {
  mint = await createMint(
    conn,
    payer,
    payer.publicKey,
    null,
    decimals,
    mintKp,
    undefined,
    TOKEN_PROGRAM_ID,
  );
  console.log(
    `mint:    ${mint.toBase58()} (created, ${decimals} decimals, no freeze authority)`,
  );

  // Persist the keypair whenever we generated it: without this file nobody can
  // ever mint more of this token, which for a faucet-style test asset makes it
  // useless the moment testers run out.
  const outPath = expand(
    mintKeypairPath ?? arg("--keypair-out", "./test-quote-mint.json"),
  );
  writeFileSync(outPath, JSON.stringify(Array.from(mintKp.secretKey)));
  console.log(
    `         mint keypair saved to ${outPath} — keep it to mint more`,
  );
}

// --- fund the recipients ---------------------------------------------------
const recipients = (arg("--mint-to") ?? payer.publicKey.toBase58())
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean)
  .map((s) => {
    try {
      return new PublicKey(s);
    } catch {
      return die(`--mint-to: ${s} is not a valid base58 pubkey`);
    }
  });

console.log(`\nminting ${amountUI} tokens to ${recipients.length} account(s):`);
const funded = [];
for (const owner of recipients) {
  const ata = await getOrCreateAssociatedTokenAccount(
    conn,
    payer,
    mint,
    owner,
    false,
    undefined,
    undefined,
    TOKEN_PROGRAM_ID,
  );
  await mintTo(
    conn,
    payer,
    mint,
    ata.address,
    payer,
    amountBase,
    [],
    undefined,
    TOKEN_PROGRAM_ID,
  );
  console.log(`  ${owner.toBase58()} -> ata ${ata.address.toBase58()}`);
  funded.push({
    owner: owner.toBase58(),
    tokenAccount: ata.address.toBase58(),
  });
}

// --- what to do with it ----------------------------------------------------
console.log(`
== paste into scripts/bootstrap.config.json ==
  "quoteMint": "${mint.toBase58()}",
  "quoteDecimals": ${decimals}

== paste into the server config ==
  contract:
    quote_mint: "${mint.toBase58()}"
    quote_decimals: ${decimals}

Both must agree: bootstrap.mjs aborts if quoteDecimals differs from the mint's
own decimals, and the vault's initialize re-checks it on-chain.`);

const summaryPath = arg("--out");
if (summaryPath) {
  const summary = {
    cluster,
    genesis,
    quoteMint: mint.toBase58(),
    quoteDecimals: decimals,
    tokenProgram: TOKEN_PROGRAM_ID.toBase58(),
    mintAuthority: payer.publicKey.toBase58(),
    freezeAuthority: null,
    amountPerRecipient: amountUI,
    funded,
  };
  writeFileSync(expand(summaryPath), JSON.stringify(summary, null, 2));
  console.log(`\nsummary written to ${summaryPath}`);
}
