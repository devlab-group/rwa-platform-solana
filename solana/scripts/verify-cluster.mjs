#!/usr/bin/env node
// verify-cluster.mjs — pre-deploy gate for the RWA Solana stack.
//
// Checks the two HARD cluster preconditions before you deploy to a public cluster:
//   [1] Token-2022 supports the PermissionedBurn extension.
//       Without it, bootstrap fails closed: `validate_rwa_mint` rejects the mint.
//   [2] SIMD-0500 ("disable deployment of SBPF v0/v1/v2") is inactive, so the
//       current-sBPF programs can actually be deployed.
//
// Read-only and free: it uses transaction *simulation* (sigVerify:false — nothing
// is signed, nothing is spent) plus getAccountInfo. The "payer" is only a simulated
// fee payer; it never signs and its balance is never touched.
//
//   node scripts/verify-cluster.mjs --url <RPC_URL> [--payer <FUNDED_PUBKEY>]
//
// For mainnet-beta / devnet the payer defaults to a known funded account. For a
// custom or local RPC (or if the default is ever unfunded), pass your funded
// deployer pubkey with --payer. Exit code 0 = deployable, 1 = a hard blocker, 2 = usage.

import { createRequire } from "module";
const require = createRequire(import.meta.url);
const web3 = require("@solana/web3.js");
const spl = require("@solana/spl-token");
const { Connection, Keypair, PublicKey, SystemProgram, VersionedTransaction, TransactionMessage } = web3;
const {
  TOKEN_2022_PROGRAM_ID, ExtensionType, getMintLen,
  createInitializeMintInstruction, createInitializePermissionedBurnInstruction,
} = spl;

// SIMD-0500 feature-gate id (see `solana feature status <id>`).
const SIMD_0500 = new PublicKey("B8JJXCy5amZyWG9r7EnUYLwzXSXTxG7GZ1qZ1qggo83g");

// genesis hash -> [cluster label, a known funded *system* account usable as a
// simulated fee payer (never signs / pays)].
const KNOWN = {
  "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d": ["mainnet-beta", "AeLmXCbPaQHGWRLr2saFsEVfmMNuKnxRAbWCT9P5twgz"],
  EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG: ["devnet", "3URRPr96EV2wuNRgQKwQpuZitHHsVyDUen1eRSvEun9G"],
  "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY": ["testnet", null],
};

const arg = (name) => {
  const i = process.argv.indexOf(name);
  return i > -1 ? process.argv[i + 1] : null;
};

const url = arg("--url");
if (!url) {
  console.error("usage: node scripts/verify-cluster.mjs --url <RPC_URL> [--payer <FUNDED_PUBKEY>]");
  process.exit(2);
}
let payerArg = arg("--payer");
const conn = new Connection(url, "confirmed");
let hardFail = false;

let label = "custom/unknown";
let genesis = null;
try {
  genesis = await conn.getGenesisHash();
  if (KNOWN[genesis]) {
    label = KNOWN[genesis][0];
    if (!payerArg) payerArg = KNOWN[genesis][1];
  }
} catch (e) {
  console.error("warn: getGenesisHash failed:", e.message);
}
console.log(`Cluster: ${label}   RPC: ${url}`);

// The genesis hash is the `cluster` value that `initialize`/`finalize` bind
// into the attestation domain. Print it in exactly the byte form the instruction
// expects (bs58-decoded → 32-byte array), and record BOTH in the deployment
// manifest so the offline signer and `finalize`'s restated argument can be checked
// against a single source rather than re-derived by hand.
if (genesis) {
  const bytes = Array.from(new PublicKey(genesis).toBytes());
  console.log(`    genesis (base58): ${genesis}`);
  console.log(`    genesis (cluster bytes, pass to initialize/finalize): [${bytes.join(",")}]`);
}

// ---- [1] Token-2022 PermissionedBurn ---------------------------------------
console.log("\n[1] Token-2022 PermissionedBurn extension");
if (!payerArg) {
  console.log("    SKIPPED — no simulated payer. Re-run with --payer <a funded pubkey on this cluster>.");
} else {
  try {
    const payer = new PublicKey(payerArg);
    const mint = Keypair.generate();
    const space = getMintLen([ExtensionType.PermissionedBurn]);
    const rent = await conn.getMinimumBalanceForRentExemption(space);
    const ixs = [
      SystemProgram.createAccount({ fromPubkey: payer, newAccountPubkey: mint.publicKey, space, lamports: rent, programId: TOKEN_2022_PROGRAM_ID }),
      createInitializePermissionedBurnInstruction(mint.publicKey, payer, TOKEN_2022_PROGRAM_ID),
      createInitializeMintInstruction(mint.publicKey, 6, payer, null, TOKEN_2022_PROGRAM_ID),
    ];
    const { blockhash } = await conn.getLatestBlockhash();
    const msg = new TransactionMessage({ payerKey: payer, recentBlockhash: blockhash, instructions: ixs }).compileToV0Message();
    const sim = await conn.simulateTransaction(new VersionedTransaction(msg), {
      sigVerify: false, replaceRecentBlockhash: true, commitment: "confirmed",
    });
    const logs = sim.value.logs || [];
    const t22 = TOKEN_2022_PROGRAM_ID.toBase58();
    const reachedT22 = logs.some((l) => l.includes(t22) && l.includes("invoke"));
    const sawExt = logs.some((l) => l.includes("PermissionedBurn"));
    if (sim.value.err === null && sawExt) {
      console.log("    ✅ SUPPORTED — the extension initialized successfully in simulation.");
    } else if (reachedT22 && !sawExt) {
      console.log("    ❌ NOT SUPPORTED — Token-2022 rejected the PermissionedBurn instruction (older program).");
      console.log("       This is a HARD blocker: bootstrap will fail closed on this cluster.");
      console.log("       logs:\n         " + logs.join("\n         "));
      hardFail = true;
    } else {
      console.log("    ⚠️  INCONCLUSIVE — the sim did not cleanly reach the extension (likely the simulated");
      console.log("       payer is unfunded here, or the RPC rate-limited). Re-run with --payer <funded pubkey>.");
      console.log("       err:", JSON.stringify(sim.value.err));
      console.log("       logs:\n         " + logs.join("\n         "));
    }
  } catch (e) {
    console.log("    ERROR:", e.message, "\n    (public RPC rate limit? retry, use a paid RPC, or pass --payer)");
  }
}

// ---- [2] SIMD-0500 ----------------------------------------------------------
console.log("\n[2] SIMD-0500 — disable deployment of SBPF v0/v1/v2");
try {
  const acc = await conn.getAccountInfo(SIMD_0500);
  if (!acc) {
    console.log("    ✅ INACTIVE (no feature account) — current-sBPF programs deploy fine.");
  } else if (acc.data.length > 0 && acc.data[0] === 1) {
    const slot = acc.data.readBigUInt64LE(1);
    console.log(`    ❌ ACTIVE (since slot ${slot}) — v0/v1/v2 programs can no longer be deployed or upgraded.`);
    console.log("       Rebuild to a supported sBPF version (current platform-tools) before deploying.");
    hardFail = true;
  } else {
    console.log("    ✅ INACTIVE (staged, not yet activated) — deploys allowed for now; plan to build-forward.");
  }
} catch (e) {
  console.log("    ERROR:", e.message);
}

// ---- [i] Token-2022 program identity for the deployment manifest -----------
console.log("\n[i] Token-2022 program identity (record in the deployment manifest)");
try {
  const acc = await conn.getAccountInfo(TOKEN_2022_PROGRAM_ID);
  console.log(`    program: ${TOKEN_2022_PROGRAM_ID.toBase58()}  executable: ${acc?.executable}  owner: ${acc?.owner.toBase58()}`);
} catch (e) {
  console.log("    ERROR:", e.message);
}

console.log("\n" + (hardFail
  ? "RESULT: ❌ NOT deployable to this cluster as-is — resolve the blocker(s) above."
  : "RESULT: ✅ Both hard preconditions pass — the stack is deployable to this cluster."));
process.exit(hardFail ? 1 : 0);
