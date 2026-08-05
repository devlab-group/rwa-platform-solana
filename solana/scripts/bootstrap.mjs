#!/usr/bin/env node
// bootstrap.mjs — first-class, idempotent RWA-stack bootstrap.
//
// Promotes the bootstrap sequence out of tests/fullflow.ts into a reviewed,
// re-runnable production tool. It runs the SAME instruction sequence the passing
// integration test exercises (create the Token-2022 mint with the transfer-hook +
// permissioned-burn extensions, set mint authority to the supply-controller PDA,
// revoke the hook update authority, create the four canonical custody ATAs,
// initialize the five programs in dependency order, build the extra-account-meta
// list, pin the system addresses, and finalize), but is driven by a checked-in
// config file, verifies each step's on-chain result before proceeding, prints the
// values that become PERMANENT for explicit confirmation, and ends by re-reading
// the deployment and emitting a manifest.
//
//   node scripts/bootstrap.mjs --config bootstrap.config.json [--yes]
//
// PRECONDITION: the six programs must already be deployed (upgradeable) on the target
// cluster, with their ids set in Anchor.toml/declare_id!, and the quote mint must
// already exist. This tool does NOT deploy program binaries — it initializes, wires,
// and finalizes them. See solana/README.md "Deployment process" for the full sequence.
//
// Idempotent: every program config PDA, custody ATA, meta-list, and the mint are
// created only if absent, so a re-run resumes rather than fails. `set_system_addresses`
// is re-runnable on-chain until `finalize`, so a corrected pin is picked up on re-run.
// The auditor mint/burn attestations are NOT signed here — use the offline signer.

import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { homedir } from "node:os";
import { createInterface } from "node:readline";

const require = createRequire(import.meta.url);
const anchor = require("@coral-xyz/anchor");
const web3 = require("@solana/web3.js");
const spl = require("@solana/spl-token");
const { Connection, Keypair, PublicKey, SystemProgram, Transaction, sendAndConfirmTransaction } = web3;
const {
  TOKEN_2022_PROGRAM_ID, ExtensionType, getMintLen,
  createInitializeMintInstruction, createInitializeTransferHookInstruction,
  createInitializePermissionedBurnInstruction, createSetAuthorityInstruction,
  AuthorityType, getOrCreateAssociatedTokenAccount, getMint,
} = spl;
const { BN } = anchor;

const arg = (name) => { const i = process.argv.indexOf(name); return i > -1 ? process.argv[i + 1] : null; };
const has = (name) => process.argv.includes(name);
const die = (m) => { console.error("ERROR:", m); process.exit(1); };
const expand = (p) => (p?.startsWith("~") ? p.replace("~", homedir()) : p);
const loadKp = (p) => Keypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync(expand(p), "utf8"))));
const hex32 = (s) => { const b = Buffer.from(s.replace(/^0x/, ""), "hex"); if (b.length !== 32) die(`expected 32-byte hex, got ${b.length}`); return Array.from(b); };

const cfgPath = arg("--config") || die("usage: node scripts/bootstrap.mjs --config <file> [--yes]");
const cfg = JSON.parse(readFileSync(cfgPath, "utf8"));
const conn = new Connection(cfg.rpcUrl, "confirmed");
const payer = loadKp(cfg.payerKeypair);
const pk = (s) => new PublicKey(s);

async function confirm(question) {
  if (has("--yes")) return true;
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const ans = await new Promise((r) => rl.question(question + " [y/N] ", r));
  rl.close();
  return ans.trim().toLowerCase() === "y";
}
const exists = async (p) => (await conn.getAccountInfo(p)) !== null;

// Load the six program IDLs Anchor emitted at build time.
const idlDir = new URL("../target/idl/", import.meta.url);
const prog = (name) => {
  const idl = JSON.parse(readFileSync(new URL(`${name}.json`, idlDir), "utf8"));
  return new anchor.Program(idl, new anchor.AnchorProvider(conn, new anchor.Wallet(payer), { commitment: "confirmed" }));
};

async function main() {
  const compliance = prog("rwa_compliance");
  const pricing = prog("rwa_pricing");
  const hook = prog("rwa_transfer_hook");
  const supply = prog("rwa_supply_controller");
  const vault = prog("rwa_vault");
  const redemption = prog("rwa_redemption");

  const pda = (seed, programId) => PublicKey.findProgramAddressSync([Buffer.from(seed)], programId)[0];
  const registry = pda("registry", compliance.programId);
  const strategy = pda("strategy", pricing.programId);
  const supplyConfig = pda("supply-config", supply.programId);
  const vaultConfig = pda("vault-config", vault.programId);
  const redemptionConfig = pda("redemption-config", redemption.programId);
  const BPF_LOADER = new PublicKey("BPFLoaderUpgradeab1e11111111111111111111111");
  const programData = (id) => PublicKey.findProgramAddressSync([id.toBuffer()], BPF_LOADER)[0];
  const gate = (id) => ({ program: id, programData: programData(id) });
  const recordPda = (w) => PublicKey.findProgramAddressSync([Buffer.from("record"), w.toBuffer()], compliance.programId)[0];
  const extraMetas = (m) => PublicKey.findProgramAddressSync([Buffer.from("extra-account-metas"), m.toBuffer()], hook.programId)[0];

  const admin = pk(cfg.roles.admin);
  const quoteMint = pk(cfg.quoteMint);
  const cluster = Array.from(anchor.utils.bytes.bs58.decode(await conn.getGenesisHash()));
  const profileDigest = hex32(cfg.profileDigest);

  // --- the RWA mint (create if absent) ---------------------------------------
  const rwaMintKp = loadKp(cfg.rwaMintKeypair);
  const rwaMint = rwaMintKp.publicKey;
  if (!(await exists(rwaMint))) {
    const len = getMintLen([ExtensionType.TransferHook, ExtensionType.PermissionedBurn]);
    const lamports = await conn.getMinimumBalanceForRentExemption(len);
    await sendAndConfirmTransaction(conn, new Transaction().add(
      SystemProgram.createAccount({ fromPubkey: payer.publicKey, newAccountPubkey: rwaMint, space: len, lamports, programId: TOKEN_2022_PROGRAM_ID }),
      createInitializeTransferHookInstruction(rwaMint, admin, hook.programId, TOKEN_2022_PROGRAM_ID),
      createInitializePermissionedBurnInstruction(rwaMint, supplyConfig, TOKEN_2022_PROGRAM_ID),
      createInitializeMintInstruction(rwaMint, cfg.rwaDecimals, supplyConfig, null, TOKEN_2022_PROGRAM_ID),
    ), [payer, rwaMintKp]);
    // Revoke the hook update authority so the hook is immutable.
    await sendAndConfirmTransaction(conn, new Transaction().add(
      createSetAuthorityInstruction(rwaMint, admin, AuthorityType.TransferHookProgramId, null, [], TOKEN_2022_PROGRAM_ID),
    ), [payer]);
    console.log(`created RWA mint ${rwaMint.toBase58()} (hook immutable, authority = supply PDA)`);
  } else {
    console.log(`RWA mint ${rwaMint.toBase58()} already exists — reusing`);
  }
  const qm = await getMint(conn, quoteMint, undefined, (await conn.getAccountInfo(quoteMint)).owner);
  if (qm.decimals !== cfg.quoteDecimals) die(`quoteDecimals ${cfg.quoteDecimals} != on-chain quote mint decimals ${qm.decimals}`);

  // --- PERMANENT-VALUE confirmation ------------------------------------------
  console.log("\n== these values become PERMANENT at finalize ==");
  console.log("  cluster (genesis):", await conn.getGenesisHash());
  console.log("  rwaMint:          ", rwaMint.toBase58(), `(${cfg.rwaDecimals} dp)`);
  console.log("  quoteMint:        ", quoteMint.toBase58(), `(${cfg.quoteDecimals} dp)`);
  console.log("  admin/deployer:   ", admin.toBase58());
  console.log("  profileDigest:    ", cfg.profileDigest);
  console.log("  redemptionTimeout:", cfg.redemptionTimeout, "s");
  console.log("  supplyController: ", supply.programId.toBase58());
  if (!(await confirm("\nproceed with initialize + finalize using these permanent values?"))) die("aborted by operator");

  const quoteOwner = (await conn.getAccountInfo(quoteMint)).owner;
  const R = (...a) => a; // readability
  const initIfAbsent = async (label, addr, fn) => {
    if (await exists(addr)) { console.log(`  ${label} already initialized — skip`); return; }
    await fn(); console.log(`  ${label} initialized`);
  };

  console.log("\n== initialize programs ==");
  await initIfAbsent("compliance", registry, () => compliance.methods
    .initialize(admin, pk(cfg.roles.complianceAuthority), pk(cfg.roles.pauser))
    .accounts({ registry, payer: payer.publicKey, ...gate(compliance.programId), systemProgram: SystemProgram.programId }).rpc());
  await initIfAbsent("pricing", strategy, () => pricing.methods
    .initialize(cfg.rwaDecimals, new BN(cfg.purchasePrice), new BN(cfg.redemptionPrice), admin, pk(cfg.roles.pricer))
    .accounts({ strategy, payer: payer.publicKey, ...gate(pricing.programId), systemProgram: SystemProgram.programId }).rpc());
  await initIfAbsent("supply-controller", supplyConfig, () => supply.methods
    .initialize(admin, Array.from(getBytesEth(cfg)), profileDigest, cluster)
    .accounts({ config: supplyConfig, mint: rwaMint, vaultAuthority: vaultConfig, registry, payer: payer.publicKey, ...gate(supply.programId), systemProgram: SystemProgram.programId }).rpc());
  await initIfAbsent("vault", vaultConfig, () => vault.methods
    .initialize(admin, pk(cfg.roles.treasurer), pk(cfg.roles.treasury), supplyConfig, cfg.quoteDecimals)
    .accounts({ config: vaultConfig, rwaMint, quoteMint, strategy, registry, payer: payer.publicKey, ...gate(vault.programId), systemProgram: SystemProgram.programId }).rpc());
  await initIfAbsent("redemption", redemptionConfig, () => redemption.methods
    .initialize(admin, pk(cfg.roles.treasurer), pk(cfg.roles.redemptionManager), vaultConfig, new BN(cfg.redemptionTimeout), cfg.quoteDecimals)
    .accounts({ config: redemptionConfig, rwaMint, quoteMint, strategy, registry, payer: payer.publicKey, ...gate(redemption.programId), systemProgram: SystemProgram.programId }).rpc());
  await initIfAbsent("hook meta-list", extraMetas(rwaMint), () => hook.methods
    .initializeExtraAccountMetaList()
    .accounts({ payer: payer.publicKey, extraAccountMetaList: extraMetas(rwaMint), mint: rwaMint, ...gate(hook.programId), systemProgram: SystemProgram.programId }).rpc());

  console.log("\n== custody ATAs ==");
  const ata = async (mint, owner, prog) => (await getOrCreateAssociatedTokenAccount(conn, payer, mint, owner, true, undefined, undefined, prog)).address;
  const vaultRwa = await ata(rwaMint, vaultConfig, TOKEN_2022_PROGRAM_ID);
  const vaultQuote = await ata(quoteMint, vaultConfig, quoteOwner);
  const escrowRwa = await ata(rwaMint, redemptionConfig, TOKEN_2022_PROGRAM_ID);
  const escrowQuote = await ata(quoteMint, redemptionConfig, quoteOwner);
  console.log("  vaultRwa", vaultRwa.toBase58(), "vaultQuote", vaultQuote.toBase58());
  console.log("  escrowRwa", escrowRwa.toBase58(), "escrowQuote", escrowQuote.toBase58());

  console.log("\n== pin system addresses (re-runnable until finalize) ==");
  const reg = await compliance.account.registry.fetch(registry);
  if (!reg.finalized) {
    // prevVaultRecord/prevEscrowRecord clear a superseded pin on a corrective
    // re-run. The happy path (and any idempotent re-run with unchanged pins) passes
    // null; if you re-run after mistakenly pinning a DIFFERENT address, pass
    // recordPda(<old vault/escrow>) for the pin that changed so it is reset to
    // Unknown rather than left permanently allowlisted.
    await compliance.methods.setSystemAddresses()
      .accounts({ registry, admin, vault: vaultConfig, escrow: redemptionConfig,
        supplyControllerProgram: supply.programId, rwaMint,
        vaultRecord: recordPda(vaultConfig), escrowRecord: recordPda(redemptionConfig),
        prevVaultRecord: null, prevEscrowRecord: null,
        payer: payer.publicKey, systemProgram: SystemProgram.programId }).rpc();
    console.log("  system addresses pinned");
  } else { console.log("  already finalized — pins frozen"); }

  console.log("\n== finalize (restated cluster) ==");
  const reg2 = await compliance.account.registry.fetch(registry);
  if (!reg2.finalized) {
    await supply.methods.finalize(cluster)
      .accounts({ config: supplyConfig, admin, mint: rwaMint, registry, vaultConfig, redemptionConfig, strategy,
        registryAdmin: admin, complianceProgram: compliance.programId, complianceProgramData: programData(compliance.programId),
        // finalize proves the mint's hook ExtraAccountMetaList PDA.
        extraAccountMetaList: extraMetas(rwaMint) }).rpc();
    console.log("  FINALIZED — deployment is live");
  } else { console.log("  already finalized"); }

  // --- manifest --------------------------------------------------------------
  const manifest = {
    cluster: await conn.getGenesisHash(),
    finalizedAt: (await compliance.account.registry.fetch(registry)).finalized,
    programs: {
      compliance: compliance.programId.toBase58(), pricing: pricing.programId.toBase58(),
      transferHook: hook.programId.toBase58(), supplyController: supply.programId.toBase58(),
      vault: vault.programId.toBase58(), redemption: redemption.programId.toBase58(),
    },
    rwaMint: rwaMint.toBase58(), rwaDecimals: cfg.rwaDecimals,
    quoteMint: quoteMint.toBase58(), quoteDecimals: cfg.quoteDecimals, quoteOwner: quoteOwner.toBase58(),
    pdas: { registry: registry.toBase58(), strategy: strategy.toBase58(), supplyConfig: supplyConfig.toBase58(), vaultConfig: vaultConfig.toBase58(), redemptionConfig: redemptionConfig.toBase58() },
    custody: { vaultRwa: vaultRwa.toBase58(), vaultQuote: vaultQuote.toBase58(), escrowRwa: escrowRwa.toBase58(), escrowQuote: escrowQuote.toBase58() },
    profileDigest: cfg.profileDigest,
    note: "Record the six program sBPF sha256 hashes (CI 'solana-program-hashes' artifact) and the on-chain Token-2022 program hash alongside this manifest.",
  };
  const out = cfg.manifestOut || "./deployment-manifest.json";
  writeFileSync(out, JSON.stringify(manifest, null, 2));
  console.log(`\nmanifest written to ${out}`);
}

// The auditor eth address is derived from the configured 20-byte value; the
// attestation SIGNATURES are produced offline by the Go signer, not here.
function getBytesEth(cfg) {
  const b = Buffer.from(String(cfg.auditorEth || "").replace(/^0x/, ""), "hex");
  if (b.length !== 20) die("config.auditorEth must be a 20-byte 0x-hex eth address");
  return b;
}

main().catch((e) => die(e.stack || e.message));
