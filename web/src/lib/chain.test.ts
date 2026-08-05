// @vitest-environment node
//
// PublicKey.findProgramAddressSync's on-curve check (@noble/curves) does a
// strict `instanceof Uint8Array` against typed arrays produced by the
// `buffer` package; under jsdom, jsdom's own realm provides a DIFFERENT
// Uint8Array global than Node's, so that check spuriously fails and every
// derivation looks "on-curve" (see the long PDA-search failure this used to
// produce). Real browsers have only one realm, so this is a test-harness-only
// issue — forcing the Node environment for this file sidesteps it.
import { BN, BorshCoder, type Idl } from "@coral-xyz/anchor";
import { getAssociatedTokenAddressSync } from "@solana/spl-token";
import {
  Keypair,
  PublicKey,
  SystemProgram,
  type Connection,
  type TransactionInstruction,
} from "@solana/web3.js";
import { describe, expect, it, vi } from "vitest";
import {
  bigIntToBytes32,
  bytesToHex,
  buildAcceptAdminIx,
  buildFundRedemptionIx,
  buildMintIx,
  buildProposeAdminIx,
  buildRejectRedemptionIx,
  buildSetPriceIx,
  buildSetRoleHolderIx,
  buildWithdrawProceedsIx,
  configure,
  extraAccountMetaListPda,
  hexToBytes,
  noncePda,
  recordKeyPda,
  recordPda,
  redemptionConfigPda,
  registryPda,
  requestPda,
  strategyPda,
  supplyConfigPda,
  TOKEN_2022_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  u64LeBytes,
  vaultConfigPda,
  type ProgramIds,
} from "./chain";
import redemptionIdl from "./idl/rwa_redemption.json";
import supplyControllerIdl from "./idl/rwa_supply_controller.json";
import vaultIdl from "./idl/rwa_vault.json";

// Local coders — built from the exact same checked-in IDL JSON lib/chain.ts
// uses internally — let these tests encode fake on-chain account bytes for
// `fetchDecoded` to consume, without needing lib/chain.ts to export its own
// (deliberately private) coder instances.
const vaultCoder = new BorshCoder(vaultIdl as Idl);
const redemptionCoder = new BorshCoder(redemptionIdl as Idl);
const supplyCoder = new BorshCoder(supplyControllerIdl as Idl);

/** A base58/isSigner/isWritable summary of an instruction's account list — easier to compare than raw AccountMeta[] (whose PublicKey entries don't compare well with toEqual). */
function keySummary(ix: TransactionInstruction) {
  return ix.keys.map((k) => ({
    pubkey: k.pubkey.toBase58(),
    isSigner: k.isSigner,
    isWritable: k.isWritable,
  }));
}

function fakeProgramIds(overrides: Partial<ProgramIds> = {}): ProgramIds {
  return {
    compliance: PublicKey.unique().toBase58(),
    vault: PublicKey.unique().toBase58(),
    pricing: PublicKey.unique().toBase58(),
    transferHook: PublicKey.unique().toBase58(),
    redemption: PublicKey.unique().toBase58(),
    supplyController: PublicKey.unique().toBase58(),
    ...overrides,
  };
}

// Cross-checks lib/chain.ts's PDA seed constants against the exact
// const-seed byte arrays embedded in the checked-in Anchor IDLs (see e.g.
// web/src/lib/idl/rwa_supply_controller.json's `mint` instruction accounts),
// which are themselves generated from solana/programs/*/src/lib.rs's
// `#[account(seeds = [...])]` attributes — the same source
// solana/tests/fullflow.ts derives its PDAs from.
describe("PDA seed constants", () => {
  const asciiBytes = (s: string) => Array.from(Buffer.from(s, "utf8"));

  it("matches the const seed bytes embedded in the IDLs", () => {
    // web/src/lib/idl/rwa_supply_controller.json's `mint` ix declares the
    // `config` account's seed as this exact byte array.
    expect(asciiBytes("supply-config")).toEqual([
      115, 117, 112, 112, 108, 121, 45, 99, 111, 110, 102, 105, 103,
    ]);
    // rwa_compliance.json / rwa_vault.json / rwa_redemption.json / rwa_pricing.json.
    expect(asciiBytes("registry")).toEqual([
      114, 101, 103, 105, 115, 116, 114, 121,
    ]);
    expect(asciiBytes("strategy")).toEqual([
      115, 116, 114, 97, 116, 101, 103, 121,
    ]);
  });

  const programId = PublicKey.unique();

  it("derives deterministic, distinct PDAs per account kind", () => {
    const registry = registryPda(programId);
    const strategy = strategyPda(programId);
    const supplyConfig = supplyConfigPda(programId);
    const vaultConfig = vaultConfigPda(programId);
    const redemptionConfig = redemptionConfigPda(programId);

    // Same program id, different seed strings -> different addresses.
    const all = [registry, strategy, supplyConfig, vaultConfig, redemptionConfig];
    const unique = new Set(all.map((k) => k.toBase58()));
    expect(unique.size).toBe(all.length);

    // Deterministic: re-deriving gives the identical address.
    expect(registryPda(programId).toBase58()).toBe(registry.toBase58());
  });

  it("derives the record PDA from [\"record\", wallet] — matches fullflow.ts's recordPda helper", () => {
    const wallet = PublicKey.unique();
    const expected = PublicKey.findProgramAddressSync(
      [Buffer.from("record"), wallet.toBuffer()],
      programId,
    )[0];
    expect(recordPda(programId, wallet).toBase58()).toBe(expected.toBase58());
  });

  it("derives the nonce/record-key marker PDAs with const-then-arg seed order", () => {
    const nonce = new Uint8Array(32).fill(7);
    const recordKey = new Uint8Array(32).fill(9);
    const expectedNonce = PublicKey.findProgramAddressSync(
      [Buffer.from("nonce"), Buffer.from(nonce)],
      programId,
    )[0];
    const expectedRecordKey = PublicKey.findProgramAddressSync(
      [Buffer.from("record-key"), Buffer.from(recordKey)],
      programId,
    )[0];
    expect(noncePda(programId, nonce).toBase58()).toBe(expectedNonce.toBase58());
    expect(recordKeyPda(programId, recordKey).toBase58()).toBe(
      expectedRecordKey.toBase58(),
    );
  });

  it("derives the redemption request PDA from [\"request\", id as little-endian u64]", () => {
    const id = 258n; // 0x0102 -> LE bytes [2, 1, 0, 0, 0, 0, 0, 0]
    const expected = PublicKey.findProgramAddressSync(
      [Buffer.from("request"), Buffer.from([2, 1, 0, 0, 0, 0, 0, 0])],
      programId,
    )[0];
    expect(requestPda(programId, id).toBase58()).toBe(expected.toBase58());
  });

  it("derives the hook's extra-account-metas PDA from [\"extra-account-metas\", mint]", () => {
    const mint = PublicKey.unique();
    const expected = PublicKey.findProgramAddressSync(
      [Buffer.from("extra-account-metas"), mint.toBuffer()],
      programId,
    )[0];
    expect(extraAccountMetaListPda(programId, mint).toBase58()).toBe(
      expected.toBase58(),
    );
  });
});

describe("byte helpers", () => {
  it("hexToBytes/bytesToHex round-trip, with or without a 0x prefix", () => {
    const hex = "0xdeadbeef";
    const bytes = hexToBytes(hex);
    expect(Array.from(bytes)).toEqual([0xde, 0xad, 0xbe, 0xef]);
    expect(bytesToHex(bytes)).toBe(hex);
    expect(Array.from(hexToBytes("deadbeef"))).toEqual([0xde, 0xad, 0xbe, 0xef]);
  });

  it("bigIntToBytes32 big-endian pads to 32 bytes and round-trips through BigInt(hex)", () => {
    const value = 1n;
    const bytes = bigIntToBytes32(value);
    expect(bytes.length).toBe(32);
    expect(bytes[31]).toBe(1);
    expect(BigInt(bytesToHex(bytes))).toBe(value);

    const large = (1n << 200n) + 42n;
    expect(BigInt(bytesToHex(bigIntToBytes32(large)))).toBe(large);
  });

  it("u64LeBytes encodes little-endian", () => {
    expect(Array.from(u64LeBytes(1n))).toEqual([1, 0, 0, 0, 0, 0, 0, 0]);
    expect(Array.from(u64LeBytes(258n))).toEqual([2, 1, 0, 0, 0, 0, 0, 0]);
  });
});

describe("buildSetRoleHolderIx — role-to-program dispatch (single-holder roles)", () => {
  const complianceKey = PublicKey.unique();
  const vaultKey = PublicKey.unique();
  const pricingKey = PublicKey.unique();
  const redemptionKey = PublicKey.unique();
  const programIds: ProgramIds = {
    compliance: complianceKey.toBase58(),
    vault: vaultKey.toBase58(),
    pricing: pricingKey.toBase58(),
    transferHook: PublicKey.unique().toBase58(),
    redemption: redemptionKey.toBase58(),
    supplyController: PublicKey.unique().toBase58(),
  };
  const admin = PublicKey.unique();
  const newHolder = PublicKey.unique();

  it("routes PAUSER_ROLE to the compliance program's set_pauser", () => {
    const ix = buildSetRoleHolderIx(
      "PAUSER_ROLE",
      new PublicKey(programIds.compliance),
      admin,
      newHolder,
      programIds,
    );
    expect(ix.programId.toBase58()).toBe(programIds.compliance);
  });

  it("routes TREASURER_ROLE to whichever of vault/redemption is passed", () => {
    const vaultIx = buildSetRoleHolderIx(
      "TREASURER_ROLE",
      new PublicKey(programIds.vault),
      admin,
      newHolder,
      programIds,
    );
    expect(vaultIx.programId.toBase58()).toBe(programIds.vault);

    const redemptionIx = buildSetRoleHolderIx(
      "TREASURER_ROLE",
      new PublicKey(programIds.redemption),
      admin,
      newHolder,
      programIds,
    );
    expect(redemptionIx.programId.toBase58()).toBe(programIds.redemption);
  });

  it("rejects a role/program mismatch rather than silently building the wrong call", () => {
    expect(() =>
      buildSetRoleHolderIx(
        "PRICER_ROLE",
        new PublicKey(programIds.vault), // PRICER_ROLE lives on pricing, not vault
        admin,
        newHolder,
        programIds,
      ),
    ).toThrow(/pricing program/);
  });
});

// Pins the account list (order, isSigner, isWritable) of every remaining
// instruction builder against the IDL's `accounts` list, the same source
// buildSetRoleHolderIx's dispatch above and solana/tests/fullflow.ts both
// derive from. buildSetPriceIx/buildProposeAdminIx/buildAcceptAdminIx are
// synchronous (no on-chain read); the rest read a Config (and, for
// fund/reject, the RedemptionRequest too) off a fake Connection first.
describe("instruction builders — exact IDL-ordered account lists", () => {
  it("buildSetPriceIx: [strategy(w), pricer(signer)] for both purchase and redemption sides", () => {
    const pricing = PublicKey.unique();
    const pricer = PublicKey.unique();
    const strategy = strategyPda(pricing);
    const expected = [
      { pubkey: strategy.toBase58(), isSigner: false, isWritable: true },
      { pubkey: pricer.toBase58(), isSigner: true, isWritable: false },
    ];

    const purchaseIx = buildSetPriceIx(pricing, pricer, "purchase", 100n);
    expect(purchaseIx.programId.toBase58()).toBe(pricing.toBase58());
    expect(keySummary(purchaseIx)).toEqual(expected);

    const redemptionIx = buildSetPriceIx(pricing, pricer, "redemption", 50n);
    expect(keySummary(redemptionIx)).toEqual(expected);
  });

  it("buildWithdrawProceedsIx: reads Config on-chain, builds [config, registry, quote_mint, vault_quote(w), treasury_quote(w), treasurer(signer), token_program]", async () => {
    const vaultProgram = PublicKey.unique();
    const treasurer = PublicKey.unique();
    const compliance = PublicKey.unique();
    configure({
      programIds: fakeProgramIds({ compliance: compliance.toBase58(), vault: vaultProgram.toBase58() }),
    });

    const quoteMint = PublicKey.unique();
    // getAssociatedTokenAddressSync's owner must be on-curve here (allowOwnerOffCurve
    // is false for treasury_quote) — a real Keypair, not PublicKey.unique() (which
    // isn't guaranteed on-curve).
    const treasury = Keypair.generate().publicKey;
    const cfgAccount = {
      admin: PublicKey.unique(),
      pending_admin: PublicKey.default,
      treasurer,
      treasury,
      supply_controller: PublicKey.unique(),
      rwa_mint: PublicKey.unique(),
      quote_mint: quoteMint,
      quote_decimals: 6,
      strategy: PublicKey.unique(),
      registry: PublicKey.unique(),
      bump: 255,
    };
    const data = await vaultCoder.accounts.encode("Config", cfgAccount);
    // First call: the Config account (fetchDecoded). Second call: the quote
    // mint's own account, to resolve its owning token program
    // (resolveTokenProgram).
    const getAccountInfo = vi
      .fn()
      .mockResolvedValueOnce({ data })
      .mockResolvedValueOnce({ owner: TOKEN_PROGRAM_ID });
    const connection = { getAccountInfo } as unknown as Connection;

    const ix = await buildWithdrawProceedsIx(connection, vaultProgram, treasurer, 100n);

    const config = vaultConfigPda(vaultProgram);
    const registry = registryPda(compliance);
    const vaultQuote = getAssociatedTokenAddressSync(quoteMint, config, true, TOKEN_PROGRAM_ID);
    const treasuryQuote = getAssociatedTokenAddressSync(quoteMint, treasury, false, TOKEN_PROGRAM_ID);

    expect(ix.programId.toBase58()).toBe(vaultProgram.toBase58());
    expect(keySummary(ix)).toEqual([
      { pubkey: config.toBase58(), isSigner: false, isWritable: false },
      { pubkey: registry.toBase58(), isSigner: false, isWritable: false },
      { pubkey: quoteMint.toBase58(), isSigner: false, isWritable: false },
      { pubkey: vaultQuote.toBase58(), isSigner: false, isWritable: true },
      { pubkey: treasuryQuote.toBase58(), isSigner: false, isWritable: true },
      { pubkey: treasurer.toBase58(), isSigner: true, isWritable: false },
      { pubkey: TOKEN_PROGRAM_ID.toBase58(), isSigner: false, isWritable: false },
    ]);
  });

  it("buildFundRedemptionIx: reads Config + the request on-chain, builds [config, registry, request(w), quote_mint, treasurer(signer), treasurer_quote(w), escrow_quote(w), beneficiary_record, token_program]", async () => {
    const redemptionProgram = PublicKey.unique();
    // On-curve — this is the owner of treasurer_quote (allowOwnerOffCurve false).
    const treasurer = Keypair.generate().publicKey;
    const compliance = PublicKey.unique();
    configure({
      programIds: fakeProgramIds({ compliance: compliance.toBase58(), redemption: redemptionProgram.toBase58() }),
    });

    const quoteMint = PublicKey.unique();
    const beneficiary = PublicKey.unique();
    const cfgAccount = {
      admin: PublicKey.unique(),
      pending_admin: PublicKey.default,
      treasurer,
      redemption_manager: PublicKey.unique(),
      vault: PublicKey.unique(),
      rwa_mint: PublicKey.unique(),
      quote_mint: quoteMint,
      quote_decimals: 6,
      strategy: PublicKey.unique(),
      registry: PublicKey.unique(),
      redemption_timeout: new BN(86_400),
      next_id: new BN(2),
      bump: 255,
    };
    const reqAccount = {
      id: new BN(1),
      beneficiary,
      rwa_amount: new BN(100),
      quote_amount: new BN(50),
      created_at: new BN(0),
      status: 1,
      bump: 254,
    };
    const cfgData = await redemptionCoder.accounts.encode("Config", cfgAccount);
    const reqData = await redemptionCoder.accounts.encode("RedemptionRequest", reqAccount);
    // Config, then the RedemptionRequest, then the quote mint's own account
    // (resolveTokenProgram), in the order buildFundRedemptionIx
    // reads them.
    const getAccountInfo = vi
      .fn()
      .mockResolvedValueOnce({ data: cfgData })
      .mockResolvedValueOnce({ data: reqData })
      .mockResolvedValueOnce({ owner: TOKEN_PROGRAM_ID });
    const connection = { getAccountInfo } as unknown as Connection;

    const ix = await buildFundRedemptionIx(connection, redemptionProgram, treasurer, 1n);

    const config = redemptionConfigPda(redemptionProgram);
    const registry = registryPda(compliance);
    const request = requestPda(redemptionProgram, 1n);
    const treasurerQuote = getAssociatedTokenAddressSync(quoteMint, treasurer, false, TOKEN_PROGRAM_ID);
    const escrowQuote = getAssociatedTokenAddressSync(quoteMint, config, true, TOKEN_PROGRAM_ID);
    const beneficiaryRecord = recordPda(compliance, beneficiary);

    expect(ix.programId.toBase58()).toBe(redemptionProgram.toBase58());
    expect(keySummary(ix)).toEqual([
      { pubkey: config.toBase58(), isSigner: false, isWritable: false },
      { pubkey: registry.toBase58(), isSigner: false, isWritable: false },
      { pubkey: request.toBase58(), isSigner: false, isWritable: true },
      { pubkey: quoteMint.toBase58(), isSigner: false, isWritable: false },
      { pubkey: treasurer.toBase58(), isSigner: true, isWritable: false },
      { pubkey: treasurerQuote.toBase58(), isSigner: false, isWritable: true },
      { pubkey: escrowQuote.toBase58(), isSigner: false, isWritable: true },
      { pubkey: beneficiaryRecord.toBase58(), isSigner: false, isWritable: false },
      { pubkey: TOKEN_PROGRAM_ID.toBase58(), isSigner: false, isWritable: false },
    ]);
  });

  it("buildRejectRedemptionIx: strict list plus the hook's 6 remainingAccounts appended in [hook, extraMetas, compliance, registry, srcRecord, dstRecord] order", async () => {
    const redemptionProgram = PublicKey.unique();
    const redemptionManager = PublicKey.unique();
    const compliance = PublicKey.unique();
    const hook = PublicKey.unique();
    configure({
      programIds: fakeProgramIds({
        compliance: compliance.toBase58(),
        transferHook: hook.toBase58(),
        redemption: redemptionProgram.toBase58(),
      }),
    });

    const rwaMint = PublicKey.unique();
    // On-curve — this is the owner of beneficiary_token (allowOwnerOffCurve false).
    const beneficiary = Keypair.generate().publicKey;
    const cfgAccount = {
      admin: PublicKey.unique(),
      pending_admin: PublicKey.default,
      treasurer: PublicKey.unique(),
      redemption_manager: redemptionManager,
      vault: PublicKey.unique(),
      rwa_mint: rwaMint,
      quote_mint: PublicKey.unique(),
      quote_decimals: 6,
      strategy: PublicKey.unique(),
      registry: PublicKey.unique(),
      redemption_timeout: new BN(86_400),
      next_id: new BN(8),
      bump: 255,
    };
    const reqAccount = {
      id: new BN(7),
      beneficiary,
      rwa_amount: new BN(100),
      quote_amount: new BN(50),
      created_at: new BN(0),
      status: 0,
      bump: 254,
    };
    const cfgData = await redemptionCoder.accounts.encode("Config", cfgAccount);
    const reqData = await redemptionCoder.accounts.encode("RedemptionRequest", reqAccount);
    const getAccountInfo = vi
      .fn()
      .mockResolvedValueOnce({ data: cfgData })
      .mockResolvedValueOnce({ data: reqData });
    const connection = { getAccountInfo } as unknown as Connection;

    const ix = await buildRejectRedemptionIx(
      connection,
      redemptionProgram,
      redemptionManager,
      7n,
      new Uint8Array(32).fill(3),
    );

    const config = redemptionConfigPda(redemptionProgram);
    const registry = registryPda(compliance);
    const request = requestPda(redemptionProgram, 7n);
    const escrowToken = getAssociatedTokenAddressSync(rwaMint, config, true, TOKEN_2022_PROGRAM_ID);
    const beneficiaryToken = getAssociatedTokenAddressSync(rwaMint, beneficiary, false, TOKEN_2022_PROGRAM_ID);
    const beneficiaryRecord = recordPda(compliance, beneficiary);
    const extraMetas = extraAccountMetaListPda(hook, rwaMint);
    const srcRecord = recordPda(compliance, config);

    expect(ix.programId.toBase58()).toBe(redemptionProgram.toBase58());
    expect(keySummary(ix)).toEqual([
      { pubkey: config.toBase58(), isSigner: false, isWritable: false },
      { pubkey: registry.toBase58(), isSigner: false, isWritable: false },
      { pubkey: request.toBase58(), isSigner: false, isWritable: true },
      { pubkey: rwaMint.toBase58(), isSigner: false, isWritable: false },
      { pubkey: escrowToken.toBase58(), isSigner: false, isWritable: true },
      { pubkey: beneficiaryToken.toBase58(), isSigner: false, isWritable: true },
      { pubkey: beneficiaryRecord.toBase58(), isSigner: false, isWritable: false },
      { pubkey: redemptionManager.toBase58(), isSigner: true, isWritable: false },
      { pubkey: TOKEN_2022_PROGRAM_ID.toBase58(), isSigner: false, isWritable: false },
      // remainingAccounts (the hook's ExtraAccountMetaList resolution set):
      { pubkey: hook.toBase58(), isSigner: false, isWritable: false },
      { pubkey: extraMetas.toBase58(), isSigner: false, isWritable: false },
      { pubkey: compliance.toBase58(), isSigner: false, isWritable: false },
      { pubkey: registry.toBase58(), isSigner: false, isWritable: false },
      { pubkey: srcRecord.toBase58(), isSigner: false, isWritable: false }, // escrow (source) record
      { pubkey: beneficiaryRecord.toBase58(), isSigner: false, isWritable: false }, // beneficiary (destination) record
    ]);
  });

  it("buildMintIx: reads Config on-chain, builds [config, registry, mint(w), vault_token(w), nonce_marker(w), record_marker(w), payer(signer,w), token_program, system_program], and encodes signature/recoveryId verbatim", async () => {
    const supplyControllerProgram = PublicKey.unique();
    const compliance = PublicKey.unique();
    const payer = PublicKey.unique();
    configure({
      programIds: fakeProgramIds({
        compliance: compliance.toBase58(),
        supplyController: supplyControllerProgram.toBase58(),
      }),
    });

    const tokenMint = PublicKey.unique();
    const vault = PublicKey.unique();
    const cfgAccount = {
      admin: PublicKey.unique(),
      pending_admin: PublicKey.default,
      auditor_eth: new Array(20).fill(1),
      token_mint: tokenMint,
      vault,
      registry: PublicKey.unique(),
      profile_digest: new Array(32).fill(2),
      cluster: new Array(32).fill(3),
      finalized: true,
      bump: 255,
    };
    const data = await supplyCoder.accounts.encode("rwa_supply_controller::Config", cfgAccount);
    const connection = { getAccountInfo: async () => ({ data }) } as unknown as Connection;

    const recordKey = new Uint8Array(32).fill(9);
    const metadataDigest = new Uint8Array(32).fill(8);
    const nonce = new Uint8Array(32).fill(7);
    const signature = new Uint8Array(64).fill(5);

    const ix = await buildMintIx(
      connection,
      supplyControllerProgram,
      payer,
      recordKey,
      metadataDigest,
      100n,
      nonce,
      999n,
      signature,
      1,
    );

    const config = supplyConfigPda(supplyControllerProgram);
    const registry = registryPda(compliance);
    const vaultToken = getAssociatedTokenAddressSync(tokenMint, vault, true, TOKEN_2022_PROGRAM_ID);
    const nonceMarker = noncePda(supplyControllerProgram, nonce);
    const recordMarker = recordKeyPda(supplyControllerProgram, recordKey);

    expect(ix.programId.toBase58()).toBe(supplyControllerProgram.toBase58());
    expect(keySummary(ix)).toEqual([
      { pubkey: config.toBase58(), isSigner: false, isWritable: false },
      { pubkey: registry.toBase58(), isSigner: false, isWritable: false },
      { pubkey: tokenMint.toBase58(), isSigner: false, isWritable: true },
      { pubkey: vaultToken.toBase58(), isSigner: false, isWritable: true },
      { pubkey: nonceMarker.toBase58(), isSigner: false, isWritable: true },
      { pubkey: recordMarker.toBase58(), isSigner: false, isWritable: true },
      { pubkey: payer.toBase58(), isSigner: true, isWritable: true },
      { pubkey: TOKEN_2022_PROGRAM_ID.toBase58(), isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId.toBase58(), isSigner: false, isWritable: false },
    ]);

    // The 64-byte compact signature + 1-byte recovery id are encoded
    // verbatim (not re-derived) — decode the instruction data back with the
    // same coder and check they round-trip exactly.
    const decoded = supplyCoder.instruction.decode(ix.data) as {
      name: string;
      data: Record<string, unknown>;
    } | null;
    expect(decoded?.name).toBe("mint");
    expect(Array.from(decoded!.data.signature as number[])).toEqual(Array.from(signature));
    expect(decoded!.data.recovery_id).toBe(1);
  });

  // All five programs with a two-step admin (the RWA mint has none, and
  // rwa-transfer-hook's has no propose_admin/accept_admin at all — see
  // roles.ts's AdminContractSpec doc comment) share the SAME account shape:
  // [configPda(w), signer]. Table-driven so every program's PDA deriver is
  // exercised, not just compliance's registry.
  const ADMIN_PROGRAM_CASES: [
    key: Parameters<typeof buildProposeAdminIx>[1],
    configPda: (programId: PublicKey) => PublicKey,
  ][] = [
    ["compliance", registryPda],
    ["vault", vaultConfigPda],
    ["pricing", strategyPda],
    ["redemption", redemptionConfigPda],
    ["supplyController", supplyConfigPda],
  ];

  it.each(ADMIN_PROGRAM_CASES)(
    "buildProposeAdminIx / buildAcceptAdminIx (%s): [configPda(w), signer]",
    (programKey, configPda) => {
      const program = PublicKey.unique();
      const admin = PublicKey.unique();
      const newAdmin = PublicKey.unique();
      const config = configPda(program);

      const proposeIx = buildProposeAdminIx(program, programKey, admin, newAdmin);
      expect(proposeIx.programId.toBase58()).toBe(program.toBase58());
      expect(keySummary(proposeIx)).toEqual([
        { pubkey: config.toBase58(), isSigner: false, isWritable: true },
        { pubkey: admin.toBase58(), isSigner: true, isWritable: false },
      ]);

      const acceptIx = buildAcceptAdminIx(program, programKey, newAdmin);
      expect(acceptIx.programId.toBase58()).toBe(program.toBase58());
      expect(keySummary(acceptIx)).toEqual([
        { pubkey: config.toBase58(), isSigner: false, isWritable: true },
        { pubkey: newAdmin.toBase58(), isSigner: true, isWritable: false },
      ]);
    },
  );
});
