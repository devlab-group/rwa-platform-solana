// Full-flow integration test (mirrors contracts/test/integration/FullFlow.t.sol):
//   authorized bootstrap → allow investor → mint(auditor sig) → buy → request →
//   fund → claim → burn(handshake), plus reject-while-restoring, replay, and
//   not-allowed negatives.
//
// Notable behaviours exercised here: finalize takes a restated `cluster`;
// vault/redemption initialize take `quote_decimals`; set_system_addresses takes the
// supply-controller program (executable) + RWA mint accounts; finalize forwards the
// compliance ProgramData so set_finalized binds go-live to the deployer; the
// redemption timeout must be within [1 day, 365 days]; high-S signatures are
// rejected. The successful timeout-cancel path can't be exercised here (a 1-day min
// can't be real-time warped in the validator harness) and is covered by
// `redemption-core`'s `can_cancel` boundary tests; the reject leg's escrow-return is
// exercised instead.
//
// Requires the SBF toolchain + a validator whose Token-2022 supports permissioned
// burn (program v11) — see solana/README for the build-and-inject recipe, or the
// scheduled `solana-anchor` CI job. This exercises the program/CPI/hook layer the
// host `cargo test` crates cannot. Written against the @coral-xyz/anchor 0.32 TS
// client + Anchor 1.1 programs; treat the bootstrap sequence as the executable spec.

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { RwaCompliance } from "../target/types/rwa_compliance";
import { RwaPricing } from "../target/types/rwa_pricing";
import { RwaTransferHook } from "../target/types/rwa_transfer_hook";
import { RwaSupplyController } from "../target/types/rwa_supply_controller";
import { RwaVault } from "../target/types/rwa_vault";
import { RwaRedemption } from "../target/types/rwa_redemption";
import {
  TOKEN_2022_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  ExtensionType,
  createInitializeMintInstruction,
  createInitializeTransferHookInstruction,
  createInitializePermissionedBurnInstruction,
  createSetAuthorityInstruction,
  createBurnCheckedInstruction,
  AuthorityType,
  getMintLen,
  createMint,
  mintTo,
  getOrCreateAssociatedTokenAccount,
  getAssociatedTokenAddressSync,
  createAssociatedTokenAccountIdempotent,
  createInitializeAccountInstruction,
  getAccountLenForMint,
  getMint,
  getAccount,
  approve,
  createTransferCheckedWithTransferHookInstruction,
} from "@solana/spl-token";
import {
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  sendAndConfirmTransaction,
  LAMPORTS_PER_SOL,
  ComputeBudgetProgram,
} from "@solana/web3.js";
import {
  Wallet as EthWallet,
  keccak256,
  concat,
  zeroPadValue,
  toBeHex,
  getBytes,
  Signature,
} from "ethers";
import { expect } from "chai";
import { BN } from "bn.js";

const AUDITOR_PRIV =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const RWA_DECIMALS = 6;
const QUOTE_DECIMALS = 6;
const REDEMPTION_TIMEOUT = 86_400; // minimum valid timeout (1 day)
const PROFILE_DIGEST = new Array(32).fill(0x44);
const BPF_LOADER_UPGRADEABLE = new PublicKey(
  "BPFLoaderUpgradeab1e11111111111111111111111",
);

describe("rwa solana — full flow", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const conn = provider.connection;
  const payer = (provider.wallet as anchor.Wallet).payer;

  const compliance = anchor.workspace.RwaCompliance as Program<RwaCompliance>;
  const pricing = anchor.workspace.RwaPricing as Program<RwaPricing>;
  const hook = anchor.workspace.RwaTransferHook as Program<RwaTransferHook>;
  const supply = anchor.workspace
    .RwaSupplyController as Program<RwaSupplyController>;
  const vault = anchor.workspace.RwaVault as Program<RwaVault>;
  const redemption = anchor.workspace.RwaRedemption as Program<RwaRedemption>;

  // Actors. The provider wallet (`payer`) is the programs' upgrade authority on a
  // fresh `anchor test` deploy, so it is the only account allowed to initialize.
  const admin = payer;
  const auditor = new EthWallet(AUDITOR_PRIV);
  const auditorEth = Array.from(getBytes(auditor.address));
  const investor = Keypair.generate();
  const treasurer = Keypair.generate();
  const pricer = Keypair.generate();
  const redemptionManager = Keypair.generate();
  const treasury = Keypair.generate();

  const [registry] = PublicKey.findProgramAddressSync(
    [Buffer.from("registry")],
    compliance.programId,
  );
  const [strategy] = PublicKey.findProgramAddressSync(
    [Buffer.from("strategy")],
    pricing.programId,
  );
  const [supplyConfig] = PublicKey.findProgramAddressSync(
    [Buffer.from("supply-config")],
    supply.programId,
  );
  const [vaultConfig] = PublicKey.findProgramAddressSync(
    [Buffer.from("vault-config")],
    vault.programId,
  );
  const [redemptionConfig] = PublicKey.findProgramAddressSync(
    [Buffer.from("redemption-config")],
    redemption.programId,
  );

  let rwaMint: PublicKey;
  let quoteMint: PublicKey;
  let cluster: number[];
  // token accounts (filled in bootstrap)
  let vaultRwa: PublicKey,
    vaultQuote: PublicKey,
    escrowRwa: PublicKey,
    escrowQuote: PublicKey;
  let investorRwa: PublicKey,
    investorQuote: PublicKey,
    treasurerQuote: PublicKey,
    treasuryQuote: PublicKey;

  const programData = (programId: PublicKey) =>
    PublicKey.findProgramAddressSync(
      [programId.toBuffer()],
      BPF_LOADER_UPGRADEABLE,
    )[0];
  const gate = (programId: PublicKey) => ({
    program: programId,
    programData: programData(programId),
  });
  // Boxed account contexts + secp256k1_recover + hook CPIs push several
  // instructions past the default 200k compute budget; bump it for the heavy ones.
  const cuBump = () => [
    ComputeBudgetProgram.setComputeUnitLimit({ units: 600_000 }),
  ];

  const recordPda = (wallet: PublicKey) =>
    PublicKey.findProgramAddressSync(
      [Buffer.from("record"), wallet.toBuffer()],
      compliance.programId,
    )[0];
  const extraMetas = (mint: PublicKey) =>
    PublicKey.findProgramAddressSync(
      [Buffer.from("extra-account-metas"), mint.toBuffer()],
      hook.programId,
    )[0];

  // Extra accounts forwarded to invoke_transfer_checked so the hook can resolve.
  const hookRemaining = (
    mint: PublicKey,
    srcOwner: PublicKey,
    dstOwner: PublicKey,
  ) => [
    { pubkey: hook.programId, isSigner: false, isWritable: false },
    { pubkey: extraMetas(mint), isSigner: false, isWritable: false },
    { pubkey: compliance.programId, isSigner: false, isWritable: false },
    { pubkey: registry, isSigner: false, isWritable: false },
    { pubkey: recordPda(srcOwner), isSigner: false, isWritable: false },
    { pubkey: recordPda(dstOwner), isSigner: false, isWritable: false },
  ];

  async function fund(pk: PublicKey, sol = 2) {
    await conn.confirmTransaction(
      await conn.requestAirdrop(pk, sol * LAMPORTS_PER_SOL),
    );
  }

  function mintDigest(m: {
    recordKey: number[];
    metadataDigest: number[];
    amount: bigint;
    nonce: number[];
    validUntil: number;
  }): Uint8Array {
    return attestationDigest(
      "MintAttestation(bytes32 auditor,bytes32 profileDigest,bytes32 recordKey,bytes32 metadataDigest,uint64 amount,bytes32 nonce,uint64 validUntil,bytes32 vault)",
      m.recordKey,
      m.metadataDigest,
      m.amount,
      m.nonce,
      m.validUntil,
    );
  }
  function burnDigest(m: {
    operationId: number[];
    metadataDigest: number[];
    amount: bigint;
    nonce: number[];
    validUntil: number;
  }): Uint8Array {
    return attestationDigest(
      "BurnAttestation(bytes32 auditor,bytes32 profileDigest,bytes32 operationId,bytes32 metadataDigest,uint64 amount,bytes32 nonce,uint64 validUntil,bytes32 vault)",
      m.operationId,
      m.metadataDigest,
      m.amount,
      m.nonce,
      m.validUntil,
    );
  }
  function attestationDigest(
    typeStr: string,
    key32: number[],
    metadataDigest: number[],
    amount: bigint,
    nonce: number[],
    validUntil: number,
  ): Uint8Array {
    const kText = (s: string) => keccak256(new TextEncoder().encode(s));
    const dsep = keccak256(
      concat([
        kText(
          "SolanaSupplyAttestation(string name,string version,bytes32 cluster,bytes32 program,bytes32 config)",
        ),
        kText("RWA-Supply-Attestation-Solana"),
        kText("1"),
        new Uint8Array(cluster),
        supply.programId.toBytes(),
        supplyConfig.toBytes(),
      ]),
    );
    const hs = keccak256(
      concat([
        kText(typeStr),
        zeroPadValue(auditor.address, 32),
        Buffer.from(PROFILE_DIGEST),
        Buffer.from(key32),
        Buffer.from(metadataDigest),
        zeroPadValue(toBeHex(amount), 32),
        Buffer.from(nonce),
        zeroPadValue(toBeHex(BigInt(validUntil)), 32),
        vaultConfig.toBytes(),
      ]),
    );
    return getBytes(keccak256(concat(["0x1901", dsep, hs])));
  }
  function sign(digest: Uint8Array): { sig: number[]; recid: number } {
    const s = Signature.from(auditor.signingKey.sign(digest));
    return { sig: Array.from(getBytes(concat([s.r, s.s]))), recid: s.yParity };
  }
  const nonce32 = (n: number) =>
    Array.from(getBytes(zeroPadValue(toBeHex(BigInt(n)), 32)));

  before(async () => {
    for (const k of [investor, treasurer, pricer, redemptionManager, treasury])
      await fund(k.publicKey);
    cluster = Array.from(
      anchor.utils.bytes.bs58.decode(await conn.getGenesisHash()),
    );

    // Token-2022 RWA mint with a transfer hook; mint authority = supply config PDA.
    const mintKp = Keypair.generate();
    rwaMint = mintKp.publicKey;
    // The RWA mint carries the PermissionedBurn extension with the
    // supply-controller config PDA as burn authority, so a plain holder Burn is
    // rejected and every burn must go through the attested supply→vault handshake.
    const len = getMintLen([
      ExtensionType.TransferHook,
      ExtensionType.PermissionedBurn,
    ]);
    const lamports = await conn.getMinimumBalanceForRentExemption(len);
    await sendAndConfirmTransaction(
      conn,
      new Transaction().add(
        SystemProgram.createAccount({
          fromPubkey: payer.publicKey,
          newAccountPubkey: rwaMint,
          space: len,
          lamports,
          programId: TOKEN_2022_PROGRAM_ID,
        }),
        // hook authority is `admin` for now; revoked below so the mint's hook is immutable.
        createInitializeTransferHookInstruction(
          rwaMint,
          admin.publicKey,
          hook.programId,
          TOKEN_2022_PROGRAM_ID,
        ),
        createInitializePermissionedBurnInstruction(
          rwaMint,
          supplyConfig,
          TOKEN_2022_PROGRAM_ID,
        ),
        createInitializeMintInstruction(
          rwaMint,
          RWA_DECIMALS,
          supplyConfig,
          null,
          TOKEN_2022_PROGRAM_ID,
        ),
      ),
      [payer, mintKp],
    );
    quoteMint = await createMint(
      conn,
      payer,
      admin.publicKey,
      null,
      QUOTE_DECIMALS,
      undefined,
      undefined,
      TOKEN_PROGRAM_ID,
    );

    // Revoke the transfer-hook update authority so the hook is immutable.
    await sendAndConfirmTransaction(
      conn,
      new Transaction().add(
        createSetAuthorityInstruction(
          rwaMint,
          admin.publicKey,
          AuthorityType.TransferHookProgramId,
          null,
          [],
          TOKEN_2022_PROGRAM_ID,
        ),
      ),
      [payer],
    );
  });

  it("bootstraps the whole stack (upgrade-authority gated)", async () => {
    await compliance.methods
      .initialize(admin.publicKey, admin.publicKey, admin.publicKey)
      .accountsStrict({
        registry,
        payer: payer.publicKey,
        ...gate(compliance.programId),
        systemProgram: SystemProgram.programId,
      })
      .rpc();
    await pricing.methods
      .initialize(
        RWA_DECIMALS,
        new BN(2_000_000),
        new BN(1_950_000),
        admin.publicKey,
        pricer.publicKey,
      )
      .accountsStrict({
        strategy,
        payer: payer.publicKey,
        ...gate(pricing.programId),
        systemProgram: SystemProgram.programId,
      })
      .rpc();
    await supply.methods
      .initialize(admin.publicKey, auditorEth, PROFILE_DIGEST, cluster)
      .accountsStrict({
        config: supplyConfig,
        mint: rwaMint,
        vaultAuthority: vaultConfig,
        registry,
        payer: payer.publicKey,
        ...gate(supply.programId),
        systemProgram: SystemProgram.programId,
      })
      .rpc();
    await vault.methods
      .initialize(
        admin.publicKey,
        treasurer.publicKey,
        treasury.publicKey,
        supplyConfig,
        QUOTE_DECIMALS,
      )
      .accountsStrict({
        config: vaultConfig,
        rwaMint,
        quoteMint,
        strategy,
        registry,
        payer: payer.publicKey,
        ...gate(vault.programId),
        systemProgram: SystemProgram.programId,
      })
      .rpc();
    await redemption.methods
      .initialize(
        admin.publicKey,
        treasurer.publicKey,
        redemptionManager.publicKey,
        vaultConfig,
        new BN(REDEMPTION_TIMEOUT),
        QUOTE_DECIMALS,
      )
      .accountsStrict({
        config: redemptionConfig,
        rwaMint,
        quoteMint,
        strategy,
        registry,
        payer: payer.publicKey,
        ...gate(redemption.programId),
        systemProgram: SystemProgram.programId,
      })
      .rpc();
    await hook.methods
      .initializeExtraAccountMetaList()
      .accountsStrict({
        payer: payer.publicKey,
        extraAccountMetaList: extraMetas(rwaMint),
        mint: rwaMint,
        ...gate(hook.programId),
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    // Pinning atomically allowlists vault + escrow, pins the supply-controller
    // program id (robust to `anchor keys sync`) — passed as an executable account —
    // and pins the RWA mint for the hook's mint check.
    //
    // A corrective re-pin must atomically clear the superseded record so a mistaken
    // bootstrap pin cannot leave a wallet permanently allowlisted. First pin a wrong
    // pair, then correct to the real vault/escrow passing the old records to be
    // reset to Unknown.
    const wrongVault = Keypair.generate().publicKey;
    const wrongEscrow = Keypair.generate().publicKey;
    await compliance.methods
      .setSystemAddresses()
      .accountsStrict({
        registry,
        admin: admin.publicKey,
        vault: wrongVault,
        escrow: wrongEscrow,
        supplyControllerProgram: supply.programId,
        rwaMint,
        vaultRecord: recordPda(wrongVault),
        escrowRecord: recordPda(wrongEscrow),
        prevVaultRecord: null,
        prevEscrowRecord: null,
        payer: payer.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();
    await compliance.methods
      .setSystemAddresses()
      .accountsStrict({
        registry,
        admin: admin.publicKey,
        vault: vaultConfig,
        escrow: redemptionConfig,
        supplyControllerProgram: supply.programId,
        rwaMint,
        vaultRecord: recordPda(vaultConfig),
        escrowRecord: recordPda(redemptionConfig),
        prevVaultRecord: recordPda(wrongVault),
        prevEscrowRecord: recordPda(wrongEscrow),
        payer: payer.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();
    // The superseded wallets are no longer allowlisted (reset to Unknown = 0).
    expect(
      (await compliance.account.complianceRecord.fetch(recordPda(wrongVault)))
        .status,
    ).to.equal(0);
    expect(
      (await compliance.account.complianceRecord.fetch(recordPda(wrongEscrow)))
        .status,
    ).to.equal(0);

    // Allow the investor.
    await compliance.methods
      .setStatus(1, new BN(0))
      .accountsStrict({
        registry,
        authority: admin.publicKey,
        wallet: investor.publicKey,
        record: recordPda(investor.publicKey),
        payer: payer.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    // finalize — cross-checks the whole singleton mesh against the canonical PDAs
    // and flips the global go-live flag. Mint/buy/redeem all refuse to run until
    // this passes. admin == registryAdmin == the provider wallet here.
    const finalizeAccounts = {
      config: supplyConfig,
      admin: admin.publicKey,
      mint: rwaMint,
      registry,
      vaultConfig,
      redemptionConfig,
      strategy,
      registryAdmin: admin.publicKey,
      complianceProgram: compliance.programId,
      complianceProgramData: programData(compliance.programId),
      // The mint's ExtraAccountMetaList PDA, proven to exist and carry the
      // canonical entries before go-live.
      extraAccountMetaList: extraMetas(rwaMint),
    };

    // finalize must reject a registry whose pinned rwa_mint differs from the mesh's
    // mint. Temporarily mis-pin the mint (vault/escrow unchanged, so no prev
    // records), prove finalize fails, then restore the correct pin.
    const wrongMint = Keypair.generate().publicKey;
    await compliance.methods
      .setSystemAddresses()
      .accountsStrict({
        registry,
        admin: admin.publicKey,
        vault: vaultConfig,
        escrow: redemptionConfig,
        supplyControllerProgram: supply.programId,
        rwaMint: wrongMint,
        vaultRecord: recordPda(vaultConfig),
        escrowRecord: recordPda(redemptionConfig),
        prevVaultRecord: null,
        prevEscrowRecord: null,
        payer: payer.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();
    let m01Threw = false;
    try {
      await supply.methods
        .finalize(cluster)
        .accountsStrict(finalizeAccounts)
        .rpc();
    } catch {
      m01Threw = true;
    }
    expect(m01Threw).to.equal(true);
    await compliance.methods
      .setSystemAddresses()
      .accountsStrict({
        registry,
        admin: admin.publicKey,
        vault: vaultConfig,
        escrow: redemptionConfig,
        supplyControllerProgram: supply.programId,
        rwaMint,
        vaultRecord: recordPda(vaultConfig),
        escrowRecord: recordPda(redemptionConfig),
        prevVaultRecord: null,
        prevEscrowRecord: null,
        payer: payer.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    // finalize must reject a wrong/absent ExtraAccountMetaList account (here the
    // registry account: wrong key, and hook-program not its owner).
    let m02Threw = false;
    try {
      await supply.methods
        .finalize(cluster)
        .accountsStrict({ ...finalizeAccounts, extraAccountMetaList: registry })
        .rpc();
    } catch {
      m02Threw = true;
    }
    expect(m02Threw).to.equal(true);

    await supply.methods
      .finalize(cluster)
      .accountsStrict(finalizeAccounts)
      .rpc();

    const reg = await compliance.account.registry.fetch(registry);
    expect(reg.systemSet).to.equal(true);
    expect(reg.finalized).to.equal(true);
    expect(reg.paused).to.equal(false);
  });

  it("rejects a second finalize (AlreadyFinalized guard)", async () => {
    let threw = false;
    try {
      await supply.methods
        .finalize(cluster)
        .accountsStrict({
          config: supplyConfig,
          admin: admin.publicKey,
          mint: rwaMint,
          registry,
          vaultConfig,
          redemptionConfig,
          strategy,
          registryAdmin: admin.publicKey,
          complianceProgram: compliance.programId,
          complianceProgramData: programData(compliance.programId),
          extraAccountMetaList: extraMetas(rwaMint),
        })
        .rpc();
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);

    // Token accounts. Vault/escrow are owned by PDAs (off the ed25519 curve), so
    // their ATAs must be created with allowOwnerOffCurve = true.
    const ataOffCurve = async (
      mint: PublicKey,
      owner: PublicKey,
      prog: PublicKey,
    ) =>
      (
        await getOrCreateAssociatedTokenAccount(
          conn,
          payer,
          mint,
          owner,
          true,
          undefined,
          undefined,
          prog,
        )
      ).address;
    vaultRwa = await ataOffCurve(rwaMint, vaultConfig, TOKEN_2022_PROGRAM_ID);
    vaultQuote = await ataOffCurve(quoteMint, vaultConfig, TOKEN_PROGRAM_ID);
    escrowRwa = await ataOffCurve(
      rwaMint,
      redemptionConfig,
      TOKEN_2022_PROGRAM_ID,
    );
    escrowQuote = await ataOffCurve(
      quoteMint,
      redemptionConfig,
      TOKEN_PROGRAM_ID,
    );
    investorRwa = await createAssociatedTokenAccountIdempotent(
      conn,
      payer,
      rwaMint,
      investor.publicKey,
      {},
      TOKEN_2022_PROGRAM_ID,
    );
    investorQuote = (
      await getOrCreateAssociatedTokenAccount(
        conn,
        payer,
        quoteMint,
        investor.publicKey,
        false,
        undefined,
        undefined,
        TOKEN_PROGRAM_ID,
      )
    ).address;
    treasurerQuote = (
      await getOrCreateAssociatedTokenAccount(
        conn,
        payer,
        quoteMint,
        treasurer.publicKey,
        false,
        undefined,
        undefined,
        TOKEN_PROGRAM_ID,
      )
    ).address;
    treasuryQuote = await createAssociatedTokenAccountIdempotent(
      conn,
      payer,
      quoteMint,
      treasury.publicKey,
      {},
      TOKEN_PROGRAM_ID,
    );
    await mintTo(
      conn,
      payer,
      quoteMint,
      investorQuote,
      admin,
      BigInt(1_000_000_000),
      [],
      undefined,
      TOKEN_PROGRAM_ID,
    );
    await mintTo(
      conn,
      payer,
      quoteMint,
      treasurerQuote,
      admin,
      BigInt(1_000_000_000),
      [],
      undefined,
      TOKEN_PROGRAM_ID,
    );
  });

  it("rejects initialization by a non-upgrade-authority", async () => {
    const attacker = Keypair.generate();
    await fund(attacker.publicKey);
    let threw = false;
    try {
      // Re-initializing is impossible anyway; the gate rejects before that. Use a
      // fresh-looking attempt: the attacker as payer fails the ProgramData check.
      await compliance.methods
        .initialize(attacker.publicKey, attacker.publicKey, attacker.publicKey)
        .accountsStrict({
          registry,
          payer: attacker.publicKey,
          ...gate(compliance.programId),
          systemProgram: SystemProgram.programId,
        })
        .signers([attacker])
        .rpc();
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  const amount = BigInt(100) * BigInt(10) ** BigInt(RWA_DECIMALS);

  it("mints to the vault under a valid auditor signature", async () => {
    const recordKey = new Array(32).fill(0x55);
    const metadataDigest = new Array(32).fill(0x66);
    const nonce = nonce32(1);
    const validUntil = Math.floor(Date.now() / 1000) + 3600;
    const { sig, recid } = sign(
      mintDigest({ recordKey, metadataDigest, amount, nonce, validUntil }),
    );
    await supply.methods
      .mint(
        recordKey,
        metadataDigest,
        new BN(amount.toString()),
        nonce,
        new BN(validUntil),
        sig,
        recid,
      )
      .preInstructions(cuBump())
      .accountsStrict({
        config: supplyConfig,
        registry,
        mint: rwaMint,
        vaultToken: vaultRwa,
        nonceMarker: PublicKey.findProgramAddressSync(
          [Buffer.from("nonce"), Buffer.from(nonce)],
          supply.programId,
        )[0],
        recordMarker: PublicKey.findProgramAddressSync(
          [Buffer.from("record-key"), Buffer.from(recordKey)],
          supply.programId,
        )[0],
        payer: payer.publicKey,
        tokenProgram: TOKEN_2022_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .rpc();
    expect(
      (await getAccount(conn, vaultRwa, undefined, TOKEN_2022_PROGRAM_ID))
        .amount,
    ).to.equal(amount);
  });

  it("rejects a mint replaying a used nonce", async () => {
    const recordKey = new Array(32).fill(0x77);
    const nonce = nonce32(1); // reuse
    const validUntil = Math.floor(Date.now() / 1000) + 3600;
    const { sig, recid } = sign(
      mintDigest({
        recordKey,
        metadataDigest: new Array(32).fill(0x66),
        amount,
        nonce,
        validUntil,
      }),
    );
    let threw = false;
    try {
      await supply.methods
        .mint(
          recordKey,
          new Array(32).fill(0x66),
          new BN(amount.toString()),
          nonce,
          new BN(validUntil),
          sig,
          recid,
        )
        .preInstructions(cuBump())
        .accountsStrict({
          config: supplyConfig,
          registry,
          mint: rwaMint,
          vaultToken: vaultRwa,
          nonceMarker: PublicKey.findProgramAddressSync(
            [Buffer.from("nonce"), Buffer.from(nonce)],
            supply.programId,
          )[0],
          recordMarker: PublicKey.findProgramAddressSync(
            [Buffer.from("record-key"), Buffer.from(recordKey)],
            supply.programId,
          )[0],
          payer: payer.publicKey,
          tokenProgram: TOKEN_2022_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it("rejects a malleable high-S signature over an otherwise-valid mint", async () => {
    // secp256k1 curve order n. Given a canonical low-S signature (r, s, v), the
    // mutated (r, n - s, v ^ 1) recovers to the same key but is the high-S encoding
    // the EVM twin rejects. verify_signature must reject it before recovery.
    const N = BigInt(
      "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    );
    const recordKey = new Array(32).fill(0xa5);
    const metadataDigest = new Array(32).fill(0x66);
    const nonce = nonce32(9001);
    const validUntil = Math.floor(Date.now() / 1000) + 3600;
    const { sig, recid } = sign(
      mintDigest({ recordKey, metadataDigest, amount, nonce, validUntil }),
    );
    const s = BigInt("0x" + Buffer.from(sig.slice(32)).toString("hex"));
    const highS = Array.from(getBytes(zeroPadValue(toBeHex(N - s), 32)));
    const malleable = sig.slice(0, 32).concat(highS);
    let threw = false;
    try {
      await supply.methods
        .mint(
          recordKey,
          metadataDigest,
          new BN(amount.toString()),
          nonce,
          new BN(validUntil),
          malleable,
          recid ^ 1,
        )
        .preInstructions(cuBump())
        .accountsStrict({
          config: supplyConfig,
          registry,
          mint: rwaMint,
          vaultToken: vaultRwa,
          nonceMarker: PublicKey.findProgramAddressSync(
            [Buffer.from("nonce"), Buffer.from(nonce)],
            supply.programId,
          )[0],
          recordMarker: PublicKey.findProgramAddressSync(
            [Buffer.from("record-key"), Buffer.from(recordKey)],
            supply.programId,
          )[0],
          payer: payer.publicKey,
          tokenProgram: TOKEN_2022_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  const buyAmount = BigInt(10) * BigInt(10) ** BigInt(RWA_DECIMALS);

  it("lets an allowed investor buy, and blocks a non-allowed recipient", async () => {
    const deadline = Math.floor(Date.now() / 1000) + 3600;
    await vault.methods
      .buy(new BN(buyAmount.toString()), new BN("1000000000"), new BN(deadline))
      .preInstructions(cuBump())
      .accountsStrict({
        config: vaultConfig,
        registry,
        strategy,
        rwaMint,
        quoteMint,
        vaultToken: vaultRwa,
        vaultQuote,
        buyer: investor.publicKey,
        buyerQuote: investorQuote,
        recipientToken: investorRwa,
        buyerRecord: recordPda(investor.publicKey),
        recipientRecord: recordPda(investor.publicKey),
        quoteTokenProgram: TOKEN_PROGRAM_ID,
        rwaTokenProgram: TOKEN_2022_PROGRAM_ID,
      })
      .remainingAccounts(
        hookRemaining(rwaMint, vaultConfig, investor.publicKey),
      )
      .signers([investor])
      .rpc();
    expect(
      (await getAccount(conn, investorRwa, undefined, TOKEN_2022_PROGRAM_ID))
        .amount,
    ).to.equal(buyAmount);

    // A non-allowed recipient (fresh wallet, no record) must be rejected.
    const stranger = Keypair.generate();
    const strangerRwa = await createAssociatedTokenAccountIdempotent(
      conn,
      payer,
      rwaMint,
      stranger.publicKey,
      {},
      TOKEN_2022_PROGRAM_ID,
    );
    let threw = false;
    try {
      await vault.methods
        .buy(
          new BN(buyAmount.toString()),
          new BN("1000000000"),
          new BN(deadline),
        )
        .preInstructions(cuBump())
        .accountsStrict({
          config: vaultConfig,
          registry,
          strategy,
          rwaMint,
          quoteMint,
          vaultToken: vaultRwa,
          vaultQuote,
          buyer: investor.publicKey,
          buyerQuote: investorQuote,
          recipientToken: strangerRwa,
          buyerRecord: recordPda(investor.publicKey),
          recipientRecord: recordPda(stranger.publicKey),
          quoteTokenProgram: TOKEN_PROGRAM_ID,
          rwaTokenProgram: TOKEN_2022_PROGRAM_ID,
        })
        .remainingAccounts(
          hookRemaining(rwaMint, vaultConfig, stranger.publicKey),
        )
        .signers([investor])
        .rpc();
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it("runs request → fund → claim", async () => {
    const deadline = Math.floor(Date.now() / 1000) + 3600;
    const [req0] = PublicKey.findProgramAddressSync(
      [Buffer.from("request"), new BN(0).toArrayLike(Buffer, "le", 8)],
      redemption.programId,
    );
    await redemption.methods
      .requestRedemption(
        new BN(buyAmount.toString()),
        new BN(0),
        new BN(deadline),
      )
      .preInstructions(cuBump())
      .accountsStrict({
        config: redemptionConfig,
        registry,
        strategy,
        rwaMint,
        request: req0,
        beneficiary: investor.publicKey,
        beneficiaryToken: investorRwa,
        escrowToken: escrowRwa,
        beneficiaryRecord: recordPda(investor.publicKey),
        rwaTokenProgram: TOKEN_2022_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts(
        hookRemaining(rwaMint, investor.publicKey, redemptionConfig),
      )
      .signers([investor])
      .rpc();
    await redemption.methods
      .fundRedemption(new BN(0))
      .preInstructions(cuBump())
      .accountsStrict({
        config: redemptionConfig,
        registry,
        request: req0,
        quoteMint,
        treasurer: treasurer.publicKey,
        treasurerQuote,
        escrowQuote,
        beneficiaryRecord: recordPda(investor.publicKey),
        quoteTokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([treasurer])
      .rpc();
    await redemption.methods
      .claimRedemption(new BN(0))
      .preInstructions(cuBump())
      .accountsStrict({
        config: redemptionConfig,
        registry,
        request: req0,
        rwaMint,
        quoteMint,
        escrowToken: escrowRwa,
        escrowQuote,
        vaultToken: vaultRwa,
        beneficiaryQuote: investorQuote,
        rwaTokenProgram: TOKEN_2022_PROGRAM_ID,
        quoteTokenProgram: TOKEN_PROGRAM_ID,
      })
      .remainingAccounts(hookRemaining(rwaMint, redemptionConfig, vaultConfig))
      .rpc();
    expect(
      (await redemption.account.redemptionRequest.fetch(req0)).status,
    ).to.equal(3); // Completed
  });

  it("cancel before the 1-day timeout is rejected; reject returns the escrow", async () => {
    const deadline = Math.floor(Date.now() / 1000) + 3600;
    // The prior claim moved the investor's RWA to the vault; buy a fresh lot so the
    // investor has RWA to escrow here (reject returns it, for the later burn test).
    await vault.methods
      .buy(new BN(buyAmount.toString()), new BN("1000000000"), new BN(deadline))
      .preInstructions(cuBump())
      .accountsStrict({
        config: vaultConfig,
        registry,
        strategy,
        rwaMint,
        quoteMint,
        vaultToken: vaultRwa,
        vaultQuote,
        buyer: investor.publicKey,
        buyerQuote: investorQuote,
        recipientToken: investorRwa,
        buyerRecord: recordPda(investor.publicKey),
        recipientRecord: recordPda(investor.publicKey),
        quoteTokenProgram: TOKEN_PROGRAM_ID,
        rwaTokenProgram: TOKEN_2022_PROGRAM_ID,
      })
      .remainingAccounts(
        hookRemaining(rwaMint, vaultConfig, investor.publicKey),
      )
      .signers([investor])
      .rpc();
    const [req1] = PublicKey.findProgramAddressSync(
      [Buffer.from("request"), new BN(1).toArrayLike(Buffer, "le", 8)],
      redemption.programId,
    );
    await redemption.methods
      .requestRedemption(
        new BN(buyAmount.toString()),
        new BN(0),
        new BN(deadline),
      )
      .preInstructions(cuBump())
      .accountsStrict({
        config: redemptionConfig,
        registry,
        strategy,
        rwaMint,
        request: req1,
        beneficiary: investor.publicKey,
        beneficiaryToken: investorRwa,
        escrowToken: escrowRwa,
        beneficiaryRecord: recordPda(investor.publicKey),
        rwaTokenProgram: TOKEN_2022_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts(
        hookRemaining(rwaMint, investor.publicKey, redemptionConfig),
      )
      .signers([investor])
      .rpc();

    // The redemption timeout is bounded to a 1-day minimum (EVM parity), which a
    // validator mocha run can't real-time warp, so an immediate cancel is
    // rejected with TimeoutNotReached. (The successful post-timeout cancel + the
    // hook's escrow pause-bypass are covered by `redemption-core::can_cancel` tests.)
    // The cancel is attempted while paused to confirm the pause-bypass path is still
    // reached before the timeout guard fires.
    await compliance.methods
      .pause()
      .accountsStrict({ registry, pauser: admin.publicKey })
      .rpc();
    let cancelThrew = false;
    try {
      await redemption.methods
        .cancelRedemption(new BN(1))
        .preInstructions(cuBump())
        .accountsStrict({
          config: redemptionConfig,
          registry,
          request: req1,
          rwaMint,
          escrowToken: escrowRwa,
          beneficiaryToken: investorRwa,
          beneficiaryRecord: recordPda(investor.publicKey),
          beneficiary: investor.publicKey,
          rwaTokenProgram: TOKEN_2022_PROGRAM_ID,
        })
        .remainingAccounts(
          hookRemaining(rwaMint, redemptionConfig, investor.publicKey),
        )
        .signers([investor])
        .rpc();
    } catch {
      cancelThrew = true;
    }
    expect(cancelThrew).to.equal(true);
    await compliance.methods
      .unpause()
      .accountsStrict({ registry, pauser: admin.publicKey })
      .rpc();

    // Reject (redemption manager) unwinds the Pending request, returning the escrow
    // to the investor — exercises the reject escrow-return leg on-chain and leaves
    // the investor holding RWA for the burn / delegate negatives below.
    const reasonCode = new Array(32).fill(0x01);
    await redemption.methods
      .rejectRedemption(new BN(1), reasonCode)
      .preInstructions(cuBump())
      .accountsStrict({
        config: redemptionConfig,
        registry,
        request: req1,
        rwaMint,
        escrowToken: escrowRwa,
        beneficiaryToken: investorRwa,
        beneficiaryRecord: recordPda(investor.publicKey),
        redemptionManager: redemptionManager.publicKey,
        rwaTokenProgram: TOKEN_2022_PROGRAM_ID,
      })
      .remainingAccounts(
        hookRemaining(rwaMint, redemptionConfig, investor.publicKey),
      )
      .signers([redemptionManager])
      .rpc();
    expect(
      (await redemption.account.redemptionRequest.fetch(req1)).status,
    ).to.equal(4); // Rejected

    // The terminal request's rent can be reclaimed to the beneficiary.
    await redemption.methods
      .closeRequest(new BN(1))
      .accountsStrict({
        config: redemptionConfig,
        registry,
        request: req1,
        beneficiary: investor.publicKey,
      })
      .rpc();
    let closed = false;
    try {
      await redemption.account.redemptionRequest.fetch(req1);
    } catch {
      closed = true;
    }
    expect(closed).to.equal(true);
  });

  it("burns returned inventory via the supply→vault handshake", async () => {
    const burnAmount = BigInt(5) * BigInt(10) ** BigInt(RWA_DECIMALS);
    const operationId = new Array(32).fill(0x0a);
    const nonce = nonce32(2);
    const validUntil = Math.floor(Date.now() / 1000) + 3600;
    const { sig, recid } = sign(
      burnDigest({
        operationId,
        metadataDigest: new Array(32).fill(0x66),
        amount: burnAmount,
        nonce,
        validUntil,
      }),
    );
    const before = (
      await getAccount(conn, vaultRwa, undefined, TOKEN_2022_PROGRAM_ID)
    ).amount;
    await supply.methods
      .burnSupply(
        operationId,
        new Array(32).fill(0x66),
        new BN(burnAmount.toString()),
        nonce,
        new BN(validUntil),
        sig,
        recid,
      )
      .preInstructions(cuBump())
      .accountsStrict({
        config: supplyConfig,
        registry,
        mint: rwaMint,
        vaultConfig,
        vaultToken: vaultRwa,
        nonceMarker: PublicKey.findProgramAddressSync(
          [Buffer.from("nonce"), Buffer.from(nonce)],
          supply.programId,
        )[0],
        operationMarker: PublicKey.findProgramAddressSync(
          [Buffer.from("operation"), Buffer.from(operationId)],
          supply.programId,
        )[0],
        payer: payer.publicKey,
        vaultProgram: vault.programId,
        tokenProgram: TOKEN_2022_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
      })
      .rpc();
    expect(
      (await getAccount(conn, vaultRwa, undefined, TOKEN_2022_PROGRAM_ID))
        .amount,
    ).to.equal(before - burnAmount);
  });

  // ---- Audit-2 negative security cases -------------------------------------

  it("rejects wiring a mint that retains a freeze authority", async () => {
    // A Token-2022 mint with our hook but a non-null freeze authority must be
    // refused by validate_rwa_mint (reached here via the hook's meta-list init).
    const badKp = Keypair.generate();
    const len = getMintLen([ExtensionType.TransferHook]);
    const lamports = await conn.getMinimumBalanceForRentExemption(len);
    await sendAndConfirmTransaction(
      conn,
      new Transaction().add(
        SystemProgram.createAccount({
          fromPubkey: payer.publicKey,
          newAccountPubkey: badKp.publicKey,
          space: len,
          lamports,
          programId: TOKEN_2022_PROGRAM_ID,
        }),
        createInitializeTransferHookInstruction(
          badKp.publicKey,
          admin.publicKey,
          hook.programId,
          TOKEN_2022_PROGRAM_ID,
        ),
        // freeze authority = admin (non-null) → must be rejected.
        createInitializeMintInstruction(
          badKp.publicKey,
          RWA_DECIMALS,
          supplyConfig,
          admin.publicKey,
          TOKEN_2022_PROGRAM_ID,
        ),
      ),
      [payer, badKp],
    );
    let threw = false;
    try {
      await hook.methods
        .initializeExtraAccountMetaList()
        .accountsStrict({
          payer: payer.publicKey,
          extraAccountMetaList: extraMetas(badKp.publicKey),
          mint: badKp.publicKey,
          ...gate(hook.programId),
          systemProgram: SystemProgram.programId,
        })
        .rpc();
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it("rejects receipt into a mutable (non-ImmutableOwner) token account", async () => {
    // A raw (non-ATA) Token-2022 account for an *allowed* owner has no
    // ImmutableOwner extension, so its owner could later be reassigned. The hook
    // must reject any RWA transfer into it — even though the owner is allowed.
    const mutableAcc = Keypair.generate();
    // Size the raw account for the mint's required account extensions (e.g.
    // TransferHookAccount) but WITHOUT ImmutableOwner — only ATAs add that.
    const mintInfo = await getMint(
      conn,
      rwaMint,
      undefined,
      TOKEN_2022_PROGRAM_ID,
    );
    const accLen = getAccountLenForMint(mintInfo);
    const rent = await conn.getMinimumBalanceForRentExemption(accLen);
    await sendAndConfirmTransaction(
      conn,
      new Transaction().add(
        SystemProgram.createAccount({
          fromPubkey: payer.publicKey,
          newAccountPubkey: mutableAcc.publicKey,
          space: accLen,
          lamports: rent,
          programId: TOKEN_2022_PROGRAM_ID,
        }),
        createInitializeAccountInstruction(
          mutableAcc.publicKey,
          rwaMint,
          investor.publicKey,
          TOKEN_2022_PROGRAM_ID,
        ),
      ),
      [payer, mutableAcc],
    );
    const deadline = Math.floor(Date.now() / 1000) + 3600;
    let threw = false;
    try {
      await vault.methods
        .buy(
          new BN(buyAmount.toString()),
          new BN("1000000000"),
          new BN(deadline),
        )
        .preInstructions(cuBump())
        .accountsStrict({
          config: vaultConfig,
          registry,
          strategy,
          rwaMint,
          quoteMint,
          vaultToken: vaultRwa,
          vaultQuote,
          buyer: investor.publicKey,
          buyerQuote: investorQuote,
          recipientToken: mutableAcc.publicKey,
          buyerRecord: recordPda(investor.publicKey),
          recipientRecord: recordPda(investor.publicKey),
          quoteTokenProgram: TOKEN_PROGRAM_ID,
          rwaTokenProgram: TOKEN_2022_PROGRAM_ID,
        })
        .remainingAccounts(
          hookRemaining(rwaMint, vaultConfig, investor.publicKey),
        )
        .signers([investor])
        .rpc();
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  it("rejects a direct hook Execute outside an active transfer", async () => {
    // Calling the hook handler directly (no in-flight Token-2022 transfer) leaves
    // the source account's `transferring` flag false → NotTransferring.
    let threw = false;
    try {
      await hook.methods
        .transferHook(new BN(0))
        .accountsStrict({
          sourceToken: investorRwa,
          mint: rwaMint,
          destinationToken: vaultRwa,
          owner: investor.publicKey,
          extraAccountMetaList: extraMetas(rwaMint),
          complianceProgram: compliance.programId,
          registry,
          sourceRecord: recordPda(investor.publicKey),
          destinationRecord: recordPda(vaultConfig),
        })
        .rpc();
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  // The mint's PermissionedBurn extension makes the Token-2022 program reject a
  // plain holder Burn/BurnChecked. An investor holding RWA cannot self-burn; supply
  // can only change through the attested supply→vault permissioned-burn handshake.
  it("a direct holder Burn is rejected by the permissioned-burn extension", async () => {
    const bal = (
      await getAccount(conn, investorRwa, undefined, TOKEN_2022_PROGRAM_ID)
    ).amount;
    expect(bal > BigInt(0)).to.equal(true); // investor holds RWA from the earlier buy
    let threw = false;
    try {
      await sendAndConfirmTransaction(
        conn,
        new Transaction().add(
          createBurnCheckedInstruction(
            investorRwa,
            rwaMint,
            investor.publicKey,
            BigInt(1),
            RWA_DECIMALS,
            [],
            TOKEN_2022_PROGRAM_ID,
          ),
        ),
        [payer, investor],
      );
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
    // Balance unchanged — the burn did not go through.
    expect(
      (await getAccount(conn, investorRwa, undefined, TOKEN_2022_PROGRAM_ID))
        .amount,
    ).to.equal(bal);
  });

  // Delegate policy (strict authority == owner). A hook-aware delegated
  // transfer (approve + createTransferCheckedWithTransferHookInstruction with the
  // delegate as authority) must fail with DelegateNotAllowed: the hook checks the
  // Execute authority (index 3) equals the source token account owner, and a
  // delegate is not the owner.
  it("an approved delegate cannot move an allowed owner's RWA", async () => {
    const bal = (
      await getAccount(conn, investorRwa, undefined, TOKEN_2022_PROGRAM_ID)
    ).amount;
    expect(bal > BigInt(0)).to.equal(true); // investor holds RWA from the earlier buy
    const delegate = Keypair.generate();
    await fund(delegate.publicKey);
    // Approve the delegate for 1 unit of the investor's RWA.
    await approve(
      conn,
      payer,
      investorRwa,
      delegate.publicKey,
      investor,
      BigInt(1),
      [],
      undefined,
      TOKEN_2022_PROGRAM_ID,
    );
    // Build a hook-resolving transferChecked with the DELEGATE as the authority.
    const ix = await createTransferCheckedWithTransferHookInstruction(
      conn,
      investorRwa,
      rwaMint,
      vaultRwa,
      delegate.publicKey,
      BigInt(1),
      RWA_DECIMALS,
      [],
      undefined,
      TOKEN_2022_PROGRAM_ID,
    );
    let threw = false;
    try {
      await sendAndConfirmTransaction(conn, new Transaction().add(ix), [
        payer,
        delegate,
      ]);
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
    // Balance unchanged — the delegated transfer did not go through.
    expect(
      (await getAccount(conn, investorRwa, undefined, TOKEN_2022_PROGRAM_ID))
        .amount,
    ).to.equal(bal);
  });

  // `set_finalized` is reachable only as the supply-controller `finalize` CPI
  // (which signs as the supply config PDA). A direct call cannot produce that
  // signature, so it fails at account resolution — closing both the go-live bypass
  // and the permanent-DoS the direct call used to cause.
  it("a direct set_finalized is rejected (no supply-controller signature)", async () => {
    let threw = false;
    try {
      await compliance.methods
        .setFinalized()
        .accountsStrict({
          registry,
          admin: admin.publicKey,
          supplyConfig: supplyConfig,
          ...gate(compliance.programId),
        })
        .rpc();
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });

  // A mint directed at a Vault-owned account that is NOT the canonical
  // inventory ATA must be rejected (NotCanonicalAta), so a leaked/front-run
  // attestation cannot be redirected into an unspendable shadow account.
  it("rejects a mint to a non-canonical Vault-owned account", async () => {
    // A raw (non-ATA) Token-2022 account owned by the vault config PDA.
    const shadow = Keypair.generate();
    const mintInfo = await getMint(
      conn,
      rwaMint,
      undefined,
      TOKEN_2022_PROGRAM_ID,
    );
    const accLen = getAccountLenForMint(mintInfo);
    const rent = await conn.getMinimumBalanceForRentExemption(accLen);
    await sendAndConfirmTransaction(
      conn,
      new Transaction().add(
        SystemProgram.createAccount({
          fromPubkey: payer.publicKey,
          newAccountPubkey: shadow.publicKey,
          space: accLen,
          lamports: rent,
          programId: TOKEN_2022_PROGRAM_ID,
        }),
        createInitializeAccountInstruction(
          shadow.publicKey,
          rwaMint,
          vaultConfig,
          TOKEN_2022_PROGRAM_ID,
        ),
      ),
      [payer, shadow],
    );
    const recordKey = new Array(32).fill(0x99);
    const nonce = nonce32(42);
    const validUntil = Math.floor(Date.now() / 1000) + 3600;
    const { sig, recid } = sign(
      mintDigest({
        recordKey,
        metadataDigest: new Array(32).fill(0x66),
        amount,
        nonce,
        validUntil,
      }),
    );
    let threw = false;
    try {
      await supply.methods
        .mint(
          recordKey,
          new Array(32).fill(0x66),
          new BN(amount.toString()),
          nonce,
          new BN(validUntil),
          sig,
          recid,
        )
        .preInstructions(cuBump())
        .accountsStrict({
          config: supplyConfig,
          registry,
          mint: rwaMint,
          vaultToken: shadow.publicKey,
          nonceMarker: PublicKey.findProgramAddressSync(
            [Buffer.from("nonce"), Buffer.from(nonce)],
            supply.programId,
          )[0],
          recordMarker: PublicKey.findProgramAddressSync(
            [Buffer.from("record-key"), Buffer.from(recordKey)],
            supply.programId,
          )[0],
          payer: payer.publicKey,
          tokenProgram: TOKEN_2022_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });
});
