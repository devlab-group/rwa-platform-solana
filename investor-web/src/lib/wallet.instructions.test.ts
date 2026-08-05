// @vitest-environment node
//
// Instruction-building coverage for lib/wallet.ts's send calls: sendBuy,
// sendRequestRedemption, sendClaimRedemption, sendCancelRedemption. These are
// the highest-value uncovered surface in this app — a wrong account or a
// reversed hook source/destination here silently resolves the wrong
// compliance record and either lets a blocked transfer through the hook or
// wrongly rejects an allowed one. It also covers pinned program ids/mints
// being hard-asserted before a signature is requested, and the quote leg's
// token program being resolved from the mint, not hardcoded to legacy SPL.
//
// Each of the four calls a `Program` built by lib/chain/provider.ts
// (vaultProgram/redemptionProgram), so that module is mocked wholesale:
// vaultProgram/redemptionProgram resolve to a stub whose
// `.methods.<ix>(...).accountsStrict(...).remainingAccounts(...).instruction()`
// chain records exactly what wallet.ts passed, without needing a live
// validator. getConnection/getInjectedProvider are stubbed just
// enough for the sign-and-broadcast plumbing (signAndSend, private to
// wallet.ts) to complete — including the getAccountInfo (mint-owner lookup)
// and simulateTransaction (pre-sign backstop) calls it now makes.
//
// Expected account maps are computed with the very same lib/chain/pda.ts
// helpers wallet.ts itself uses, and each assertion cites the corresponding
// on-chain call in solana/tests/fullflow.ts — the authoritative reference for
// account/PDA shapes — so a regression here diverging from that fixture is
// caught even though this file never touches a validator.
//
// Runs under node, not jsdom: PublicKey.findProgramAddressSync misbehaves
// under jsdom's `crypto` shim in this toolchain (see pda.test.ts).
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import { TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID } from "@solana/spl-token";
import {
  hookRemainingAccounts,
  quoteAta,
  recordPda,
  redemptionConfigPda,
  registryPda,
  requestPda,
  rwaAta,
  strategyPda,
  vaultConfigPda,
  walletRwaAta,
  type AccountMeta,
} from "./chain/pda";
import {
  sendBuy,
  sendCancelRedemption,
  sendClaimRedemption,
  sendRequestRedemption,
  sendRwaTransfer,
  type BuyInput,
  type ChainContext,
  type RequestRedemptionInput,
  type ProgramAddresses,
} from "./wallet";
import {
  getInjectedProvider,
  getConnection,
  nextRedemptionRequestId,
  redemptionProgram,
  vaultProgram,
  type InjectedProvider,
} from "./chain/provider";
import { PinMismatchError } from "./chain/pins";

vi.mock("./chain/provider", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./chain/provider")>();
  return {
    ...actual,
    vaultProgram: vi.fn(),
    redemptionProgram: vi.fn(),
    nextRedemptionRequestId: vi.fn(),
    getConnection: vi.fn(),
    getInjectedProvider: vi.fn(),
  };
});

// ---------------------------------------------------------------------------
// Fixtures — arbitrary but stable program ids / wallets for this run, same
// spirit as pda.test.ts's fixtures (not real deployed programs).
// ---------------------------------------------------------------------------

const COMPLIANCE = Keypair.generate().publicKey;
const PRICING = Keypair.generate().publicKey;
const VAULT_PROGRAM = Keypair.generate().publicKey;
const REDEMPTION_PROGRAM = Keypair.generate().publicKey;
const HOOK = Keypair.generate().publicKey;
const RWA_MINT = Keypair.generate().publicKey;
const QUOTE_MINT = Keypair.generate().publicKey;
const BUYER = Keypair.generate().publicKey;
const RECIPIENT = Keypair.generate().publicKey;
const BENEFICIARY = Keypair.generate().publicKey;

const PROGRAM_ADDRESSES: ProgramAddresses = {
  complianceProgramId: COMPLIANCE.toBase58(),
  pricingProgramId: PRICING.toBase58(),
  vaultProgramId: VAULT_PROGRAM.toBase58(),
  redemptionProgramId: REDEMPTION_PROGRAM.toBase58(),
  rwaMint: RWA_MINT.toBase58(),
  quoteMint: QUOTE_MINT.toBase58(),
};

const CTX: ChainContext = {
  hookProgramId: HOOK.toBase58(),
};

// VITE_SOLANA_RPC_URL is the SOLE source of the
// RPC endpoint now — ChainContext no longer carries one at all (GET
// /project stopped returning one). Stubbed globally in beforeEach below so
// every existing test keeps working without individually pinning it; tests
// that care about the pin itself override/unset it explicitly.
const RPC_URL = "http://localhost:8899";

const FAKE_SIGNATURE = "fake-signature-123";
const FAKE_BLOCKHASH = {
  blockhash: "11111111111111111111111111111111111111111111",
  lastValidBlockHeight: 1,
};
// Only `programId`/`keys`/`data` need to exist for Transaction.add() to accept
// it as an instruction — the fake AnchorProvider below never actually
// serializes the transaction, so their values are irrelevant.
const FAKE_IX = { programId: SystemProgram.programId, keys: [], data: Buffer.alloc(0) };

/**
 * A fresh getConnection() stub: blockhash/send for signAndSend,
 * simulateTransaction succeeding (the pre-sign backstop), and
 * getAccountInfo resolving every mint to `quoteOwner` (legacy SPL Token by
 * default — see resolveTokenProgram). Callers needing a Token-2022 quote
 * mint pass `TOKEN_2022_PROGRAM_ID`.
 */
function connectionStub(quoteOwner: PublicKey = TOKEN_PROGRAM_ID) {
  return {
    getLatestBlockhash: vi.fn().mockResolvedValue(FAKE_BLOCKHASH),
    sendRawTransaction: vi.fn().mockResolvedValue(FAKE_SIGNATURE),
    simulateTransaction: vi.fn().mockResolvedValue({ value: { err: null } }),
    getAccountInfo: vi.fn().mockResolvedValue({ owner: quoteOwner }),
  } as unknown as ReturnType<typeof getConnection>;
}

// ---------------------------------------------------------------------------
// Program stub: mimics the slice of an Anchor `Program` that wallet.ts
// touches — `.methods.<ix>(...).accountsStrict(...)
// .remainingAccounts(...).instruction()`, capturing each call, plus (for the
// claim test) `.account.redemptionRequest.fetch(...)`.
// ---------------------------------------------------------------------------

interface CapturedCall {
  method: string;
  args: unknown[];
  accounts: Record<string, unknown>;
  remainingAccounts: unknown[];
}

function programStub(calls: CapturedCall[], extra: Record<string, unknown> = {}) {
  const methods = new Proxy(
    {},
    {
      get: (_target: object, prop: string | symbol) => {
        const method = String(prop);
        return (...args: unknown[]) => ({
          accountsStrict: (accounts: Record<string, unknown>) => ({
            remainingAccounts: (remainingAccounts: unknown[]) => ({
              instruction: async () => {
                calls.push({ method, args, accounts, remainingAccounts });
                return FAKE_IX;
              },
            }),
          }),
        });
      },
    },
  );
  return { methods, ...extra };
}

/** BN (and plain number/bigint) instruction args, stringified for comparison. */
function bnStrings(args: unknown[]): string[] {
  return args.map((a) => String(a));
}

/** An accountsStrict() map (all values are PublicKeys) reduced to base58 for
 * comparison — avoids relying on PublicKey's internal representation for
 * equality, same reasoning as pda.test.ts's .toBase58() comparisons. */
function toBase58Map(accounts: Record<string, unknown>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(accounts).map(([k, v]) => [k, (v as PublicKey).toBase58()]),
  );
}

function toBase58Metas(metas: unknown[]) {
  return (metas as AccountMeta[]).map((m) => ({
    pubkey: m.pubkey.toBase58(),
    isSigner: m.isSigner,
    isWritable: m.isWritable,
  }));
}

beforeEach(() => {
  vi.stubEnv("VITE_SOLANA_RPC_URL", RPC_URL);
  vi.mocked(getConnection).mockReturnValue(connectionStub());
  vi.mocked(getInjectedProvider).mockReturnValue({
    signTransaction: vi.fn(async () => ({ serialize: () => Buffer.alloc(0) })),
  } as unknown as InjectedProvider);
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.resetAllMocks();
});

describe("sendBuy", () => {
  it("builds the buy instruction's accounts and hook remaining-accounts exactly as fullflow.ts's buy call", async () => {
    const calls: CapturedCall[] = [];
    vi.mocked(vaultProgram).mockReturnValue(
      programStub(calls) as unknown as ReturnType<typeof vaultProgram>,
    );
    // Re-assert the connection/provider stubs cleared by the previous test's
    // afterEach (mockResetAllMocks wipes implementations, not just calls).
    vi.mocked(getConnection).mockReturnValue(connectionStub());
    vi.mocked(getInjectedProvider).mockReturnValue({
      signTransaction: vi.fn(async () => ({ serialize: () => Buffer.alloc(0) })),
    } as unknown as InjectedProvider);

    const deadline = 1_700_000_000n;
    const input: BuyInput = {
      tokenAmount: 1_000_000n,
      maxQuoteAmount: 2_000_000n,
      recipient: RECIPIENT.toBase58(),
      deadline,
      programAddresses: PROGRAM_ADDRESSES,
    };

    const signature = await sendBuy(
      CTX,
      BUYER.toBase58(),
      VAULT_PROGRAM.toBase58(),
      input,
    );

    expect(signature).toBe(FAKE_SIGNATURE);
    expect(vaultProgram).toHaveBeenCalledWith(RPC_URL, VAULT_PROGRAM.toBase58());
    expect(calls).toHaveLength(1);
    const call = calls[0];
    expect(call.method).toBe("buy");
    expect(bnStrings(call.args)).toEqual(["1000000", "2000000", deadline.toString()]);

    const config = vaultConfigPda(VAULT_PROGRAM);
    const expectedAccounts = {
      config,
      registry: registryPda(COMPLIANCE),
      strategy: strategyPda(PRICING),
      rwaMint: RWA_MINT,
      quoteMint: QUOTE_MINT,
      vaultToken: rwaAta(RWA_MINT, config),
      vaultQuote: quoteAta(QUOTE_MINT, config, TOKEN_PROGRAM_ID, true),
      buyer: BUYER,
      buyerQuote: quoteAta(QUOTE_MINT, BUYER, TOKEN_PROGRAM_ID, false),
      recipientToken: walletRwaAta(RWA_MINT, RECIPIENT),
      buyerRecord: recordPda(COMPLIANCE, BUYER),
      recipientRecord: recordPda(COMPLIANCE, RECIPIENT),
      quoteTokenProgram: TOKEN_PROGRAM_ID,
      rwaTokenProgram: TOKEN_2022_PROGRAM_ID,
    };
    expect(toBase58Map(call.accounts)).toEqual(toBase58Map(expectedAccounts));

    // Hook remaining accounts: src = vault-config (the vault's own inventory
    // ATA is the transfer source), dst = the buy's recipient. Matches
    // fullflow.ts's `hookRemaining(rwaMint, vaultConfig, investor.publicKey)`
    // for its `buy` call. Reversed src/dst would resolve the wrong pair of
    // compliance records.
    expect(toBase58Metas(call.remainingAccounts)).toEqual(
      toBase58Metas(
        hookRemainingAccounts(RWA_MINT, config, RECIPIENT, HOOK, COMPLIANCE),
      ),
    );
  });

  it("resolves a Token-2022 quote mint's owning program instead of assuming legacy SPL", async () => {
    const calls: CapturedCall[] = [];
    const t22QuoteMint = Keypair.generate().publicKey;
    vi.mocked(vaultProgram).mockReturnValue(
      programStub(calls) as unknown as ReturnType<typeof vaultProgram>,
    );
    vi.mocked(getConnection).mockReturnValue(
      connectionStub(TOKEN_2022_PROGRAM_ID),
    );
    vi.mocked(getInjectedProvider).mockReturnValue({
      signTransaction: vi.fn(async () => ({ serialize: () => Buffer.alloc(0) })),
    } as unknown as InjectedProvider);

    const input: BuyInput = {
      tokenAmount: 1_000_000n,
      maxQuoteAmount: 2_000_000n,
      recipient: RECIPIENT.toBase58(),
      deadline: 1_700_000_000n,
      programAddresses: { ...PROGRAM_ADDRESSES, quoteMint: t22QuoteMint.toBase58() },
    };

    await sendBuy(CTX, BUYER.toBase58(), VAULT_PROGRAM.toBase58(), input);

    const call = calls[0];
    expect((call.accounts.quoteTokenProgram as PublicKey).toBase58()).toBe(
      TOKEN_2022_PROGRAM_ID.toBase58(),
    );
    const config = vaultConfigPda(VAULT_PROGRAM);
    expect((call.accounts.vaultQuote as PublicKey).toBase58()).toBe(
      quoteAta(t22QuoteMint, config, TOKEN_2022_PROGRAM_ID, true).toBase58(),
    );
  });
});

describe("sendRequestRedemption", () => {
  it("derives the request PDA from the redemption Config's next_id and builds correct accounts/hook accounts", async () => {
    const calls: CapturedCall[] = [];
    vi.mocked(redemptionProgram).mockReturnValue(
      programStub(calls) as unknown as ReturnType<typeof redemptionProgram>,
    );
    vi.mocked(nextRedemptionRequestId).mockResolvedValue(7n);

    const deadline = 1_700_000_100n;
    const input: RequestRedemptionInput = {
      rwaAmount: 500_000n,
      minQuoteOut: 400_000n,
      deadline,
      programAddresses: PROGRAM_ADDRESSES,
    };

    const signature = await sendRequestRedemption(
      CTX,
      BENEFICIARY.toBase58(),
      REDEMPTION_PROGRAM.toBase58(),
      input,
    );

    expect(signature).toBe(FAKE_SIGNATURE);
    const config = redemptionConfigPda(REDEMPTION_PROGRAM);
    // next_id was read off THIS deployment's redemption-config PDA.
    expect(nextRedemptionRequestId).toHaveBeenCalledTimes(1);
    expect(
      (vi.mocked(nextRedemptionRequestId).mock.calls[0][1] as PublicKey).toBase58(),
    ).toBe(config.toBase58());

    const call = calls[0];
    expect(call.method).toBe("requestRedemption");
    expect(bnStrings(call.args)).toEqual([
      "500000",
      "400000",
      deadline.toString(),
    ]);

    const request = requestPda(REDEMPTION_PROGRAM, 7n);
    const expectedAccounts = {
      config,
      registry: registryPda(COMPLIANCE),
      strategy: strategyPda(PRICING),
      rwaMint: RWA_MINT,
      request,
      beneficiary: BENEFICIARY,
      beneficiaryToken: walletRwaAta(RWA_MINT, BENEFICIARY),
      escrowToken: rwaAta(RWA_MINT, config),
      beneficiaryRecord: recordPda(COMPLIANCE, BENEFICIARY),
      rwaTokenProgram: TOKEN_2022_PROGRAM_ID,
      systemProgram: SystemProgram.programId,
    };
    expect(toBase58Map(call.accounts)).toEqual(toBase58Map(expectedAccounts));

    // src = beneficiary (the wallet the RWA leaves), dst = the redemption
    // config PDA (its escrow ATA). Matches fullflow.ts's
    // `hookRemaining(rwaMint, investor.publicKey, redemptionConfig)`.
    expect(toBase58Metas(call.remainingAccounts)).toEqual(
      toBase58Metas(
        hookRemainingAccounts(RWA_MINT, BENEFICIARY, config, HOOK, COMPLIANCE),
      ),
    );
  });
});

describe("sendClaimRedemption", () => {
  it("reads the request's recorded beneficiary and builds accounts with escrow->vault hook ordering", async () => {
    const calls: CapturedCall[] = [];
    const fetchRequest = vi.fn().mockResolvedValue({ beneficiary: BENEFICIARY });
    vi.mocked(redemptionProgram).mockReturnValue(
      programStub(calls, {
        account: { redemptionRequest: { fetch: fetchRequest } },
      }) as unknown as ReturnType<typeof redemptionProgram>,
    );

    const caller = Keypair.generate().publicKey;
    const id = 3n;
    const signature = await sendClaimRedemption(
      CTX,
      caller.toBase58(),
      REDEMPTION_PROGRAM.toBase58(),
      id,
      PROGRAM_ADDRESSES,
    );

    expect(signature).toBe(FAKE_SIGNATURE);
    const request = requestPda(REDEMPTION_PROGRAM, id);
    expect(fetchRequest).toHaveBeenCalledTimes(1);
    expect((fetchRequest.mock.calls[0][0] as PublicKey).toBase58()).toBe(
      request.toBase58(),
    );

    const call = calls[0];
    expect(call.method).toBe("claimRedemption");
    expect(bnStrings(call.args)).toEqual([id.toString()]);

    const config = redemptionConfigPda(REDEMPTION_PROGRAM);
    const vaultConfig = vaultConfigPda(VAULT_PROGRAM);
    const expectedAccounts = {
      config,
      registry: registryPda(COMPLIANCE),
      request,
      rwaMint: RWA_MINT,
      quoteMint: QUOTE_MINT,
      escrowToken: rwaAta(RWA_MINT, config),
      escrowQuote: quoteAta(QUOTE_MINT, config, TOKEN_PROGRAM_ID, true),
      vaultToken: rwaAta(RWA_MINT, vaultConfig),
      // The beneficiary's quote ATA — read off the fetched request, NOT off
      // `caller` (claim is permissionless: it always pays the beneficiary
      // recorded at request time, never the tx sender).
      beneficiaryQuote: quoteAta(QUOTE_MINT, BENEFICIARY, TOKEN_PROGRAM_ID, false),
      rwaTokenProgram: TOKEN_2022_PROGRAM_ID,
      quoteTokenProgram: TOKEN_PROGRAM_ID,
    };
    expect(toBase58Map(call.accounts)).toEqual(toBase58Map(expectedAccounts));

    // src = the redemption escrow (config), dst = the vault's own inventory —
    // claim moves the escrowed RWA back into vault custody. A reversed order
    // here would resolve the wrong compliance record pair. Matches
    // fullflow.ts's `hookRemaining(rwaMint, redemptionConfig, vaultConfig)`.
    expect(toBase58Metas(call.remainingAccounts)).toEqual(
      toBase58Metas(
        hookRemainingAccounts(RWA_MINT, config, vaultConfig, HOOK, COMPLIANCE),
      ),
    );
  });
});

describe("sendCancelRedemption", () => {
  it("builds accounts with escrow->beneficiary hook ordering for the refund leg", async () => {
    const calls: CapturedCall[] = [];
    vi.mocked(redemptionProgram).mockReturnValue(
      programStub(calls) as unknown as ReturnType<typeof redemptionProgram>,
    );

    const id = 1n;
    const signature = await sendCancelRedemption(
      CTX,
      BENEFICIARY.toBase58(),
      REDEMPTION_PROGRAM.toBase58(),
      id,
      PROGRAM_ADDRESSES,
    );

    expect(signature).toBe(FAKE_SIGNATURE);
    const call = calls[0];
    expect(call.method).toBe("cancelRedemption");
    expect(bnStrings(call.args)).toEqual([id.toString()]);

    const config = redemptionConfigPda(REDEMPTION_PROGRAM);
    const request = requestPda(REDEMPTION_PROGRAM, id);
    const expectedAccounts = {
      config,
      registry: registryPda(COMPLIANCE),
      request,
      rwaMint: RWA_MINT,
      escrowToken: rwaAta(RWA_MINT, config),
      beneficiaryToken: walletRwaAta(RWA_MINT, BENEFICIARY),
      beneficiaryRecord: recordPda(COMPLIANCE, BENEFICIARY),
      beneficiary: BENEFICIARY,
      rwaTokenProgram: TOKEN_2022_PROGRAM_ID,
    };
    expect(toBase58Map(call.accounts)).toEqual(toBase58Map(expectedAccounts));

    // src = escrow (config), dst = beneficiary — the refund direction, the
    // mirror image of request_redemption's src/dst. fullflow.ts only exercises
    // the sibling reject-leg on-chain (cancel's real success path needs a
    // 1-day timeout a validator harness can't warp — see that file's header
    // comment), but reject and cancel share the exact same refund account
    // shape: `hookRemaining(rwaMint, redemptionConfig, investor.publicKey)`.
    expect(toBase58Metas(call.remainingAccounts)).toEqual(
      toBase58Metas(
        hookRemainingAccounts(RWA_MINT, config, BENEFICIARY, HOOK, COMPLIANCE),
      ),
    );
  });
});

describe("argument guards shared by all four calls", () => {
  it("sendBuy requires ProgramAddresses", async () => {
    await expect(
      sendBuy(CTX, BUYER.toBase58(), VAULT_PROGRAM.toBase58(), {
        tokenAmount: 1n,
        maxQuoteAmount: 1n,
        recipient: RECIPIENT.toBase58(),
        deadline: 1n,
      }),
    ).rejects.toThrow(/Program addresses are required/);
  });

  it("sendRequestRedemption requires the hook program id from ctx", async () => {
    const ctxNoHook: ChainContext = { ...CTX, hookProgramId: undefined };
    await expect(
      sendRequestRedemption(
        ctxNoHook,
        BENEFICIARY.toBase58(),
        REDEMPTION_PROGRAM.toBase58(),
        {
          rwaAmount: 1n,
          minQuoteOut: 1n,
          deadline: 1n,
          programAddresses: PROGRAM_ADDRESSES,
        },
      ),
    ).rejects.toThrow(/Transfer-hook program id/);
  });
});

// ---------------------------------------------------------------------------
// A pinned build must refuse to build an instruction from a
// server-supplied program id/mint that disagrees with the pin, BEFORE it
// ever reaches the wallet for a signature.
// ---------------------------------------------------------------------------

describe("pin enforcement", () => {
  it("sendBuy throws PinMismatchError when the server's vault program id disagrees with the pin", async () => {
    vi.stubEnv("VITE_SOLANA_PROGRAM_VAULT", Keypair.generate().publicKey.toBase58());

    await expect(
      sendBuy(CTX, BUYER.toBase58(), VAULT_PROGRAM.toBase58(), {
        tokenAmount: 1n,
        maxQuoteAmount: 1n,
        recipient: RECIPIENT.toBase58(),
        deadline: 1n,
        programAddresses: PROGRAM_ADDRESSES,
      }),
    ).rejects.toThrow(PinMismatchError);
  });

  it("sendClaimRedemption throws PinMismatchError when the server's transfer-hook program id disagrees with the pin", async () => {
    vi.stubEnv(
      "VITE_SOLANA_PROGRAM_TRANSFER_HOOK",
      Keypair.generate().publicKey.toBase58(),
    );

    await expect(
      sendClaimRedemption(
        CTX,
        BENEFICIARY.toBase58(),
        REDEMPTION_PROGRAM.toBase58(),
        1n,
        PROGRAM_ADDRESSES,
      ),
    ).rejects.toThrow(PinMismatchError);
  });

  it("sendRwaTransfer throws PinMismatchError when the mint disagrees with the pinned RWA mint", async () => {
    vi.stubEnv("VITE_SOLANA_RWA_MINT", Keypair.generate().publicKey.toBase58());

    await expect(
      sendRwaTransfer(
        BENEFICIARY.toBase58(),
        RWA_MINT.toBase58(),
        RECIPIENT.toBase58(),
        1n,
      ),
    ).rejects.toThrow(PinMismatchError);
  });

  it("does not throw when the pin agrees with the server-supplied value", async () => {
    vi.stubEnv("VITE_SOLANA_PROGRAM_VAULT", PROGRAM_ADDRESSES.vaultProgramId);
    vi.stubEnv("VITE_SOLANA_PROGRAM_COMPLIANCE", PROGRAM_ADDRESSES.complianceProgramId);
    vi.stubEnv("VITE_SOLANA_PROGRAM_PRICING", PROGRAM_ADDRESSES.pricingProgramId);
    vi.stubEnv(
      "VITE_SOLANA_PROGRAM_REDEMPTION",
      PROGRAM_ADDRESSES.redemptionProgramId,
    );
    vi.stubEnv("VITE_SOLANA_PROGRAM_TRANSFER_HOOK", CTX.hookProgramId);
    vi.stubEnv("VITE_SOLANA_RWA_MINT", PROGRAM_ADDRESSES.rwaMint);
    vi.stubEnv("VITE_SOLANA_QUOTE_MINT", PROGRAM_ADDRESSES.quoteMint);

    const calls: CapturedCall[] = [];
    vi.mocked(vaultProgram).mockReturnValue(
      programStub(calls) as unknown as ReturnType<typeof vaultProgram>,
    );

    await expect(
      sendBuy(CTX, BUYER.toBase58(), VAULT_PROGRAM.toBase58(), {
        tokenAmount: 1n,
        maxQuoteAmount: 1n,
        recipient: RECIPIENT.toBase58(),
        deadline: 1n,
        programAddresses: PROGRAM_ADDRESSES,
      }),
    ).resolves.toBe(FAKE_SIGNATURE);
  });
});

// ---------------------------------------------------------------------------
// The pin on `input.programAddresses.vaultProgramId`/`.redemptionProgramId`
// doesn't, by itself, prove anything about the *separate* positional
// `vault`/`escrow` argument each function actually builds its Program/PDAs
// from. These pin the ProgramAddresses field (so the existing
// assertProgramAddressesPinned check passes) but pass a DIFFERENT positional
// argument, proving the positional value is checked independently.
// ---------------------------------------------------------------------------

describe("positional program-id pin enforcement", () => {
  it("sendBuy throws when the positional `vault` disagrees with the pin, even though sol.vaultProgramId matches it", async () => {
    vi.stubEnv("VITE_SOLANA_PROGRAM_VAULT", PROGRAM_ADDRESSES.vaultProgramId);
    const differentVault = Keypair.generate().publicKey.toBase58();

    await expect(
      sendBuy(CTX, BUYER.toBase58(), differentVault, {
        tokenAmount: 1n,
        maxQuoteAmount: 1n,
        recipient: RECIPIENT.toBase58(),
        deadline: 1n,
        programAddresses: PROGRAM_ADDRESSES,
      }),
    ).rejects.toThrow(PinMismatchError);
  });

  it("sendRequestRedemption throws when the positional `escrow` disagrees with the pin", async () => {
    vi.stubEnv(
      "VITE_SOLANA_PROGRAM_REDEMPTION",
      PROGRAM_ADDRESSES.redemptionProgramId,
    );
    const differentEscrow = Keypair.generate().publicKey.toBase58();

    await expect(
      sendRequestRedemption(CTX, BENEFICIARY.toBase58(), differentEscrow, {
        rwaAmount: 1n,
        minQuoteOut: 1n,
        deadline: 1n,
        programAddresses: PROGRAM_ADDRESSES,
      }),
    ).rejects.toThrow(PinMismatchError);
  });

  it("sendClaimRedemption throws when the positional `escrow` disagrees with the pin", async () => {
    vi.stubEnv(
      "VITE_SOLANA_PROGRAM_REDEMPTION",
      PROGRAM_ADDRESSES.redemptionProgramId,
    );
    const differentEscrow = Keypair.generate().publicKey.toBase58();

    await expect(
      sendClaimRedemption(
        CTX,
        BENEFICIARY.toBase58(),
        differentEscrow,
        1n,
        PROGRAM_ADDRESSES,
      ),
    ).rejects.toThrow(PinMismatchError);
  });

  it("sendCancelRedemption throws when the positional `escrow` disagrees with the pin", async () => {
    vi.stubEnv(
      "VITE_SOLANA_PROGRAM_REDEMPTION",
      PROGRAM_ADDRESSES.redemptionProgramId,
    );
    const differentEscrow = Keypair.generate().publicKey.toBase58();

    await expect(
      sendCancelRedemption(
        CTX,
        BENEFICIARY.toBase58(),
        differentEscrow,
        1n,
        PROGRAM_ADDRESSES,
      ),
    ).rejects.toThrow(PinMismatchError);
  });
});

// ---------------------------------------------------------------------------
// VITE_SOLANA_RPC_URL is now the SOLE source of the
// RPC endpoint — there is no server-supplied value left to read or
// compare against (GET /project dropped `publicRpcUrl`; ChainContext has no
// `rpcUrl` field at all). requireRpcUrl/resolveRpcUrl use the pin when set
// and fall back to a hardcoded local-dev default (not a thrown error, and
// not anything server-supplied) when it's unset.
// ---------------------------------------------------------------------------

describe("RPC URL resolution", () => {
  it("sendBuy falls back to the local-dev RPC default when VITE_SOLANA_RPC_URL is unset, without throwing", async () => {
    vi.stubEnv("VITE_SOLANA_RPC_URL", "");
    const calls: CapturedCall[] = [];
    vi.mocked(vaultProgram).mockReturnValue(
      programStub(calls) as unknown as ReturnType<typeof vaultProgram>,
    );

    await expect(
      sendBuy(CTX, BUYER.toBase58(), VAULT_PROGRAM.toBase58(), {
        tokenAmount: 1n,
        maxQuoteAmount: 1n,
        recipient: RECIPIENT.toBase58(),
        deadline: 1n,
        programAddresses: PROGRAM_ADDRESSES,
      }),
    ).resolves.toBe(FAKE_SIGNATURE);
    expect(vaultProgram).toHaveBeenCalledWith(
      "http://127.0.0.1:8899",
      VAULT_PROGRAM.toBase58(),
    );
  });

  it("sendBuy builds the vault Program from the pinned RPC URL", async () => {
    const calls: CapturedCall[] = [];
    vi.mocked(vaultProgram).mockReturnValue(
      programStub(calls) as unknown as ReturnType<typeof vaultProgram>,
    );

    await sendBuy(CTX, BUYER.toBase58(), VAULT_PROGRAM.toBase58(), {
      tokenAmount: 1n,
      maxQuoteAmount: 1n,
      recipient: RECIPIENT.toBase58(),
      deadline: 1n,
      programAddresses: PROGRAM_ADDRESSES,
    });

    expect(vaultProgram).toHaveBeenCalledWith(RPC_URL, VAULT_PROGRAM.toBase58());
  });
});
