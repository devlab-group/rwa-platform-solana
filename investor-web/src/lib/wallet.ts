// Minimal, abstracted wallet integration. Every call the app broadcasts is
// encoded here from a pinned Anchor IDL (lib/idl/) — the investor's own
// Vault.buy and RedemptionEscrow request/claim/cancel instructions, plus a
// hook-aware Token-2022 transfer for a direct RWA transfer. Nothing is ever
// submitted from server-supplied calldata, and the buy/redeem prices are
// read from the same chain rather than quoted by the server. Deliberately
// isolated behind this module so the rest of the app — and the production
// build — never needs a live wallet to run.
//
// Documented inline against solana/tests/fullflow.ts, the authoritative
// reference for account/PDA shapes.
import { BN } from "@coral-xyz/anchor";
import { formatUnits } from "viem";
import {
  ComputeBudgetProgram,
  Connection,
  PublicKey,
  SystemProgram,
  Transaction,
  type TransactionInstruction,
} from "@solana/web3.js";
import {
  TOKEN_2022_PROGRAM_ID,
  createAssociatedTokenAccountIdempotentInstruction,
  createTransferCheckedWithTransferHookInstruction,
  getAccount,
  getMint,
  TokenAccountNotFoundError,
  TokenInvalidAccountOwnerError,
} from "@solana/spl-token";
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
} from "./chain/pda";
import {
  assertClusterGenesis,
  connectInjectedWallet,
  getInjectedProvider,
  getConnection,
  nextRedemptionRequestId,
  readStrategyAccount,
  redemptionProgram,
  signMessageWithProvider,
  vaultProgram,
  type InjectedProvider,
} from "./chain/provider";
import {
  assertPinnedRedemptionProgramId,
  assertPinnedRwaMint,
  assertPinnedVaultProgramId,
  assertProgramAddressesPinned,
  resolveRpcUrl,
} from "./chain/pins";
import { resolveTokenProgram } from "./chain/tokenProgram";

/**
 * The transfer-hook program id is the one program id GET /project's
 * `addresses` doesn't carry — it must come from GET /api/v1/config's
 * BootstrapConfig.programIds.transferHook (see useHookProgramId in
 * routes/investor/Investor.tsx). It's required on every call that moves the
 * RWA (Token-2022) token: buy, request/claim/cancel redemption, and a direct
 * RWA transfer.
 *
 * There is deliberately no `rpcUrl` field here: the RPC endpoint is no
 * longer server-supplied at all (GET /project dropped it) — it comes solely
 * from the build-time `VITE_SOLANA_RPC_URL` pin, resolved directly off
 * `lib/chain/pins.ts` by `requireRpcUrl` below, with nothing for the caller
 * to thread through `ChainContext`.
 */
export interface ChainContext {
  hookProgramId?: string;
}

/**
 * The program ids and mints a buy/redemption call needs beyond the
 * single `vault`/`escrow` program id already passed positionally (which is
 * itself project.addresses.vault or .redemptionEscrow) — mirrors
 * project.addresses 1:1.
 */
export interface ProgramAddresses {
  complianceProgramId: string;
  pricingProgramId: string;
  vaultProgramId: string;
  redemptionProgramId: string;
  rwaMint: string;
  quoteMint: string;
}

/** Which SPL mint a balance/decimals read targets — the RWA mint is always
 * Token-2022 (with the transfer hook); the quote mint is always classic SPL
 * (no hook) per the vault/redemption programs' `quote_token_program` pin. */
export type TokenKind = "rwa" | "quote";

function requireProgramAddresses(
  programAddresses: ProgramAddresses | undefined,
): ProgramAddresses {
  if (!programAddresses) {
    throw new Error(
      "Program addresses are required for this call but were not provided.",
    );
  }
  return programAddresses;
}

/**
 * Thin wrapper around `resolveRpcUrl` used at every
 * `getConnection(...)` call site below, so the build-time
 * `VITE_SOLANA_RPC_URL` pin — the sole source now that GET /project no
 * longer returns one — decides which node answers every read and
 * write this app makes. Falls back to a local-dev default rather than
 * throwing when the pin is unset (see resolveRpcUrl's doc comment) —
 * `pinsConfigured`'s warning banner is what flags an unpinned
 * deployment, not an exception here.
 */
function requireRpcUrl(): string {
  return resolveRpcUrl();
}

function requireHookProgramId(ctx: ChainContext): string {
  if (!ctx.hookProgramId) {
    throw new Error(
      "Transfer-hook program id is not set — fetch it from GET /api/v1/config first.",
    );
  }
  return ctx.hookProgramId;
}

export interface ConnectedWallet {
  address: string;
}

export async function connectWallet(): Promise<ConnectedWallet> {
  const wallet = await connectInjectedWallet();
  return { address: wallet.address };
}

/**
 * Signs `message` with the connected wallet via the Wallet Standard's
 * `signMessage` (returning a base58 ed25519 signature — see
 * lib/chain/provider.ts's signMessageWithProvider and the frozen wallet-auth
 * contract). Used for both the admin-style and investor ownership-challenge
 * flows; never for a transaction.
 */
export async function signMessage(message: string): Promise<string> {
  return signMessageWithProvider(message);
}

// ---------------------------------------------------------------------------
// Balance / decimals reads
// ---------------------------------------------------------------------------

/**
 * The RWA leg is always Token-2022 (fixed by the platform, never read from
 * chain); the quote leg's owning program is resolved from the mint account
 * itself — it is not always legacy SPL, see lib/chain/tokenProgram.ts.
 */
async function tokenProgramId(
  connection: Connection,
  kind: TokenKind,
  mint: PublicKey,
): Promise<PublicKey> {
  return kind === "rwa" ? TOKEN_2022_PROGRAM_ID : resolveTokenProgram(connection, mint);
}

export async function readTokenBalance(
  token: string,
  holder: string,
  tokenKind: TokenKind = "rwa",
): Promise<string> {
  const connection = getConnection(requireRpcUrl());
  const programId = await tokenProgramId(
    connection,
    tokenKind,
    new PublicKey(token),
  );
  const ata =
    tokenKind === "rwa"
      ? walletRwaAta(new PublicKey(token), new PublicKey(holder))
      : quoteAta(new PublicKey(token), new PublicKey(holder), programId, false);
  try {
    const account = await getAccount(connection, ata, "confirmed", programId);
    return account.amount.toString();
  } catch (err) {
    // No ATA yet == a zero balance, not an error — the investor simply
    // hasn't received this token yet.
    if (
      err instanceof TokenAccountNotFoundError ||
      err instanceof TokenInvalidAccountOwnerError
    ) {
      return "0";
    }
    throw err;
  }
}

/**
 * Project.decimals is not reliably populated for every deployment (in
 * particular the RWA mint decimals — see resolveRwaDecimals in
 * lib/decimals.ts), so it's read directly from the token's Token-2022/SPL
 * mint account. Robust regardless of what the API does or doesn't expose.
 */
export async function readTokenDecimals(
  token: string,
  tokenKind: TokenKind = "rwa",
): Promise<number> {
  const connection = getConnection(requireRpcUrl());
  const mintPk = new PublicKey(token);
  const mint = await getMint(
    connection,
    mintPk,
    "confirmed",
    await tokenProgramId(connection, tokenKind, mintPk),
  );
  return mint.decimals;
}

// ---------------------------------------------------------------------------
// Price previews
// ---------------------------------------------------------------------------

/** ceil(a*b/denom) without overflow risk in JS BigInt (arbitrary precision). */
function mulDivCeil(a: bigint, b: bigint, denom: bigint): bigint {
  const product = a * b;
  if (product === BigInt(0)) return BigInt(0);
  return (product - BigInt(1)) / denom + BigInt(1);
}

function mulDivFloor(a: bigint, b: bigint, denom: bigint): bigint {
  return (a * b) / denom;
}

/**
 * The fixed-price quote for `tokenAmount` (RWA minimal units) at
 * `pricePerWholeToken` (quote-token minimal units per one whole RWA token),
 * scaled by `tokenDecimals`. Mirrors solana/crates/pricing-math exactly:
 * purchase rounds up, redemption rounds down.
 */
function quote(
  tokenAmount: bigint,
  pricePerWholeToken: bigint,
  tokenDecimals: number,
  rounding: "ceil" | "floor",
): bigint {
  const denom = BigInt(10) ** BigInt(tokenDecimals);
  return rounding === "ceil"
    ? mulDivCeil(tokenAmount, pricePerWholeToken, denom)
    : mulDivFloor(tokenAmount, pricePerWholeToken, denom);
}

/**
 * What buying `tokenAmount` RWA costs at the current on-chain price, in
 * quote-token minimal units — read from the pricing program's `Strategy`
 * account directly off-chain. This used to trust
 * `project.purchasePricePerWholeToken` from the server; now it reads the
 * same on-chain value the vault program itself would. `programAddresses` must
 * include `pricingProgramId`, which is pin-verified before the read (see
 * lib/chain/pins.ts). The figure the slippage ceiling (and therefore the
 * approved spend) is derived from never passes through the server.
 */
export async function readPreviewBuy(
  tokenAmount: bigint,
  programAddresses?: ProgramAddresses,
): Promise<bigint> {
  const sol = requireProgramAddresses(programAddresses);
  assertProgramAddressesPinned(sol);
  const connection = getConnection(requireRpcUrl());
  const strategy = await readStrategyAccount(
    connection,
    new PublicKey(sol.pricingProgramId),
  );
  return quote(
    tokenAmount,
    strategy.purchasePrice,
    strategy.tokenDecimals,
    "ceil",
  );
}

/**
 * The counterpart of readPreviewBuy for a redemption's on-chain price; feeds
 * the slippage floor carried in `minQuoteOut`.
 */
export async function readPreviewRedeem(
  rwaAmount: bigint,
  programAddresses?: ProgramAddresses,
): Promise<bigint> {
  const sol = requireProgramAddresses(programAddresses);
  assertProgramAddressesPinned(sol);
  const connection = getConnection(requireRpcUrl());
  const strategy = await readStrategyAccount(
    connection,
    new PublicKey(sol.pricingProgramId),
  );
  return quote(
    rwaAmount,
    strategy.redemptionPrice,
    strategy.tokenDecimals,
    "floor",
  );
}

export function formatWithDecimals(raw: string, decimals: number): string {
  return formatUnits(BigInt(raw), decimals);
}

// ---------------------------------------------------------------------------
// Writes: transfer / buy / redemption request-claim-cancel
// ---------------------------------------------------------------------------

function getInjectedProviderOrThrow(): InjectedProvider {
  const provider = getInjectedProvider();
  if (!provider) throw new Error("No injected wallet found.");
  return provider;
}

async function signAndSend(
  connection: Connection,
  provider: InjectedProvider,
  feePayer: PublicKey,
  instructions: TransactionInstruction[],
): Promise<string> {
  // Optional cluster-identity cross-check — no-op unless
  // VITE_SOLANA_CLUSTER_GENESIS is pinned; cached per RPC endpoint for the
  // session, so this is a no-op RPC round trip after the first call. Every
  // write in this file funnels through this one function.
  await assertClusterGenesis(connection);
  const { blockhash, lastValidBlockHeight } =
    await connection.getLatestBlockhash("confirmed");
  const tx = new Transaction({
    feePayer,
    blockhash,
    lastValidBlockHeight,
  }).add(...instructions);
  // Backstop: simulate BEFORE asking the wallet to sign, not
  // just after sending. This doesn't replace the pin checks above (a
  // simulation of a fully-valid, pinned-mismatched instruction can still
  // succeed) — it catches the OTHER class of bug: a malformed/incorrect
  // account list that would otherwise only surface as an opaque wallet
  // rejection or a wasted signature.
  const simulation = await connection.simulateTransaction(tx);
  if (simulation.value.err) {
    throw new Error(
      `Refusing to request a wallet signature: transaction simulation failed (${JSON.stringify(simulation.value.err)}).`,
    );
  }
  const signed = await provider.signTransaction(tx);
  const signature = await connection.sendRawTransaction(signed.serialize(), {
    skipPreflight: false,
  });
  return signature;
}

/**
 * Sends a hook-aware Token-2022 `transferChecked` from the connected
 * wallet — this app's Transfer section moves the RWA token itself, which
 * carries the compliance transfer hook, so a plain SPL transfer instruction
 * would be rejected. `createTransferCheckedWithTransferHookInstruction`
 * resolves the extra hook accounts on-chain (reading the mint's
 * ExtraAccountMetaList) automatically, unlike the buy/redemption program
 * calls below where the extra accounts must be supplied by hand (see
 * lib/chain/pda.ts's hookRemainingAccounts) because they're forwarded
 * through a wrapping instruction, not resolved directly against the mint.
 */
export async function sendRwaTransfer(
  owner: string,
  token: string,
  to: string,
  amount: bigint,
): Promise<string> {
  // This app only ever calls sendRwaTransfer for the RWA (Token-2022) leg
  // (see Investor.tsx's TransferSection) — pin-check `token` against the
  // deployment's RWA mint before building anything.
  assertPinnedRwaMint(token);
  const connection = getConnection(requireRpcUrl());
  const provider = getInjectedProviderOrThrow();
  const ownerPk = new PublicKey(owner);
  const mintPk = new PublicKey(token);
  const toPk = new PublicKey(to);
  const decimals = (
    await getMint(connection, mintPk, "confirmed", TOKEN_2022_PROGRAM_ID)
  ).decimals;
  const sourceAta = walletRwaAta(mintPk, ownerPk);
  const destAta = walletRwaAta(mintPk, toPk);
  const ix = await createTransferCheckedWithTransferHookInstruction(
    connection,
    sourceAta,
    mintPk,
    destAta,
    ownerPk,
    amount,
    decimals,
    [],
    "confirmed",
    TOKEN_2022_PROGRAM_ID,
  );
  return signAndSend(connection, provider, ownerPk, [
    createAssociatedTokenAccountIdempotentInstruction(
      ownerPk,
      destAta,
      toPk,
      mintPk,
      TOKEN_2022_PROGRAM_ID,
    ),
    ix,
  ]);
}

/**
 * The vault program's `buy` instruction args. `tokenAmount` is in RWA
 * minimal units, `maxQuoteAmount` the slippage-bounded spend ceiling in
 * quote-token minimal units, and `deadline` unix seconds. `programAddresses`
 * carries the extra program ids/mints the instruction needs beyond `vault`
 * itself (see ProgramAddresses).
 */
export interface BuyInput {
  tokenAmount: bigint;
  maxQuoteAmount: bigint;
  recipient: string;
  deadline: bigint;
  programAddresses?: ProgramAddresses;
}

/**
 * Broadcasts the vault program's `buy` instruction from the connected
 * investor wallet. The buyer signs directly and the vault program CPIs the
 * quote-SPL transfer with the buyer as authority — there is no approve step —
 * and the RWA Token-2022 transfer out of its own inventory ATA, which is why
 * the hook's remaining accounts here are computed for vaultConfig -> recipient
 * (see solana/tests/fullflow.ts's
 * `hookRemaining(rwaMint, vaultConfig, investor.publicKey)`). Both the
 * caller and `recipient` must be Allowed.
 */
export async function sendBuy(
  ctx: ChainContext,
  from: string,
  vault: string,
  input: BuyInput,
): Promise<string> {
  const sol = requireProgramAddresses(input.programAddresses);
  const hookProgramIdStr = requireHookProgramId(ctx);
  // Hard-assert every server-supplied program id/mint against this build's
  // pins BEFORE constructing a single PublicKey from them — a
  // compromised server otherwise hands us a program id we'd happily build a
  // wallet-signed, fund-draining instruction from.
  assertProgramAddressesPinned(sol, hookProgramIdStr);
  // sol.vaultProgramId above and this `vault` positional argument both
  // originate from project.addresses.vault today, but nothing enforces
  // that — assert the value the vault Program/PDAs are actually built from
  // too.
  assertPinnedVaultProgramId(vault);
  const hookProgramId = new PublicKey(hookProgramIdStr);
  const rpcUrl = requireRpcUrl();
  const buyer = new PublicKey(from);
  const recipient = new PublicKey(input.recipient);
  const vaultProgramId = new PublicKey(vault);
  const complianceProgramId = new PublicKey(sol.complianceProgramId);
  const rwaMint = new PublicKey(sol.rwaMint);
  const quoteMint = new PublicKey(sol.quoteMint);
  const config = vaultConfigPda(vaultProgramId);
  const registry = registryPda(complianceProgramId);
  const strategy = strategyPda(new PublicKey(sol.pricingProgramId));
  const recipientToken = walletRwaAta(rwaMint, recipient);

  // The quote mint isn't always legacy SPL Token — resolve its actual
  // owning program from the mint account itself rather than assuming.
  const connection = getConnection(rpcUrl);
  const quoteTokenProgram = await resolveTokenProgram(connection, quoteMint);

  const program = vaultProgram(rpcUrl, vault);
  const ix = await program.methods
    .buy(
      new BN(input.tokenAmount.toString()),
      new BN(input.maxQuoteAmount.toString()),
      new BN(input.deadline.toString()),
    )
    .accountsStrict({
      config,
      registry,
      strategy,
      rwaMint,
      quoteMint,
      vaultToken: rwaAta(rwaMint, config),
      vaultQuote: quoteAta(quoteMint, config, quoteTokenProgram, true),
      buyer,
      buyerQuote: quoteAta(quoteMint, buyer, quoteTokenProgram, false),
      recipientToken,
      buyerRecord: recordPda(complianceProgramId, buyer),
      recipientRecord: recordPda(complianceProgramId, recipient),
      quoteTokenProgram,
      rwaTokenProgram: TOKEN_2022_PROGRAM_ID,
    })
    .remainingAccounts(
      hookRemainingAccounts(
        rwaMint,
        config,
        recipient,
        hookProgramId,
        complianceProgramId,
      ),
    )
    .instruction();

  const provider = getInjectedProviderOrThrow();
  return signAndSend(connection, provider, buyer, [
    ComputeBudgetProgram.setComputeUnitLimit({ units: 600_000 }),
    createAssociatedTokenAccountIdempotentInstruction(
      buyer,
      recipientToken,
      recipient,
      rwaMint,
      TOKEN_2022_PROGRAM_ID,
    ),
    ix,
  ]);
}

/**
 * The redemption program's `request_redemption` instruction args.
 * `rwaAmount` is in RWA minimal units, `minQuoteOut` the slippage-bounded
 * payout floor in quote-token minimal units, `deadline` unix seconds.
 */
export interface RequestRedemptionInput {
  rwaAmount: bigint;
  minQuoteOut: bigint;
  deadline: bigint;
  programAddresses?: ProgramAddresses;
}

/**
 * Broadcasts the redemption program's `request_redemption` instruction from
 * the connected investor wallet. The beneficiary signs directly (no
 * approve step) and the request id is whatever the redemption program's
 * `Config.next_id` currently holds — read just before submitting (see
 * lib/chain/provider.ts's nextRedemptionRequestId) since the `request` PDA
 * is seeded by that id. There's an inherent TOCTOU race if two requests from
 * the SAME wallet race each other client-side, which a single-tab investor
 * flow doesn't hit; concurrent requests from OTHER wallets don't affect this
 * wallet's PDA derivation since each request gets its own id/PDA regardless
 * of order.
 */
export async function sendRequestRedemption(
  ctx: ChainContext,
  from: string,
  escrow: string,
  input: RequestRedemptionInput,
): Promise<string> {
  const sol = requireProgramAddresses(input.programAddresses);
  const hookProgramIdStr = requireHookProgramId(ctx);
  assertProgramAddressesPinned(sol, hookProgramIdStr);
  // See sendBuy's matching comment — asserts the positional
  // `escrow` argument the redemption Program/PDAs are actually built from,
  // not just sol.redemptionProgramId.
  assertPinnedRedemptionProgramId(escrow);
  const hookProgramId = new PublicKey(hookProgramIdStr);
  const rpcUrl = requireRpcUrl();
  const beneficiary = new PublicKey(from);
  const redemptionProgramId = new PublicKey(escrow);
  const complianceProgramId = new PublicKey(sol.complianceProgramId);
  const rwaMint = new PublicKey(sol.rwaMint);
  const config = redemptionConfigPda(redemptionProgramId);
  const registry = registryPda(complianceProgramId);
  const strategy = strategyPda(new PublicKey(sol.pricingProgramId));

  const program = redemptionProgram(rpcUrl, escrow);
  const nextId = await nextRedemptionRequestId(program, config);
  const request = requestPda(redemptionProgramId, nextId);

  const ix = await program.methods
    .requestRedemption(
      new BN(input.rwaAmount.toString()),
      new BN(input.minQuoteOut.toString()),
      new BN(input.deadline.toString()),
    )
    .accountsStrict({
      config,
      registry,
      strategy,
      rwaMint,
      request,
      beneficiary,
      beneficiaryToken: walletRwaAta(rwaMint, beneficiary),
      escrowToken: rwaAta(rwaMint, config),
      beneficiaryRecord: recordPda(complianceProgramId, beneficiary),
      rwaTokenProgram: TOKEN_2022_PROGRAM_ID,
      systemProgram: SystemProgram.programId,
    })
    .remainingAccounts(
      hookRemainingAccounts(
        rwaMint,
        beneficiary,
        config,
        hookProgramId,
        complianceProgramId,
      ),
    )
    .instruction();

  const connection = getConnection(rpcUrl);
  const provider = getInjectedProviderOrThrow();
  return signAndSend(connection, provider, beneficiary, [
    ComputeBudgetProgram.setComputeUnitLimit({ units: 600_000 }),
    ix,
  ]);
}

/**
 * The redemption program's `claim_redemption` instruction — permissionless
 * once the request is funded. Anyone may broadcast it; the escrow always
 * pays the beneficiary recorded at request time, never the caller.
 */
export async function sendClaimRedemption(
  ctx: ChainContext,
  from: string,
  escrow: string,
  id: bigint,
  programAddresses?: ProgramAddresses,
): Promise<string> {
  const sol = requireProgramAddresses(programAddresses);
  const hookProgramIdStr = requireHookProgramId(ctx);
  assertProgramAddressesPinned(sol, hookProgramIdStr);
  assertPinnedRedemptionProgramId(escrow);
  const hookProgramId = new PublicKey(hookProgramIdStr);
  const rpcUrl = requireRpcUrl();
  const caller = new PublicKey(from);
  const redemptionProgramId = new PublicKey(escrow);
  const complianceProgramId = new PublicKey(sol.complianceProgramId);
  const rwaMint = new PublicKey(sol.rwaMint);
  const quoteMint = new PublicKey(sol.quoteMint);
  const vaultConfig = vaultConfigPda(new PublicKey(sol.vaultProgramId));
  const config = redemptionConfigPda(redemptionProgramId);
  const registry = registryPda(complianceProgramId);
  const request = requestPda(redemptionProgramId, id);

  const connection = getConnection(rpcUrl);
  const quoteTokenProgram = await resolveTokenProgram(connection, quoteMint);

  // Beneficiary isn't a param here (claim is permissionless and always pays
  // the request's recorded beneficiary), but the beneficiary's quote ATA is
  // still an account the instruction writes to — read it off the request.
  const program = redemptionProgram(rpcUrl, escrow);
  const req = await program.account.redemptionRequest.fetch(request);
  const beneficiary = req.beneficiary;
  const beneficiaryQuote = quoteAta(quoteMint, beneficiary, quoteTokenProgram, false);

  const ix = await program.methods
    .claimRedemption(new BN(id.toString()))
    .accountsStrict({
      config,
      registry,
      request,
      rwaMint,
      quoteMint,
      escrowToken: rwaAta(rwaMint, config),
      escrowQuote: quoteAta(quoteMint, config, quoteTokenProgram, true),
      vaultToken: rwaAta(rwaMint, vaultConfig),
      beneficiaryQuote,
      rwaTokenProgram: TOKEN_2022_PROGRAM_ID,
      quoteTokenProgram,
    })
    .remainingAccounts(
      hookRemainingAccounts(
        rwaMint,
        config,
        vaultConfig,
        hookProgramId,
        complianceProgramId,
      ),
    )
    .instruction();

  const provider = getInjectedProviderOrThrow();
  return signAndSend(connection, provider, caller, [
    ComputeBudgetProgram.setComputeUnitLimit({ units: 600_000 }),
    createAssociatedTokenAccountIdempotentInstruction(
      caller,
      beneficiaryQuote,
      beneficiary,
      quoteMint,
      quoteTokenProgram,
    ),
    ix,
  ]);
}

/**
 * The redemption program's `cancel_redemption` instruction — refunds the
 * escrowed RWA to the beneficiary of a still-Pending request whose timeout
 * has elapsed. Reverts before then, and (like every RWA transfer) needs both
 * parties Allowed.
 */
export async function sendCancelRedemption(
  ctx: ChainContext,
  from: string,
  escrow: string,
  id: bigint,
  programAddresses?: ProgramAddresses,
): Promise<string> {
  const sol = requireProgramAddresses(programAddresses);
  const hookProgramIdStr = requireHookProgramId(ctx);
  assertProgramAddressesPinned(sol, hookProgramIdStr);
  assertPinnedRedemptionProgramId(escrow);
  const hookProgramId = new PublicKey(hookProgramIdStr);
  const rpcUrl = requireRpcUrl();
  const beneficiary = new PublicKey(from);
  const redemptionProgramId = new PublicKey(escrow);
  const complianceProgramId = new PublicKey(sol.complianceProgramId);
  const rwaMint = new PublicKey(sol.rwaMint);
  const config = redemptionConfigPda(redemptionProgramId);
  const registry = registryPda(complianceProgramId);
  const request = requestPda(redemptionProgramId, id);

  const program = redemptionProgram(rpcUrl, escrow);
  const ix = await program.methods
    .cancelRedemption(new BN(id.toString()))
    .accountsStrict({
      config,
      registry,
      request,
      rwaMint,
      escrowToken: rwaAta(rwaMint, config),
      beneficiaryToken: walletRwaAta(rwaMint, beneficiary),
      beneficiaryRecord: recordPda(complianceProgramId, beneficiary),
      beneficiary,
      rwaTokenProgram: TOKEN_2022_PROGRAM_ID,
    })
    .remainingAccounts(
      hookRemainingAccounts(
        rwaMint,
        config,
        beneficiary,
        hookProgramId,
        complianceProgramId,
      ),
    )
    .instruction();

  const connection = getConnection(rpcUrl);
  const provider = getInjectedProviderOrThrow();
  return signAndSend(connection, provider, beneficiary, [
    ComputeBudgetProgram.setComputeUnitLimit({ units: 600_000 }),
    ix,
  ]);
}
