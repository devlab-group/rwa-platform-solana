// PDA/ATA derivation for the on-chain programs — mirrors solana/tests/fullflow.ts
// exactly (seeds, owner-off-curve ATAs, hook remaining-accounts shape). Pure
// functions only (no network calls) so they're unit-testable without a
// validator.
//
// Every program id here comes from the deployment's own Project record
// (GET /api/v1/project's `addresses`, plus the transfer-hook program id from
// GET /api/v1/config — see provider.ts) rather than any constant baked
// into a copied IDL file: this platform deploys an independent program set per
// installation, so a hardcoded program id would silently derive PDAs for the
// wrong deployment.
import { PublicKey } from "@solana/web3.js";
import {
  TOKEN_2022_PROGRAM_ID,
  getAssociatedTokenAddressSync,
} from "@solana/spl-token";

const enc = (s: string) => Buffer.from(s, "utf8");

/** u64 little-endian, 8 bytes — how `request`/`nonce`/etc PDA seeds encode a numeric id. */
export function u64LE(value: bigint): Buffer {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(value);
  return buf;
}

/** compliance program's `registry` singleton PDA (seed: "registry"). */
export function registryPda(complianceProgramId: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [enc("registry")],
    complianceProgramId,
  )[0];
}

/** compliance program's per-wallet `record` PDA (seed: "record", wallet). */
export function recordPda(
  complianceProgramId: PublicKey,
  wallet: PublicKey,
): PublicKey {
  return PublicKey.findProgramAddressSync(
    [enc("record"), wallet.toBuffer()],
    complianceProgramId,
  )[0];
}

/** pricing program's `strategy` singleton PDA (seed: "strategy"). */
export function strategyPda(pricingProgramId: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [enc("strategy")],
    pricingProgramId,
  )[0];
}

/** vault program's `vault-config` singleton PDA (seed: "vault-config"). */
export function vaultConfigPda(vaultProgramId: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync(
    [enc("vault-config")],
    vaultProgramId,
  )[0];
}

/** redemption program's `redemption-config` singleton PDA (seed: "redemption-config"). */
export function redemptionConfigPda(
  redemptionProgramId: PublicKey,
): PublicKey {
  return PublicKey.findProgramAddressSync(
    [enc("redemption-config")],
    redemptionProgramId,
  )[0];
}

/** redemption program's per-request PDA (seed: "request", id as u64 LE). */
export function requestPda(
  redemptionProgramId: PublicKey,
  id: bigint,
): PublicKey {
  return PublicKey.findProgramAddressSync(
    [enc("request"), u64LE(id)],
    redemptionProgramId,
  )[0];
}

/** transfer-hook program's per-mint ExtraAccountMetaList PDA. */
export function extraAccountMetaListPda(
  hookProgramId: PublicKey,
  mint: PublicKey,
): PublicKey {
  return PublicKey.findProgramAddressSync(
    [enc("extra-account-metas"), mint.toBuffer()],
    hookProgramId,
  )[0];
}

/**
 * The RWA mint's canonical inventory/escrow ATA for a PDA owner (vault-config
 * or redemption-config) — off-curve, so `getAssociatedTokenAddressSync` needs
 * `allowOwnerOffCurve = true`, and it's a Token-2022 mint.
 */
export function rwaAta(mint: PublicKey, owner: PublicKey): PublicKey {
  return getAssociatedTokenAddressSync(
    mint,
    owner,
    true,
    TOKEN_2022_PROGRAM_ID,
  );
}

/**
 * The quote mint's ATA. `ownerIsPda` toggles allowOwnerOffCurve — true for the
 * vault/escrow's own proceeds ATA, false for an ordinary wallet's ATA.
 * `tokenProgram` is the quote mint's OWNING program — legacy SPL Token or
 * Token-2022 — resolved by the caller from the mint account itself (see
 * lib/chain/tokenProgram.ts's resolveTokenProgram), never assumed to be
 * legacy SPL: the on-chain programs pin `quote_token_program = *quote_mint.owner`
 * and accept either.
 */
export function quoteAta(
  mint: PublicKey,
  owner: PublicKey,
  tokenProgram: PublicKey,
  ownerIsPda = false,
): PublicKey {
  return getAssociatedTokenAddressSync(
    mint,
    owner,
    ownerIsPda,
    tokenProgram,
  );
}

/** An ordinary wallet's own RWA (Token-2022) ATA. */
export function walletRwaAta(mint: PublicKey, wallet: PublicKey): PublicKey {
  return getAssociatedTokenAddressSync(
    mint,
    wallet,
    false,
    TOKEN_2022_PROGRAM_ID,
  );
}

export interface AccountMeta {
  pubkey: PublicKey;
  isSigner: boolean;
  isWritable: boolean;
}

/**
 * The extra accounts every RWA (Token-2022) transfer must forward for the
 * transfer hook to resolve compliance — appended as `remainingAccounts` on
 * every vault/redemption instruction that moves the RWA token (buy,
 * request/claim/cancel redemption), and via the SPL helper for a direct
 * wallet-to-wallet transfer. Order matches solana/tests/fullflow.ts's
 * `hookRemaining` exactly: [hook program, ExtraAccountMetaList, compliance
 * program, registry, source record, destination record].
 */
export function hookRemainingAccounts(
  mint: PublicKey,
  srcOwner: PublicKey,
  dstOwner: PublicKey,
  hookProgramId: PublicKey,
  complianceProgramId: PublicKey,
): AccountMeta[] {
  const registry = registryPda(complianceProgramId);
  return [
    { pubkey: hookProgramId, isSigner: false, isWritable: false },
    {
      pubkey: extraAccountMetaListPda(hookProgramId, mint),
      isSigner: false,
      isWritable: false,
    },
    { pubkey: complianceProgramId, isSigner: false, isWritable: false },
    { pubkey: registry, isSigner: false, isWritable: false },
    {
      pubkey: recordPda(complianceProgramId, srcOwner),
      isSigner: false,
      isWritable: false,
    },
    {
      pubkey: recordPda(complianceProgramId, dstOwner),
      isSigner: false,
      isWritable: false,
    },
  ];
}
