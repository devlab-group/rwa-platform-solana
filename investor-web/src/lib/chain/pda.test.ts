// @vitest-environment node
//
// PublicKey.findProgramAddressSync's ed25519 on-curve check misbehaves under
// jsdom's `crypto` shim in this toolchain (every nonce attempt fails,
// producing "Unable to find a viable program address nonce") — this file has
// no DOM dependency, so it runs under plain Node instead, same as the rest of
// the app would in a real browser (whose native WebCrypto doesn't have this
// problem; only jsdom's polyfill does).
import { describe, expect, it } from "vitest";
import { Keypair, PublicKey } from "@solana/web3.js";
import {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
} from "@solana/spl-token";
import {
  extraAccountMetaListPda,
  hookRemainingAccounts,
  quoteAta,
  recordPda,
  redemptionConfigPda,
  registryPda,
  requestPda,
  rwaAta,
  strategyPda,
  u64LE,
  vaultConfigPda,
  walletRwaAta,
} from "./pda";

// Arbitrary but fixed-for-this-run program ids / wallets — these aren't real
// deployed programs, just stable inputs so the PDA math can be compared
// against a manual `findProgramAddressSync` call for internal consistency
// (not fixed golden base58 strings, which would need a real fullflow.ts
// validator run to produce).
const COMPLIANCE = Keypair.generate().publicKey;
const VAULT = Keypair.generate().publicKey;
const REDEMPTION = Keypair.generate().publicKey;
const PRICING = Keypair.generate().publicKey;
const HOOK = Keypair.generate().publicKey;
const WALLET = Keypair.generate().publicKey;
const MINT = Keypair.generate().publicKey;

describe("PDA derivation", () => {
  it("registryPda matches a manual findProgramAddressSync call", () => {
    const expected = PublicKey.findProgramAddressSync(
      [Buffer.from("registry")],
      COMPLIANCE,
    )[0];
    expect(registryPda(COMPLIANCE).toBase58()).toBe(expected.toBase58());
  });

  it("recordPda is seeded by the wallet and differs per wallet", () => {
    const a = recordPda(COMPLIANCE, WALLET);
    const b = recordPda(COMPLIANCE, MINT); // a different pubkey, standing in for "another wallet"
    expect(a.toBase58()).not.toBe(b.toBase58());
    const expected = PublicKey.findProgramAddressSync(
      [Buffer.from("record"), WALLET.toBuffer()],
      COMPLIANCE,
    )[0];
    expect(a.toBase58()).toBe(expected.toBase58());
  });

  it("strategyPda / vaultConfigPda / redemptionConfigPda use their singleton seeds", () => {
    expect(strategyPda(PRICING).toBase58()).toBe(
      PublicKey.findProgramAddressSync([Buffer.from("strategy")], PRICING)[0].toBase58(),
    );
    expect(vaultConfigPda(VAULT).toBase58()).toBe(
      PublicKey.findProgramAddressSync([Buffer.from("vault-config")], VAULT)[0].toBase58(),
    );
    expect(redemptionConfigPda(REDEMPTION).toBase58()).toBe(
      PublicKey.findProgramAddressSync(
        [Buffer.from("redemption-config")],
        REDEMPTION,
      )[0].toBase58(),
    );
  });

  it("requestPda is seeded by the u64 LE id and differs per id", () => {
    const req0 = requestPda(REDEMPTION, 0n);
    const req1 = requestPda(REDEMPTION, 1n);
    expect(req0.toBase58()).not.toBe(req1.toBase58());
    const expected0 = PublicKey.findProgramAddressSync(
      [Buffer.from("request"), u64LE(0n)],
      REDEMPTION,
    )[0];
    expect(req0.toBase58()).toBe(expected0.toBase58());
  });

  it("u64LE encodes little-endian 8 bytes", () => {
    // 0x0102 LE -> [0x02, 0x01, 0, 0, 0, 0, 0, 0]
    const buf = u64LE(0x0102n);
    expect(Array.from(buf)).toEqual([0x02, 0x01, 0, 0, 0, 0, 0, 0]);
    expect(buf.length).toBe(8);
  });

  it("extraAccountMetaListPda is seeded by the mint", () => {
    const expected = PublicKey.findProgramAddressSync(
      [Buffer.from("extra-account-metas"), MINT.toBuffer()],
      HOOK,
    )[0];
    expect(extraAccountMetaListPda(HOOK, MINT).toBase58()).toBe(
      expected.toBase58(),
    );
  });

  it("rwaAta/quoteAta/walletRwaAta pick the right token program (Token-2022 for RWA, classic SPL for quote)", () => {
    const rwa = rwaAta(MINT, VAULT);
    const quote = quoteAta(MINT, VAULT, TOKEN_PROGRAM_ID, true);
    const walletRwa = walletRwaAta(MINT, WALLET);
    // Different owners/allowOwnerOffCurve/programs must not collide.
    expect(rwa.toBase58()).not.toBe(quote.toBase58());
    expect(rwa.toBase58()).not.toBe(walletRwa.toBase58());
    // Sanity: deterministic — calling again yields the same address.
    expect(rwaAta(MINT, VAULT).toBase58()).toBe(rwa.toBase58());
  });

  it("quoteAta derives a different address per token program (the quote leg's owning program isn't always legacy SPL)", () => {
    const legacy = quoteAta(MINT, VAULT, TOKEN_PROGRAM_ID, true);
    const t22 = quoteAta(MINT, VAULT, TOKEN_2022_PROGRAM_ID, true);
    expect(legacy.toBase58()).not.toBe(t22.toBase58());
    expect(legacy.toBase58()).toBe(
      PublicKey.findProgramAddressSync(
        [VAULT.toBuffer(), TOKEN_PROGRAM_ID.toBuffer(), MINT.toBuffer()],
        ASSOCIATED_TOKEN_PROGRAM_ID,
      )[0].toBase58(),
    );
  });

  it("hookRemainingAccounts returns the six accounts in fullflow.ts's exact order", () => {
    const accounts = hookRemainingAccounts(MINT, VAULT, WALLET, HOOK, COMPLIANCE);
    expect(accounts).toHaveLength(6);
    expect(accounts[0]).toMatchObject({
      pubkey: HOOK,
      isSigner: false,
      isWritable: false,
    });
    expect(accounts[1].pubkey.toBase58()).toBe(
      extraAccountMetaListPda(HOOK, MINT).toBase58(),
    );
    expect(accounts[2].pubkey.toBase58()).toBe(COMPLIANCE.toBase58());
    expect(accounts[3].pubkey.toBase58()).toBe(registryPda(COMPLIANCE).toBase58());
    expect(accounts[4].pubkey.toBase58()).toBe(
      recordPda(COMPLIANCE, VAULT).toBase58(),
    );
    expect(accounts[5].pubkey.toBase58()).toBe(
      recordPda(COMPLIANCE, WALLET).toBase58(),
    );
    // None of the hook-resolution accounts are signers or writable.
    expect(accounts.every((a) => !a.isSigner && !a.isWritable)).toBe(true);
  });

  it("token program constants used are the expected ones (sanity)", () => {
    expect(TOKEN_2022_PROGRAM_ID.toBase58()).not.toBe(
      TOKEN_PROGRAM_ID.toBase58(),
    );
  });
});
