// @vitest-environment node
//
// Pins sendMint's signature split (see wallet.ts: a 65-byte hex `signature` —
// 64-byte compact secp256k1 [R||S] + 1-byte recovery id, packed by
// Assets.tsx's parseSignedResult — is split back apart before being passed to
// lib/chain.ts's buildMintIx). lib/chain.ts is mocked so this only
// exercises the split, not PDA derivation or account-list building (covered
// by chain.test.ts) — a separate file from wallet.test.ts so this file's
// vi.mock("./chain") doesn't affect that file's real-PDA assertions.
import { PublicKey } from "@solana/web3.js";
import { beforeEach, describe, expect, it, vi } from "vitest";

// vi.mock is hoisted above regular top-level const declarations, so the spies
// it captures must come from vi.hoisted() rather than plain module-scope
// consts (see https://vitest.dev/api/vi.html#vi-hoisted).
const { buildMintIx, sendInstruction } = vi.hoisted(() => ({
  buildMintIx: vi.fn().mockResolvedValue({ fakeIx: true }),
  sendInstruction: vi.fn().mockResolvedValue("fakeSignature"),
}));

vi.mock("./chain", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./chain")>();
  return {
    ...actual,
    buildMintIx,
    sendInstruction,
    // Real getConnection() needs a resolved RPC URL from config; the
    // split under test never touches the connection, so a stub is enough.
    getConnection: () => ({}),
  };
});

import { sendMint, type MintAttestationInput } from "./wallet";

// A real base58 pubkey — sendMint parses `from` via
// `new PublicKey(...)` before reaching the (mocked) buildMintIx.
const PAYER = PublicKey.unique().toBase58();
const SUPPLY_CONTROLLER = PublicKey.unique().toBase58();

const ATTESTATION: MintAttestationInput = {
  auditor: "0x1111111111111111111111111111111111111111",
  profileDigest: `0x${"aa".repeat(32)}`,
  recordKey: `0x${"bb".repeat(32)}`,
  metadataDigest: `0x${"cc".repeat(32)}`,
  amount: 100n,
  nonce: 7n,
  validUntil: 999n,
};

describe("sendMint — signature split (65 bytes -> 64-byte signature + 1-byte recoveryId)", () => {
  beforeEach(() => {
    buildMintIx.mockClear();
    sendInstruction.mockClear();
  });

  it("splits recoveryId 0 (last byte 0x00)", async () => {
    const signature = `0x${"11".repeat(64)}00` as const;
    await sendMint(PAYER, SUPPLY_CONTROLLER, ATTESTATION, signature);

    expect(buildMintIx).toHaveBeenCalledTimes(1);
    const args = buildMintIx.mock.calls[0];
    const sigArg = args[8] as Uint8Array;
    const recoveryIdArg = args[9] as number;
    expect(Array.from(sigArg)).toEqual(Array(64).fill(0x11));
    expect(sigArg.length).toBe(64);
    expect(recoveryIdArg).toBe(0);
    expect(sendInstruction).toHaveBeenCalledWith(PAYER, { fakeIx: true });
  });

  it("splits recoveryId 1 (last byte 0x01)", async () => {
    const signature = `0x${"22".repeat(64)}01` as const;
    await sendMint(PAYER, SUPPLY_CONTROLLER, ATTESTATION, signature);

    const args = buildMintIx.mock.calls[0];
    const sigArg = args[8] as Uint8Array;
    const recoveryIdArg = args[9] as number;
    expect(Array.from(sigArg)).toEqual(Array(64).fill(0x22));
    expect(recoveryIdArg).toBe(1);
  });

  it("rejects a signature that isn't exactly 65 bytes", async () => {
    const tooShort = `0x${"11".repeat(64)}` as const; // 64 bytes, no recovery id
    await expect(
      sendMint(PAYER, SUPPLY_CONTROLLER, ATTESTATION, tooShort),
    ).rejects.toThrow(/65 bytes/);
    expect(buildMintIx).not.toHaveBeenCalled();
  });
});
