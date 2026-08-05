// @vitest-environment node
//
// Unit coverage for the build-time pins module: getPins/
// pinsConfigured, resolveRpcUrl, and the standalone vault/redemption
// program-id assertions. wallet.instructions.test.ts covers these wired
// into the actual send*() call sites; this file covers the pure logic
// (fallback, mismatch) directly, same split as pda.test.ts vs
// wallet.instructions.test.ts for the PDA helpers.
//
// Runs under node for the same reason as pda.test.ts: PublicKey construction
// misbehaves under this toolchain's jsdom crypto shim.
import { afterEach, describe, expect, it, vi } from "vitest";
import { Keypair } from "@solana/web3.js";
import {
  assertPinnedRedemptionProgramId,
  assertPinnedVaultProgramId,
  getPins,
  resolveRpcUrl,
  pinsConfigured,
  pinsPartiallyConfigured,
  PinMismatchError,
} from "./pins";

const VAULT = Keypair.generate().publicKey.toBase58();
const REDEMPTION = Keypair.generate().publicKey.toBase58();

// Every pin REQUIRED_FOR_INSTRUCTIONS needs, so pinsConfigured() tests
// below start from a fully-pinned baseline and toggle one at a time.
function stubAllRequiredPins() {
  vi.stubEnv("VITE_SOLANA_PROGRAM_COMPLIANCE", Keypair.generate().publicKey.toBase58());
  vi.stubEnv("VITE_SOLANA_PROGRAM_VAULT", VAULT);
  vi.stubEnv("VITE_SOLANA_PROGRAM_PRICING", Keypair.generate().publicKey.toBase58());
  vi.stubEnv("VITE_SOLANA_PROGRAM_TRANSFER_HOOK", Keypair.generate().publicKey.toBase58());
  vi.stubEnv("VITE_SOLANA_PROGRAM_REDEMPTION", REDEMPTION);
  vi.stubEnv("VITE_SOLANA_RWA_MINT", Keypair.generate().publicKey.toBase58());
  vi.stubEnv("VITE_SOLANA_QUOTE_MINT", Keypair.generate().publicKey.toBase58());
  vi.stubEnv("VITE_SOLANA_RPC_URL", "https://rpc.example.com");
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("getPins", () => {
  it("reads rpcUrl and clusterGenesis alongside the existing program id/mint pins", () => {
    vi.stubEnv("VITE_SOLANA_RPC_URL", "https://rpc.example.com");
    vi.stubEnv("VITE_SOLANA_CLUSTER_GENESIS", "some-genesis-hash");

    const pins = getPins();
    expect(pins.rpcUrl).toBe("https://rpc.example.com");
    expect(pins.clusterGenesis).toBe("some-genesis-hash");
  });

  it("leaves rpcUrl/clusterGenesis undefined when unset", () => {
    // .env.test pins a real VITE_SOLANA_RPC_URL/VITE_SOLANA_WS_URL so the
    // unit tests below (and cspPolicy.test.ts's build-level
    // check) exercise the real Connection/CSP path — override both back to
    // empty here to exercise the genuinely-unset case this test is about.
    vi.stubEnv("VITE_SOLANA_RPC_URL", "");
    const pins = getPins();
    expect(pins.rpcUrl).toBeUndefined();
    expect(pins.clusterGenesis).toBeUndefined();
  });
});

describe("pinsConfigured (rpcUrl is required)", () => {
  it("is false when every other pin is set but VITE_SOLANA_RPC_URL is not", () => {
    stubAllRequiredPins();
    vi.stubEnv("VITE_SOLANA_RPC_URL", "");

    expect(pinsConfigured()).toBe(false);
    expect(pinsPartiallyConfigured()).toBe(true);
  });

  it("is true once the RPC URL pin joins every other required pin", () => {
    stubAllRequiredPins();

    expect(pinsConfigured()).toBe(true);
    expect(pinsPartiallyConfigured()).toBe(false);
  });
});

describe("resolveRpcUrl (build-time pin is the SOLE source)", () => {
  it("returns the pinned VITE_SOLANA_RPC_URL when set", () => {
    vi.stubEnv("VITE_SOLANA_RPC_URL", "https://pinned.example.com");
    expect(resolveRpcUrl()).toBe("https://pinned.example.com");
  });

  it("falls back to the local-dev default when unset, without throwing — there is no server value to read instead", () => {
    // See the .env.test note above — override the fixture pin back to empty.
    vi.stubEnv("VITE_SOLANA_RPC_URL", "");
    expect(resolveRpcUrl()).toBe("http://127.0.0.1:8899");
  });
});

describe("assertPinnedVaultProgramId / assertPinnedRedemptionProgramId", () => {
  it("does not throw when unpinned (dev fallback)", () => {
    expect(() => assertPinnedVaultProgramId(VAULT)).not.toThrow();
    expect(() => assertPinnedRedemptionProgramId(REDEMPTION)).not.toThrow();
  });

  it("does not throw when the positional argument agrees with the pin", () => {
    vi.stubEnv("VITE_SOLANA_PROGRAM_VAULT", VAULT);
    vi.stubEnv("VITE_SOLANA_PROGRAM_REDEMPTION", REDEMPTION);

    expect(() => assertPinnedVaultProgramId(VAULT)).not.toThrow();
    expect(() => assertPinnedRedemptionProgramId(REDEMPTION)).not.toThrow();
  });

  it("throws PinMismatchError when the positional vault program id disagrees with the pin", () => {
    vi.stubEnv("VITE_SOLANA_PROGRAM_VAULT", VAULT);
    const other = Keypair.generate().publicKey.toBase58();

    expect(() => assertPinnedVaultProgramId(other)).toThrow(PinMismatchError);
  });

  it("throws PinMismatchError when the positional redemption program id disagrees with the pin", () => {
    vi.stubEnv("VITE_SOLANA_PROGRAM_REDEMPTION", REDEMPTION);
    const other = Keypair.generate().publicKey.toBase58();

    expect(() => assertPinnedRedemptionProgramId(other)).toThrow(PinMismatchError);
  });
});
