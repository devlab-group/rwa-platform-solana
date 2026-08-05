import { describe, expect, it } from "vitest";
import type { components } from "./api-types";
import { adminContractTargets, hasRole, roleTargets, ROLES } from "./roles";

type Addresses = components["schemas"]["Addresses"];

const ADDRESSES: Addresses = {
  token: "Token111111111111111111111111111111111111",
  compliance: "Comp1111111111111111111111111111111111111",
  supplyController: "Supp1111111111111111111111111111111111111",
  vault: "Vau11111111111111111111111111111111111111",
  redemptionEscrow: "Rede1111111111111111111111111111111111111",
  strategy: "Pric1111111111111111111111111111111111111",
  quoteToken: "Quot1111111111111111111111111111111111111",
};

describe("hasRole", () => {
  const PUBKEY = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
  const roles = {
    PAUSER_ROLE: [PUBKEY],
  };

  it("matches the exact holder", () => {
    expect(hasRole(roles, ROLES.pauser, PUBKEY)).toBe(true);
  });

  it("returns false for a non-holder", () => {
    expect(
      hasRole(roles, ROLES.pauser, "SomeOtherPubkey1111111111111111111111111"),
    ).toBe(false);
  });

  it("returns false for an unknown role or a role with no holders", () => {
    expect(hasRole(roles, ROLES.treasurer, PUBKEY)).toBe(false);
  });

  it("returns false when roles or address are missing", () => {
    expect(hasRole(undefined, ROLES.admin, PUBKEY)).toBe(false);
    expect(hasRole(roles, ROLES.admin, null)).toBe(false);
    expect(hasRole(roles, ROLES.admin, undefined)).toBe(false);
  });

  // base58 case is significant — unlike EIP-55 checksum casing
  // on EVM hex, lowercasing a Solana pubkey is not a cosmetic no-op, it can
  // denote a completely different key. hasRole must compare exactly.
  it("does NOT match a lowercased variant of a real holder — case folding must not be applied", () => {
    const lowercased = PUBKEY.toLowerCase();
    expect(lowercased).not.toBe(PUBKEY); // sanity: this pubkey has mixed case
    expect(hasRole(roles, ROLES.pauser, lowercased)).toBe(false);
  });
});

describe("roleTargets / adminContractTargets", () => {
  it("maps each granular role to the programs it is held on", () => {
    expect(roleTargets(ROLES.pauser, ADDRESSES)).toEqual([ADDRESSES.compliance]);
    expect(roleTargets(ROLES.pricer, ADDRESSES)).toEqual([ADDRESSES.strategy]);
    expect(roleTargets(ROLES.treasurer, ADDRESSES)).toEqual([
      ADDRESSES.vault,
      ADDRESSES.redemptionEscrow,
    ]);
    expect(roleTargets(ROLES.redemptionManager, ADDRESSES)).toEqual([
      ADDRESSES.redemptionEscrow,
    ]);
    expect(roleTargets(ROLES.compliance, ADDRESSES)).toEqual([
      ADDRESSES.compliance,
    ]);
  });

  it("returns no targets when addresses are missing", () => {
    expect(roleTargets(ROLES.pricer, undefined)).toEqual([]);
  });

  // Solana admins are per-program (5 independent `admin` fields) rather than
  // a single DEFAULT_ADMIN_ROLE shared by every governance program
  // (V1 used to scope this to compliance only, silently leaving the
  // other four under the old admin key). The RWA mint/token has no on-chain
  // admin instruction, so it's excluded here.
  it("targets all five two-step-admin programs, each named and addressed", () => {
    expect(adminContractTargets(ADDRESSES)).toEqual([
      {
        name: "Compliance Registry",
        address: ADDRESSES.compliance,
        programKey: "compliance",
      },
      {
        name: "Supply Controller",
        address: ADDRESSES.supplyController,
        programKey: "supplyController",
      },
      { name: "Vault", address: ADDRESSES.vault, programKey: "vault" },
      {
        name: "Redemption Escrow",
        address: ADDRESSES.redemptionEscrow,
        programKey: "redemption",
      },
      {
        name: "Fixed-Price Strategy",
        address: ADDRESSES.strategy,
        programKey: "pricing",
      },
    ]);
  });

  it("returns no targets when addresses are missing", () => {
    expect(adminContractTargets(undefined)).toEqual([]);
  });
});
