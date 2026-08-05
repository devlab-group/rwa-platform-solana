import { useContext } from "react";
import type { components } from "./api-types";
import { WalletContext } from "../context/walletContextValue";

type RoleHolders = components["schemas"]["RoleHolders"];
type Addresses = components["schemas"]["Addresses"];

/**
 * On-chain role names, exactly as the server projects them into Project.roles
 * (server/internal/project/security.go). Used to gate admin actions in the UI
 * by the connected wallet's role.
 *
 * Note this gate is a UX convenience, not a security boundary: the instruction
 * the gated forms build is still authorized on-chain by the program's own role
 * check when it is finally submitted. Hiding an action the connected wallet
 * can't perform just avoids building an instruction that would revert.
 */
export const ROLES = {
  admin: "DEFAULT_ADMIN_ROLE",
  pauser: "PAUSER_ROLE",
  pricer: "PRICER_ROLE",
  treasurer: "TREASURER_ROLE",
  redemptionManager: "REDEMPTION_MANAGER_ROLE",
  compliance: "COMPLIANCE_ROLE",
} as const;

/**
 * Which program `propose_admin`/`accept_admin` (lib/chain.ts's
 * buildProposeAdminIx/buildAcceptAdminIx) is dispatched to — matches
 * lib/chain.ts's ProgramIds field names, not Addresses' (e.g.
 * "pricing"/"redemption" rather than "strategy"/"redemptionEscrow").
 */
export type AdminProgramKey =
  | "compliance"
  | "vault"
  | "pricing"
  | "redemption"
  | "supplyController";

/**
 * One admin-owned program the two-step admin-transfer UI renders a form for.
 * `field` resolves its on-chain address from Project.addresses (which holds
 * every deployed program id under these field names — see
 * ROLE_TARGET_FIELDS's doc comment). `programKey` is the program's key in
 * lib/chain.ts's ProgramIds/lib/wallet.ts's admin functions; the RWA mint has
 * no on-chain admin instruction at all (the mint has no governance analog
 * to a two-step admin), so it isn't in this list.
 */
export interface AdminContractSpec {
  /** Display name shown on the transfer/accept form, e.g. "Vault". */
  name: string;
  field: keyof Addresses;
  programKey: AdminProgramKey;
}

/**
 * Every admin-owned program with an independent per-program `admin` field and
 * its own propose_admin/accept_admin two-step (see each program's lib.rs
 * under solana/programs). The RWA mint/token itself has no on-chain admin
 * instruction, so it isn't listed here — see adminContractTargets.
 */
export const ADMIN_CONTRACTS: AdminContractSpec[] = [
  { name: "Compliance Registry", field: "compliance", programKey: "compliance" },
  {
    name: "Supply Controller",
    field: "supplyController",
    programKey: "supplyController",
  },
  { name: "Vault", field: "vault", programKey: "vault" },
  {
    name: "Redemption Escrow",
    field: "redemptionEscrow",
    programKey: "redemption",
  },
  { name: "Fixed-Price Strategy", field: "strategy", programKey: "pricing" },
];

/**
 * Which deployed program each granular role is held on, exactly mirroring how
 * the server provisions and projects them (server/internal/project/security.go).
 * Replacing a role's holder must target every program in its set to keep the
 * on-chain holders consistent with the platform's model. DEFAULT_ADMIN_ROLE is
 * excluded here — it is changed via the two-step admin transfer, not a role
 * set_* call. PAUSER_ROLE lives on the compliance program (its Registry), not
 * the RWA mint — there is no pause instruction on the mint itself.
 * PRICER_ROLE has one target (pricing only — the vault program has no
 * set_pricer).
 */
export const ROLE_TARGET_FIELDS: Record<string, (keyof Addresses)[]> = {
  [ROLES.pauser]: ["compliance"],
  [ROLES.pricer]: ["strategy"],
  [ROLES.treasurer]: ["vault", "redemptionEscrow"],
  [ROLES.redemptionManager]: ["redemptionEscrow"],
  [ROLES.compliance]: ["compliance"],
};

/** The roles a DEFAULT_ADMIN can replace the holder of from the UI (admin itself excluded — see transfer flow). */
export const GRANTABLE_ROLES = [
  ROLES.pauser,
  ROLES.pricer,
  ROLES.treasurer,
  ROLES.redemptionManager,
  ROLES.compliance,
] as const;

/** Resolves the deployed program addresses a role change must be sent to. */
export function roleTargets(
  role: string,
  addresses: Addresses | undefined,
): string[] {
  const fields = ROLE_TARGET_FIELDS[role] ?? [];
  return resolveAddresses(fields, addresses);
}

function resolveAddresses(
  fields: (keyof Addresses)[],
  addresses: Addresses | undefined,
): string[] {
  if (!addresses) return [];
  const out: string[] = [];
  for (const f of fields) {
    const a = addresses[f];
    if (typeof a === "string" && a) out.push(a);
  }
  return out;
}

/** One admin-owned program, resolved to its live on-chain address — what AdminTransferForm/AcceptAdminForm (routes/admin/Security.tsx) render one pair of forms per entry of. */
export interface AdminContractTarget {
  name: string;
  address: string;
  programKey: AdminProgramKey;
}

/**
 * Resolves every admin-owned program this deployment has (the five with a
 * two-step admin — the RWA mint doesn't). An entry is omitted if its address
 * isn't yet known (project not deployed, or an older server missing the
 * field) — the caller renders one "Begin admin transfer" + "Accept admin
 * transfer" form pair per entry returned, each labeled with `name` and
 * `address`.
 */
export function adminContractTargets(
  addresses: Addresses | undefined,
): AdminContractTarget[] {
  if (!addresses) return [];
  const out: AdminContractTarget[] = [];
  for (const spec of ADMIN_CONTRACTS) {
    const addr = addresses[spec.field];
    if (typeof addr === "string" && addr) {
      out.push({ name: spec.name, address: addr, programKey: spec.programKey });
    }
  }
  return out;
}

/**
 * Whether `address` is one of the holders of `role` in the project's role
 * map. Base58 public keys are compared EXACTLY, byte-for-byte case included —
 * base58 case is significant (it's part of the encoding, not decoration the
 * way hex-address checksum casing is), so lowercasing a
 * base58 pubkey can silently change which key it denotes: folding case could
 * make a valid holder stop matching, or make two distinct holders wrongly
 * compare equal.
 */
export function hasRole(
  roles: RoleHolders | undefined,
  role: string,
  address: string | null | undefined,
): boolean {
  if (!roles || !address) return false;
  const holders = roles[role];
  if (!holders) return false;
  return holders.some((h) => h === address);
}

/**
 * Whether the connected wallet holds `role` in the given project role map.
 * `false` while the wallet is disconnected, the roles haven't loaded, or the
 * hook is used outside a <WalletProvider> (read defensively so a gated form
 * simply reports "no access" rather than throwing).
 */
export function useHasRole(
  roles: RoleHolders | undefined,
  role: string,
): boolean {
  const ctx = useContext(WalletContext);
  return hasRole(roles, role, ctx?.address ?? null);
}
