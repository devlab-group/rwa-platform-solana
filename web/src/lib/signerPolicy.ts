// The offline signer's trust-root policy (the `--policy policy.json` file the
// admin hands the auditor). The signer parses it with DisallowUnknownFields, so
// it MUST carry exactly these keys and nothing else — an extra or stale key is a
// hard parse failure, not a warning. See signer/internal/policy/policy.go and
// docs/auditor/auditor-guide.md.
import type { components } from "./api-types";

type Project = components["schemas"]["Project"];
type BootstrapConfig = components["schemas"]["BootstrapConfig"];

/**
 * The Solana policy shape. Note which values are DOMAIN inputs rather than
 * program ids — the two are easy to confuse and both are plausible-looking
 * base58:
 *
 * - `config` is the supply-controller **Config PDA**, not the supply-controller
 *   program id.
 * - `vault` is the vault **Config PDA**, not the vault program id. The on-chain
 *   supply-controller binds every mint attestation's `vault` field to this PDA,
 *   so a policy built from the program id yields signatures the program
 *   rejects — after the auditor has already signed.
 *
 * Both therefore come from GET /api/v1/config (which reads them from the
 * server's `contract.supply_config` / `contract.vault_config`), never from
 * Project.addresses, which carries program ids.
 */
export interface SignerPolicy {
  /** Cluster genesis hash, base58 — the attestation domain's `cluster`. */
  cluster: string;
  /** SupplyController program id, base58 — the domain's `program`. */
  program: string;
  /** SupplyController Config PDA, base58 — the domain's `config`. */
  config: string;
  /** Vault Config PDA, base58 — the attestation message's `vault`. */
  vault: string;
  /** The auditor's 0x… secp256k1 (eth-shaped) address. */
  auditor: string;
  /** The project UUID string (NOT the bytes32 profileDigest/keccak). */
  projectId: string;
  /** 0x-prefixed bytes32 profile digest. */
  profileDigest: string;
}

/**
 * Assembles the signer policy from the loaded project and the deployment's
 * bootstrap config, or returns null when any required value is missing — so the
 * download is never a broken or partial file the auditor would have to debug on
 * an air-gapped machine.
 *
 * `maxAttestationLifetimeHours` is deliberately omitted: it is optional and the
 * signer applies its own 30-day default. Emitting a value here would let the
 * console silently widen the auditor's own risk limit.
 *
 * Key order matches the signer's documented shape.
 */
export function buildSignerPolicy(
  project: Project | undefined,
  projectUuid: string | undefined,
  bootstrap: BootstrapConfig | undefined,
): SignerPolicy | null {
  if (!project || !bootstrap) return null;

  const program = bootstrap.programIds?.supplyController;
  const cluster = bootstrap.clusterGenesis;
  const config = bootstrap.supplyConfig;
  const vault = bootstrap.vaultConfig;
  const { auditor, profileDigest } = project;

  if (
    !cluster ||
    !program ||
    !config ||
    !vault ||
    !auditor ||
    !profileDigest ||
    !projectUuid
  ) {
    return null;
  }
  return {
    cluster,
    program,
    config,
    vault,
    auditor,
    projectId: projectUuid,
    profileDigest,
  };
}
