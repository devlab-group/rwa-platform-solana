import { bytesToHex, type Hex } from "./chain";
import { sha256 } from "./sha256";

/**
 * Encodes a rejection reason into the 32-byte value redemption.reject_redemption
 * expects, matching the old server encoder (internal/redemption
 * EncodeReasonCode):
 *
 * - A `0x` + exactly 64 hex chars input is already the right shape → used verbatim.
 * - Any other non-empty text is hashed: `sha256(utf8Bytes(text))`.
 *
 * Empty input is rejected — a reason code is required on-chain.
 */
export function encodeReasonCode(input: string): Hex {
  if (!input) {
    throw new Error("A rejection reason code is required.");
  }
  if (/^0x[0-9a-fA-F]{64}$/.test(input)) {
    return input as Hex;
  }
  return bytesToHex(sha256(new TextEncoder().encode(input)));
}
