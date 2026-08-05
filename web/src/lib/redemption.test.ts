import { describe, expect, it } from "vitest";
import { bytesToHex } from "./chain";
import { sha256 } from "./sha256";
import { encodeReasonCode } from "./redemption";

describe("encodeReasonCode", () => {
  it("passes a 0x + 64-hex value through unchanged", () => {
    const bytes32 = `0x${"ab".repeat(32)}`;
    expect(encodeReasonCode(bytes32)).toBe(bytes32);
  });

  it("hashes free text with sha256 of its UTF-8 bytes", () => {
    const text = "NON_COMPLIANT";
    expect(encodeReasonCode(text)).toBe(
      bytesToHex(sha256(new TextEncoder().encode(text))),
    );
  });

  it("hashes a 0x string that is not exactly 64 hex chars (treated as text)", () => {
    const notBytes32 = "0xdeadbeef";
    expect(encodeReasonCode(notBytes32)).toBe(
      bytesToHex(sha256(new TextEncoder().encode(notBytes32))),
    );
  });

  it("rejects an empty reason code", () => {
    expect(() => encodeReasonCode("")).toThrow();
  });
});
