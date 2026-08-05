import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { sha256 } from "./sha256";

function hex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function nodeSha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(Buffer.from(bytes)).digest("hex");
}

// Standard NIST/FIPS 180-4 test vectors — pin this in-house implementation
// against known-good digests rather than trusting the hand-rolled arithmetic
// on faith.
describe("sha256 — known test vectors", () => {
  it("hashes the empty string", () => {
    expect(hex(sha256(new TextEncoder().encode("")))).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });

  it('hashes "abc"', () => {
    expect(hex(sha256(new TextEncoder().encode("abc")))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it('hashes "The quick brown fox jumps over the lazy dog"', () => {
    expect(
      hex(
        sha256(
          new TextEncoder().encode(
            "The quick brown fox jumps over the lazy dog",
          ),
        ),
      ),
    ).toBe("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
  });
});

// Cross-checks this implementation against Node's own (independently
// verified) SHA-256 across every message-length boundary the block-padding
// logic has to get right: exactly filling the last block (55/56 bytes, where
// the 9 bytes of padding either just fit or force a whole extra block), a
// clean multiple of 64, and lengths that span two and three blocks.
describe("sha256 — matches node:crypto across block-boundary lengths", () => {
  const lengths = [0, 1, 32, 55, 56, 63, 64, 65, 127, 128, 129, 200];

  it.each(lengths)("length %i bytes", (len) => {
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = i % 256;
    expect(hex(sha256(bytes))).toBe(nodeSha256Hex(bytes));
  });
});
