// Cross-language parity for the Solana auditor-attestation digest.
//
// Recomputes the domain separator, hashStruct, and EIP-712-style digest in
// TypeScript (ethers) and checks them against the frozen Rust golden vector in
// tests/vectors/mint-attestation.json — the same values the on-chain
// `rwa-supply-controller` program derives and the future offline signer must
// produce. Pure test: no validator required (`yarn ts-mocha tests/attestation-parity.ts`).
//
// The burn vector below is pinned against shared/vectors/burn-attestation.json
// directly rather than a local tests/vectors copy, because no such copy exists yet.

import {
  keccak256,
  concat,
  zeroPadValue,
  toBeHex,
  getBytes,
  recoverAddress,
  Signature,
} from "ethers";
import { expect } from "chai";
import golden from "./vectors/mint-attestation.json" with { type: "json" };
import burnGolden from "../../shared/vectors/burn-attestation.json" with { type: "json" };

const enc = new TextEncoder();
const DOMAIN_TYPE =
  "SolanaSupplyAttestation(string name,string version,bytes32 cluster,bytes32 program,bytes32 config)";
const DOMAIN_NAME = "RWA-Supply-Attestation-Solana";
const DOMAIN_VERSION = "1";
const MINT_TYPE =
  "MintAttestation(bytes32 auditor,bytes32 profileDigest,bytes32 recordKey,bytes32 metadataDigest,uint64 amount,bytes32 nonce,uint64 validUntil,bytes32 vault)";
const BURN_TYPE =
  "BurnAttestation(bytes32 auditor,bytes32 profileDigest,bytes32 operationId,bytes32 metadataDigest,uint64 amount,bytes32 nonce,uint64 validUntil,bytes32 vault)";

const kText = (s: string) => keccak256(enc.encode(s));
const word = (hexOrAddr: string) => zeroPadValue(hexOrAddr, 32); // left-pad to 32 bytes
const wordU64 = (v: string | number | bigint) =>
  zeroPadValue(toBeHex(BigInt(v)), 32);

function domainSeparator(
  cluster: string,
  program: string,
  config: string,
): string {
  return keccak256(
    concat([
      kText(DOMAIN_TYPE),
      kText(DOMAIN_NAME),
      kText(DOMAIN_VERSION),
      cluster,
      program,
      config,
    ]),
  );
}

function mintHashStruct(m: typeof golden.message): string {
  return keccak256(
    concat([
      kText(MINT_TYPE),
      word(m.auditor),
      m.profileDigest,
      m.recordKey,
      m.metadataDigest,
      wordU64(m.amount),
      m.nonce,
      wordU64(m.validUntil),
      m.vault,
    ]),
  );
}

function burnHashStruct(m: typeof burnGolden.message): string {
  return keccak256(
    concat([
      kText(BURN_TYPE),
      word(m.auditor),
      m.profileDigest,
      m.operationId,
      m.metadataDigest,
      wordU64(m.amount),
      m.nonce,
      wordU64(m.validUntil),
      m.vault,
    ]),
  );
}

function digest(dsep: string, hs: string): string {
  return keccak256(concat(["0x1901", dsep, hs]));
}

describe("attestation parity (TS <-> Rust golden)", () => {
  const d = golden.domain;

  it("domain separator matches the Rust golden", () => {
    expect(domainSeparator(d.cluster, d.program, d.config)).to.equal(
      golden.domainSeparator,
    );
  });

  it("hashStruct matches the Rust golden", () => {
    expect(mintHashStruct(golden.message)).to.equal(golden.hashStruct);
  });

  it("digest matches the Rust golden", () => {
    const dsep = domainSeparator(d.cluster, d.program, d.config);
    expect(digest(dsep, mintHashStruct(golden.message))).to.equal(
      golden.digest,
    );
  });

  it("signature recovers the auditor eth address", () => {
    // Reassemble r||s||v and recover, exactly as secp256k1_recover does on-chain.
    const sigBytes = getBytes(golden.signature); // 64 bytes r||s
    const sig = Signature.from({
      r: golden.signature.slice(0, 66),
      s: "0x" + golden.signature.slice(66, 130),
      v: 27 + golden.recoveryId,
    });
    const recovered = recoverAddress(golden.digest, sig).toLowerCase();
    expect(recovered).to.equal(golden.message.auditor.toLowerCase());
    expect(sigBytes.length).to.equal(64);
  });
});

// Burn counterpart of the suite above: the mint vector already closes the
// domain/hashStruct/digest/signature loop for TS, while the burn vector was
// previously pinned only in server/internal/eip712/attestation_test.go
// (domain/hashStruct/digest, no signature) and the Go signer's
// TestSolanaVectors (mint only) -- its signature/recoveryId were never
// recovered outside the Go signer's new burn-specific test.
describe("burn attestation parity (TS <-> Rust golden)", () => {
  const d = burnGolden.domain;

  it("domain separator matches the Rust golden", () => {
    expect(domainSeparator(d.cluster, d.program, d.config)).to.equal(
      burnGolden.domainSeparator,
    );
  });

  it("hashStruct matches the Rust golden", () => {
    expect(burnHashStruct(burnGolden.message)).to.equal(burnGolden.hashStruct);
  });

  it("digest matches the Rust golden", () => {
    const dsep = domainSeparator(d.cluster, d.program, d.config);
    expect(digest(dsep, burnHashStruct(burnGolden.message))).to.equal(
      burnGolden.digest,
    );
  });

  it("signature recovers the auditor eth address", () => {
    // Reassemble r||s||v and recover, exactly as secp256k1_recover does on-chain.
    const sigBytes = getBytes(burnGolden.signature); // 64 bytes r||s
    const sig = Signature.from({
      r: burnGolden.signature.slice(0, 66),
      s: "0x" + burnGolden.signature.slice(66, 130),
      v: 27 + burnGolden.recoveryId,
    });
    const recovered = recoverAddress(burnGolden.digest, sig).toLowerCase();
    expect(recovered).to.equal(burnGolden.message.auditor.toLowerCase());
    expect(sigBytes.length).to.equal(64);
  });
});
