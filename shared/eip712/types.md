# Canonical auditor-attestation type strings (Solana)

These strings are the single source of truth for the on-chain Rust verifier
(`solana/crates/attestation`), the Go offline signer, the Go server's package
builder, and the TS parity test. They MUST match byte-for-byte.

The digest reproduces the EIP-712 *structure* —
`keccak256(0x1901 ‖ domainSeparator ‖ hashStruct(message))` — because the auditor
signs with secp256k1/ECDSA and the on-chain program verifies with the
`secp256k1_recover` syscall. What differs from an EVM deployment is the **domain**:
it binds a Solana cluster + program + config PDA instead of
`(chainId, verifyingContract)`.

## Domain

```
name:    "RWA-Supply-Attestation-Solana"
version: "1"
cluster: <cluster genesis hash, 32 bytes>
program: <rwa-supply-controller program id, 32 bytes>
config:  <SupplyController config PDA, 32 bytes>
```

`SolanaSupplyAttestation(string name,string version,bytes32 cluster,bytes32 program,bytes32 config)`

The domain name is deliberately distinct from any other deployment's, so an
attestation for one chain family can never hash to a valid one for another.

## MintAttestation

Canonical type string (used for the type hash):

```
MintAttestation(bytes32 auditor,bytes32 profileDigest,bytes32 recordKey,bytes32 metadataDigest,uint64 amount,bytes32 nonce,uint64 validUntil,bytes32 vault)
```

`MINT_ATTESTATION_TYPEHASH = keccak256(<string above>)`

Field order (must not change):
1. `bytes32 auditor` — the 20-byte secp256k1 eth-style auditor address, left-padded
2. `bytes32 profileDigest`
3. `bytes32 recordKey`
4. `bytes32 metadataDigest`
5. `uint64  amount`
6. `bytes32 nonce`
7. `uint64  validUntil`
8. `bytes32 vault` — the Vault authority's Solana pubkey, verbatim

## BurnAttestation

```
BurnAttestation(bytes32 auditor,bytes32 profileDigest,bytes32 operationId,bytes32 metadataDigest,uint64 amount,bytes32 nonce,uint64 validUntil,bytes32 vault)
```

`BURN_ATTESTATION_TYPEHASH = keccak256(<string above>)`

Field order:
1. `bytes32 auditor`
2. `bytes32 profileDigest`
3. `bytes32 operationId`
4. `bytes32 metadataDigest`
5. `uint64  amount`
6. `bytes32 nonce`
7. `uint64  validUntil`
8. `bytes32 vault`

## Digest construction

```
digest = keccak256(0x1901 ‖ domainSeparator ‖ hashStruct(message))
domainSeparator = keccak256(
    keccak256("SolanaSupplyAttestation(string name,string version,bytes32 cluster,bytes32 program,bytes32 config)")
  ‖ keccak256("RWA-Supply-Attestation-Solana")
  ‖ keccak256("1")
  ‖ cluster ‖ program ‖ config)
hashStruct(m) = keccak256(TYPEHASH ‖ word(m.field1) ‖ ... ‖ word(m.fieldN))
```

Every field is encoded to exactly one 32-byte word, matching Solidity's
`abi.encode`, so the pre-image rules stay trivial and unambiguous:

- `bytes32` — verbatim (a Solana pubkey is already 32 bytes).
- `uint64` — big-endian, right-aligned (left-padded with 24 zero bytes).
- the 20-byte `auditor` address — right-aligned (left-padded with 12 zero bytes).

Note `amount` and `validUntil` are `uint64` here (Solana token amounts are `u64`),
and `nonce` is a raw `bytes32` — it seeds an on-chain replay-marker PDA verbatim
rather than being a counter.

## Definitions

- `recordKey   = keccak256(bytes(recordId))` — unique per project mint.
- `operationId` — unique per de-tokenization event (server-generated random bytes32).
- `metadataDigest` / `profileDigest` — **SHA-256** of RFC 8785 canonical bytes (NOT keccak).
- `nonce` — server-generated random 256-bit value; shared namespace across mint & burn.
- `validUntil` — mandatory unix seconds; SHOULD be ≤ 30 days after package creation.

Note: profileDigest/metadataDigest use SHA-256 (per IPFS raw/sha2-256 CID convention);
only the struct/domain hashing above uses keccak256.

## Frozen golden values

`shared/vectors/mint-attestation.json` and
`shared/vectors/burn-attestation.json` pin the domain separator, hashStruct,
digest, and a recoverable signature. They are reproduced independently by the Rust
crate, the Go signer, the Go server, and the TypeScript parity test — nothing above
may change without changing all four and the deployed on-chain program.
