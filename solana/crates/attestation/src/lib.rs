//! Solana-bound auditor attestation digests.
//!
//! The offline signer already produces **secp256k1 / ECDSA** signatures (the same
//! primitive as Ethereum EIP-712). To secure both chains with the *same auditor
//! key and the same offline signer*, this crate reproduces the EIP-712 digest
//! *structure* — `keccak256(0x1901 ‖ domainSeparator ‖ hashStruct)` — but binds
//! the domain to a Solana deployment instead of `(chainId, verifyingContract)`:
//!
//! ```text
//! domainSeparator = keccak256(
//!     keccak256("SolanaSupplyAttestation(string name,string version,bytes32 cluster,bytes32 program,bytes32 config)")
//!     ‖ keccak256(name) ‖ keccak256(version) ‖ cluster ‖ program ‖ config)
//! ```
//!
//! - `cluster` — 32-byte cluster id (genesis hash) the attestation is valid on
//!   (replaces `chainId`).
//! - `program` — the `rwa-supply-controller` program id (32 bytes).
//! - `config`  — the SupplyController config PDA (replaces `verifyingContract`).
//!
//! Every message field is ABI-word-encoded to 32 bytes exactly as Solidity's
//! `abi.encode` does, so a signer can build the pre-image with trivial, unambiguous
//! rules: `bytes32` verbatim, `uint64` big-endian right-aligned, a 20-byte eth
//! `auditor` address left-padded with 12 zero bytes, a 32-byte Solana pubkey
//! (`vault`) verbatim.
//!
//! `verify` is done in the program with the `secp256k1_recover` syscall +
//! [`eth_address_from_pubkey`]. The host tests below pin the digest against a
//! frozen golden vector and check the eth-address derivation against the known
//! anvil auditor pubkey; signature *recovery* is proven end-to-end by the TS
//! parity test (ethers) and, on-chain, by the syscall itself.

#![forbid(unsafe_code)]

use tiny_keccak::{Hasher, Keccak};

pub const DOMAIN_TYPE_STRING: &[u8] =
    b"SolanaSupplyAttestation(string name,string version,bytes32 cluster,bytes32 program,bytes32 config)";
pub const DOMAIN_NAME: &[u8] = b"RWA-Supply-Attestation-Solana";
pub const DOMAIN_VERSION: &[u8] = b"1";

pub const MINT_TYPE_STRING: &[u8] =
    b"MintAttestation(bytes32 auditor,bytes32 profileDigest,bytes32 recordKey,bytes32 metadataDigest,uint64 amount,bytes32 nonce,uint64 validUntil,bytes32 vault)";
pub const BURN_TYPE_STRING: &[u8] =
    b"BurnAttestation(bytes32 auditor,bytes32 profileDigest,bytes32 operationId,bytes32 metadataDigest,uint64 amount,bytes32 nonce,uint64 validUntil,bytes32 vault)";

fn keccak(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    for p in parts {
        hasher.update(p);
    }
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

/// `abi.encode(uint64)` — big-endian, right-aligned in a 32-byte word.
fn word_u64(x: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&x.to_be_bytes());
    w
}

/// `abi.encode(address)` — 20-byte eth address right-aligned in a 32-byte word.
fn word_address(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

/// The 32-byte domain binding a signature to one cluster + program + config PDA.
#[derive(Debug, Clone, Copy)]
pub struct Domain {
    /// Cluster id (genesis hash) the attestation is valid on.
    pub cluster: [u8; 32],
    /// `rwa-supply-controller` program id.
    pub program: [u8; 32],
    /// SupplyController config PDA.
    pub config: [u8; 32],
}

impl Domain {
    pub fn separator(&self) -> [u8; 32] {
        keccak(&[
            &keccak(&[DOMAIN_TYPE_STRING]),
            &keccak(&[DOMAIN_NAME]),
            &keccak(&[DOMAIN_VERSION]),
            &self.cluster,
            &self.program,
            &self.config,
        ])
    }
}

/// Mint authorization payload — field order matches `MINT_TYPE_STRING`.
#[derive(Debug, Clone)]
pub struct MintAttestation {
    /// 20-byte eth address the signature must recover to.
    pub auditor: [u8; 20],
    pub profile_digest: [u8; 32],
    pub record_key: [u8; 32],
    pub metadata_digest: [u8; 32],
    pub amount: u64,
    pub nonce: [u8; 32],
    pub valid_until: u64,
    /// Vault Solana pubkey the mint credits.
    pub vault: [u8; 32],
}

/// Burn authorization payload — field order matches `BURN_TYPE_STRING`.
#[derive(Debug, Clone)]
pub struct BurnAttestation {
    pub auditor: [u8; 20],
    pub profile_digest: [u8; 32],
    pub operation_id: [u8; 32],
    pub metadata_digest: [u8; 32],
    pub amount: u64,
    pub nonce: [u8; 32],
    pub valid_until: u64,
    pub vault: [u8; 32],
}

impl MintAttestation {
    pub fn hash_struct(&self) -> [u8; 32] {
        keccak(&[
            &keccak(&[MINT_TYPE_STRING]),
            &word_address(&self.auditor),
            &self.profile_digest,
            &self.record_key,
            &self.metadata_digest,
            &word_u64(self.amount),
            &self.nonce,
            &word_u64(self.valid_until),
            &self.vault,
        ])
    }

    /// EIP-712-style digest that `secp256k1_recover` must recover `auditor` from.
    pub fn digest(&self, domain: &Domain) -> [u8; 32] {
        eip712_digest(&domain.separator(), &self.hash_struct())
    }
}

impl BurnAttestation {
    pub fn hash_struct(&self) -> [u8; 32] {
        keccak(&[
            &keccak(&[BURN_TYPE_STRING]),
            &word_address(&self.auditor),
            &self.profile_digest,
            &self.operation_id,
            &self.metadata_digest,
            &word_u64(self.amount),
            &self.nonce,
            &word_u64(self.valid_until),
            &self.vault,
        ])
    }

    pub fn digest(&self, domain: &Domain) -> [u8; 32] {
        eip712_digest(&domain.separator(), &self.hash_struct())
    }
}

/// `keccak256(0x19 ‖ 0x01 ‖ domainSeparator ‖ hashStruct)`.
pub fn eip712_digest(domain_separator: &[u8; 32], hash_struct: &[u8; 32]) -> [u8; 32] {
    keccak(&[&[0x19, 0x01], domain_separator, hash_struct])
}

/// Ethereum-style address of an uncompressed secp256k1 public key (the 64-byte
/// `(x‖y)` form returned by `secp256k1_recover`): `keccak256(pubkey)[12..32]`.
pub fn eth_address_from_pubkey(pubkey64: &[u8; 64]) -> [u8; 20] {
    let h = keccak(&[pubkey64]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&h[12..]);
    addr
}

#[cfg(test)]
mod tests {
    use super::*;

    // Anvil account 0 — the same auditor key used by shared/vectors/mint-eip712.json.
    const AUDITOR_ADDR: &str = "f39fd6e51aad88f6f4ce6ab8827279cfffb92266";
    // Its uncompressed secp256k1 public key (x ‖ y, no 0x04 prefix), the form
    // `secp256k1_recover` returns on-chain.
    const AUDITOR_PUB64: &str = "8318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed753547f11ca8696646f2f3acb08e31016afac23e630c5d11f59f61fef57b0d2aa5";

    fn auditor_addr_bytes() -> [u8; 20] {
        let mut a = [0u8; 20];
        hex::decode_to_slice(AUDITOR_ADDR, &mut a).unwrap();
        a
    }

    #[test]
    fn eth_address_derivation_matches_known_auditor() {
        // keccak256(pubkey)[12..] must equal the well-known anvil account-0 address.
        // This is the exact derivation the program applies to the recovered pubkey.
        let mut pubkey64 = [0u8; 64];
        hex::decode_to_slice(AUDITOR_PUB64, &mut pubkey64).unwrap();
        assert_eq!(
            hex::encode(eth_address_from_pubkey(&pubkey64)),
            AUDITOR_ADDR
        );
    }

    fn sample_domain() -> Domain {
        Domain {
            cluster: [0x11; 32],
            program: [0x22; 32],
            config: [0x33; 32],
        }
    }

    fn sample_mint(auditor: [u8; 20]) -> MintAttestation {
        MintAttestation {
            auditor,
            profile_digest: [0x44; 32],
            record_key: [0x55; 32],
            metadata_digest: [0x66; 32],
            amount: 1_000_000_000_000u64,
            nonce: {
                let mut n = [0u8; 32];
                n[31] = 42;
                n
            },
            valid_until: 1_800_000_000,
            vault: [0x77; 32],
        }
    }

    #[test]
    fn digest_is_deterministic_and_field_sensitive() {
        let d = sample_domain();
        let a = sample_mint([0xAB; 20]);
        let digest = a.digest(&d);
        assert_eq!(digest, a.digest(&d), "digest must be pure");

        // Flip one field -> different digest.
        let mut b = a.clone();
        b.amount += 1;
        assert_ne!(digest, b.digest(&d));

        // Different domain (e.g. wrong config PDA) -> different digest: a signature
        // for one deployment can't be replayed on another.
        let mut d2 = d;
        d2.config = [0x99; 32];
        assert_ne!(digest, a.digest(&d2));

        // The cluster genesis hash is part of the domain, so the SAME
        // attestation signed for cluster A produces a different digest — and thus
        // fails signature recovery — under cluster B. This is what stops a valid
        // signature being replayed on a second deployment that shares program ids
        // but sits on a different cluster.
        let mut d3 = d;
        d3.cluster = [0xEE; 32];
        assert_ne!(digest, a.digest(&d3));
        // And the program-id binding likewise.
        let mut d4 = d;
        d4.program = [0xDD; 32];
        assert_ne!(digest, a.digest(&d4));
    }

    #[test]
    fn frozen_golden_vector() {
        // Pins the values in solana/tests/vectors/mint-attestation.json. Any change
        // to the domain/type strings or word encoding breaks this — the
        // cross-language parity anchor. The committed golden's `signature` /
        // `recoveryId` are checked against this digest by the TS parity test
        // (ethers) and on-chain by `secp256k1_recover`.
        let mut att = sample_mint([0u8; 20]);
        att.auditor = auditor_addr_bytes();
        let domain = sample_domain();
        assert_eq!(
            hex::encode(domain.separator()),
            "d2ea3f95cff955b96bd1461fca655fdfff232e80eb349cfca6079b2e21df89db"
        );
        assert_eq!(
            hex::encode(att.hash_struct()),
            "85ebfb974ff2a032cd56064572d280ad8378cdf9186db5cc8a9ea3371bf53bad"
        );
        assert_eq!(
            hex::encode(att.digest(&domain)),
            "27e6aed00dd4a6599420b86eefa0fdb517886df306636544c0aa1640d39d7894"
        );
    }

    // ---- Frozen cross-language parity: shared/vectors/burn-attestation.json ----
    //
    // Unlike `frozen_golden_vector` above (which transcribes the mint constants),
    // this reads the shared vector file directly via `include_str!`, so the
    // anchor is the lead-owned file itself rather than a copy of its numbers —
    // any future edit to the burn vector is caught here with no matching edit
    // needed in this test. Without this assertion a change to
    // `BURN_TYPE_STRING` or the burn word encoding could pass
    // `make vectors-check` (which runs `cargo test -p attestation`) while
    // silently diverging from the Go signer and this vector.

    use serde::Deserialize;

    #[derive(Deserialize)]
    struct VectorDomain {
        cluster: String,
        program: String,
        config: String,
    }

    #[derive(Deserialize)]
    struct BurnMessage {
        auditor: String,
        #[serde(rename = "profileDigest")]
        profile_digest: String,
        #[serde(rename = "operationId")]
        operation_id: String,
        #[serde(rename = "metadataDigest")]
        metadata_digest: String,
        amount: String,
        nonce: String,
        #[serde(rename = "validUntil")]
        valid_until: u64,
        vault: String,
    }

    #[derive(Deserialize)]
    struct BurnVector {
        domain: VectorDomain,
        message: BurnMessage,
        #[serde(rename = "domainSeparator")]
        domain_separator: String,
        #[serde(rename = "hashStruct")]
        hash_struct: String,
        digest: String,
    }

    fn hex_bytes32(s: &str) -> [u8; 32] {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let mut out = [0u8; 32];
        hex::decode_to_slice(s, &mut out).expect("32-byte hex field");
        out
    }

    fn hex_bytes20(s: &str) -> [u8; 20] {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let mut out = [0u8; 20];
        hex::decode_to_slice(s, &mut out).expect("20-byte hex field");
        out
    }

    #[test]
    fn frozen_burn_golden_vector() {
        // Path is relative to this crate's manifest dir at test time.
        let raw = include_str!("../../../../shared/vectors/burn-attestation.json");
        let v: BurnVector = serde_json::from_str(raw).expect("parse burn-attestation.json");

        let domain = Domain {
            cluster: hex_bytes32(&v.domain.cluster),
            program: hex_bytes32(&v.domain.program),
            config: hex_bytes32(&v.domain.config),
        };
        let att = BurnAttestation {
            auditor: hex_bytes20(&v.message.auditor),
            profile_digest: hex_bytes32(&v.message.profile_digest),
            operation_id: hex_bytes32(&v.message.operation_id),
            metadata_digest: hex_bytes32(&v.message.metadata_digest),
            amount: v.message.amount.parse().expect("amount"),
            nonce: hex_bytes32(&v.message.nonce),
            valid_until: v.message.valid_until,
            vault: hex_bytes32(&v.message.vault),
        };

        assert_eq!(
            domain.separator(),
            hex_bytes32(&v.domain_separator),
            "domain separator mismatch against shared/vectors/burn-attestation.json"
        );
        assert_eq!(
            att.hash_struct(),
            hex_bytes32(&v.hash_struct),
            "hashStruct mismatch against shared/vectors/burn-attestation.json"
        );
        assert_eq!(
            att.digest(&domain),
            hex_bytes32(&v.digest),
            "digest mismatch against shared/vectors/burn-attestation.json"
        );
    }
}
