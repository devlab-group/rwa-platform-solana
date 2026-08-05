//! Recomputes the *deterministic* fields of the golden Solana mint-attestation
//! vector (domain separator, hashStruct, digest) for
//! `solana/tests/vectors/mint-attestation.json`. Run:
//! `cargo run -p attestation --example golden`.
//!
//! The vector's `signature` / `recoveryId` are frozen in the committed JSON
//! (produced once with the anvil auditor key); they are verified against this
//! digest by the TS parity test (ethers) and on-chain by `secp256k1_recover`.
//! This example deliberately pulls in no secp256k1 signing crate (see the note in
//! Cargo.toml about the zeroize/curve25519-dalek workspace conflict).

use attestation::{Domain, MintAttestation};

fn hexb(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

fn main() {
    // Anvil account 0 address (recovered auditor).
    let mut auditor = [0u8; 20];
    hex::decode_to_slice("f39fd6e51aad88f6f4ce6ab8827279cfffb92266", &mut auditor).unwrap();

    let domain = Domain {
        cluster: [0x11; 32],
        program: [0x22; 32],
        config: [0x33; 32],
    };
    let mut nonce = [0u8; 32];
    nonce[31] = 42;
    let att = MintAttestation {
        auditor,
        profile_digest: [0x44; 32],
        record_key: [0x55; 32],
        metadata_digest: [0x66; 32],
        amount: 1_000_000_000_000u64,
        nonce,
        valid_until: 1_800_000_000,
        vault: [0x77; 32],
    };

    println!("domainSeparator = {}", hexb(&domain.separator()));
    println!("hashStruct      = {}", hexb(&att.hash_struct()));
    println!("digest          = {}", hexb(&att.digest(&domain)));
}
