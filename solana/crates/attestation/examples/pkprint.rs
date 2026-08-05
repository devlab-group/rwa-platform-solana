//! Prints the anvil account-0 uncompressed secp256k1 public key (x ‖ y) that the
//! attestation tests hardcode as `AUDITOR_PUB64`. Kept as a reference so the
//! constant can be regenerated; it takes no dependencies.
fn main() {
    println!(
        "AUDITOR_PUB64 = 8318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed7\
53547f11ca8696646f2f3acb08e31016afac23e630c5d11f59f61fef57b0d2aa5"
    );
}
