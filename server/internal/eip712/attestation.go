// Package eip712 computes the RWA-Supply-Attestation domain separator,
// struct hashes, and digest for the Solana auditor attestation. Type
// strings and field order are FROZEN by shared/eip712/types.md and MUST
// match byte-for-byte across Rust, the Go signer, and this package. See
// shared/vectors/mint-attestation.json.
//
// This file is a byte-exact port of signer/internal/attestation/attestation.go's
// digest construction (domain separator + hashStruct + final digest) into
// the server, so the .rwa package builder (internal/auditpkg) can compute the
// SAME digest the offline signer will sign and the on-chain rwa-supply-
// controller program will verify. It intentionally omits everything
// signing/recovery-related (Sign, Recover, the compact-signature
// conversion) — the server never holds the auditor key and never verifies a
// signature itself; it only needs to reproduce the pre-image.
//
// The Solana deployment verifies auditor signatures with the same primitive
// as the EVM one — secp256k1 ECDSA over a keccak256 digest — so the same
// auditor key and the same offline signer cover both chains.
// What changes is the domain: instead of (chainId, verifyingContract) it
// binds (cluster genesis hash, supply-controller program id, supply-config
// PDA), and amount/validUntil are uint64 (not uint256) while nonce is a raw
// bytes32 (not a right-aligned integer word — it seeds a replay-marker PDA
// on-chain).
//
// FROZEN: pinned from four sides — Rust (solana/crates/attestation, the
// verifier), the Go signer, a TypeScript parity test, and this file — against
// the golden vector shared/vectors/mint-attestation.json (see
// TestDigestMatchesGoldenVector). Nothing here may change without
// changing all four and the on-chain program.
package eip712

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Canonical Solana type strings — must match
// solana/crates/attestation/src/lib.rs and signer/internal/attestation/
// solana.go byte-for-byte.
const (
	domainTypeString = "SolanaSupplyAttestation(string name,string version,bytes32 cluster,bytes32 program,bytes32 config)"
	mintTypeString   = "MintAttestation(bytes32 auditor,bytes32 profileDigest,bytes32 recordKey,bytes32 metadataDigest,uint64 amount,bytes32 nonce,uint64 validUntil,bytes32 vault)"
	burnTypeString   = "BurnAttestation(bytes32 auditor,bytes32 profileDigest,bytes32 operationId,bytes32 metadataDigest,uint64 amount,bytes32 nonce,uint64 validUntil,bytes32 vault)"

	// DomainName is deliberately distinct from the EVM attestation's domain
	// name, so an EVM attestation can never hash to a valid Solana one or
	// vice versa.
	DomainName    = "RWA-Supply-Attestation-Solana"
	DomainVersion = "1"
)

// DomainTypehash, MintTypehash, BurnTypehash are exported
// so callers (and tests) can compare directly against
// shared/vectors/mint-attestation.json / typehashes, mirroring
// DomainTypehash/MintTypehash/BurnTypehash above.
var (
	DomainTypehash = crypto.Keccak256Hash([]byte(domainTypeString))
	MintTypehash   = crypto.Keccak256Hash([]byte(mintTypeString))
	BurnTypehash   = crypto.Keccak256Hash([]byte(burnTypeString))
	domainNameHash = crypto.Keccak256Hash([]byte(DomainName))
	domainVerHash  = crypto.Keccak256Hash([]byte(DomainVersion))
)

// Domain binds a signature to exactly one Solana deployment — the
// Solana analogue of an EVM EIP-712 domain (ChainID, VerifyingContract).
// Every field is a raw 32-byte value (a base58 pubkey/hash decoded to
// bytes); this package does no base58 decoding itself, matching how an
// EVM domain takes an already-typed common.Address rather than parsing
// hex.
type Domain struct {
	// Cluster is the cluster's genesis hash — the Solana analogue of
	// chainId. It stops a signature valid on devnet being replayed on
	// mainnet-beta by a deployment that reuses the same program ids.
	Cluster [32]byte
	// Program is the rwa-supply-controller program id.
	Program [32]byte
	// Config is the SupplyController config PDA — the analogue of
	// verifyingContract.
	Config [32]byte
}

// DomainSeparator computes the Solana domain separator. Unlike an EVM
// domain separator, it cannot fail: every field is a fixed 32-byte value
// with no range to violate.
func DomainSeparator(d Domain) [32]byte {
	buf := make([]byte, 0, 32*6)
	buf = append(buf, DomainTypehash.Bytes()...)
	buf = append(buf, domainNameHash.Bytes()...)
	buf = append(buf, domainVerHash.Bytes()...)
	buf = append(buf, d.Cluster[:]...)
	buf = append(buf, d.Program[:]...)
	buf = append(buf, d.Config[:]...)
	return crypto.Keccak256Hash(buf)
}

// MintAttestation mirrors the Rust MintAttestation struct. Field order
// matters and must not change.
type MintAttestation struct {
	// Auditor is the 20-byte eth address the signature must recover to. It
	// is encoded as a right-aligned 32-byte word, exactly as an EVM address
	// would be, even though the type string calls it bytes32.
	Auditor        common.Address
	ProfileDigest  [32]byte
	RecordKey      [32]byte
	MetadataDigest [32]byte
	Amount         uint64
	// Nonce is bytes32 verbatim (it seeds a replay-marker PDA on-chain), NOT
	// a right-aligned integer word like the EVM MintAttestation.Nonce.
	Nonce      [32]byte
	ValidUntil uint64
	// Vault is the Vault authority's Solana pubkey, used verbatim.
	Vault [32]byte
}

// BurnAttestation mirrors the Rust BurnAttestation struct. Field order
// matters and must not change. Word-for-word identical to
// MintAttestation apart from the type hash and OperationID replacing
// RecordKey.
type BurnAttestation struct {
	Auditor        common.Address
	ProfileDigest  [32]byte
	OperationID    [32]byte
	MetadataDigest [32]byte
	Amount         uint64
	Nonce          [32]byte
	ValidUntil     uint64
	Vault          [32]byte
}

// wordU64 encodes a uint64 big-endian, right-aligned in a 32-byte word
// — abi.encode's representation of a uint64 static argument.
func wordU64(x uint64) [32]byte {
	var w [32]byte
	for i := 0; i < 8; i++ {
		w[31-i] = byte(x >> (8 * i))
	}
	return w
}

// Amount converts a decimal smallest-unit amount (as stored on
// models.AssetRecord, chain-agnostic) to the uint64 the Solana encoding
// uses, rejecting anything that would not survive the conversion. An amount
// that overflows uint64 must be a hard failure: silently truncating it would
// produce a digest — and therefore a signature — authorizing a different
// quantity than the one the auditor reviewed.
func Amount(v *big.Int) (uint64, error) {
	if v == nil {
		return 0, errors.New("eip712: solana amount is nil")
	}
	if v.Sign() < 0 {
		return 0, errors.New("eip712: solana amount must not be negative")
	}
	if !v.IsUint64() {
		return 0, fmt.Errorf("eip712: solana amount %s exceeds uint64, which the Solana encoding cannot represent", v.String())
	}
	return v.Uint64(), nil
}

// HashMintAttestation computes keccak256(abi.encode(MINT_TYPEHASH, ...))
// for the Solana mint payload.
func HashMintAttestation(m MintAttestation) [32]byte {
	buf := make([]byte, 0, 32*9)
	buf = append(buf, MintTypehash.Bytes()...)
	buf = append(buf, common.LeftPadBytes(m.Auditor.Bytes(), 32)...)
	buf = append(buf, m.ProfileDigest[:]...)
	buf = append(buf, m.RecordKey[:]...)
	buf = append(buf, m.MetadataDigest[:]...)
	amountWord := wordU64(m.Amount)
	buf = append(buf, amountWord[:]...)
	buf = append(buf, m.Nonce[:]...)
	validUntilWord := wordU64(m.ValidUntil)
	buf = append(buf, validUntilWord[:]...)
	buf = append(buf, m.Vault[:]...)
	return crypto.Keccak256Hash(buf)
}

// HashBurnAttestation computes keccak256(abi.encode(BURN_TYPEHASH, ...))
// for the Solana burn payload.
func HashBurnAttestation(b BurnAttestation) [32]byte {
	buf := make([]byte, 0, 32*9)
	buf = append(buf, BurnTypehash.Bytes()...)
	buf = append(buf, common.LeftPadBytes(b.Auditor.Bytes(), 32)...)
	buf = append(buf, b.ProfileDigest[:]...)
	buf = append(buf, b.OperationID[:]...)
	buf = append(buf, b.MetadataDigest[:]...)
	amountWord := wordU64(b.Amount)
	buf = append(buf, amountWord[:]...)
	buf = append(buf, b.Nonce[:]...)
	validUntilWord := wordU64(b.ValidUntil)
	buf = append(buf, validUntilWord[:]...)
	buf = append(buf, b.Vault[:]...)
	return crypto.Keccak256Hash(buf)
}

// Digest computes keccak256(0x1901 || domainSeparator || hashStruct) — the
// standard EIP-712-style final digest framing, reused verbatim for the
// Solana attestation (see this file's header comment).
func Digest(domainSeparator, hashStruct [32]byte) [32]byte {
	buf := make([]byte, 0, 2+32+32)
	buf = append(buf, 0x19, 0x01)
	buf = append(buf, domainSeparator[:]...)
	buf = append(buf, hashStruct[:]...)
	return crypto.Keccak256Hash(buf)
}

// MintDigest is a convenience wrapper computing the full digest
// keccak256(0x1901 || domainSeparator || hashStruct) for a mint attestation
// under domain d.
func MintDigest(d Domain, m MintAttestation) [32]byte {
	return Digest(DomainSeparator(d), HashMintAttestation(m))
}

// BurnDigest is the burn counterpart of MintDigest.
func BurnDigest(d Domain, b BurnAttestation) [32]byte {
	return Digest(DomainSeparator(d), HashBurnAttestation(b))
}
