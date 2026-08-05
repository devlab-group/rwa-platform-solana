// Package attestation implements the auditor-attestation domain separator,
// type hashes, struct hashes, and digest construction for MintAttestation
// and BurnAttestation, plus the primitives shared by digest construction and
// signing.
//
// The digest construction follows the EIP-712 typed-data pattern
// (keccak256(0x1901 || domainSeparator || hashStruct)) even though this
// signer targets Solana: the rwa-supply-controller program verifies auditor
// signatures with secp256k1_recover over exactly that shape of digest, so
// the same construction and the same auditor key serve it.
//
// This file is a byte-exact Go reimplementation of solana/crates/attestation
// (the pre-image the on-chain program derives). The encoding is FROZEN: it is
// pinned from three sides -- Rust (the verifier), TypeScript (the parity test),
// and here -- against solana/tests/vectors/mint-attestation.json. Nothing in
// here may change without changing all three and the on-chain program.
//
// Two differences from a plain EIP-712/EVM encoding are easy to miss and
// both are load-bearing:
//
//   - amount and validUntil are uint64, not uint256. The token amount
//     genuinely cannot exceed 2^64-1, so Amount rejects anything larger
//     rather than silently truncating.
//   - nonce is bytes32 verbatim (it seeds a replay-marker PDA on-chain), not a
//     right-aligned integer word.
package attestation

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Canonical type strings. These must match
// solana/crates/attestation/src/lib.rs byte-for-byte.
const (
	DomainTypeString = "SolanaSupplyAttestation(string name,string version,bytes32 cluster,bytes32 program,bytes32 config)"
	MintTypeString   = "MintAttestation(bytes32 auditor,bytes32 profileDigest,bytes32 recordKey,bytes32 metadataDigest,uint64 amount,bytes32 nonce,uint64 validUntil,bytes32 vault)"
	BurnTypeString   = "BurnAttestation(bytes32 auditor,bytes32 profileDigest,bytes32 operationId,bytes32 metadataDigest,uint64 amount,bytes32 nonce,uint64 validUntil,bytes32 vault)"

	// DomainName deliberately does not reuse the plain EIP-712
	// "RWA-Supply-Attestation" domain name some other deployment might use,
	// so a typed-data digest computed for one can never collide with the other.
	DomainName    = "RWA-Supply-Attestation-Solana"
	DomainVersion = "1"
)

var (
	domainTypeHash = crypto.Keccak256Hash([]byte(DomainTypeString))
	mintTypeHash   = crypto.Keccak256Hash([]byte(MintTypeString))
	burnTypeHash   = crypto.Keccak256Hash([]byte(BurnTypeString))
	domainNameHash = crypto.Keccak256Hash([]byte(DomainName))
	domainVerHash  = crypto.Keccak256Hash([]byte(DomainVersion))
)

// DomainTypeHash, MintTypeHash, BurnTypeHash expose the type hashes for
// diagnostics and tests.
func DomainTypeHash() common.Hash { return domainTypeHash }
func MintTypeHash() common.Hash   { return mintTypeHash }
func BurnTypeHash() common.Hash   { return burnTypeHash }

// Digest computes the final digest: keccak256(0x1901 || domainSeparator ||
// hashStruct).
func Digest(domainSeparator, hashStruct common.Hash) common.Hash {
	buf := make([]byte, 0, 2+32+32)
	buf = append(buf, 0x19, 0x01)
	buf = append(buf, domainSeparator.Bytes()...)
	buf = append(buf, hashStruct.Bytes()...)
	return crypto.Keccak256Hash(buf)
}

// RecordKey computes keccak256(bytes(recordId)), the mint-side unique key
// derived from the metadata record's recordId.
func RecordKey(recordID string) [32]byte {
	return crypto.Keccak256Hash([]byte(recordID))
}

// Sign signs the raw 32-byte digest (no EIP-191 personal-message prefix)
// with key, returning the standard 65-byte [R || S || V] Ethereum signature
// with V in {27, 28}. SignCompact converts this into the compact [R || S] +
// recoveryId form the on-chain secp256k1_recover syscall consumes.
func Sign(digest common.Hash, key *ecdsa.PrivateKey) ([]byte, error) {
	if key == nil {
		return nil, errors.New("attestation: signing key is nil")
	}
	sig, err := crypto.Sign(digest.Bytes(), key)
	if err != nil {
		return nil, fmt.Errorf("attestation: sign: %w", err)
	}
	// go-ethereum's crypto.Sign returns V in {0,1}; the wire convention used
	// here uses V in {27,28}.
	sig[64] += 27
	return sig, nil
}

// Domain binds a signature to exactly one deployment.
type Domain struct {
	// Cluster is the cluster's genesis hash -- the Solana analogue of
	// chainId. It is what stops a signature valid on devnet being replayed
	// on mainnet-beta by a deployment that reuses the same program ids.
	Cluster [32]byte
	// Program is the rwa-supply-controller program id.
	Program [32]byte
	// Config is the SupplyController config PDA -- the analogue of
	// verifyingContract.
	Config [32]byte
}

// Separator computes the domain separator. Unlike a plain EIP-712
// Domain.Separator it cannot fail: every field is a fixed 32-byte value with
// no range to violate.
func (d Domain) Separator() common.Hash {
	buf := make([]byte, 0, 32*6)
	buf = append(buf, domainTypeHash.Bytes()...)
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
	Nonce          [32]byte
	ValidUntil     uint64
	// Vault is the Vault authority's Solana pubkey, used verbatim.
	Vault [32]byte
}

// BurnAttestation mirrors the Rust BurnAttestation struct. Field order
// matters and must not change.
//
// Note that this is word-for-word identical to MintAttestation apart
// from the type hash -- which is exactly why the review screen has to make the
// mint/burn distinction impossible to miss.
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

// wordU64 encodes a uint64 big-endian, right-aligned in a 32-byte word.
func wordU64(x uint64) []byte {
	w := make([]byte, 32)
	for i := 0; i < 8; i++ {
		w[31-i] = byte(x >> (8 * i))
	}
	return w
}

// Amount converts a decimal smallest-unit amount to the uint64 the encoding
// uses, rejecting anything that would not survive the conversion. An amount
// that overflows uint64 must be a hard failure: silently truncating it would
// produce a signature authorizing a different quantity than the one the
// auditor reviewed.
func Amount(v *big.Int, field string) (uint64, error) {
	if v == nil {
		return 0, fmt.Errorf("attestation: %s is nil", field)
	}
	if v.Sign() < 0 {
		return 0, fmt.Errorf("attestation: %s must not be negative", field)
	}
	if !v.IsUint64() {
		return 0, fmt.Errorf("attestation: %s %s exceeds uint64, which this encoding cannot represent", field, v.String())
	}
	return v.Uint64(), nil
}

// HashStruct computes keccak256(abi.encode(MINT_TYPEHASH, ...)) for the
// mint payload.
func (m MintAttestation) HashStruct() common.Hash {
	buf := make([]byte, 0, 32*9)
	buf = append(buf, mintTypeHash.Bytes()...)
	buf = append(buf, common.LeftPadBytes(m.Auditor.Bytes(), 32)...)
	buf = append(buf, m.ProfileDigest[:]...)
	buf = append(buf, m.RecordKey[:]...)
	buf = append(buf, m.MetadataDigest[:]...)
	buf = append(buf, wordU64(m.Amount)...)
	buf = append(buf, m.Nonce[:]...)
	buf = append(buf, wordU64(m.ValidUntil)...)
	buf = append(buf, m.Vault[:]...)
	return crypto.Keccak256Hash(buf)
}

// HashStruct computes keccak256(abi.encode(BURN_TYPEHASH, ...)) for the
// burn payload.
func (b BurnAttestation) HashStruct() common.Hash {
	buf := make([]byte, 0, 32*9)
	buf = append(buf, burnTypeHash.Bytes()...)
	buf = append(buf, common.LeftPadBytes(b.Auditor.Bytes(), 32)...)
	buf = append(buf, b.ProfileDigest[:]...)
	buf = append(buf, b.OperationID[:]...)
	buf = append(buf, b.MetadataDigest[:]...)
	buf = append(buf, wordU64(b.Amount)...)
	buf = append(buf, b.Nonce[:]...)
	buf = append(buf, wordU64(b.ValidUntil)...)
	buf = append(buf, b.Vault[:]...)
	return crypto.Keccak256Hash(buf)
}

// Digest computes the final digest the on-chain secp256k1_recover must
// recover the auditor from: keccak256(0x1901 || domainSeparator ||
// hashStruct).
func (m MintAttestation) Digest(d Domain) common.Hash {
	return Digest(d.Separator(), m.HashStruct())
}

// Digest computes the final digest for a burn payload.
func (b BurnAttestation) Digest(d Domain) common.Hash {
	return Digest(d.Separator(), b.HashStruct())
}

// CompactSignature is the form the on-chain sol_secp256k1_recover syscall
// consumes: a 64-byte compact [R || S] signature plus a separate recovery id
// in {0, 1}. There is no 65th V byte and no 27 offset -- passing the EVM
// wire form here would make the program recover a different key.
type CompactSignature struct {
	// Compact is R || S, 32 bytes each. S is always in the lower half of
	// the curve order (see CompactSignatureFromEth).
	Compact [64]byte
	// RecoveryID is 0 or 1.
	RecoveryID byte
}

// Hex renders the 64-byte compact signature as 0x-prefixed hex.
func (s CompactSignature) Hex() string { return "0x" + common.Bytes2Hex(s.Compact[:]) }

// secp256k1HalfN is n/2 for the secp256k1 group order; an S above it is the
// malleable "high-S" form.
var (
	secp256k1N     = crypto.S256().Params().N
	secp256k1HalfN = new(big.Int).Rsh(secp256k1N, 1)
)

// CompactSignatureFromEth converts a standard 65-byte [R || S || V] Ethereum
// signature (V in {0,1} or {27,28}) to the compact form the on-chain program
// consumes, normalizing S into the lower half of the curve order.
//
// The low-S normalization is not cosmetic. The on-chain verifier rejects
// high-S signatures, so an un-normalized signature would simply fail to
// verify. Negating S and flipping the recovery id yields the other valid
// encoding of the same signature over the same digest, recovering the same
// key -- it authorizes nothing new. go-ethereum's own signer already produces
// low-S, but a hardware adapter is free not to, so every signature
// is normalized here rather than assumed canonical.
func CompactSignatureFromEth(sig []byte) (CompactSignature, error) {
	var out CompactSignature
	if len(sig) != 65 {
		return out, fmt.Errorf("attestation: signature must be 65 bytes, got %d", len(sig))
	}
	v := sig[64]
	if v >= 27 {
		v -= 27
	}
	if v > 1 {
		return out, fmt.Errorf("attestation: signature recovery byte must be 0, 1, 27 or 28, got %d", sig[64])
	}

	r := new(big.Int).SetBytes(sig[0:32])
	s := new(big.Int).SetBytes(sig[32:64])
	if r.Sign() == 0 || r.Cmp(secp256k1N) >= 0 {
		return out, errors.New("attestation: signature r is out of range")
	}
	if s.Sign() == 0 || s.Cmp(secp256k1N) >= 0 {
		return out, errors.New("attestation: signature s is out of range")
	}
	if s.Cmp(secp256k1HalfN) > 0 {
		s = new(big.Int).Sub(secp256k1N, s)
		v ^= 1
	}

	copy(out.Compact[0:32], common.LeftPadBytes(r.Bytes(), 32))
	copy(out.Compact[32:64], common.LeftPadBytes(s.Bytes(), 32))
	out.RecoveryID = v
	return out, nil
}

// EthSignature is the inverse of CompactSignatureFromEth: the 65-byte
// [R || S || V] form (V in {0,1}) go-ethereum's recovery accepts.
func (s CompactSignature) EthSignature() []byte {
	sig := make([]byte, 65)
	copy(sig, s.Compact[:])
	sig[64] = s.RecoveryID
	return sig
}

// IsLowS reports whether S sits in the lower half of the curve order, i.e.
// whether the on-chain malleability check will accept this signature.
func (s CompactSignature) IsLowS() bool {
	v := new(big.Int).SetBytes(s.Compact[32:64])
	return v.Sign() != 0 && v.Cmp(secp256k1HalfN) <= 0
}

// SignCompact signs a raw 32-byte attestation digest with key and returns
// the canonical low-S compact signature plus its recovery id.
func SignCompact(digest common.Hash, key *ecdsa.PrivateKey) (CompactSignature, error) {
	if key == nil {
		return CompactSignature{}, errors.New("attestation: signing key is nil")
	}
	sig, err := crypto.Sign(digest.Bytes(), key)
	if err != nil {
		return CompactSignature{}, fmt.Errorf("attestation: sign: %w", err)
	}
	return CompactSignatureFromEth(sig)
}

// RecoverCompact recovers the auditor's 20-byte eth address from a compact
// signature over digest, exactly as the on-chain program does: recover the
// uncompressed public key, then take keccak256(pubkey)[12:].
func RecoverCompact(digest common.Hash, sig CompactSignature) (common.Address, error) {
	if sig.RecoveryID > 1 {
		return common.Address{}, fmt.Errorf("attestation: recovery id must be 0 or 1, got %d", sig.RecoveryID)
	}
	pub, err := crypto.SigToPub(digest.Bytes(), sig.EthSignature())
	if err != nil {
		return common.Address{}, fmt.Errorf("attestation: recover: %w", err)
	}
	return crypto.PubkeyToAddress(*pub), nil
}
