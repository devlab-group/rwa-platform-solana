package attestation

import (
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// mintVector is the shape of solana/tests/vectors/mint-attestation.json
// and shared/vectors/mint-attestation.json. Both files carry the same
// frozen values; the first is the vector the Rust crate and the TypeScript
// parity test pin themselves against, the second is the cross-language parity
// copy under shared/vectors.
type mintVector struct {
	Domain struct {
		Cluster string `json:"cluster"`
		Program string `json:"program"`
		Config  string `json:"config"`
	} `json:"domain"`
	DomainSeparator string `json:"domainSeparator"`
	Message         struct {
		Auditor        string `json:"auditor"`
		ProfileDigest  string `json:"profileDigest"`
		RecordKey      string `json:"recordKey"`
		MetadataDigest string `json:"metadataDigest"`
		Amount         string `json:"amount"`
		Nonce          string `json:"nonce"`
		ValidUntil     uint64 `json:"validUntil"`
		Vault          string `json:"vault"`
	} `json:"message"`
	HashStruct       string `json:"hashStruct"`
	Digest           string `json:"digest"`
	SignerPrivateKey string `json:"signerPrivateKey"`
	Signature        string `json:"signature"`
	RecoveryID       byte   `json:"recoveryId"`
}

// vectorPaths returns every committed copy of the golden vector. Both are
// checked, so the shared/vectors parity copy can never silently drift from
// the one the Rust and TypeScript sides are pinned against.
func vectorPaths(t *testing.T) map[string]string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("resolving repo root: %v", err)
	}
	paths := map[string]string{
		"solana/tests/vectors/mint-attestation.json": filepath.Join(root, "solana", "tests", "vectors", "mint-attestation.json"),
		"shared/vectors/mint-attestation.json":       filepath.Join(root, "shared", "vectors", "mint-attestation.json"),
	}
	for name, p := range paths {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s not found at %s: %v", name, p, err)
		}
	}
	return paths
}

// burnVector is the shape of shared/vectors/burn-attestation.json.
// Unlike the mint vector, this one has no solana/tests/vectors copy today: the
// Rust crate and the TypeScript parity test are pinned only against the mint
// vector (see burnVectorPath's comment). This Go signer test is
// currently the only place any language exercises the burn vector's
// signature/recoveryId end to end.
type burnVector struct {
	Domain struct {
		Cluster string `json:"cluster"`
		Program string `json:"program"`
		Config  string `json:"config"`
	} `json:"domain"`
	DomainSeparator string `json:"domainSeparator"`
	Message         struct {
		Auditor        string `json:"auditor"`
		ProfileDigest  string `json:"profileDigest"`
		OperationID    string `json:"operationId"`
		MetadataDigest string `json:"metadataDigest"`
		Amount         string `json:"amount"`
		Nonce          string `json:"nonce"`
		ValidUntil     uint64 `json:"validUntil"`
		Vault          string `json:"vault"`
	} `json:"message"`
	HashStruct       string `json:"hashStruct"`
	Digest           string `json:"digest"`
	SignerPrivateKey string `json:"signerPrivateKey"`
	Signature        string `json:"signature"`
	RecoveryID       byte   `json:"recoveryId"`
}

// burnVectorPath returns the single committed copy of the burn golden
// vector. As of this writing solana/tests/vectors has no burn-attestation.json
// counterpart, and the Rust/TS parity tests pin only the mint vector, so this
// file's comment is corrected below (in the vector file itself) to not
// overclaim parity coverage it doesn't have.
func burnVectorPath(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("resolving repo root: %v", err)
	}
	p := filepath.Join(root, "shared", "vectors", "burn-attestation.json")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("shared/vectors/burn-attestation.json not found at %s: %v", p, err)
	}
	return p
}

func mustAmountU64(t *testing.T, s string) uint64 {
	t.Helper()
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		t.Fatalf("parsing decimal amount %q", s)
	}
	amount, err := Amount(v, "amount")
	if err != nil {
		t.Fatalf("Amount(%q): %v", s, err)
	}
	return amount
}

// TestVectors reproduces the frozen golden vector exactly:
// domain separator, hashStruct, digest, and a canonical low-S signature that
// recovers to the auditor. Any drift from solana/crates/attestation's encoding
// -- a reordered field, a changed type string, a wrong word encoding -- fails
// here, which is the whole point of gating the Go signer against the same
// vector the Rust verifier and the TypeScript parity test use.
func TestVectors(t *testing.T) {
	for name, path := range vectorPaths(t) {
		t.Run(name, func(t *testing.T) {
			v := loadJSON[mintVector](t, path)

			domain := Domain{
				Cluster: mustHash32(t, v.Domain.Cluster),
				Program: mustHash32(t, v.Domain.Program),
				Config:  mustHash32(t, v.Domain.Config),
			}
			sep := domain.Separator()
			if got, want := sep.Hex(), v.DomainSeparator; !strings.EqualFold(got, want) {
				t.Errorf("domainSeparator = %s, want %s", got, want)
			}

			msg := MintAttestation{
				Auditor:        common.HexToAddress(v.Message.Auditor),
				ProfileDigest:  mustHash32(t, v.Message.ProfileDigest),
				RecordKey:      mustHash32(t, v.Message.RecordKey),
				MetadataDigest: mustHash32(t, v.Message.MetadataDigest),
				Amount:         mustAmountU64(t, v.Message.Amount),
				Nonce:          mustHash32(t, v.Message.Nonce),
				ValidUntil:     v.Message.ValidUntil,
				Vault:          mustHash32(t, v.Message.Vault),
			}

			hs := msg.HashStruct()
			if got, want := hs.Hex(), v.HashStruct; !strings.EqualFold(got, want) {
				t.Errorf("hashStruct = %s, want %s", got, want)
			}

			digest := msg.Digest(domain)
			if got, want := digest.Hex(), v.Digest; !strings.EqualFold(got, want) {
				t.Errorf("digest = %s, want %s", got, want)
			}

			keyBytes, err := hex.DecodeString(strings.TrimPrefix(v.SignerPrivateKey, "0x"))
			if err != nil {
				t.Fatalf("decoding signerPrivateKey: %v", err)
			}
			key, err := crypto.ToECDSA(keyBytes)
			if err != nil {
				t.Fatalf("ToECDSA: %v", err)
			}

			sig, err := SignCompact(digest, key)
			if err != nil {
				t.Fatalf("SignCompact: %v", err)
			}
			if got, want := sig.Hex(), v.Signature; !strings.EqualFold(got, want) {
				t.Errorf("signature = %s, want %s (RFC 6979 deterministic ECDSA must reproduce the golden signature exactly)", got, want)
			}
			if sig.RecoveryID != v.RecoveryID {
				t.Errorf("recoveryId = %d, want %d", sig.RecoveryID, v.RecoveryID)
			}
			if !sig.IsLowS() {
				t.Error("signature is high-S; the on-chain verifier rejects malleable signatures")
			}

			recovered, err := RecoverCompact(digest, sig)
			if err != nil {
				t.Fatalf("RecoverCompact: %v", err)
			}
			if want := common.HexToAddress(v.Message.Auditor); recovered != want {
				t.Errorf("recovered signer = %s, want auditor %s", recovered.Hex(), want.Hex())
			}
		})
	}
}

// TestBurnVector is the burn counterpart of TestVectors: the mint
// vector's signature/recoveryId were already recovered and low-S-checked
// here, but the burn vector's were not, despite
// shared/vectors/burn-attestation.json claiming to be a cross-language
// parity anchor. This closes that gap for the Go signer: it recomputes
// domainSeparator/hashStruct/digest, reproduces the frozen signature via RFC
// 6979 deterministic ECDSA, checks low-S, and recovers the auditor address.
func TestBurnVector(t *testing.T) {
	v := loadJSON[burnVector](t, burnVectorPath(t))

	domain := Domain{
		Cluster: mustHash32(t, v.Domain.Cluster),
		Program: mustHash32(t, v.Domain.Program),
		Config:  mustHash32(t, v.Domain.Config),
	}
	sep := domain.Separator()
	if got, want := sep.Hex(), v.DomainSeparator; !strings.EqualFold(got, want) {
		t.Errorf("domainSeparator = %s, want %s", got, want)
	}

	msg := BurnAttestation{
		Auditor:        common.HexToAddress(v.Message.Auditor),
		ProfileDigest:  mustHash32(t, v.Message.ProfileDigest),
		OperationID:    mustHash32(t, v.Message.OperationID),
		MetadataDigest: mustHash32(t, v.Message.MetadataDigest),
		Amount:         mustAmountU64(t, v.Message.Amount),
		Nonce:          mustHash32(t, v.Message.Nonce),
		ValidUntil:     v.Message.ValidUntil,
		Vault:          mustHash32(t, v.Message.Vault),
	}

	hs := msg.HashStruct()
	if got, want := hs.Hex(), v.HashStruct; !strings.EqualFold(got, want) {
		t.Errorf("hashStruct = %s, want %s", got, want)
	}

	digest := msg.Digest(domain)
	if got, want := digest.Hex(), v.Digest; !strings.EqualFold(got, want) {
		t.Errorf("digest = %s, want %s", got, want)
	}

	keyBytes, err := hex.DecodeString(strings.TrimPrefix(v.SignerPrivateKey, "0x"))
	if err != nil {
		t.Fatalf("decoding signerPrivateKey: %v", err)
	}
	key, err := crypto.ToECDSA(keyBytes)
	if err != nil {
		t.Fatalf("ToECDSA: %v", err)
	}

	sig, err := SignCompact(digest, key)
	if err != nil {
		t.Fatalf("SignCompact: %v", err)
	}
	if got, want := sig.Hex(), v.Signature; !strings.EqualFold(got, want) {
		t.Errorf("signature = %s, want %s (RFC 6979 deterministic ECDSA must reproduce the golden signature exactly)", got, want)
	}
	if sig.RecoveryID != v.RecoveryID {
		t.Errorf("recoveryId = %d, want %d", sig.RecoveryID, v.RecoveryID)
	}
	if !sig.IsLowS() {
		t.Error("signature is high-S; the on-chain verifier rejects malleable signatures")
	}

	recovered, err := RecoverCompact(digest, sig)
	if err != nil {
		t.Fatalf("RecoverCompact: %v", err)
	}
	if want := common.HexToAddress(v.Message.Auditor); recovered != want {
		t.Errorf("recovered signer = %s, want auditor %s", recovered.Hex(), want.Hex())
	}
}

// TestVectors_FrozenHexesAreHardcoded pins the three digest values
// literally, independent of any committed JSON file. If someone edits the
// vector files and the encoding together, the test above still passes; this
// one does not.
func TestVectors_FrozenHexesAreHardcoded(t *testing.T) {
	domain := Domain{
		Cluster: bytes32Repeated(0x11),
		Program: bytes32Repeated(0x22),
		Config:  bytes32Repeated(0x33),
	}
	var nonce [32]byte
	nonce[31] = 42
	msg := MintAttestation{
		Auditor:        common.HexToAddress("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"),
		ProfileDigest:  bytes32Repeated(0x44),
		RecordKey:      bytes32Repeated(0x55),
		MetadataDigest: bytes32Repeated(0x66),
		Amount:         1_000_000_000_000,
		Nonce:          nonce,
		ValidUntil:     1_800_000_000,
		Vault:          bytes32Repeated(0x77),
	}

	for _, c := range []struct{ name, got, want string }{
		{"domainSeparator", domain.Separator().Hex(), "0xd2ea3f95cff955b96bd1461fca655fdfff232e80eb349cfca6079b2e21df89db"},
		{"hashStruct", msg.HashStruct().Hex(), "0x85ebfb974ff2a032cd56064572d280ad8378cdf9186db5cc8a9ea3371bf53bad"},
		{"digest", msg.Digest(domain).Hex(), "0x27e6aed00dd4a6599420b86eefa0fdb517886df306636544c0aa1640d39d7894"},
	} {
		if !strings.EqualFold(c.got, c.want) {
			t.Errorf("%s = %s, want %s", c.name, c.got, c.want)
		}
	}
}

func bytes32Repeated(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}

// TestTypeHashes_IndependentlyDerivable guards against a type string
// being edited without noticing: each hash must come from the exact canonical
// string in solana/crates/attestation/src/lib.rs.
func TestTypeHashes_IndependentlyDerivable(t *testing.T) {
	for _, c := range []struct {
		name string
		got  common.Hash
		want common.Hash
	}{
		{"domain", DomainTypeHash(), crypto.Keccak256Hash([]byte(DomainTypeString))},
		{"mint", MintTypeHash(), crypto.Keccak256Hash([]byte(MintTypeString))},
		{"burn", BurnTypeHash(), crypto.Keccak256Hash([]byte(BurnTypeString))},
	} {
		if c.got != c.want {
			t.Errorf("%s type hash = %s, want %s", c.name, c.got.Hex(), c.want.Hex())
		}
	}
}

// TestMintAndBurnDigestsDiffer pins the invariant that the mint and
// burn payloads are word-for-word identical apart from the type hash, so the
// only thing separating an authorization to create supply from one to destroy
// it is that hash. If it ever stopped mattering, a template error in tooling
// would silently turn one into the other.
func TestMintAndBurnDigestsDiffer(t *testing.T) {
	d := Domain{Cluster: bytes32Repeated(0x11), Program: bytes32Repeated(0x22), Config: bytes32Repeated(0x33)}
	auditor := common.HexToAddress("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266")
	var nonce [32]byte
	nonce[31] = 7

	mint := MintAttestation{
		Auditor: auditor, ProfileDigest: bytes32Repeated(0x44), RecordKey: bytes32Repeated(0x55),
		MetadataDigest: bytes32Repeated(0x66), Amount: 1000, Nonce: nonce, ValidUntil: 1_800_000_000,
		Vault: bytes32Repeated(0x77),
	}
	burn := BurnAttestation{
		Auditor: auditor, ProfileDigest: bytes32Repeated(0x44), OperationID: bytes32Repeated(0x55),
		MetadataDigest: bytes32Repeated(0x66), Amount: 1000, Nonce: nonce, ValidUntil: 1_800_000_000,
		Vault: bytes32Repeated(0x77),
	}
	if mint.Digest(d) == burn.Digest(d) {
		t.Fatal("mint and burn digests are equal for identical field values")
	}
}

// TestDomain_BindsClusterProgramAndConfig checks that each domain
// component actually enters the separator: a signature must not be replayable
// on another cluster, another program id, or another config PDA.
func TestDomain_BindsClusterProgramAndConfig(t *testing.T) {
	base := Domain{Cluster: bytes32Repeated(0x11), Program: bytes32Repeated(0x22), Config: bytes32Repeated(0x33)}
	sep := base.Separator()

	for _, c := range []struct {
		name string
		d    Domain
	}{
		{"cluster", Domain{Cluster: bytes32Repeated(0xEE), Program: base.Program, Config: base.Config}},
		{"program", Domain{Cluster: base.Cluster, Program: bytes32Repeated(0xDD), Config: base.Config}},
		{"config", Domain{Cluster: base.Cluster, Program: base.Program, Config: bytes32Repeated(0x99)}},
	} {
		if c.d.Separator() == sep {
			t.Errorf("changing %s did not change the domain separator", c.name)
		}
	}
}

// TestCompactSignatureFromEth_NormalizesHighS pins the invariant that the
// on-chain verifier rejects high-S signatures, so the signer must never emit
// one. Flipping S to n-S (and the recovery id with it) must still recover the
// same signer.
func TestCompactSignatureFromEth_NormalizesHighS(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	addr := crypto.PubkeyToAddress(key.PublicKey)
	digest := crypto.Keccak256Hash([]byte("solana-high-s-normalization"))

	canonical, err := SignCompact(digest, key)
	if err != nil {
		t.Fatalf("SignCompact: %v", err)
	}
	if !canonical.IsLowS() {
		t.Fatal("SignCompact produced a high-S signature")
	}

	// Build the malleated twin by hand: same R, S' = n - S, recovery id
	// flipped. Feeding it back through the converter must return the
	// canonical form.
	malleated := make([]byte, 65)
	copy(malleated, canonical.Compact[:32])
	s := new(big.Int).SetBytes(canonical.Compact[32:])
	high := new(big.Int).Sub(secp256k1N, s)
	copy(malleated[32:64], common.LeftPadBytes(high.Bytes(), 32))
	malleated[64] = canonical.RecoveryID ^ 1

	normalized, err := CompactSignatureFromEth(malleated)
	if err != nil {
		t.Fatalf("CompactSignatureFromEth: %v", err)
	}
	if !normalized.IsLowS() {
		t.Fatal("normalization left a high-S signature")
	}
	if normalized != canonical {
		t.Fatalf("normalized signature %s/%d != canonical %s/%d", normalized.Hex(), normalized.RecoveryID, canonical.Hex(), canonical.RecoveryID)
	}
	recovered, err := RecoverCompact(digest, normalized)
	if err != nil {
		t.Fatalf("RecoverCompact: %v", err)
	}
	if recovered != addr {
		t.Fatalf("recovered %s, want %s", recovered.Hex(), addr.Hex())
	}
}

func TestCompactSignatureFromEth_RejectsMalformed(t *testing.T) {
	cases := map[string][]byte{
		"too short":         make([]byte, 64),
		"bad recovery byte": append(append(make([]byte, 32, 65), make([]byte, 32)...), 5),
		"zero r and s":      make([]byte, 65),
	}
	// Give the "bad recovery byte" case a valid r/s so it fails on v alone.
	bad := cases["bad recovery byte"]
	bad[31], bad[63] = 1, 1
	for name, sig := range cases {
		if _, err := CompactSignatureFromEth(sig); err == nil {
			t.Errorf("%s: accepted, want an error", name)
		}
	}
}

func TestAmount_RejectsOverflowAndNegative(t *testing.T) {
	tooBig := new(big.Int).Lsh(big.NewInt(1), 64)
	if _, err := Amount(tooBig, "amount"); err == nil {
		t.Error("accepted an amount exceeding uint64")
	}
	if _, err := Amount(big.NewInt(-1), "amount"); err == nil {
		t.Error("accepted a negative amount")
	}
	if _, err := Amount(nil, "amount"); err == nil {
		t.Error("accepted a nil amount")
	}
	maxU64, _ := new(big.Int).SetString("18446744073709551615", 10)
	got, err := Amount(maxU64, "amount")
	if err != nil {
		t.Fatalf("Amount(max uint64): %v", err)
	}
	if got != ^uint64(0) {
		t.Fatalf("Amount(max uint64) = %d", got)
	}
}
