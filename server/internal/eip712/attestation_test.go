package eip712

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// mintVector is the shape of shared/vectors/mint-attestation.json
// — mirrors signer/internal/attestation/attestation_test.go's mintVector
// (the same oracle, read on the other side of the frozen contract). The
// server never signs, so this only reproduces domainSeparator/hashStruct/
// digest — not the signature/recovery half signer_test.go additionally
// covers.
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
	HashStruct string `json:"hashStruct"`
	Digest     string `json:"digest"`
}

// vectorPath locates shared/vectors/mint-attestation.json
// relative to this package — server/internal/eip712 is 3 directories below
// the repo root (server/internal/eip712 -> server/internal -> server ->
// root), mirroring how internal/auditpkg/typeddata_test.go locates
// shared/schemas from the same depth.
func vectorPath(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "..", "shared", "vectors", "mint-attestation.json")
}

// burnVector is the shape of
// shared/vectors/burn-attestation.json — the burn counterpart of
// mintVector above (recordKey replaced by operationId; everything
// else, including the domain, is field-for-field identical to the mint
// vector by construction — see that file's header comment).
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
	HashStruct string `json:"hashStruct"`
	Digest     string `json:"digest"`
}

func burnVectorPath(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "..", "shared", "vectors", "burn-attestation.json")
}

func mustHash32(t *testing.T, hexStr string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(hexStr, "0x"))
	if err != nil {
		t.Fatalf("decoding %q: %v", hexStr, err)
	}
	if len(b) != 32 {
		t.Fatalf("%q is %d bytes, want 32", hexStr, len(b))
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

func mustAmountU64(t *testing.T, decimal string) uint64 {
	t.Helper()
	v, ok := new(big.Int).SetString(decimal, 10)
	if !ok {
		t.Fatalf("parsing decimal amount %q", decimal)
	}
	amount, err := Amount(v)
	if err != nil {
		t.Fatalf("Amount: %v", err)
	}
	return amount
}

// TestDigestMatchesGoldenVector reproduces
// shared/vectors/mint-attestation.json's domainSeparator, hashStruct,
// and digest exactly — the correctness guarantee that this server package
// builds the SAME digest the offline signer (signer/internal/attestation/
// solana.go) will sign and the on-chain rwa-supply-controller program will
// verify. Any drift here — a reordered field, a changed type string, a wrong
// word encoding — must fail, since it would mean the server hands the
// auditor a package whose embedded/derived digest the on-chain program can
// never actually recover the signature against.
func TestDigestMatchesGoldenVector(t *testing.T) {
	raw, err := os.ReadFile(vectorPath(t))
	if err != nil {
		t.Fatalf("reading golden vector: %v", err)
	}
	var v mintVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parsing golden vector: %v", err)
	}

	domain := Domain{
		Cluster: mustHash32(t, v.Domain.Cluster),
		Program: mustHash32(t, v.Domain.Program),
		Config:  mustHash32(t, v.Domain.Config),
	}
	sep := DomainSeparator(domain)
	if got, want := "0x"+hex.EncodeToString(sep[:]), v.DomainSeparator; !strings.EqualFold(got, want) {
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
	hs := HashMintAttestation(msg)
	if got, want := "0x"+hex.EncodeToString(hs[:]), v.HashStruct; !strings.EqualFold(got, want) {
		t.Errorf("hashStruct = %s, want %s", got, want)
	}

	digest := MintDigest(domain, msg)
	if got, want := "0x"+hex.EncodeToString(digest[:]), v.Digest; !strings.EqualFold(got, want) {
		t.Errorf("digest = %s, want %s", got, want)
	}
}

// TestBurnDigestMatchesGoldenVector is TestDigestMatchesGoldenVector's
// burn counterpart: it reproduces shared/vectors/burn-attestation.json's
// domainSeparator, hashStruct and digest exactly. Until this test existed the
// burn half of the Solana encoding had zero coverage — HashBurnAttestation
// and BurnDigest are the code path a future burn-package feature (see
// NewBurnTypedDataDoc's doc comment) would depend on, and an audit that
// touched only the mint payload could silently break it.
func TestBurnDigestMatchesGoldenVector(t *testing.T) {
	raw, err := os.ReadFile(burnVectorPath(t))
	if err != nil {
		t.Fatalf("reading golden vector: %v", err)
	}
	var v burnVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parsing golden vector: %v", err)
	}

	domain := Domain{
		Cluster: mustHash32(t, v.Domain.Cluster),
		Program: mustHash32(t, v.Domain.Program),
		Config:  mustHash32(t, v.Domain.Config),
	}
	sep := DomainSeparator(domain)
	if got, want := "0x"+hex.EncodeToString(sep[:]), v.DomainSeparator; !strings.EqualFold(got, want) {
		t.Errorf("domainSeparator = %s, want %s", got, want)
	}
	// The domain separator does not depend on the attestation type, so the
	// burn vector's domain separator must equal the mint vector's — both
	// vectors were generated against the same domain.
	mintRaw, err := os.ReadFile(vectorPath(t))
	if err != nil {
		t.Fatalf("reading mint vector: %v", err)
	}
	var mv mintVector
	if err := json.Unmarshal(mintRaw, &mv); err != nil {
		t.Fatalf("parsing mint vector: %v", err)
	}
	if !strings.EqualFold(v.DomainSeparator, mv.DomainSeparator) {
		t.Errorf("burn vector domainSeparator %s != mint vector domainSeparator %s", v.DomainSeparator, mv.DomainSeparator)
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
	hs := HashBurnAttestation(msg)
	if got, want := "0x"+hex.EncodeToString(hs[:]), v.HashStruct; !strings.EqualFold(got, want) {
		t.Errorf("hashStruct = %s, want %s", got, want)
	}

	digest := BurnDigest(domain, msg)
	if got, want := "0x"+hex.EncodeToString(digest[:]), v.Digest; !strings.EqualFold(got, want) {
		t.Errorf("digest = %s, want %s", got, want)
	}
}

// TestMintAttestationFieldSensitivity guards against a swapped or
// dropped field in HashMintAttestation's encoding: mutating any single
// field of an otherwise-fixed MintAttestation must change the hash.
// This is the class of bug a golden vector alone would not necessarily catch
// (a vector generated with two fields already accidentally swapped would
// still "match" a hand-derived expectation that made the same mistake).
func TestMintAttestationFieldSensitivity(t *testing.T) {
	base := MintAttestation{
		Auditor:        common.HexToAddress("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"),
		ProfileDigest:  fieldBytes32(0x44),
		RecordKey:      fieldBytes32(0x55),
		MetadataDigest: fieldBytes32(0x66),
		Amount:         1_000_000_000_000,
		Nonce:          fieldBytes32(0x2a),
		ValidUntil:     1_800_000_000,
		Vault:          fieldBytes32(0x77),
	}
	baseHash := HashMintAttestation(base)

	cases := map[string]MintAttestation{
		"auditor": withField(base, func(m *MintAttestation) {
			m.Auditor = common.HexToAddress("0x000000000000000000000000000000000000aa")
		}),
		"profileDigest":  withField(base, func(m *MintAttestation) { m.ProfileDigest = fieldBytes32(0x99) }),
		"recordKey":      withField(base, func(m *MintAttestation) { m.RecordKey = fieldBytes32(0x99) }),
		"metadataDigest": withField(base, func(m *MintAttestation) { m.MetadataDigest = fieldBytes32(0x99) }),
		"amount":         withField(base, func(m *MintAttestation) { m.Amount = base.Amount + 1 }),
		"nonce":          withField(base, func(m *MintAttestation) { m.Nonce = fieldBytes32(0x99) }),
		"validUntil":     withField(base, func(m *MintAttestation) { m.ValidUntil = base.ValidUntil + 1 }),
		"vault":          withField(base, func(m *MintAttestation) { m.Vault = fieldBytes32(0x99) }),
	}
	for name, mutated := range cases {
		if got := HashMintAttestation(mutated); got == baseHash {
			t.Errorf("mutating %s did not change HashMintAttestation", name)
		}
	}

	// The audit-relevant special case: swapping RecordKey and MetadataDigest
	// (both bytes32, adjacent in the struct) must not be a silent no-op.
	swapped := base
	swapped.RecordKey, swapped.MetadataDigest = base.MetadataDigest, base.RecordKey
	if HashMintAttestation(swapped) == baseHash {
		t.Error("swapping recordKey and metadataDigest did not change the hash")
	}
}

// TestBurnAttestationFieldSensitivity is
// TestMintAttestationFieldSensitivity's burn counterpart — the audit
// finding this specifically guards is a swapped OperationID/MetadataDigest,
// which on the burn side are the two fields most easily confused (both
// bytes32, adjacent, and OperationID plays RecordKey's structural role).
func TestBurnAttestationFieldSensitivity(t *testing.T) {
	base := BurnAttestation{
		Auditor:        common.HexToAddress("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"),
		ProfileDigest:  fieldBytes32(0x44),
		OperationID:    fieldBytes32(0x55),
		MetadataDigest: fieldBytes32(0x66),
		Amount:         1_000_000_000_000,
		Nonce:          fieldBytes32(0x2a),
		ValidUntil:     1_800_000_000,
		Vault:          fieldBytes32(0x77),
	}
	baseHash := HashBurnAttestation(base)

	cases := map[string]BurnAttestation{
		"auditor": withFieldBurn(base, func(m *BurnAttestation) {
			m.Auditor = common.HexToAddress("0x000000000000000000000000000000000000aa")
		}),
		"profileDigest":  withFieldBurn(base, func(m *BurnAttestation) { m.ProfileDigest = fieldBytes32(0x99) }),
		"operationId":    withFieldBurn(base, func(m *BurnAttestation) { m.OperationID = fieldBytes32(0x99) }),
		"metadataDigest": withFieldBurn(base, func(m *BurnAttestation) { m.MetadataDigest = fieldBytes32(0x99) }),
		"amount":         withFieldBurn(base, func(m *BurnAttestation) { m.Amount = base.Amount + 1 }),
		"nonce":          withFieldBurn(base, func(m *BurnAttestation) { m.Nonce = fieldBytes32(0x99) }),
		"validUntil":     withFieldBurn(base, func(m *BurnAttestation) { m.ValidUntil = base.ValidUntil + 1 }),
		"vault":          withFieldBurn(base, func(m *BurnAttestation) { m.Vault = fieldBytes32(0x99) }),
	}
	for name, mutated := range cases {
		if got := HashBurnAttestation(mutated); got == baseHash {
			t.Errorf("mutating %s did not change HashBurnAttestation", name)
		}
	}

	swapped := base
	swapped.OperationID, swapped.MetadataDigest = base.MetadataDigest, base.OperationID
	if HashBurnAttestation(swapped) == baseHash {
		t.Error("swapping operationId and metadataDigest did not change the hash")
	}
}

func fieldBytes32(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}

func withField(base MintAttestation, mutate func(*MintAttestation)) MintAttestation {
	m := base
	mutate(&m)
	return m
}

func withFieldBurn(base BurnAttestation, mutate func(*BurnAttestation)) BurnAttestation {
	m := base
	mutate(&m)
	return m
}

// TestTypehashesAreFrozen pins the exact type strings — a change to
// any of them (reordering a field, renaming a type) changes every downstream
// hash even if nothing else in this file does, so this test exists
// independent of the golden vector to make that class of drift loud.
func TestTypehashesAreFrozen(t *testing.T) {
	if domainTypeString != "SolanaSupplyAttestation(string name,string version,bytes32 cluster,bytes32 program,bytes32 config)" {
		t.Errorf("domainTypeString changed: %s", domainTypeString)
	}
	if mintTypeString != "MintAttestation(bytes32 auditor,bytes32 profileDigest,bytes32 recordKey,bytes32 metadataDigest,uint64 amount,bytes32 nonce,uint64 validUntil,bytes32 vault)" {
		t.Errorf("mintTypeString changed: %s", mintTypeString)
	}
	if burnTypeString != "BurnAttestation(bytes32 auditor,bytes32 profileDigest,bytes32 operationId,bytes32 metadataDigest,uint64 amount,bytes32 nonce,uint64 validUntil,bytes32 vault)" {
		t.Errorf("burnTypeString changed: %s", burnTypeString)
	}
	if DomainName != "RWA-Supply-Attestation-Solana" {
		t.Errorf("DomainName changed: %s", DomainName)
	}
}

// TestAmountRejectsOverflowAndNegative covers Amount's failure
// modes — silently truncating an over-uint64 amount would authorize a
// different quantity than the one the auditor reviewed.
func TestAmountRejectsOverflowAndNegative(t *testing.T) {
	if _, err := Amount(nil); err == nil {
		t.Error("expected an error for a nil amount")
	}
	if _, err := Amount(big.NewInt(-1)); err == nil {
		t.Error("expected an error for a negative amount")
	}
	tooBig := new(big.Int).Lsh(big.NewInt(1), 64) // 2^64, one past uint64 max
	if _, err := Amount(tooBig); err == nil {
		t.Error("expected an error for an amount exceeding uint64")
	}
	got, err := Amount(big.NewInt(1000000000000))
	if err != nil {
		t.Fatalf("Amount: %v", err)
	}
	if got != 1000000000000 {
		t.Errorf("Amount = %d, want 1000000000000", got)
	}
}
