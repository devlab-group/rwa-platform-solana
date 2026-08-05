package auditpkg

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/mr-tron/base58"
	"github.com/santhosh-tekuri/jsonschema/v5"

	"github.com/rwa-platform/server/internal/eip712"
)

// loadTypedDataSchema compiles the FROZEN shared/schemas/typed-data.schema.json
// so this package's typed-data.json output is checked against the real
// schema the offline signer also validates against, not just our own Go
// structs.
func loadTypedDataSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	p := filepath.Join("..", "..", "..", "shared", "schemas", "typed-data.schema.json")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Skipf("shared schema not found: %v", err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("typed-data.json", bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile("typed-data.json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// signerTypedData mirrors signer/cmd/signer/typeddata.go's
// typedData JSON shape byte-for-byte, including its
// dec.DisallowUnknownFields() strictness — since the signer module can't be
// imported here (separate go.mod), this is the closest thing to a real
// cross-module compatibility check: if TypedDataDoc's JSON ever grows
// an extra field, is missing one, or renames one, decoding into THIS struct
// with strict mode fails exactly like the real signer would.
type signerTypedData struct {
	Chain       string `json:"chain"`
	PrimaryType string `json:"primaryType"`
	Domain      struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Cluster string `json:"cluster"`
		Program string `json:"program"`
		Config  string `json:"config"`
	} `json:"domain"`
	Message struct {
		Auditor        string `json:"auditor"`
		ProfileDigest  string `json:"profileDigest"`
		RecordID       string `json:"recordId,omitempty"`
		RecordKey      string `json:"recordKey,omitempty"`
		OperationID    string `json:"operationId,omitempty"`
		MetadataDigest string `json:"metadataDigest"`
		Amount         string `json:"amount"`
		Nonce          string `json:"nonce"`
		ValidUntil     uint64 `json:"validUntil"`
		Vault          string `json:"vault"`
	} `json:"message"`
}

func decodeStrictSignerShape(t *testing.T, raw []byte) signerTypedData {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var out signerTypedData
	if err := dec.Decode(&out); err != nil {
		t.Fatalf("decoding against the signer's strict typedData shape: %v", err)
	}
	return out
}

// TestNewMintTypedDataDocMatchesSignerShapeAndGoldenDigest is the
// correctness guarantee for the Solana .rwa attestation-request document:
// it round-trips through JSON exactly as signer/cmd/signer/
// typeddata.go's strict parser expects (field names, base58 vs hex
// vs decimal encodings), and re-deriving the digest from the round-tripped
// fields reproduces shared/vectors/mint-attestation.json's digest —
// proving the document actually commits the auditor to the SAME bytes
// TestDigestMatchesGoldenVector (eip712/attestation_test.go) already proved
// correct.
func TestNewMintTypedDataDocMatchesSignerShapeAndGoldenDigest(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "shared", "vectors", "mint-attestation.json"))
	if err != nil {
		t.Fatalf("reading golden vector: %v", err)
	}
	var v struct {
		Domain  struct{ Cluster, Program, Config string } `json:"domain"`
		Message struct {
			Auditor, ProfileDigest, RecordKey, MetadataDigest, Amount, Nonce, Vault string
			ValidUntil                                                              uint64
		} `json:"message"`
		Digest string `json:"digest"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parsing golden vector: %v", err)
	}

	hash32 := func(hexStr string) [32]byte {
		b, err := hex.DecodeString(strings.TrimPrefix(hexStr, "0x"))
		if err != nil || len(b) != 32 {
			t.Fatalf("decoding %q: %v", hexStr, err)
		}
		var out [32]byte
		copy(out[:], b)
		return out
	}
	cluster, program, config := hash32(v.Domain.Cluster), hash32(v.Domain.Program), hash32(v.Domain.Config)
	vault := hash32(v.Message.Vault)
	amountBig, ok := new(big.Int).SetString(v.Message.Amount, 10)
	if !ok {
		t.Fatalf("parsing amount %q", v.Message.Amount)
	}
	amount, err := eip712.Amount(amountBig)
	if err != nil {
		t.Fatal(err)
	}

	attestation := eip712.MintAttestation{
		Auditor: common.HexToAddress(v.Message.Auditor), ProfileDigest: hash32(v.Message.ProfileDigest),
		RecordKey: hash32(v.Message.RecordKey), MetadataDigest: hash32(v.Message.MetadataDigest),
		Amount: amount, Nonce: hash32(v.Message.Nonce), ValidUntil: v.Message.ValidUntil, Vault: vault,
	}
	domainView := DomainView{
		Cluster: base58.Encode(cluster[:]), Program: base58.Encode(program[:]), Config: base58.Encode(config[:]),
	}
	doc := NewMintTypedDataDoc(domainView, "asset-001", attestation, base58.Encode(vault[:]))

	if doc.PrimaryType != "MintAttestation" {
		t.Errorf("primaryType = %q, want MintAttestation", doc.PrimaryType)
	}

	docJSON, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// 1. Strict-shape compatibility with the signer's own parser.
	parsed := decodeStrictSignerShape(t, docJSON)
	if parsed.Chain != "solana" {
		t.Errorf("chain = %q, want %q", parsed.Chain, "solana")
	}
	if parsed.Domain.Name != eip712.DomainName || parsed.Domain.Version != eip712.DomainVersion {
		t.Errorf("domain name/version = %s/%s, want %s/%s", parsed.Domain.Name, parsed.Domain.Version, eip712.DomainName, eip712.DomainVersion)
	}
	if parsed.Message.RecordID != "asset-001" {
		t.Errorf("recordId = %q, want asset-001", parsed.Message.RecordID)
	}
	if parsed.Message.OperationID != "" {
		t.Error("operationId must be empty/omitted for a MintAttestation")
	}

	// 1b. Conformance with the FROZEN shared/schemas/typed-data.schema.json
	// itself (the "solana" branch of the chain-discriminated union),
	// not just this test's local mirror of the signer's Go struct.
	schema := loadTypedDataSchema(t)
	var instance any
	if err := json.Unmarshal(docJSON, &instance); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(instance); err != nil {
		t.Fatalf("typed-data.json does not conform to the schema: %v\ndoc: %s", err, docJSON)
	}

	// 2. Decode the round-tripped fields back to raw bytes exactly as the
	// signer's parseTypedData does, and recompute the digest.
	decodePubkey := func(s string) [32]byte {
		b, err := base58.Decode(s)
		if err != nil || len(b) != 32 {
			t.Fatalf("decoding base58 %q: %v", s, err)
		}
		var out [32]byte
		copy(out[:], b)
		return out
	}
	gotDomain := eip712.Domain{
		Cluster: decodePubkey(parsed.Domain.Cluster), Program: decodePubkey(parsed.Domain.Program), Config: decodePubkey(parsed.Domain.Config),
	}
	gotAmount, err := eip712.Amount(mustBigInt(t, parsed.Message.Amount))
	if err != nil {
		t.Fatal(err)
	}
	gotAttestation := eip712.MintAttestation{
		Auditor: common.HexToAddress(parsed.Message.Auditor), ProfileDigest: hash32(parsed.Message.ProfileDigest),
		RecordKey: hash32(parsed.Message.RecordKey), MetadataDigest: hash32(parsed.Message.MetadataDigest),
		Amount: gotAmount, Nonce: hash32(parsed.Message.Nonce), ValidUntil: parsed.Message.ValidUntil,
		Vault: decodePubkey(parsed.Message.Vault),
	}

	gotDigest := eip712.MintDigest(gotDomain, gotAttestation)
	if got, want := "0x"+hex.EncodeToString(gotDigest[:]), v.Digest; !strings.EqualFold(got, want) {
		t.Errorf("re-derived digest = %s, want golden vector digest %s", got, want)
	}
}

// TestNewBurnTypedDataDocMatchesSignerShapeAndGoldenDigest is
// TestNewMintTypedDataDocMatchesSignerShapeAndGoldenDigest's burn
// counterpart: it round-trips NewBurnTypedDataDoc's output through the
// signer's strict shape and the frozen typed-data.schema.json, then
// re-derives the digest from the round-tripped fields and checks it against
// shared/vectors/burn-attestation.json.
func TestNewBurnTypedDataDocMatchesSignerShapeAndGoldenDigest(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "shared", "vectors", "burn-attestation.json"))
	if err != nil {
		t.Fatalf("reading golden vector: %v", err)
	}
	var v struct {
		Domain  struct{ Cluster, Program, Config string } `json:"domain"`
		Message struct {
			Auditor, ProfileDigest, OperationID, MetadataDigest, Amount, Nonce, Vault string
			ValidUntil                                                                uint64
		} `json:"message"`
		Digest string `json:"digest"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parsing golden vector: %v", err)
	}

	hash32 := func(hexStr string) [32]byte {
		b, err := hex.DecodeString(strings.TrimPrefix(hexStr, "0x"))
		if err != nil || len(b) != 32 {
			t.Fatalf("decoding %q: %v", hexStr, err)
		}
		var out [32]byte
		copy(out[:], b)
		return out
	}
	cluster, program, config := hash32(v.Domain.Cluster), hash32(v.Domain.Program), hash32(v.Domain.Config)
	vault := hash32(v.Message.Vault)
	amountBig, ok := new(big.Int).SetString(v.Message.Amount, 10)
	if !ok {
		t.Fatalf("parsing amount %q", v.Message.Amount)
	}
	amount, err := eip712.Amount(amountBig)
	if err != nil {
		t.Fatal(err)
	}

	attestation := eip712.BurnAttestation{
		Auditor: common.HexToAddress(v.Message.Auditor), ProfileDigest: hash32(v.Message.ProfileDigest),
		OperationID: hash32(v.Message.OperationID), MetadataDigest: hash32(v.Message.MetadataDigest),
		Amount: amount, Nonce: hash32(v.Message.Nonce), ValidUntil: v.Message.ValidUntil, Vault: vault,
	}
	domainView := DomainView{
		Cluster: base58.Encode(cluster[:]), Program: base58.Encode(program[:]), Config: base58.Encode(config[:]),
	}
	doc := NewBurnTypedDataDoc(domainView, attestation, base58.Encode(vault[:]))

	if doc.PrimaryType != "BurnAttestation" {
		t.Errorf("primaryType = %q, want BurnAttestation", doc.PrimaryType)
	}

	docJSON, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// 1. Strict-shape compatibility with the signer's own parser.
	parsed := decodeStrictSignerShape(t, docJSON)
	if parsed.Chain != "solana" {
		t.Errorf("chain = %q, want %q", parsed.Chain, "solana")
	}
	if parsed.Domain.Name != eip712.DomainName || parsed.Domain.Version != eip712.DomainVersion {
		t.Errorf("domain name/version = %s/%s, want %s/%s", parsed.Domain.Name, parsed.Domain.Version, eip712.DomainName, eip712.DomainVersion)
	}
	if parsed.Message.RecordID != "" || parsed.Message.RecordKey != "" {
		t.Error("recordId/recordKey must be empty/omitted for a BurnAttestation")
	}
	if parsed.Message.OperationID == "" {
		t.Error("operationId must be set for a BurnAttestation")
	}

	// 1b. Conformance with the FROZEN shared/schemas/typed-data.schema.json
	// itself, not just this test's local mirror of the signer's Go struct.
	schema := loadTypedDataSchema(t)
	var instance any
	if err := json.Unmarshal(docJSON, &instance); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(instance); err != nil {
		t.Fatalf("burn typed-data.json does not conform to the schema: %v\ndoc: %s", err, docJSON)
	}

	// 2. Decode the round-tripped fields back to raw bytes exactly as the
	// signer's parseTypedData does, and recompute the digest.
	decodePubkey := func(s string) [32]byte {
		b, err := base58.Decode(s)
		if err != nil || len(b) != 32 {
			t.Fatalf("decoding base58 %q: %v", s, err)
		}
		var out [32]byte
		copy(out[:], b)
		return out
	}
	gotDomain := eip712.Domain{
		Cluster: decodePubkey(parsed.Domain.Cluster), Program: decodePubkey(parsed.Domain.Program), Config: decodePubkey(parsed.Domain.Config),
	}
	gotAmount, err := eip712.Amount(mustBigInt(t, parsed.Message.Amount))
	if err != nil {
		t.Fatal(err)
	}
	gotAttestation := eip712.BurnAttestation{
		Auditor: common.HexToAddress(parsed.Message.Auditor), ProfileDigest: hash32(parsed.Message.ProfileDigest),
		OperationID: hash32(parsed.Message.OperationID), MetadataDigest: hash32(parsed.Message.MetadataDigest),
		Amount: gotAmount, Nonce: hash32(parsed.Message.Nonce), ValidUntil: parsed.Message.ValidUntil,
		Vault: decodePubkey(parsed.Message.Vault),
	}

	gotDigest := eip712.BurnDigest(gotDomain, gotAttestation)
	if got, want := "0x"+hex.EncodeToString(gotDigest[:]), v.Digest; !strings.EqualFold(got, want) {
		t.Errorf("re-derived digest = %s, want golden vector digest %s", got, want)
	}
}

func mustBigInt(t *testing.T, decimal string) *big.Int {
	t.Helper()
	v, ok := new(big.Int).SetString(decimal, 10)
	if !ok {
		t.Fatalf("parsing decimal %q", decimal)
	}
	return v
}

// TestBase58EncodeRoundTrips is a small sanity check on the helper
// RecordService's wiring uses to render its configured 32-byte vault
// pubkey for the typed-data document.
func TestBase58EncodeRoundTrips(t *testing.T) {
	var vault [32]byte
	for i := range vault {
		vault[i] = byte(i + 1)
	}
	encoded := base58Encode(vault)
	decoded, err := base58.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 32 {
		t.Fatalf("decoded length = %d, want 32", len(decoded))
	}
	var got [32]byte
	copy(got[:], decoded)
	if got != vault {
		t.Errorf("round trip mismatch: got %x, want %x", got, vault)
	}
}
