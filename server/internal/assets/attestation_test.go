package assets

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/mr-tron/base58"
	"github.com/santhosh-tekuri/jsonschema/v5"

	"github.com/rwa-platform/server/internal/auditpkg"
	"github.com/rwa-platform/server/internal/dal/memory"
	"github.com/rwa-platform/server/internal/dal/models"
	"github.com/rwa-platform/server/internal/eip712"
)

// TestReconcileMintedFlipsMatchingRecordByProgramID confirms ReconcileMinted
// (projector_test.go's TestReconcileMintedFlipsMatchingRecord counterpart)
// works when driven by a base58 program ID (not an EVM address string) —
// proving it works with the addressing shape the decoder actually produces.
func TestReconcileMintedFlipsMatchingRecordByProgramID(t *testing.T) {
	records := memory.NewAssetRecordRepository()
	events := memory.NewChainEventRepository()
	ctx := context.Background()

	rec := &models.AssetRecord{
		RecordID: "GOLD-SOL-1", Status: models.RecordStatusSigned, RecordKey: "0xrecordkeysol1",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := records.Create(ctx, rec); err != nil {
		t.Fatal(err)
	}

	programID := "SuppLyCtR1111111111111111111111111111111111"
	if err := events.Create(ctx, &models.ChainEvent{
		ChainID: 900001, Address: programID, Name: "Minted", TxHash: "sig-mint-1", LogIndex: 0, BlockNumber: 10,
		Data: map[string]any{"recordKey": "0xrecordkeysol1", "amount": "1000", "vault": "VauLT1111111111111111111111111111111111111"},
	}); err != nil {
		t.Fatal(err)
	}

	svc := &RecordService{}
	if err := svc.ReconcileMinted(ctx, events, 900001, programID, records); err != nil {
		t.Fatalf("ReconcileMinted: %v", err)
	}

	updated, err := records.Get(ctx, "GOLD-SOL-1")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != models.RecordStatusMinted {
		t.Errorf("Status = %s, want Minted", updated.Status)
	}
	if updated.MintTxHash != "sig-mint-1" {
		t.Errorf("MintTxHash = %q, want sig-mint-1", updated.MintTxHash)
	}
}

// TestReconcileMintedIgnoresBurned documents that Burned events are
// intentionally left unprojected onto AssetRecord status — there is no
// RecordStatus for it — rather than an oversight.
func TestReconcileMintedIgnoresBurned(t *testing.T) {
	records := memory.NewAssetRecordRepository()
	events := memory.NewChainEventRepository()
	ctx := context.Background()

	rec := &models.AssetRecord{
		RecordID: "GOLD-SOL-2", Status: models.RecordStatusSigned, RecordKey: "0xrecordkeysol2",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := records.Create(ctx, rec); err != nil {
		t.Fatal(err)
	}
	programID := "SuppLyCtR1111111111111111111111111111111111"
	if err := events.Create(ctx, &models.ChainEvent{
		ChainID: 900001, Address: programID, Name: "Burned", TxHash: "sig-burn-1", LogIndex: 0, BlockNumber: 10,
		Data: map[string]any{"operationId": "0xop1", "amount": "1000"},
	}); err != nil {
		t.Fatal(err)
	}

	svc := &RecordService{}
	if err := svc.ReconcileMinted(ctx, events, 900001, programID, records); err != nil {
		t.Fatal(err)
	}
	unchanged, err := records.Get(ctx, "GOLD-SOL-2")
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Status != models.RecordStatusSigned {
		t.Errorf("Status = %s, want unchanged Signed (Burned is not projected)", unchanged.Status)
	}
}

// TestReconcileAuditorAppliesRotation confirms ReconcileAuditor applies
// AuditorChanged.newAuditor correctly, given the decoder's identical
// EVM-shaped 0x-hex key.
func TestReconcileAuditorAppliesRotation(t *testing.T) {
	events := memory.NewChainEventRepository()
	ctx := context.Background()
	programID := "SuppLyCtR1111111111111111111111111111111111"
	baseline := common.HexToAddress("0x00000000000000000000000000000000000001")
	rotated := common.HexToAddress("0x00000000000000000000000000000000000002")

	svc := &RecordService{auditor: baseline, baselineAuditor: baseline}

	// previous/newAuditor use "0x"+lowercase hex, the exact shape the
	// decoder produces for [u8;20] fields — NOT EIP-55 checksummed.
	if err := events.Create(ctx, &models.ChainEvent{
		ChainID: 900001, Address: programID, Name: "AuditorChanged", TxHash: "sig-rotate-1", LogIndex: 0, BlockNumber: 10,
		Data: map[string]any{"previous": strings.ToLower(baseline.Hex()), "newAuditor": strings.ToLower(rotated.Hex()), "by": "SomeAdmin111111111111111111111111111111111"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.ReconcileAuditor(ctx, events, 900001, programID); err != nil {
		t.Fatalf("ReconcileAuditor: %v", err)
	}
	if svc.currentAuditor() != rotated {
		t.Fatalf("currentAuditor() = %s, want rotated %s", svc.currentAuditor().Hex(), rotated.Hex())
	}
}

// goldenVector is the subset of shared/vectors/mint-attestation.json
// this test needs.
type goldenVector struct {
	Domain  struct{ Cluster, Program, Config string } `json:"domain"`
	Message struct {
		Auditor, ProfileDigest, RecordKey, MetadataDigest, Amount, Nonce, Vault string
		ValidUntil                                                              uint64
	} `json:"message"`
	Digest string `json:"digest"`
}

func loadGoldenVector(t *testing.T) goldenVector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "shared", "vectors", "mint-attestation.json"))
	if err != nil {
		t.Fatalf("reading golden vector: %v", err)
	}
	var v goldenVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parsing golden vector: %v", err)
	}
	return v
}

func mustHash32Bytes(t *testing.T, hexStr string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(hexStr, "0x"))
	if err != nil || len(b) != 32 {
		t.Fatalf("decoding %q: %v", hexStr, err)
	}
	return b
}

// TestBuildMintAttestationMatchesGoldenVector is the end-to-end
// correctness guarantee for the Solana wiring (cmd/platform's buildApp):
// a RecordService built via NewRecordService, fed the golden vector's
// fields through an actual stored AssetRecord (decimal-string amount/nonce,
// exactly as CreateRecord would have persisted them), reproduces
// shared/vectors/mint-attestation.json's digest exactly — proving the
// full record->attestation path (not just the isolated eip712/auditpkg
// pieces those packages' own tests already cover) is correct.
func TestBuildMintAttestationMatchesGoldenVector(t *testing.T) {
	v := loadGoldenVector(t)
	cluster := mustHash32Bytes(t, v.Domain.Cluster)
	program := mustHash32Bytes(t, v.Domain.Program)
	config := mustHash32Bytes(t, v.Domain.Config)
	vault := mustHash32Bytes(t, v.Message.Vault)
	auditor := common.HexToAddress(v.Message.Auditor)

	svc, err := NewRecordService(
		memory.NewAssetRecordRepository(), memory.NewAuditPackageRepository(), memory.NewAttestationRepository(), nil,
		base58.Encode(cluster), base58.Encode(program), base58.Encode(config), base58.Encode(vault),
		auditor,
	)
	if err != nil {
		t.Fatalf("NewRecordService: %v", err)
	}

	// The stored record carries amount/nonce as decimal strings — exactly
	// how CreateRecord persists them (see randomUint256/ValidateRecord) —
	// NOT the vector's hex/decimal wire forms directly.
	nonceBig := new(big.Int).SetBytes(mustHash32Bytes(t, v.Message.Nonce))
	record := &models.AssetRecord{
		RecordID: "asset-001", RecordKey: v.Message.RecordKey, MetadataDigest: v.Message.MetadataDigest,
		Amount: v.Message.Amount, Nonce: nonceBig.String(), ValidUntil: int64(v.Message.ValidUntil),
	}
	profileDigest := [32]byte{}
	copy(profileDigest[:], mustHash32Bytes(t, v.Message.ProfileDigest))

	doc, digest, err := svc.BuildMintAttestation(record, profileDigest)
	if err != nil {
		t.Fatalf("BuildMintAttestation: %v", err)
	}
	if got, want := "0x"+hex.EncodeToString(digest[:]), v.Digest; !strings.EqualFold(got, want) {
		t.Errorf("digest = %s, want golden vector digest %s", got, want)
	}
	// common.Address.Hex() always renders EIP-55 checksummed, unlike the
	// vector's all-lowercase auditor string — compare case-insensitively,
	// same convention the rest of this codebase uses for hex-address equality.
	if !strings.EqualFold(doc.Message.Auditor, v.Message.Auditor) {
		t.Errorf("doc.Message.Auditor = %s, want %s", doc.Message.Auditor, v.Message.Auditor)
	}
	if doc.Message.RecordID != "asset-001" {
		t.Errorf("doc.Message.RecordID = %q, want asset-001", doc.Message.RecordID)
	}
	if doc.Domain.Cluster != base58.Encode(cluster) {
		t.Errorf("doc.Domain.Cluster = %q, want the configured cluster base58", doc.Domain.Cluster)
	}
}

// TestBuildMintAttestationRejectsUnconfiguredRecordService covers the
// construction-mismatch guard: calling BuildMintAttestation on a
// zero-value RecordService (never passed through NewRecordService) must
// fail loudly, not silently compute a digest under a nil/zero-value Solana
// domain.
func TestBuildMintAttestationRejectsUnconfiguredRecordService(t *testing.T) {
	svc := &RecordService{}
	if _, _, err := svc.BuildMintAttestation(&models.AssetRecord{}, [32]byte{}); err != errNotConfigured {
		t.Fatalf("err = %v, want errNotConfigured", err)
	}
}

// loadTypedDataSchemaForAssetsTest compiles the FROZEN
// shared/schemas/typed-data.schema.json from the assets package's own test
// binary, mirroring internal/auditpkg/typeddata_test.go's identically-named
// helper (unexported there, so it can't be imported across packages) — this
// package needs its own copy to validate what BuildPackage actually put on
// disk, not just what a lower-level doc constructor produced.
func loadTypedDataSchemaForAssetsTest(t *testing.T) *jsonschema.Schema {
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

// TestBuildPackageBuildsAttestationPackage is the packaging gate: it
// drives the full server package-builder (RecordService.BuildPackage, not
// just the lower-level TypedDataDoc constructor
// TestNewMintTypedDataDocMatchesSignerShapeAndGoldenDigest in
// internal/auditpkg already covers) for a Solana-configured RecordService,
// and checks every packaging promise on the actual bytes it produced: the
// manifest still satisfies the frozen rwa-manifest rules (OpenPackage
// enforces those), the embedded typed-data.json validates against the
// now-chain-discriminated schema and carries "chain":"solana", and
// re-deriving the digest from THOSE parsed bytes reproduces the golden
// vector — proving wire round-trip, not just isolated math.
func TestBuildPackageBuildsAttestationPackage(t *testing.T) {
	v := loadGoldenVector(t)
	cluster := mustHash32Bytes(t, v.Domain.Cluster)
	program := mustHash32Bytes(t, v.Domain.Program)
	config := mustHash32Bytes(t, v.Domain.Config)
	vault := mustHash32Bytes(t, v.Message.Vault)
	auditor := common.HexToAddress(v.Message.Auditor)

	svc, err := NewRecordService(
		memory.NewAssetRecordRepository(), memory.NewAuditPackageRepository(), memory.NewAttestationRepository(), nil,
		base58.Encode(cluster), base58.Encode(program), base58.Encode(config), base58.Encode(vault),
		auditor,
	)
	if err != nil {
		t.Fatal(err)
	}

	nonceBig := new(big.Int).SetBytes(mustHash32Bytes(t, v.Message.Nonce))
	metadataRaw := []byte(`{"platformVersion":"1.0"}`)
	record := &models.AssetRecord{
		RecordID: "asset-001", RecordKey: v.Message.RecordKey, MetadataDigest: v.Message.MetadataDigest,
		MetadataRaw: metadataRaw, Amount: v.Message.Amount, Nonce: nonceBig.String(), ValidUntil: int64(v.Message.ValidUntil),
	}
	profileDigest := [32]byte{}
	copy(profileDigest[:], mustHash32Bytes(t, v.Message.ProfileDigest))
	profileRaw := []byte(`{"projectId":"p"}`)

	zipBytes, err := svc.BuildPackage(context.Background(), record, profileDigest, profileRaw)
	if err != nil {
		t.Fatalf("BuildPackage: %v", err)
	}

	// The manifest itself: OpenPackage runs the same strict rules the
	// FROZEN shared/schemas/rwa-manifest.schema.json encodes (three
	// mandatory documents, no unmanifested files, matching hashes) — a
	// Solana package must satisfy them identically to an EVM one, since
	// That schema's mandatory-document set is unchanged.
	opened, err := auditpkg.OpenPackage(zipBytes)
	if err != nil {
		t.Fatalf("OpenPackage: %v", err)
	}
	typedDataRaw, ok := opened.Files["typed-data.json"]
	if !ok {
		t.Fatal("package is missing typed-data.json")
	}

	schema := loadTypedDataSchemaForAssetsTest(t)
	var instance any
	if err := json.Unmarshal(typedDataRaw, &instance); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(instance); err != nil {
		t.Fatalf("typed-data.json does not conform to the schema: %v\ndoc: %s", err, typedDataRaw)
	}

	var doc struct {
		Chain   string `json:"chain"`
		Domain  struct{ Cluster, Program, Config string }
		Message struct {
			Auditor, ProfileDigest, RecordKey, MetadataDigest, Amount, Nonce, Vault string
			ValidUntil                                                              uint64
		}
	}
	if err := json.Unmarshal(typedDataRaw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Chain != "solana" {
		t.Errorf("typed-data.json chain = %q, want %q", doc.Chain, "solana")
	}

	// Re-derive the digest from the round-tripped, base58/hex-decoded fields
	// exactly as the offline signer's parseTypedData would, and
	// compare against the frozen golden vector digest AND the digest
	// BuildPackage itself persisted to the AuditPackage row.
	decodeBase58Pubkey := func(s string) [32]byte {
		b, err := base58.Decode(s)
		if err != nil || len(b) != 32 {
			t.Fatalf("decoding base58 %q: %v", s, err)
		}
		var out [32]byte
		copy(out[:], b)
		return out
	}
	amountBig, ok := new(big.Int).SetString(doc.Message.Amount, 10)
	if !ok {
		t.Fatalf("parsing amount %q", doc.Message.Amount)
	}
	gotAmount, err := eip712.Amount(amountBig)
	if err != nil {
		t.Fatal(err)
	}

	gotDomain := eip712.Domain{
		Cluster: decodeBase58Pubkey(doc.Domain.Cluster), Program: decodeBase58Pubkey(doc.Domain.Program), Config: decodeBase58Pubkey(doc.Domain.Config),
	}
	gotAttestation := eip712.MintAttestation{
		Auditor: common.HexToAddress(doc.Message.Auditor), ProfileDigest: mustHash32Array(t, doc.Message.ProfileDigest),
		RecordKey: mustHash32Array(t, doc.Message.RecordKey), MetadataDigest: mustHash32Array(t, doc.Message.MetadataDigest),
		Amount: gotAmount, Nonce: mustHash32Array(t, doc.Message.Nonce), ValidUntil: doc.Message.ValidUntil,
		Vault: decodeBase58Pubkey(doc.Message.Vault),
	}
	gotDigest := eip712.MintDigest(gotDomain, gotAttestation)
	gotDigestHex := "0x" + hex.EncodeToString(gotDigest[:])
	if !strings.EqualFold(gotDigestHex, v.Digest) {
		t.Errorf("re-derived digest = %s, want golden vector digest %s", gotDigestHex, v.Digest)
	}

	pkg, err := svc.packages.Get(context.Background(), record.RecordID)
	if err != nil {
		t.Fatalf("packages.Get: %v", err)
	}
	if !strings.EqualFold(pkg.TypedDataDigest, v.Digest) {
		t.Errorf("persisted AuditPackage.TypedDataDigest = %s, want golden vector digest %s", pkg.TypedDataDigest, v.Digest)
	}
	if !strings.EqualFold(pkg.Vault, base58.Encode(vault[:])) {
		t.Errorf("persisted AuditPackage.Vault = %s, want base58 %s (not the EVM hex convention)", pkg.Vault, base58.Encode(vault[:]))
	}
}

// mustHash32Array is mustHash32Bytes's fixed-size-array counterpart, for
// callers (like eip712.MintAttestation's fields) that need [32]byte
// rather than []byte.
func mustHash32Array(t *testing.T, hexStr string) [32]byte {
	t.Helper()
	var out [32]byte
	copy(out[:], mustHash32Bytes(t, hexStr))
	return out
}

// TestNewRecordServiceRejectsMalformedPubkey covers
// decodePubkey's error path via the constructor.
func TestNewRecordServiceRejectsMalformedPubkey(t *testing.T) {
	if _, err := NewRecordService(
		memory.NewAssetRecordRepository(), memory.NewAuditPackageRepository(), memory.NewAttestationRepository(), nil,
		"not-valid-base58-0OIl", "x", "y", "z", common.Address{},
	); err == nil {
		t.Fatal("expected an error for a malformed cluster_genesis pubkey")
	}
}
