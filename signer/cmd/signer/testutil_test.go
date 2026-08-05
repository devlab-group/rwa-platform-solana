package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	gokeystore "github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/rwa-platform/signer/internal/attestation"
	"github.com/rwa-platform/signer/internal/base58"
	"github.com/rwa-platform/signer/internal/canonical"
	rwakeystore "github.com/rwa-platform/signer/internal/keystore"
)

// Fixed Solana deployment coordinates shared by every e2e test in this
// package. Real base58 keys, built from recognizable byte patterns so a
// failure message is readable.
var (
	testCluster = base58.Encode(bytes.Repeat([]byte{0x11}, 32))
	testProgram = base58.Encode(bytes.Repeat([]byte{0x22}, 32))
	testConfig  = base58.Encode(bytes.Repeat([]byte{0x33}, 32))
	testVault   = base58.Encode(bytes.Repeat([]byte{0x77}, 32))
)

const testProjectID = "4fd4224f-6e65-4d6b-9fa9-c5c2b3514e61"

// testNonceHex is bytes32(42), the fixed nonce every golden package in
// this package's tests embeds.
const testNonceHex = "0x000000000000000000000000000000000000000000000000000000000000002a"

// findGoBinary locates the go tool for building the signer binary under
// test, falling back to this environment's known install path so the test
// does not depend on the test runner's PATH.
func findGoBinary(t *testing.T) string {
	t.Helper()
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	const fallback = "/usr/local/go/bin/go"
	if _, err := os.Stat(fallback); err == nil {
		return fallback
	}
	t.Skip("go toolchain not found; skipping end-to-end CLI test")
	return ""
}

// buildSignerBinary compiles cmd/signer into dir and returns its path.
func buildSignerBinary(t *testing.T, goBin, dir string) string {
	t.Helper()
	out := filepath.Join(dir, "signer")
	cmd := exec.Command(goBin, "build", "-o", out, ".")
	cmd.Dir = "." // this test file lives in cmd/signer
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("building signer binary: %v\n%s", err, stderr.String())
	}
	return out
}

// docOverrides lets a test build a package whose profile.json and
// metadata.json disagree on the fields the cross-document binding check ties
// together, or whose timing sits outside the expiry policy, instead of the
// fully self-consistent/well-timed golden pair. Zero value reproduces the
// golden package.
type docOverrides struct {
	profileProjectID  string // default testProjectID
	metadataProjectID string // default: same as profileProjectID
	tokenUnit         string // profile.tokenUnit, default "gram"
	issuanceUnit      string // metadata.issuance.unit, default: same as tokenUnit

	tokenDecimals  int    // profile.tokenDecimals, default 9
	issuanceAmount string // metadata.issuance.amount, default "1000000000000" (fits uint64)

	createdAt  time.Time // metadata.createdAt, default: now-1h
	validUntil time.Time // typed-data validUntil, default: createdAt+7d (well inside the 30d default policy horizon)

	// mutateTypedData, if set, is applied to the typed-data.json map right
	// before it's marshaled and hashed into the manifest -- so the mutation
	// is reflected consistently in both the archived file and its manifest
	// entry, unlike a post-hoc zip-rewrite (see TestE2E_RejectsTamperedAmount)
	// which deliberately leaves the manifest stale.
	mutateTypedData func(map[string]any)
}

// builtPackage is everything a test needs both to invoke the signer CLI
// against a freshly built .rwa package and to construct a policy file that
// independently matches it. --policy is mandatory, so every e2e test needs
// one whether or not that specific test is exercising policy behavior.
type builtPackage struct {
	zipBytes      []byte
	keystorePath  string
	password      string
	auditorAddr   string // 0x-prefixed
	profileDigest string // 0x-prefixed

	metadataDigest string // 0x-prefixed
	recordKey      string // 0x-prefixed
	amount         string // decimal, smallest unit
	validUntil     int64

	// typedDataJSON is the exact bytes embedded as the package's own
	// typed-data.json entry (post any ov.mutateTypedData), so a test can
	// build an external --typed-data file that starts from precisely what
	// the package itself carries.
	typedDataJSON []byte
}

// buildGoldenPackage assembles a fully self-consistent .rwa package (real
// canonical digests, real recordKey) for a Solana MintAttestation, along
// with the keystore file and password needed to sign it.
func buildGoldenPackage(t *testing.T, cluster, program, config, vault string) builtPackage {
	t.Helper()
	return buildPackageWithOverrides(t, cluster, program, config, vault, docOverrides{})
}

// buildPackageWithOverrides is buildGoldenPackage generalized to let a test
// deliberately desynchronize profile.json and metadata.json (cross-project
// package, wrong unit), push validUntil outside the expiry policy, or
// mutate the embedded typed-data.json directly.
func buildPackageWithOverrides(t *testing.T, cluster, program, config, vault string, ov docOverrides) builtPackage {
	t.Helper()

	if ov.profileProjectID == "" {
		ov.profileProjectID = testProjectID
	}
	if ov.metadataProjectID == "" {
		ov.metadataProjectID = ov.profileProjectID
	}
	if ov.tokenUnit == "" {
		ov.tokenUnit = "gram"
	}
	if ov.issuanceUnit == "" {
		ov.issuanceUnit = ov.tokenUnit
	}
	if ov.tokenDecimals == 0 {
		ov.tokenDecimals = 9
	}
	if ov.issuanceAmount == "" {
		ov.issuanceAmount = "1000000000000"
	}
	if ov.createdAt.IsZero() {
		ov.createdAt = time.Now().UTC().Add(-1 * time.Hour)
	}
	if ov.validUntil.IsZero() {
		ov.validUntil = ov.createdAt.Add(7 * 24 * time.Hour)
	}

	profileJSON := fmt.Sprintf(`{
  "profileVersion": "1.0",
  "projectId": %q,
  "assetType": "allocated-gold-bar",
  "tokenUnit": %q,
  "tokenDecimals": %d,
  "recordIdLabel": "Bar serial number",
  "displayFields": [
    { "label": "Serial", "pointer": "/serialNumber" }
  ],
  "assetSchema": {
    "type": "object",
    "additionalProperties": false,
    "required": ["serialNumber", "weightGrams", "purity"],
    "properties": {
      "serialNumber": { "type": "string", "minLength": 1 },
      "weightGrams": { "type": "string", "pattern": "^[0-9]+(\\.[0-9]+)?$" },
      "purity": { "type": "string", "pattern": "^[0-9]+(\\.[0-9]+)?$" }
    }
  }
}`, ov.profileProjectID, ov.tokenUnit, ov.tokenDecimals)
	metadataJSON := fmt.Sprintf(`{
  "platformVersion": "1.0",
  "projectId": %q,
  "recordId": "GOLD-BAR-12345",
  "asset": {
    "serialNumber": "12345",
    "weightGrams": "1000",
    "purity": "999.9"
  },
  "issuance": {
    "amount": %q,
    "unit": %q
  },
  "createdAt": %q
}`, ov.metadataProjectID, ov.issuanceAmount, ov.issuanceUnit, ov.createdAt.Format(time.RFC3339))

	profileCanon, err := canonical.Canonicalize([]byte(profileJSON))
	if err != nil {
		t.Fatalf("canonicalizing profile: %v", err)
	}
	metadataCanon, err := canonical.Canonicalize([]byte(metadataJSON))
	if err != nil {
		t.Fatalf("canonicalizing metadata: %v", err)
	}
	profileDigest := sha256.Sum256(profileCanon)
	metadataDigest := sha256.Sum256(metadataCanon)
	recordKey := attestation.RecordKey("GOLD-BAR-12345")

	// Generate the auditor keystore.
	priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	dir := t.TempDir()
	// keystore.MinScryptN/P, not gokeystore.LightScryptN/P: the signer
	// enforces a KDF strength floor on every V3 load (internal/keystore/kdf.go),
	// so a "light"-parameter keystore would be rejected before the password
	// is even tried. See TestE2E_RejectsWeakKDFParams for the negative case.
	ks := gokeystore.NewKeyStore(dir, rwakeystore.MinScryptN, rwakeystore.MinScryptP)
	const password = "e2e-test-password"
	account, err := ks.ImportECDSA(priv, password)
	if err != nil {
		t.Fatalf("ImportECDSA: %v", err)
	}

	typedData := map[string]any{
		"chain":       "solana",
		"primaryType": "MintAttestation",
		"domain": map[string]any{
			"name":    attestation.DomainName,
			"version": attestation.DomainVersion,
			"cluster": cluster,
			"program": program,
			"config":  config,
		},
		"message": map[string]any{
			"auditor":        account.Address.Hex(),
			"profileDigest":  "0x" + hex.EncodeToString(profileDigest[:]),
			"recordId":       "GOLD-BAR-12345",
			"recordKey":      "0x" + hex.EncodeToString(recordKey[:]),
			"metadataDigest": "0x" + hex.EncodeToString(metadataDigest[:]),
			"amount":         ov.issuanceAmount,
			"nonce":          testNonceHex,
			"validUntil":     ov.validUntil.Unix(),
			"vault":          vault,
		},
	}
	if ov.mutateTypedData != nil {
		ov.mutateTypedData(typedData)
	}
	typedDataJSON, err := json.Marshal(typedData)
	if err != nil {
		t.Fatalf("marshaling typed-data.json: %v", err)
	}

	fileEntry := func(name string, data []byte, mime string) map[string]any {
		sum := sha256.Sum256(data)
		return map[string]any{
			"path":   name,
			"sha256": hex.EncodeToString(sum[:]),
			"size":   len(data),
			"mime":   mime,
		}
	}
	manifest := map[string]any{
		"packageVersion": "1.0",
		"primaryType":    "MintAttestation",
		"profileDigest":  "0x" + hex.EncodeToString(profileDigest[:]),
		"metadataDigest": "0x" + hex.EncodeToString(metadataDigest[:]),
		"files": []map[string]any{
			fileEntry("profile.json", profileCanon, "application/json"),
			fileEntry("metadata.json", metadataCanon, "application/json"),
			fileEntry("typed-data.json", typedDataJSON, "application/json"),
		},
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshaling manifest.json: %v", err)
	}

	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	for name, data := range map[string][]byte{
		"manifest.json":   manifestJSON,
		"profile.json":    profileCanon,
		"metadata.json":   metadataCanon,
		"typed-data.json": typedDataJSON,
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zw.Create(%q): %v", name, err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatalf("writing %q: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zw.Close: %v", err)
	}

	return builtPackage{
		zipBytes:      zipBuf.Bytes(),
		keystorePath:  account.URL.Path,
		password:      password,
		auditorAddr:   account.Address.Hex(),
		profileDigest: "0x" + hex.EncodeToString(profileDigest[:]),

		metadataDigest: "0x" + hex.EncodeToString(metadataDigest[:]),
		recordKey:      "0x" + hex.EncodeToString(recordKey[:]),
		amount:         ov.issuanceAmount,
		validUntil:     ov.validUntil.Unix(),
		typedDataJSON:  typedDataJSON,
	}
}

// writePolicyFile writes a Solana policy JSON file matching pkg's real
// values (cluster/program/config/vault/auditor/projectId/profileDigest)
// into dir, returning its path. projectID lets a test target a specific
// profile (buildPackageWithOverrides can desync profile/metadata
// projectIds, so the caller decides which one the policy should
// independently pin).
func writePolicyFile(t *testing.T, dir, cluster, program, config, vault, projectID string, pkg builtPackage) string {
	t.Helper()
	return writePolicyFileWithOverrides(t, dir, cluster, program, config, vault, pkg.auditorAddr, projectID, pkg.profileDigest, "")
}

// writePolicyFileWithOverrides is writePolicyFile generalized so a test can
// deliberately mismatch one field or set a custom
// maxAttestationLifetimeHours.
func writePolicyFileWithOverrides(t *testing.T, dir, cluster, program, config, vault, auditor, projectID, profileDigest, maxLifetimeHours string) string {
	t.Helper()
	pol := map[string]any{
		"cluster":       cluster,
		"program":       program,
		"config":        config,
		"vault":         vault,
		"auditor":       auditor,
		"projectId":     projectID,
		"profileDigest": profileDigest,
	}
	if maxLifetimeHours != "" {
		pol["maxAttestationLifetimeHours"] = json.Number(maxLifetimeHours)
	}
	raw, err := json.Marshal(pol)
	if err != nil {
		t.Fatalf("marshaling policy file: %v", err)
	}
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("writing policy file: %v", err)
	}
	return path
}

// writeJSONFile marshals v as JSON and writes it to dir/name, returning its
// path.
func writeJSONFile(t *testing.T, dir, name string, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshaling %s: %v", name, err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return path
}
