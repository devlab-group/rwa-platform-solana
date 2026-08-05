package main

import (
	"archive/zip"
	"bytes"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	gokeystore "github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/crypto"
	rwakeystore "github.com/rwa-platform/signer/internal/keystore"
)

// This file covers "signer sign" behavior that is chain-independent --
// manifest/file agreement, the profile/metadata cross-document binding,
// keystore handling, and the audit trail -- as opposed to e2e_test.go,
// which covers the Solana domain and typed-data checks specifically.

// TestE2E_RejectsTamperedAmount proves the CLI refuses to sign when the
// typed-data amount has been tampered to diverge from metadata's
// issuance.amount -- the mint amount must exactly match the audited amount.
func TestE2E_RejectsTamperedAmount(t *testing.T) {
	goBin := findGoBinary(t)
	binDir := t.TempDir()
	signerBin := buildSignerBinary(t, goBin, binDir)

	pkg := buildGoldenPackage(t, testCluster, testProgram, testConfig, testVault)

	// Tamper: replace the archive's typed-data.json amount post-hoc by
	// re-zipping with a mismatched amount, leaving manifest hashes stale.
	zr, err := zip.NewReader(bytes.NewReader(pkg.zipBytes), int64(len(pkg.zipBytes)))
	if err != nil {
		t.Fatalf("zip.NewReader: %v", err)
	}
	tampered := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("opening %q: %v", f.Name, err)
		}
		buf := new(bytes.Buffer)
		if _, err := buf.ReadFrom(rc); err != nil {
			t.Fatalf("reading %q: %v", f.Name, err)
		}
		rc.Close()
		tampered[f.Name] = buf.Bytes()
	}
	tampered["typed-data.json"] = bytes.ReplaceAll(tampered["typed-data.json"],
		[]byte(pkg.amount), []byte("999999999999999"))

	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	for name, data := range tampered {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zw.Create: %v", err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zw.Close: %v", err)
	}

	workDir := t.TempDir()
	pkgPath := filepath.Join(workDir, "request.rwa")
	if err := os.WriteFile(pkgPath, zipBuf.Bytes(), 0o644); err != nil {
		t.Fatalf("writing package: %v", err)
	}
	policyPath := writePolicyFile(t, workDir, testCluster, testProgram, testConfig, testVault, testProjectID, pkg)

	cmd := exec.Command(signerBin, "sign", pkgPath, "--keystore", pkg.keystorePath, "--policy", policyPath, "--yes", "--unsafe-test-mode")
	cmd.Stdin = strings.NewReader(pkg.password + "\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("expected signer to reject tampered package, but it succeeded\nstdout:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "does not match") {
		t.Errorf("expected a mismatch error, got stderr:\n%s", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(workDir, "signed-result-solana.json")); err == nil {
		t.Error("signed-result-solana.json must not be written when validation fails")
	}
}

// TestE2E_RejectsCrossProjectPackage guards the cross-document binding: if
// the signer validated profile.json and metadata.json independently and never
// checked metadata.projectId == profile.projectId, a package could mint supply
// under one project while the signed metadata described another.
func TestE2E_RejectsCrossProjectPackage(t *testing.T) {
	goBin := findGoBinary(t)
	binDir := t.TempDir()
	signerBin := buildSignerBinary(t, goBin, binDir)

	pkg := buildPackageWithOverrides(t, testCluster, testProgram, testConfig, testVault,
		docOverrides{
			profileProjectID:  testProjectID,
			metadataProjectID: "00000000-0000-0000-0000-000000000000",
		})

	workDir := t.TempDir()
	pkgPath := filepath.Join(workDir, "request.rwa")
	if err := os.WriteFile(pkgPath, pkg.zipBytes, 0o644); err != nil {
		t.Fatalf("writing package: %v", err)
	}
	policyPath := writePolicyFile(t, workDir, testCluster, testProgram, testConfig, testVault, testProjectID, pkg)

	cmd := exec.Command(signerBin, "sign", pkgPath, "--keystore", pkg.keystorePath, "--policy", policyPath, "--yes", "--unsafe-test-mode")
	cmd.Stdin = strings.NewReader(pkg.password + "\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("expected signer to reject a cross-project package, but it succeeded\nstdout:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "projectId") {
		t.Errorf("expected a projectId mismatch error, got stderr:\n%s", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(workDir, "signed-result-solana.json")); err == nil {
		t.Error("signed-result-solana.json must not be written when validation fails")
	}
}

// TestE2E_RejectsWrongIssuanceUnit covers the other half of the binding
// check: metadata.issuance.unit must match profile.tokenUnit.
func TestE2E_RejectsWrongIssuanceUnit(t *testing.T) {
	goBin := findGoBinary(t)
	binDir := t.TempDir()
	signerBin := buildSignerBinary(t, goBin, binDir)

	pkg := buildPackageWithOverrides(t, testCluster, testProgram, testConfig, testVault,
		docOverrides{tokenUnit: "gram", issuanceUnit: "troy-ounce"})

	workDir := t.TempDir()
	pkgPath := filepath.Join(workDir, "request.rwa")
	if err := os.WriteFile(pkgPath, pkg.zipBytes, 0o644); err != nil {
		t.Fatalf("writing package: %v", err)
	}
	policyPath := writePolicyFile(t, workDir, testCluster, testProgram, testConfig, testVault, testProjectID, pkg)

	cmd := exec.Command(signerBin, "sign", pkgPath, "--keystore", pkg.keystorePath, "--policy", policyPath, "--yes", "--unsafe-test-mode")
	cmd.Stdin = strings.NewReader(pkg.password + "\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("expected signer to reject a mismatched issuance unit, but it succeeded\nstdout:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "unit") {
		t.Errorf("expected a unit mismatch error, got stderr:\n%s", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(workDir, "signed-result-solana.json")); err == nil {
		t.Error("signed-result-solana.json must not be written when validation fails")
	}
}

// TestE2E_RejectsWorldReadablePasswordFile checks that a --password-file
// other local accounts can read is refused rather than silently used.
func TestE2E_RejectsWorldReadablePasswordFile(t *testing.T) {
	goBin := findGoBinary(t)
	binDir := t.TempDir()
	signerBin := buildSignerBinary(t, goBin, binDir)

	pkg := buildGoldenPackage(t, testCluster, testProgram, testConfig, testVault)

	workDir := t.TempDir()
	pkgPath := filepath.Join(workDir, "request.rwa")
	if err := os.WriteFile(pkgPath, pkg.zipBytes, 0o644); err != nil {
		t.Fatalf("writing package: %v", err)
	}
	pwPath := filepath.Join(workDir, "password.txt")
	if err := os.WriteFile(pwPath, []byte(pkg.password+"\n"), 0o644); err != nil {
		t.Fatalf("writing password file: %v", err)
	}
	policyPath := writePolicyFile(t, workDir, testCluster, testProgram, testConfig, testVault, testProjectID, pkg)

	cmd := exec.Command(signerBin, "sign", pkgPath, "--keystore", pkg.keystorePath, "--policy", policyPath, "--yes", "--unsafe-test-mode", "--password-file", pwPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("expected signer to reject a world-readable --password-file, but it succeeded\nstdout:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "readable") {
		t.Errorf("expected a group/world-readable password-file error, got stderr:\n%s", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(workDir, "signed-result-solana.json")); err == nil {
		t.Error("signed-result-solana.json must not be written when the password file is rejected")
	}
}

// TestE2E_RejectsWeakKDFParams checks that a V3 keystore encrypted with
// parameters below the signer's policy floor is refused before the password
// is ever tried, not merely "discouraged".
func TestE2E_RejectsWeakKDFParams(t *testing.T) {
	goBin := findGoBinary(t)
	binDir := t.TempDir()
	signerBin := buildSignerBinary(t, goBin, binDir)

	pkg := buildGoldenPackage(t, testCluster, testProgram, testConfig, testVault)

	// Re-encrypt the same key with go-ethereum's "light" scrypt parameters
	// (N=2^12), well below MinScryptN (2^17), instead of using pkg's own
	// (policy-strength) keystore.
	weakDir := t.TempDir()
	keyJSON, err := os.ReadFile(pkg.keystorePath)
	if err != nil {
		t.Fatalf("reading golden keystore: %v", err)
	}
	key, err := gokeystore.DecryptKey(keyJSON, pkg.password)
	if err != nil {
		t.Fatalf("decrypting golden keystore: %v", err)
	}
	ks := gokeystore.NewKeyStore(weakDir, gokeystore.LightScryptN, gokeystore.LightScryptP)
	account, err := ks.ImportECDSA(key.PrivateKey, pkg.password)
	if err != nil {
		t.Fatalf("ImportECDSA (weak params): %v", err)
	}

	workDir := t.TempDir()
	pkgPath := filepath.Join(workDir, "request.rwa")
	if err := os.WriteFile(pkgPath, pkg.zipBytes, 0o644); err != nil {
		t.Fatalf("writing package: %v", err)
	}
	policyPath := writePolicyFile(t, workDir, testCluster, testProgram, testConfig, testVault, testProjectID, pkg)

	cmd := exec.Command(signerBin, "sign", pkgPath, "--keystore", account.URL.Path, "--policy", policyPath, "--yes", "--unsafe-test-mode")
	cmd.Stdin = strings.NewReader(pkg.password + "\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("expected signer to reject a weak-KDF-parameter keystore, but it succeeded\nstdout:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "weaker than the minimum policy") {
		t.Errorf("expected a KDF-strength policy error, got stderr:\n%s", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(workDir, "signed-result-solana.json")); err == nil {
		t.Error("signed-result-solana.json must not be written when the keystore's KDF parameters are rejected")
	}
}

// TestE2E_SignsWithNativeKeystoreFormat proves the signer's own Argon2id
// keystore format (internal/keystore/native.go, "rwa-argon2id-v1") is a
// fully working alternative to a standard V3 file behind the same
// --keystore flag, with no format flag needed.
func TestE2E_SignsWithNativeKeystoreFormat(t *testing.T) {
	goBin := findGoBinary(t)
	binDir := t.TempDir()
	signerBin := buildSignerBinary(t, goBin, binDir)

	pkg := buildGoldenPackage(t, testCluster, testProgram, testConfig, testVault)

	keyJSON, err := os.ReadFile(pkg.keystorePath)
	if err != nil {
		t.Fatalf("reading golden keystore: %v", err)
	}
	key, err := gokeystore.DecryptKey(keyJSON, pkg.password)
	if err != nil {
		t.Fatalf("decrypting golden keystore: %v", err)
	}
	nativeJSON, err := rwakeystore.CreateNative(key.PrivateKey, "a-strong-argon2id-password")
	if err != nil {
		t.Fatalf("CreateNative: %v", err)
	}
	workDir := t.TempDir()
	nativePath := filepath.Join(workDir, "auditor.native.json")
	if err := os.WriteFile(nativePath, nativeJSON, 0o600); err != nil {
		t.Fatalf("writing native keystore: %v", err)
	}

	pkgPath := filepath.Join(workDir, "request.rwa")
	if err := os.WriteFile(pkgPath, pkg.zipBytes, 0o644); err != nil {
		t.Fatalf("writing package: %v", err)
	}
	policyPath := writePolicyFile(t, workDir, testCluster, testProgram, testConfig, testVault, testProjectID, pkg)

	cmd := exec.Command(signerBin, "sign", pkgPath, "--keystore", nativePath, "--policy", policyPath, "--yes", "--unsafe-test-mode")
	cmd.Stdin = strings.NewReader("a-strong-argon2id-password\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("signer sign (native keystore) failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(workDir, "signed-result-solana.json")); err != nil {
		t.Errorf("expected signed-result-solana.json: %v", err)
	}
}

// TestE2E_NeverExportsPrivateKey checks that the signer exports only the
// signed result and public metadata, never the private key. It signs a real
// package with a real key and asserts the raw private-key hex appears
// nowhere in the process's stdout/stderr or in signed-result-solana.json --
// the only channels through which key material could leak out to the
// (non-air-gapped) side of the transfer medium.
func TestE2E_NeverExportsPrivateKey(t *testing.T) {
	goBin := findGoBinary(t)
	binDir := t.TempDir()
	signerBin := buildSignerBinary(t, goBin, binDir)

	pkg := buildGoldenPackage(t, testCluster, testProgram, testConfig, testVault)

	keyJSON, err := os.ReadFile(pkg.keystorePath)
	if err != nil {
		t.Fatalf("reading golden keystore: %v", err)
	}
	key, err := gokeystore.DecryptKey(keyJSON, pkg.password)
	if err != nil {
		t.Fatalf("decrypting golden keystore: %v", err)
	}
	privHex := hex.EncodeToString(crypto.FromECDSA(key.PrivateKey))

	workDir := t.TempDir()
	pkgPath := filepath.Join(workDir, "request.rwa")
	if err := os.WriteFile(pkgPath, pkg.zipBytes, 0o644); err != nil {
		t.Fatalf("writing package: %v", err)
	}
	policyPath := writePolicyFile(t, workDir, testCluster, testProgram, testConfig, testVault, testProjectID, pkg)

	cmd := exec.Command(signerBin, "sign", pkgPath, "--keystore", pkg.keystorePath, "--policy", policyPath, "--yes", "--unsafe-test-mode")
	cmd.Stdin = strings.NewReader(pkg.password + "\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("signer sign failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}

	resultData, err := os.ReadFile(filepath.Join(workDir, "signed-result-solana.json"))
	if err != nil {
		t.Fatalf("reading signed-result-solana.json: %v", err)
	}

	if strings.Contains(stdout.String(), privHex) {
		t.Error("private key hex found in stdout")
	}
	if strings.Contains(stderr.String(), privHex) {
		t.Error("private key hex found in stderr")
	}
	if strings.Contains(string(resultData), privHex) {
		t.Error("private key hex found in signed-result-solana.json")
	}
}

// TestE2E_SignWritesVerifiableAuditTrail checks that a real signing run
// through the CLI leaves behind a main audit log and anchor log that
// VerifyAuditLogAnchored accepts, with unlock_success and signed events
// recorded.
func TestE2E_SignWritesVerifiableAuditTrail(t *testing.T) {
	goBin := findGoBinary(t)
	binDir := t.TempDir()
	signerBin := buildSignerBinary(t, goBin, binDir)

	pkg := buildGoldenPackage(t, testCluster, testProgram, testConfig, testVault)
	workDir := t.TempDir()
	pkgPath := filepath.Join(workDir, "request.rwa")
	if err := os.WriteFile(pkgPath, pkg.zipBytes, 0o644); err != nil {
		t.Fatalf("writing package: %v", err)
	}
	policyPath := writePolicyFile(t, workDir, testCluster, testProgram, testConfig, testVault, testProjectID, pkg)

	cmd := exec.Command(signerBin, "sign", pkgPath, "--keystore", pkg.keystorePath, "--policy", policyPath, "--yes", "--unsafe-test-mode")
	cmd.Stdin = strings.NewReader(pkg.password + "\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("signer sign failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}

	if err := rwakeystore.VerifyAuditLogAnchored(pkg.keystorePath, rwakeystore.DefaultAnchorPath(pkg.keystorePath)); err != nil {
		t.Errorf("expected the audit trail written by a real sign to verify: %v", err)
	}
	logData, err := os.ReadFile(pkg.keystorePath + ".auditlog.jsonl")
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	for _, want := range []string{`"event":"unlock_success"`, `"event":"signed"`} {
		if !strings.Contains(string(logData), want) {
			t.Errorf("audit log missing %s:\n%s", want, logData)
		}
	}
}

// TestE2E_RefusesToSignWhenAuditLogIsCorrupted checks that the whole chain is
// verified before unlock/sign, not just the last append: a keystore whose
// pre-existing audit log has been corrupted refuses to sign at all -- it must
// not simply extend the broken chain with a fresh-looking entry.
func TestE2E_RefusesToSignWhenAuditLogIsCorrupted(t *testing.T) {
	goBin := findGoBinary(t)
	binDir := t.TempDir()
	signerBin := buildSignerBinary(t, goBin, binDir)

	pkg := buildGoldenPackage(t, testCluster, testProgram, testConfig, testVault)
	workDir := t.TempDir()
	pkgPath := filepath.Join(workDir, "request.rwa")
	if err := os.WriteFile(pkgPath, pkg.zipBytes, 0o644); err != nil {
		t.Fatalf("writing package: %v", err)
	}
	policyPath := writePolicyFile(t, workDir, testCluster, testProgram, testConfig, testVault, testProjectID, pkg)

	corrupted := []byte(`{"seq":1,"time":"2020-01-01T00:00:00Z","event":"unlock_success","prevHash":"","hash":"0000000000000000000000000000000000000000000000000000000000000000"}` + "\n")
	if err := os.WriteFile(pkg.keystorePath+".auditlog.jsonl", corrupted, 0o600); err != nil {
		t.Fatalf("writing pre-corrupted audit log: %v", err)
	}

	cmd := exec.Command(signerBin, "sign", pkgPath, "--keystore", pkg.keystorePath, "--policy", policyPath, "--yes", "--unsafe-test-mode")
	cmd.Stdin = strings.NewReader(pkg.password + "\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("expected signer to refuse to sign against a corrupted audit log\nstdout:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "audit log integrity") {
		t.Errorf("unexpected error, stderr:\n%s", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(workDir, "signed-result-solana.json")); err == nil {
		t.Error("signed-result-solana.json must not be written when the audit log is corrupted")
	}
}

// TestE2E_ProductionFailsClosedWhenAuditLogCannotBeWritten checks the
// fail-closed path: outside --unsafe-test-mode, a signing attempt whose
// audit-log write cannot be durably recorded must fail rather than silently
// proceeding to write signed-result-solana.json. A directory the process
// cannot write into is used as a portable stand-in for a disk-full
// condition, the same way TestAuditLog_AppendFailsOnUnwritableDirectory uses
// it in internal/keystore.
func TestE2E_ProductionFailsClosedWhenAuditLogCannotBeWritten(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permission bits do not work the same way on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root ignores permission bits, so this can't be exercised here")
	}
	goBin := findGoBinary(t)
	binDir := t.TempDir()
	signerBin := buildSignerBinary(t, goBin, binDir)

	pkg := buildGoldenPackage(t, testCluster, testProgram, testConfig, testVault)
	workDir := t.TempDir()
	pkgPath := filepath.Join(workDir, "request.rwa")
	if err := os.WriteFile(pkgPath, pkg.zipBytes, 0o644); err != nil {
		t.Fatalf("writing package: %v", err)
	}
	policyPath := writePolicyFile(t, workDir, testCluster, testProgram, testConfig, testVault, testProjectID, pkg)

	keystoreDir := filepath.Dir(pkg.keystorePath)
	if err := os.Chmod(keystoreDir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { os.Chmod(keystoreDir, 0o700) }) // let t.TempDir() clean up afterward

	// Deliberately NOT --unsafe-test-mode: this test is specifically about
	// production (fail-closed) behavior, so confirmation is driven via
	// stdin instead of --yes.
	cmd := exec.Command(signerBin, "sign", pkgPath, "--keystore", pkg.keystorePath, "--policy", policyPath)
	cmd.Stdin = strings.NewReader("y\n" + pkg.password + "\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("expected signer to fail closed when it cannot durably record the audit trail\nstdout:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "audit") {
		t.Errorf("expected an audit-trail-related error, got stderr:\n%s", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(workDir, "signed-result-solana.json")); err == nil {
		t.Error("signed-result-solana.json must not be written when the audit trail cannot be recorded (production/fail-closed)")
	}
}

// TestE2E_RejectsYesWithoutUnsafeTestMode checks that --yes alone does not
// silently skip the human confirmation step.
func TestE2E_RejectsYesWithoutUnsafeTestMode(t *testing.T) {
	goBin := findGoBinary(t)
	binDir := t.TempDir()
	signerBin := buildSignerBinary(t, goBin, binDir)

	pkg := buildGoldenPackage(t, testCluster, testProgram, testConfig, testVault)

	workDir := t.TempDir()
	pkgPath := filepath.Join(workDir, "request.rwa")
	if err := os.WriteFile(pkgPath, pkg.zipBytes, 0o644); err != nil {
		t.Fatalf("writing package: %v", err)
	}
	policyPath := writePolicyFile(t, workDir, testCluster, testProgram, testConfig, testVault, testProjectID, pkg)

	cmd := exec.Command(signerBin, "sign", pkgPath, "--keystore", pkg.keystorePath, "--policy", policyPath, "--yes")
	cmd.Stdin = strings.NewReader(pkg.password + "\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("expected signer to reject --yes without --unsafe-test-mode, but it succeeded\nstdout:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "unsafe-test-mode") {
		t.Errorf("expected an --unsafe-test-mode error, got stderr:\n%s", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(workDir, "signed-result-solana.json")); err == nil {
		t.Error("signed-result-solana.json must not be written when validation fails")
	}
}

// TestE2E_RejectsPolicyProjectIDMismatch checks that the signer rejects a
// package whose profile.json projectId does not match the operator's
// independently-provisioned policy, even when the package is otherwise
// internally self-consistent -- a defense the cross-document binding check
// alone does not provide, since a wholly self-consistent but wrong-project
// package would otherwise sign cleanly.
func TestE2E_RejectsPolicyProjectIDMismatch(t *testing.T) {
	goBin := findGoBinary(t)
	binDir := t.TempDir()
	signerBin := buildSignerBinary(t, goBin, binDir)

	pkg := buildGoldenPackage(t, testCluster, testProgram, testConfig, testVault)

	workDir := t.TempDir()
	pkgPath := filepath.Join(workDir, "request.rwa")
	if err := os.WriteFile(pkgPath, pkg.zipBytes, 0o644); err != nil {
		t.Fatalf("writing package: %v", err)
	}
	policyPath := writePolicyFile(t, workDir, testCluster, testProgram, testConfig, testVault, "11111111-1111-1111-1111-111111111111", pkg)

	cmd := exec.Command(signerBin, "sign", pkgPath, "--keystore", pkg.keystorePath, "--policy", policyPath, "--yes", "--unsafe-test-mode")
	cmd.Stdin = strings.NewReader(pkg.password + "\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("expected signer to reject a policy projectId mismatch, but it succeeded\nstdout:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "policy projectId") {
		t.Errorf("expected a policy projectId mismatch error, got stderr:\n%s", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(workDir, "signed-result-solana.json")); err == nil {
		t.Error("signed-result-solana.json must not be written when validation fails")
	}
}

// TestE2E_RejectsExpiredValidUntil checks that a typed-data validUntil that
// has already passed is rejected, not merely displayed for the auditor to
// notice.
func TestE2E_RejectsExpiredValidUntil(t *testing.T) {
	goBin := findGoBinary(t)
	binDir := t.TempDir()
	signerBin := buildSignerBinary(t, goBin, binDir)

	createdAt := time.Now().UTC().Add(-48 * time.Hour)
	pkg := buildPackageWithOverrides(t, testCluster, testProgram, testConfig, testVault, docOverrides{
		createdAt:  createdAt,
		validUntil: createdAt.Add(1 * time.Hour), // in the past relative to "now"
	})

	workDir := t.TempDir()
	pkgPath := filepath.Join(workDir, "request.rwa")
	if err := os.WriteFile(pkgPath, pkg.zipBytes, 0o644); err != nil {
		t.Fatalf("writing package: %v", err)
	}
	policyPath := writePolicyFile(t, workDir, testCluster, testProgram, testConfig, testVault, testProjectID, pkg)

	cmd := exec.Command(signerBin, "sign", pkgPath, "--keystore", pkg.keystorePath, "--policy", policyPath, "--yes", "--unsafe-test-mode")
	cmd.Stdin = strings.NewReader(pkg.password + "\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("expected signer to reject an expired validUntil, but it succeeded\nstdout:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "validUntil") {
		t.Errorf("expected a validUntil error, got stderr:\n%s", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(workDir, "signed-result-solana.json")); err == nil {
		t.Error("signed-result-solana.json must not be written when validation fails")
	}
}

// TestE2E_RejectsFarFutureValidUntil covers the other end of the horizon:
// a validUntil beyond the maximum attestation lifetime must be rejected,
// even though it is technically still "in the future."
func TestE2E_RejectsFarFutureValidUntil(t *testing.T) {
	goBin := findGoBinary(t)
	binDir := t.TempDir()
	signerBin := buildSignerBinary(t, goBin, binDir)

	createdAt := time.Now().UTC().Add(-1 * time.Hour)
	pkg := buildPackageWithOverrides(t, testCluster, testProgram, testConfig, testVault, docOverrides{
		createdAt:  createdAt,
		validUntil: createdAt.Add(60 * 24 * time.Hour), // 60 days: exceeds the 30-day default policy horizon
	})

	workDir := t.TempDir()
	pkgPath := filepath.Join(workDir, "request.rwa")
	if err := os.WriteFile(pkgPath, pkg.zipBytes, 0o644); err != nil {
		t.Fatalf("writing package: %v", err)
	}
	policyPath := writePolicyFile(t, workDir, testCluster, testProgram, testConfig, testVault, testProjectID, pkg)

	cmd := exec.Command(signerBin, "sign", pkgPath, "--keystore", pkg.keystorePath, "--policy", policyPath, "--yes", "--unsafe-test-mode")
	cmd.Stdin = strings.NewReader(pkg.password + "\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("expected signer to reject a far-future validUntil, but it succeeded\nstdout:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "exceeds the maximum attestation lifetime") {
		t.Errorf("expected a max-lifetime error, got stderr:\n%s", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(workDir, "signed-result-solana.json")); err == nil {
		t.Error("signed-result-solana.json must not be written when validation fails")
	}
}

// TestE2E_AcceptsExtendedLifetimePolicy proves a policy file's
// maxAttestationLifetimeHours override is actually honored: a validUntil
// that would fail the 30-day default must succeed once the policy grants a
// longer horizon -- the policy file's ceiling is a real override, not a fixed
// cap dressed up as configurable.
func TestE2E_AcceptsExtendedLifetimePolicy(t *testing.T) {
	goBin := findGoBinary(t)
	binDir := t.TempDir()
	signerBin := buildSignerBinary(t, goBin, binDir)

	createdAt := time.Now().UTC().Add(-1 * time.Hour)
	pkg := buildPackageWithOverrides(t, testCluster, testProgram, testConfig, testVault, docOverrides{
		createdAt:  createdAt,
		validUntil: createdAt.Add(60 * 24 * time.Hour), // 60 days: fine under a 90-day policy
	})

	workDir := t.TempDir()
	pkgPath := filepath.Join(workDir, "request.rwa")
	if err := os.WriteFile(pkgPath, pkg.zipBytes, 0o644); err != nil {
		t.Fatalf("writing package: %v", err)
	}
	policyPath := writePolicyFileWithOverrides(t, workDir, testCluster, testProgram, testConfig, testVault, pkg.auditorAddr, testProjectID, pkg.profileDigest, "2160" /* 90 days */)

	cmd := exec.Command(signerBin, "sign", pkgPath, "--keystore", pkg.keystorePath, "--policy", policyPath, "--yes", "--unsafe-test-mode")
	cmd.Stdin = strings.NewReader(pkg.password + "\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("signer sign failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(workDir, "signed-result-solana.json")); err != nil {
		t.Errorf("expected signed-result-solana.json to be written: %v", err)
	}
}

// TestE2E_RequiresPolicyFlag checks that the signer refuses to sign an
// otherwise-perfect package if the operator forgot --policy entirely, rather
// than falling back to trusting the package's own values.
func TestE2E_RequiresPolicyFlag(t *testing.T) {
	goBin := findGoBinary(t)
	binDir := t.TempDir()
	signerBin := buildSignerBinary(t, goBin, binDir)

	pkg := buildGoldenPackage(t, testCluster, testProgram, testConfig, testVault)

	workDir := t.TempDir()
	pkgPath := filepath.Join(workDir, "request.rwa")
	if err := os.WriteFile(pkgPath, pkg.zipBytes, 0o644); err != nil {
		t.Fatalf("writing package: %v", err)
	}

	cmd := exec.Command(signerBin, "sign", pkgPath, "--keystore", pkg.keystorePath, "--yes", "--unsafe-test-mode")
	cmd.Stdin = strings.NewReader(pkg.password + "\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatalf("expected signer to refuse to run without --policy, but it succeeded\nstdout:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "--policy is required") {
		t.Errorf("expected a --policy-required error, got stderr:\n%s", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(workDir, "signed-result-solana.json")); err == nil {
		t.Error("signed-result-solana.json must not be written when validation fails")
	}
}
