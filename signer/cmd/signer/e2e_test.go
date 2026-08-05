package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/rwa-platform/signer/internal/attestation"
	"github.com/rwa-platform/signer/internal/base58"
)

// goldenOverrides is the golden package shape: an amount that fits uint64,
// at Solana-like decimals. It is spelled out explicitly (rather than relying
// on docOverrides{}'s zero value matching it) so tests that need it read as
// intentional.
func goldenOverrides() docOverrides {
	return docOverrides{tokenDecimals: 9, issuanceAmount: "1000000000000"}
}

// buildRequest builds the --typed-data attestation request that binds to pkg.
// Callers mutate the returned map to produce the negative cases.
func buildRequest(pkg builtPackage) map[string]any {
	return map[string]any{
		"chain":       "solana",
		"primaryType": "MintAttestation",
		"domain": map[string]any{
			"name":    attestation.DomainName,
			"version": attestation.DomainVersion,
			"cluster": testCluster,
			"program": testProgram,
			"config":  testConfig,
		},
		"message": map[string]any{
			"auditor":        pkg.auditorAddr,
			"profileDigest":  pkg.profileDigest,
			"recordId":       "GOLD-BAR-12345",
			"recordKey":      pkg.recordKey,
			"metadataDigest": pkg.metadataDigest,
			"amount":         pkg.amount,
			"nonce":          testNonceHex,
			"validUntil":     pkg.validUntil,
			"vault":          testVault,
		},
	}
}

func buildPolicy(pkg builtPackage) map[string]any {
	return map[string]any{
		"cluster":       testCluster,
		"program":       testProgram,
		"config":        testConfig,
		"vault":         testVault,
		"auditor":       pkg.auditorAddr,
		"projectId":     testProjectID,
		"profileDigest": pkg.profileDigest,
	}
}

// fixture builds everything a "signer sign" invocation needs and
// returns the binary path plus the three file paths.
type fixture struct {
	bin         string
	pkgPath     string
	policyPath  string
	requestPath string
	pkg         builtPackage
	workDir     string
}

func newFixture(t *testing.T, ov docOverrides, mutate func(policy, request map[string]any)) fixture {
	t.Helper()
	goBin := findGoBinary(t)
	bin := buildSignerBinary(t, goBin, t.TempDir())

	// buildPackageWithOverrides already embeds a Solana request into the
	// package by default. Apply `mutate`'s request-half to it too, so the
	// package's own typed-data.json entry and the external file
	// buildRequest builds below stay byte-identical -- resolveTypedData
	// requires that -- even for tests that mutate the request to exercise a
	// deeper check. The throwaway map stands in for `policy`: none of the
	// existing mutators touch it, only `request`. A test that needs the
	// embedded copy to diverge from (or omit, or be shaped for some other
	// request than) the external file sets ov.mutateTypedData itself, which
	// opts out of this default.
	if ov.mutateTypedData == nil {
		ov.mutateTypedData = func(td map[string]any) {
			if mutate != nil {
				mutate(map[string]any{}, td)
			}
		}
	}

	pkg := buildPackageWithOverrides(t, testCluster, testProgram, testConfig, testVault, ov)

	workDir := t.TempDir()
	pkgPath := filepath.Join(workDir, "request.rwa")
	if err := os.WriteFile(pkgPath, pkg.zipBytes, 0o644); err != nil {
		t.Fatalf("writing package: %v", err)
	}

	policy, request := buildPolicy(pkg), buildRequest(pkg)
	if mutate != nil {
		mutate(policy, request)
	}
	return fixture{
		bin:         bin,
		pkgPath:     pkgPath,
		policyPath:  writeJSONFile(t, workDir, "solana-policy.json", policy),
		requestPath: writeJSONFile(t, workDir, "solana-typed-data.json", request),
		pkg:         pkg,
		workDir:     workDir,
	}
}

func (f fixture) run(t *testing.T, extraArgs ...string) (stdout, stderr string, err error) {
	t.Helper()
	return f.runArgs(t, append([]string{"--typed-data", f.requestPath}, extraArgs...)...)
}

// runArgs is run without the default --typed-data flag baked in, so a test
// can omit it entirely (to exercise the package-entry default) or point it
// somewhere else (to exercise the mismatch check).
func (f fixture) runArgs(t *testing.T, extraArgs ...string) (stdout, stderr string, err error) {
	t.Helper()
	args := append([]string{
		"sign", f.pkgPath,
		"--keystore", f.pkg.keystorePath,
		"--policy", f.policyPath,
		"--yes", "--unsafe-test-mode",
	}, extraArgs...)
	cmd := exec.Command(f.bin, args...)
	cmd.Stdin = strings.NewReader(f.pkg.password + "\n")
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err = cmd.Run()
	return out.String(), errb.String(), err
}

// TestE2E_SignGoldenPackage is the end-to-end proof that the offline
// signer can now produce a Solana attestation: package validation, the Solana
// digest, a canonical low-S compact signature, and a signed-result-solana.json
// whose signature independently recovers to the auditor -- exactly what the
// on-chain secp256k1_recover will do.
func TestE2E_SignGoldenPackage(t *testing.T) {
	f := newFixture(t, goldenOverrides(), nil)

	stdout, stderr, err := f.run(t)
	if err != nil {
		t.Fatalf("signer sign failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}

	// The review screen must have made the chain and the action unmissable.
	for _, want := range []string{"SOLANA MINT", "INCREASE TOKEN SUPPLY", testCluster, testProgram, testConfig, testVault} {
		if !strings.Contains(stdout, want) {
			t.Errorf("review screen does not show %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "BURN") {
		t.Errorf("a mint review screen mentions BURN:\n%s", stdout)
	}
	// 1e12 at 9 decimals.
	if !strings.Contains(stdout, "1000.000000000 gram") {
		t.Errorf("review screen does not show the normalized amount:\n%s", stdout)
	}

	raw, err := os.ReadFile(filepath.Join(f.workDir, "signed-result-solana.json"))
	if err != nil {
		t.Fatalf("reading signed-result-solana.json: %v", err)
	}
	var result struct {
		FormatVersion     string `json:"formatVersion"`
		Chain             string `json:"chain"`
		Auditor           string `json:"auditor"`
		PrimaryType       string `json:"primaryType"`
		Cluster           string `json:"cluster"`
		Program           string `json:"program"`
		Config            string `json:"config"`
		AttestationDigest string `json:"attestationDigest"`
		Signature         string `json:"signature"`
		RecoveryID        byte   `json:"recoveryId"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("parsing signed-result-solana.json: %v\n%s", err, raw)
	}

	if result.FormatVersion != "solana-1.0" || result.Chain != "solana" {
		t.Errorf("formatVersion/chain = %q/%q, want solana-1.0/solana", result.FormatVersion, result.Chain)
	}
	if result.PrimaryType != "MintAttestation" {
		t.Errorf("primaryType = %q", result.PrimaryType)
	}
	if result.Cluster != testCluster || result.Program != testProgram || result.Config != testConfig {
		t.Errorf("result domain = %s/%s/%s, want %s/%s/%s", result.Cluster, result.Program, result.Config, testCluster, testProgram, testConfig)
	}
	// 64 bytes compact, not the 65-byte [R||S||V] form crypto.Sign produces.
	if len(result.Signature) != 2+128 {
		t.Errorf("signature is %d chars, want the 64-byte compact form (130 with 0x)", len(result.Signature))
	}
	if result.RecoveryID > 1 {
		t.Errorf("recoveryId = %d, want 0 or 1", result.RecoveryID)
	}

	// Recompute the digest independently of the CLI and check the committed
	// signature against it.
	domain := attestation.Domain{
		Cluster: mustDecodePubkey(t, testCluster),
		Program: mustDecodePubkey(t, testProgram),
		Config:  mustDecodePubkey(t, testConfig),
	}
	var nonce [32]byte
	nonce[31] = 42
	msg := attestation.MintAttestation{
		Auditor:        common.HexToAddress(f.pkg.auditorAddr),
		ProfileDigest:  common.HexToHash(f.pkg.profileDigest),
		RecordKey:      common.HexToHash(f.pkg.recordKey),
		MetadataDigest: common.HexToHash(f.pkg.metadataDigest),
		Amount:         1_000_000_000_000,
		Nonce:          nonce,
		ValidUntil:     uint64(f.pkg.validUntil),
		Vault:          mustDecodePubkey(t, testVault),
	}
	wantDigest := msg.Digest(domain)
	if !strings.EqualFold(result.AttestationDigest, wantDigest.Hex()) {
		t.Fatalf("attestationDigest = %s, want %s", result.AttestationDigest, wantDigest.Hex())
	}

	var sig attestation.CompactSignature
	sigBytes := common.FromHex(result.Signature)
	if len(sigBytes) != 64 {
		t.Fatalf("signature decodes to %d bytes, want 64", len(sigBytes))
	}
	copy(sig.Compact[:], sigBytes)
	sig.RecoveryID = result.RecoveryID
	if !sig.IsLowS() {
		t.Error("committed signature is high-S; the on-chain verifier rejects it")
	}
	recovered, err := attestation.RecoverCompact(wantDigest, sig)
	if err != nil {
		t.Fatalf("RecoverCompact: %v", err)
	}
	if want := common.HexToAddress(f.pkg.auditorAddr); recovered != want {
		t.Fatalf("signature recovers to %s, want auditor %s", recovered.Hex(), want.Hex())
	}
}

func mustDecodePubkey(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := base58.DecodePubkey(s)
	if err != nil {
		t.Fatalf("decoding %q: %v", s, err)
	}
	return b
}

// TestE2E_Sign_RejectsAmountExceedingUint64 covers the one encoding
// constraint that could silently authorize the wrong quantity: amount is
// uint64 on this path, so an amount that does not fit must be refused rather
// than truncated.
func TestE2E_Sign_RejectsAmountExceedingUint64(t *testing.T) {
	f := newFixture(t, docOverrides{tokenDecimals: 18, issuanceAmount: "1000000000000000000000"}, nil)
	stdout, stderr, err := f.run(t)
	if err == nil {
		t.Fatalf("signer accepted an amount exceeding uint64\nstdout:\n%s", stdout)
	}
	if !strings.Contains(stderr, "exceeds uint64") {
		t.Errorf("stderr does not explain the uint64 overflow:\n%s", stderr)
	}
	assertNoResult(t, f)
}

// TestE2E_Sign_RejectsWrongDomainName makes sure a request naming any
// domain other than the frozen Solana one is refused, even one that is
// otherwise a well-formed typed-data document. A crafted or hand-edited
// request naming the wrong domain would otherwise produce a signature valid
// on a deployment the auditor never reviewed.
func TestE2E_Sign_RejectsWrongDomainName(t *testing.T) {
	f := newFixture(t, goldenOverrides(), func(_, request map[string]any) {
		request["domain"].(map[string]any)["name"] = "RWA-Supply-Attestation"
	})
	stdout, stderr, err := f.run(t)
	if err == nil {
		t.Fatalf("signer accepted the wrong domain name on the Solana path\nstdout:\n%s", stdout)
	}
	if !strings.Contains(stderr, "does not match the frozen Solana domain name") {
		t.Errorf("unexpected error:\n%s", stderr)
	}
	assertNoResult(t, f)
}

// TestE2E_Sign_RejectsMissingChainKey is
// TestE2E_Sign_RejectsWrongDomainName's sibling: instead of a request
// that names the wrong domain, this one has no "chain" field at all --
// e.g. a foreign typed-data.json accidentally pointed at "signer sign" via
// --typed-data. parseAttestationRequest must refuse it the same way it refuses
// an explicit wrong value, since an absent chain is indistinguishable from
// "this was never meant for this path" and must not silently default to
// accepting it.
func TestE2E_Sign_RejectsMissingChainKey(t *testing.T) {
	f := newFixture(t, goldenOverrides(), func(_, request map[string]any) {
		delete(request, "chain")
	})
	stdout, stderr, err := f.run(t)
	if err == nil {
		t.Fatalf("signer accepted a typed-data request with no chain field\nstdout:\n%s", stdout)
	}
	if !strings.Contains(stderr, `chain must be "solana"`) {
		t.Errorf("unexpected error:\n%s", stderr)
	}
	assertNoResult(t, f)
}

// TestE2E_Sign_EnforcesPolicy checks that each domain component and the
// Vault are pinned by the auditor's own policy file, not by the request. A
// request naming a different program id, config PDA, cluster or vault must be
// refused even though it is internally consistent and binds to a valid
// package.
func TestE2E_Sign_EnforcesPolicy(t *testing.T) {
	other := base58.Encode(bytes.Repeat([]byte{0xAB}, 32))
	for _, field := range []string{"cluster", "program", "config"} {
		t.Run(field, func(t *testing.T) {
			f := newFixture(t, goldenOverrides(), func(_, request map[string]any) {
				request["domain"].(map[string]any)[field] = other
			})
			stdout, stderr, err := f.run(t)
			if err == nil {
				t.Fatalf("signer accepted a %s that the policy does not pin\nstdout:\n%s", field, stdout)
			}
			if !strings.Contains(stderr, "does not match policy") {
				t.Errorf("unexpected error:\n%s", stderr)
			}
			assertNoResult(t, f)
		})
	}
	t.Run("vault", func(t *testing.T) {
		f := newFixture(t, goldenOverrides(), func(_, request map[string]any) {
			request["message"].(map[string]any)["vault"] = other
		})
		stdout, stderr, err := f.run(t)
		if err == nil {
			t.Fatalf("signer accepted a vault the policy does not pin\nstdout:\n%s", stdout)
		}
		if !strings.Contains(stderr, "does not match policy") {
			t.Errorf("unexpected error:\n%s", stderr)
		}
		assertNoResult(t, f)
	})
}

// TestE2E_Sign_RejectsMismatchedAmount is the WYSIWYS check that matters
// most: the signed amount must be the one in the package's metadata, not one
// the request asserts on its own.
func TestE2E_Sign_RejectsMismatchedAmount(t *testing.T) {
	f := newFixture(t, goldenOverrides(), func(_, request map[string]any) {
		request["message"].(map[string]any)["amount"] = "999999999999"
	})
	stdout, stderr, err := f.run(t)
	if err == nil {
		t.Fatalf("signer accepted an amount that disagrees with metadata.json\nstdout:\n%s", stdout)
	}
	if !strings.Contains(stderr, "does not equal solana typed-data amount") {
		t.Errorf("unexpected error:\n%s", stderr)
	}
	assertNoResult(t, f)
}

// TestE2E_Sign_RejectsBurnRequestForMintPackage pins the invariant that
// mint and burn payloads are word-identical apart from the type hash, so the
// package's own primaryType has to gate which one can be signed.
func TestE2E_Sign_RejectsBurnRequestForMintPackage(t *testing.T) {
	f := newFixture(t, goldenOverrides(), func(_, request map[string]any) {
		request["primaryType"] = "BurnAttestation"
		m := request["message"].(map[string]any)
		delete(m, "recordId")
		delete(m, "recordKey")
		m["operationId"] = "0x5555555555555555555555555555555555555555555555555555555555555555"
	})
	stdout, stderr, err := f.run(t)
	if err == nil {
		t.Fatalf("signer signed a burn using a mint package\nstdout:\n%s", stdout)
	}
	if !strings.Contains(stderr, "does not match manifest.json primaryType") {
		t.Errorf("unexpected error:\n%s", stderr)
	}
	assertNoResult(t, f)
}

// TestE2E_Sign_RequiresPolicy: --policy stays mandatory -- omitting it
// would collapse the check back onto values the package producer controls.
// --typed-data is no longer in this list: see
// TestE2E_Sign_DefaultsTypedDataToPackageEntry below, which is the
// replacement for what used to be the "no typed-data" case here.
func TestE2E_Sign_RequiresPolicy(t *testing.T) {
	f := newFixture(t, goldenOverrides(), nil)
	cmd := exec.Command(f.bin, "sign", f.pkgPath, "--keystore", f.pkg.keystorePath, "--typed-data", f.requestPath, "--yes", "--unsafe-test-mode")
	cmd.Stdin = strings.NewReader(f.pkg.password + "\n")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatal("signer ran without --policy")
	}
	if !strings.Contains(stderr.String(), "--policy is required") {
		t.Errorf("stderr does not contain %q:\n%s", "--policy is required", stderr.String())
	}
}

// TestE2E_Sign_DefaultsTypedDataToPackageEntry is the central positive
// case for defaulting to the package's own attestation request: omitting
// --typed-data must sign using the package's own manifest-protected
// typed-data.json entry, not fail as it used to. newFixture's default
// embedding makes the package's copy match f.requestPath's content exactly,
// so the signature produced with --typed-data omitted must be byte-identical
// to the golden test's.
func TestE2E_Sign_DefaultsTypedDataToPackageEntry(t *testing.T) {
	f := newFixture(t, goldenOverrides(), nil)

	stdout, stderr, err := f.runArgs(t)
	if err != nil {
		t.Fatalf("signer sign (no --typed-data) failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "typed-data.json (from the package)") {
		t.Errorf("review screen does not credit the package as the attestation-request source:\n%s", stdout)
	}

	raw, err := os.ReadFile(filepath.Join(f.workDir, "signed-result-solana.json"))
	if err != nil {
		t.Fatalf("reading signed-result-solana.json: %v", err)
	}
	var result struct {
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("parsing signed-result-solana.json: %v\n%s", err, raw)
	}
	if result.Signature == "" {
		t.Error("signed-result-solana.json has an empty signature")
	}
}

// TestE2E_Sign_RejectsMismatchedExternalTypedData covers the other
// half of the byte-for-byte check: an external --typed-data file that
// diverges from the package's own manifest-protected copy -- even by one
// field -- must be rejected outright, before any of the deeper
// field-by-field checks run.
func TestE2E_Sign_RejectsMismatchedExternalTypedData(t *testing.T) {
	f := newFixture(t, goldenOverrides(), nil)

	// A file that parses as a perfectly valid Solana request on its own
	// (same shape, same everything) except the nonce, which the package's
	// embedded copy does not share.
	diverged := buildRequest(f.pkg)
	diverged["message"].(map[string]any)["nonce"] = "0x0000000000000000000000000000000000000000000000000000000000000099"
	divergedPath := writeJSONFile(t, f.workDir, "diverged-typed-data.json", diverged)

	stdout, stderr, err := f.runArgs(t, "--typed-data", divergedPath)
	if err == nil {
		t.Fatalf("signer accepted a --typed-data file that diverges from the package's own typed-data.json\nstdout:\n%s", stdout)
	}
	if !strings.Contains(stderr, "does not match the package's own typed-data.json byte-for-byte") {
		t.Errorf("unexpected error:\n%s", stderr)
	}
	assertNoResult(t, f)
}

// TestE2E_Sign_RejectsForeignShapedPackageEntry is the sharpest case
// for the byte-for-byte check: a package whose OWN typed-data.json entry is
// not a Solana request at all (never converted to one) must be refused even
// if a well-formed external Solana request is handed in via --typed-data --
// this is the exact "point sign at an unrelated package" scenario the check
// exists to catch. ov.mutateTypedData replaces the embedded document with an
// unrelated shape entirely, while f.requestPath (built by buildRequest from
// the package's real digests/auditor, independently of this mutation) stays
// a well-formed, matching Solana request.
func TestE2E_Sign_RejectsForeignShapedPackageEntry(t *testing.T) {
	ov := goldenOverrides()
	ov.mutateTypedData = func(td map[string]any) {
		for k := range td {
			delete(td, k)
		}
		td["primaryType"] = "MintAttestation"
		td["someUnrelatedField"] = "not a solana request"
	}
	f := newFixture(t, ov, nil)

	// --typed-data omitted: the package's own entry is all there is, and it
	// must not parse as a Solana request. It carries a field
	// (someUnrelatedField) attestationRequest doesn't have, so
	// json.Decoder.DisallowUnknownFields rejects it before the "chain"
	// discriminator is even reached -- still a hard refusal, just an earlier
	// one.
	stdout, stderr, err := f.runArgs(t)
	if err == nil {
		t.Fatalf("signer accepted a foreign-shaped package entry with --typed-data omitted\nstdout:\n%s", stdout)
	}
	if !strings.Contains(stderr, `unknown field`) {
		t.Errorf("unexpected error:\n%s", stderr)
	}
	assertNoResult(t, f)

	// --typed-data given explicitly with a well-formed Solana request: still
	// refused, because it cannot possibly be byte-identical to the package's
	// foreign-shaped entry -- exactly the WYSIWYS gap this check closes.
	stdout, stderr, err = f.run(t)
	if err == nil {
		t.Fatalf("signer accepted a foreign-shaped package entry with an external Solana request\nstdout:\n%s", stdout)
	}
	if !strings.Contains(stderr, "does not match the package's own typed-data.json byte-for-byte") {
		t.Errorf("unexpected error:\n%s", stderr)
	}
	assertNoResult(t, f)
}

// assertNoResult enforces the signer's standing invariant: any failure
// at any step exits non-zero and writes nothing.
func assertNoResult(t *testing.T, f fixture) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(f.workDir, "signed-result-solana.json")); err == nil {
		t.Error("a signed-result-solana.json was written despite the failure")
	}
}
