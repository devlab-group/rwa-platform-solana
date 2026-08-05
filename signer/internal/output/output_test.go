package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testB58Cluster = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
	testB58Program = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
	testB58Config  = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
	testAuditor    = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	testSolDigest  = "0x27e6aed00dd4a6599420b86eefa0fdb517886df306636544c0aa1640d39d7894"
	// 64 bytes -- the compact form, no V byte.
	testCompactSig = "0x47b8e77b45baa51ced062f0ed6b693c9180379ba0d3bd1f824aa415d2fbdfe1d07e219a20a358306b3693f72f4a0ffd7afdca3b3f1cc3aba6237fa73e10b742b"
)

func newValidResult(t *testing.T) SignedResult {
	t.Helper()
	r, err := New(testAuditor, "MintAttestation", testB58Cluster, testB58Program, testB58Config, testSolDigest, testCompactSig, 1)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

func TestNew_ValidAndRoundTrips(t *testing.T) {
	r := newValidResult(t)
	if r.FormatVersion != FormatVersion || r.Chain != "solana" {
		t.Fatalf("formatVersion/chain = %q/%q", r.FormatVersion, r.Chain)
	}

	path := filepath.Join(t.TempDir(), "signed-result-solana.json")
	if err := Write(path, r); err != nil {
		t.Fatalf("Write: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading result: %v", err)
	}
	var back SignedResult
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("parsing result: %v", err)
	}
	if err := back.Validate(); err != nil {
		t.Fatalf("round-tripped result does not validate: %v", err)
	}
	// The recoveryId must survive as a number, not be dropped as a zero
	// value -- the on-chain recover needs it and there is no way to guess it.
	if back.RecoveryID != 1 {
		t.Fatalf("recoveryId = %d after round trip, want 1", back.RecoveryID)
	}
}

// TestSignedResult_RejectsEvmSignature is the important negative: an
// EVM 65-byte [R||S||V] signature written into a Solana result would be
// silently mis-parsed by a consumer splitting it as [R||S]. It must be
// refused outright.
func TestSignedResult_RejectsEvmSignature(t *testing.T) {
	evmSig := "0x9307d1a6face62d62b3687e9281687d1f7f0a86c132bd526b2d8c2124fec502f7519091eb3527078a47b5a0067c3c8eb8a4710411b7433f798b431025a0f517e1b"
	if _, err := New(testAuditor, "MintAttestation", testB58Cluster, testB58Program, testB58Config, testSolDigest, evmSig, 1); err == nil {
		t.Fatal("accepted a 65-byte EVM signature")
	}
}

func TestSignedResult_RejectsInvalidFields(t *testing.T) {
	cases := map[string]func(*SignedResult){
		"bad formatVersion": func(r *SignedResult) { r.FormatVersion = "1.0" },
		"bad chain":         func(r *SignedResult) { r.Chain = "ethereum" },
		"bad auditor":       func(r *SignedResult) { r.Auditor = "0xdeadbeef" },
		"bad primaryType":   func(r *SignedResult) { r.PrimaryType = "TransferAttestation" },
		"hex cluster":       func(r *SignedResult) { r.Cluster = "0x" + strings.Repeat("11", 32) },
		"empty program":     func(r *SignedResult) { r.Program = "" },
		"bad digest":        func(r *SignedResult) { r.AttestationDigest = "0x1234" },
		"recoveryId 2":      func(r *SignedResult) { r.RecoveryID = 2 },
		"bad signedAt":      func(r *SignedResult) { r.SignedAt = "yesterday" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := newValidResult(t)
			mutate(&r)
			if err := r.Validate(); err == nil {
				t.Fatalf("accepted %s", name)
			}
			// A rejected result must also never reach disk.
			path := filepath.Join(t.TempDir(), "out.json")
			if err := Write(path, r); err == nil {
				t.Fatalf("Write wrote an invalid result (%s)", name)
			}
			if _, err := os.Stat(path); err == nil {
				t.Fatalf("Write created a file for an invalid result (%s)", name)
			}
		})
	}
}
