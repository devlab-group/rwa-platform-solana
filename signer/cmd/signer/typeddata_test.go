package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// validAttestationRequestMap builds a self-consistent (schema-wise; it is NOT
// bound to any real .rwa package) Solana MintAttestation request map, so a
// unit test can mutate one field in isolation and call parseAttestationRequest
// directly without going through the full CLI/package-building machinery
// e2e_test.go's newFixture uses.
func validAttestationRequestMap() map[string]any {
	hex32 := func(b byte) string { return "0x" + strings.Repeat(fmt.Sprintf("%02x", b), 32) }
	return map[string]any{
		"chain":       "solana",
		"primaryType": "MintAttestation",
		"domain": map[string]any{
			"name":    "RWA-Supply-Attestation-Solana",
			"version": "1",
			"cluster": testCluster,
			"program": testProgram,
			"config":  testConfig,
		},
		"message": map[string]any{
			"auditor":        "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
			"profileDigest":  hex32(0x44),
			"recordId":       "GOLD-BAR-1",
			"recordKey":      hex32(0x55),
			"metadataDigest": hex32(0x66),
			"amount":         "1000000000000",
			"nonce":          hex32(0x2a),
			"validUntil":     uint64(1800000000),
			"vault":          testVault,
		},
	}
}

func marshalAttestationRequest(t *testing.T, m map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshaling typed-data map: %v", err)
	}
	return raw
}

// TestParseAttestationRequest_AcceptsValidDocument is the control case: proves
// validAttestationRequestMap() itself parses cleanly, so the negative tests
// below are actually exercising the chain check and not some unrelated
// validation failure in the fixture.
func TestParseAttestationRequest_AcceptsValidDocument(t *testing.T) {
	td, err := parseAttestationRequest(marshalAttestationRequest(t, validAttestationRequestMap()))
	if err != nil {
		t.Fatalf("parseAttestationRequest: %v", err)
	}
	if td.Chain != "solana" {
		t.Errorf("chain = %q, want solana", td.Chain)
	}
}

// TestParseAttestationRequest_RejectsMissingChain covers a request whose
// "chain" key is entirely absent (e.g. a plain EVM typed-data.json) --
// td.Chain decodes to its zero value "", which must be rejected exactly like
// an explicit wrong value, not treated as "chain not specified, assume
// solana".
func TestParseAttestationRequest_RejectsMissingChain(t *testing.T) {
	m := validAttestationRequestMap()
	delete(m, "chain")

	_, err := parseAttestationRequest(marshalAttestationRequest(t, m))
	if err == nil {
		t.Fatal("expected an error for a missing chain field")
	}
	if !strings.Contains(err.Error(), `chain must be "solana"`) {
		t.Errorf("error = %v, want it to explain chain must be \"solana\"", err)
	}
}

// TestParseAttestationRequest_RejectsEvmChain covers an explicit chain:"evm" --
// the plausible-operator-mistake case of feeding an EVM-flavored request
// (perhaps hand-edited) to the Solana signing path.
func TestParseAttestationRequest_RejectsEvmChain(t *testing.T) {
	m := validAttestationRequestMap()
	m["chain"] = "evm"

	_, err := parseAttestationRequest(marshalAttestationRequest(t, m))
	if err == nil {
		t.Fatal("expected an error for chain=\"evm\"")
	}
	if !strings.Contains(err.Error(), `chain must be "solana"`) {
		t.Errorf("error = %v, want it to explain chain must be \"solana\"", err)
	}
}
