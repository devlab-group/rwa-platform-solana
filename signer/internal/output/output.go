// Package output writes signed-result-solana.json, matching
// shared/schemas/signed-result.schema.json's solana branch exactly.
package output

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"time"
)

// Shared shape checks.
var (
	auditorPattern    = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
	digestPattern     = regexp.MustCompile(`^0x[0-9a-fA-F]{64}$`)
	compactSigPattern = regexp.MustCompile(`^0x[0-9a-fA-F]{128}$`)
	base58Pattern     = regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]{32,44}$`)
)

// SignedResult is the signer's output for an attestation.
//
// Its formatVersion is namespaced ("solana-1.0") and its signature field is
// the 64-byte compact [R || S] form plus a separate recoveryId, which is what
// the on-chain sol_secp256k1_recover syscall consumes -- not the standard
// 65-byte [R || S || V] form. Feeding the wrong form to that syscall recovers
// a different key, so the field width (`signature` is 128 hex chars here,
// not 130) and the explicit `chain` field both exist so this document can
// never be mistaken for something else.
type SignedResult struct {
	FormatVersion string `json:"formatVersion"`
	Chain         string `json:"chain"`
	Auditor       string `json:"auditor"`
	PrimaryType   string `json:"primaryType"`
	// Cluster, Program and Config are the base58 domain the signature is
	// bound to. They are not needed to submit the transaction -- the
	// program derives them itself -- but a signed result that does not say
	// which deployment it authorizes cannot be audited after the fact.
	Cluster string `json:"cluster"`
	Program string `json:"program"`
	Config  string `json:"config"`

	AttestationDigest string `json:"attestationDigest"`
	Signature         string `json:"signature"`
	RecoveryID        byte   `json:"recoveryId"`
	SignedAt          string `json:"signedAt"`
}

// FormatVersion tags the result document. It is deliberately namespaced
// rather than a plain "1.0", so a consumer that reads formatVersion and
// nothing else can still tell what shape the rest of the document is in.
const FormatVersion = "solana-1.0"

// New builds a SignedResult with SignedAt set to now (UTC, RFC 3339) and
// validates every field before returning it.
func New(auditor, primaryType, cluster, program, config, attestationDigest, signature string, recoveryID byte) (SignedResult, error) {
	r := SignedResult{
		FormatVersion:     FormatVersion,
		Chain:             "solana",
		Auditor:           auditor,
		PrimaryType:       primaryType,
		Cluster:           cluster,
		Program:           program,
		Config:            config,
		AttestationDigest: attestationDigest,
		Signature:         signature,
		RecoveryID:        recoveryID,
		SignedAt:          time.Now().UTC().Format(time.RFC3339),
	}
	if err := r.Validate(); err != nil {
		return SignedResult{}, err
	}
	return r, nil
}

// Validate checks every field of r.
func (r SignedResult) Validate() error {
	if r.FormatVersion != FormatVersion {
		return fmt.Errorf("output: formatVersion must be %q", FormatVersion)
	}
	if r.Chain != "solana" {
		return fmt.Errorf("output: chain must be \"solana\"")
	}
	if !auditorPattern.MatchString(r.Auditor) {
		return fmt.Errorf("output: auditor must match ^0x[0-9a-fA-F]{40}$")
	}
	if r.PrimaryType != "MintAttestation" && r.PrimaryType != "BurnAttestation" {
		return fmt.Errorf("output: primaryType must be MintAttestation or BurnAttestation")
	}
	for _, f := range []struct{ name, value string }{
		{"cluster", r.Cluster},
		{"program", r.Program},
		{"config", r.Config},
	} {
		if !base58Pattern.MatchString(f.value) {
			return fmt.Errorf("output: %s must be a base58 Solana public key, got %q", f.name, f.value)
		}
	}
	if !digestPattern.MatchString(r.AttestationDigest) {
		return fmt.Errorf("output: attestationDigest must match ^0x[0-9a-fA-F]{64}$")
	}
	// 64 bytes, not 65: the recovery id is a separate field here.
	if !compactSigPattern.MatchString(r.Signature) {
		return fmt.Errorf("output: signature must be the 64-byte compact form matching ^0x[0-9a-fA-F]{128}$")
	}
	if r.RecoveryID > 1 {
		return fmt.Errorf("output: recoveryId must be 0 or 1, got %d", r.RecoveryID)
	}
	if _, err := time.Parse(time.RFC3339, r.SignedAt); err != nil {
		return fmt.Errorf("output: signedAt must be an RFC 3339 date-time: %w", err)
	}
	return nil
}

// Write validates r and writes it as indented JSON to path.
func Write(path string, r SignedResult) error {
	if err := r.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("output: marshaling signed-result-solana.json: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("output: writing %s: %w", path, err)
	}
	return nil
}
