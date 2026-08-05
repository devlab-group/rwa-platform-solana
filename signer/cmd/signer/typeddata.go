package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"

	"github.com/ethereum/go-ethereum/common"
	"github.com/rwa-platform/signer/internal/attestation"
	"github.com/rwa-platform/signer/internal/base58"
)

var (
	addrPattern = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
	bytes32Ptn  = regexp.MustCompile(`^0x[0-9a-fA-F]{64}$`)
	decimalPtn  = regexp.MustCompile(`^[0-9]+$`)
)

// hexToHash32 decodes a 0x-prefixed hex string into a right-aligned 32-byte
// word.
func hexToHash32(s string) [32]byte {
	var out [32]byte
	b := common.FromHex(s)
	copy(out[32-len(b):], b)
	return out
}

// attestationRequest is the parsed shape of the Solana attestation request file
// (--typed-data), the Solana analogue of the .rwa package's typed-data.json.
//
// the
// frozen shared/schemas/typed-data.schema.json is now a chain-discriminated
// union and a Solana .rwa package's own typed-data.json entry carries exactly
// this shape (with "chain":"solana"). validatePackage itself stays
// chain-independent -- it never opens typed-data.json -- but
// resolveTypedData (sign.go) does: it defaults --typed-data to
// the package's own manifest-protected entry, and requires the two to be
// byte-for-byte identical when both are given, so the request actually
// signed is always the one the manifest's SHA-256 covers. Nothing is lost
// security-wise either way: every field below is either recomputed from the
// package's own documents or checked against the independently-provisioned
// --policy.
type attestationRequest struct {
	// Chain is always "solana" on this branch -- see the schema discriminator
	// the Solana attestation introduced. Required (not omitempty): a typed-data.json with no
	// chain discriminator at all must never silently parse as a Solana
	// request.
	Chain       string `json:"chain"`
	PrimaryType string `json:"primaryType"`
	Domain      struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		// Base58 Solana public keys, the form the auditor provisioned and
		// the only form they can practically verify.
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
		// Amount is a decimal string in the token's smallest unit. It must
		// fit uint64 -- see attestation.Amount.
		Amount string `json:"amount"`
		// Nonce is a 32-byte hex value, NOT a decimal integer: on Solana it
		// seeds the replay-marker PDA verbatim.
		Nonce      string `json:"nonce"`
		ValidUntil uint64 `json:"validUntil"`
		// Vault is the Vault authority PDA, base58.
		Vault string `json:"vault"`
	} `json:"message"`

	// Decoded byte forms, filled in by parseAttestationRequest so nothing
	// downstream re-parses (and possibly re-parses differently) what the
	// review screen displayed.
	cluster [32]byte
	program [32]byte
	config  [32]byte
	vault   [32]byte
	nonce   [32]byte
	amount  uint64
}

func parseAttestationRequest(raw []byte) (*attestationRequest, error) {
	var td attestationRequest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&td); err != nil {
		return nil, fmt.Errorf("solana typed-data: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("solana typed-data: trailing data")
	}

	if td.Chain != "solana" {
		return nil, fmt.Errorf("solana typed-data: chain must be %q, got %q -- a request with no chain discriminator (or the wrong one) is not a Solana attestation request", "solana", td.Chain)
	}
	if td.PrimaryType != "MintAttestation" && td.PrimaryType != "BurnAttestation" {
		return nil, fmt.Errorf("solana typed-data: primaryType must be MintAttestation or BurnAttestation, got %q", td.PrimaryType)
	}
	if td.Domain.Name != attestation.DomainName {
		return nil, fmt.Errorf("solana typed-data: domain.name %q does not match the frozen Solana domain name %q", td.Domain.Name, attestation.DomainName)
	}
	if td.Domain.Version != attestation.DomainVersion {
		return nil, fmt.Errorf("solana typed-data: domain.version %q does not match frozen domain version %q", td.Domain.Version, attestation.DomainVersion)
	}

	for _, k := range []struct {
		name  string
		value string
		out   *[32]byte
	}{
		{"domain.cluster", td.Domain.Cluster, &td.cluster},
		{"domain.program", td.Domain.Program, &td.program},
		{"domain.config", td.Domain.Config, &td.config},
		{"message.vault", td.Message.Vault, &td.vault},
	} {
		b, err := base58.DecodePubkey(k.value)
		if err != nil {
			return nil, fmt.Errorf("solana typed-data: %s must be a base58 32-byte Solana public key: %w", k.name, err)
		}
		*k.out = b
	}

	m := td.Message
	if !addrPattern.MatchString(m.Auditor) {
		return nil, fmt.Errorf("solana typed-data: message.auditor must be a 20-byte eth address")
	}
	if !bytes32Ptn.MatchString(m.ProfileDigest) {
		return nil, fmt.Errorf("solana typed-data: message.profileDigest must be a 32-byte hex value")
	}
	if !bytes32Ptn.MatchString(m.MetadataDigest) {
		return nil, fmt.Errorf("solana typed-data: message.metadataDigest must be a 32-byte hex value")
	}
	if !decimalPtn.MatchString(m.Amount) {
		return nil, fmt.Errorf("solana typed-data: message.amount must be a decimal string")
	}
	if !bytes32Ptn.MatchString(m.Nonce) {
		return nil, fmt.Errorf("solana typed-data: message.nonce must be a 32-byte hex value (the Solana nonce is bytes32, not a decimal integer)")
	}
	td.nonce = hexToHash32(m.Nonce)

	amountBig, ok := new(big.Int).SetString(m.Amount, 10)
	if !ok {
		return nil, fmt.Errorf("solana typed-data: message.amount %q is not a valid decimal integer", m.Amount)
	}
	amount, err := attestation.Amount(amountBig, "message.amount")
	if err != nil {
		return nil, fmt.Errorf("solana typed-data: %w", err)
	}
	td.amount = amount

	switch td.PrimaryType {
	case "MintAttestation":
		if m.RecordID == "" {
			return nil, fmt.Errorf("solana typed-data: message.recordId is required for MintAttestation")
		}
		if !bytes32Ptn.MatchString(m.RecordKey) {
			return nil, fmt.Errorf("solana typed-data: message.recordKey must be a 32-byte hex value")
		}
		if m.OperationID != "" {
			return nil, fmt.Errorf("solana typed-data: message.operationId must not be set for MintAttestation")
		}
	case "BurnAttestation":
		if !bytes32Ptn.MatchString(m.OperationID) {
			return nil, fmt.Errorf("solana typed-data: message.operationId must be a 32-byte hex value")
		}
		if m.RecordID != "" || m.RecordKey != "" {
			return nil, fmt.Errorf("solana typed-data: message.recordId/recordKey must not be set for BurnAttestation")
		}
	}

	return &td, nil
}

func (td *attestationRequest) domain() attestation.Domain {
	return attestation.Domain{Cluster: td.cluster, Program: td.program, Config: td.config}
}

func (td *attestationRequest) mintAttestation() attestation.MintAttestation {
	m := td.Message
	return attestation.MintAttestation{
		Auditor:        common.HexToAddress(m.Auditor),
		ProfileDigest:  hexToHash32(m.ProfileDigest),
		RecordKey:      hexToHash32(m.RecordKey),
		MetadataDigest: hexToHash32(m.MetadataDigest),
		Amount:         td.amount,
		Nonce:          td.nonce,
		ValidUntil:     m.ValidUntil,
		Vault:          td.vault,
	}
}

func (td *attestationRequest) burnAttestation() attestation.BurnAttestation {
	m := td.Message
	return attestation.BurnAttestation{
		Auditor:        common.HexToAddress(m.Auditor),
		ProfileDigest:  hexToHash32(m.ProfileDigest),
		OperationID:    hexToHash32(m.OperationID),
		MetadataDigest: hexToHash32(m.MetadataDigest),
		Amount:         td.amount,
		Nonce:          td.nonce,
		ValidUntil:     m.ValidUntil,
		Vault:          td.vault,
	}
}
