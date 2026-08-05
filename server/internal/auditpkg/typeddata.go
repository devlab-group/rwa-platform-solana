package auditpkg

import (
	"encoding/hex"
	"strconv"

	"github.com/mr-tron/base58"

	"github.com/rwa-platform/server/internal/eip712"
)

// TypedDataDoc is the auditor attestation request document, matching
// signer/cmd/signer/typeddata.go's typedData struct
// field-for-field (that struct's `dec.DisallowUnknownFields()` strict
// decode is the de-facto frozen contract this mirrors; see
// TestNewMintTypedDataDocMatchesSignerShapeAndGoldenDigest).
//
// this
// IS embedded as the .rwa package's mandatory "typed-data.json" manifest
// entry: shared/schemas/typed-data.schema.json describes exactly this shape,
// and Chain below carries the "solana" discriminator the schema requires.
// assets.RecordService.BuildPackage passes a value of this type to
// auditpkg.BuildPackage.
type TypedDataDoc struct {
	// Chain is always "solana" (never omitted) — the schema requires it
	// explicitly, so a document that omits it is rejected rather than
	// silently accepted as some other shape.
	Chain       string           `json:"chain"`
	PrimaryType string           `json:"primaryType"`
	Domain      TypedDataDomain  `json:"domain"`
	Message     TypedDataMessage `json:"message"`
}

// TypedDataDomain mirrors typedData.Domain: base58
// pubkeys/hashes, not a 0x-hex chainId/verifyingContract pair.
type TypedDataDomain struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Cluster string `json:"cluster"`
	Program string `json:"program"`
	Config  string `json:"config"`
}

// TypedDataMessage mirrors typedData.Message: nonce is 32-byte hex
// (not a decimal integer — see eip712.MintAttestation's doc comment),
// and vault is base58 (not 0x-hex) — it's a Solana pubkey, not an EVM
// address.
type TypedDataMessage struct {
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
}

// DomainView is the base58-string form of an eip712.Domain, used
// only for rendering this document — the digest itself is always computed
// from the raw 32-byte eip712.Domain (internal/eip712), never
// re-derived from these strings, so a rendering bug here can never silently
// change what gets signed.
type DomainView struct {
	Cluster string
	Program string
	Config  string
}

// NewMintTypedDataDoc builds the mint attestation request document for
// recordID. vaultBase58 is the Vault authority pubkey in the form the auditor
// provisioned (base58) — a.Vault carries only the raw 32 bytes the digest
// was computed from.
func NewMintTypedDataDoc(domain DomainView, recordID string, a eip712.MintAttestation, vaultBase58 string) TypedDataDoc {
	return TypedDataDoc{
		Chain:       "solana",
		PrimaryType: "MintAttestation",
		Domain: TypedDataDomain{
			Name: eip712.DomainName, Version: eip712.DomainVersion,
			Cluster: domain.Cluster, Program: domain.Program, Config: domain.Config,
		},
		Message: TypedDataMessage{
			Auditor:        a.Auditor.Hex(),
			ProfileDigest:  "0x" + hex.EncodeToString(a.ProfileDigest[:]),
			RecordID:       recordID,
			RecordKey:      "0x" + hex.EncodeToString(a.RecordKey[:]),
			MetadataDigest: "0x" + hex.EncodeToString(a.MetadataDigest[:]),
			Amount:         strconv.FormatUint(a.Amount, 10),
			Nonce:          "0x" + hex.EncodeToString(a.Nonce[:]),
			ValidUntil:     a.ValidUntil,
			Vault:          vaultBase58,
		},
	}
}

// NewBurnTypedDataDoc builds the burn attestation request document. Unused
// by RecordService today (nothing in internal/assets builds a burn package
// yet); provided for parity so a future burn-package feature has a ready
// encoding.
func NewBurnTypedDataDoc(domain DomainView, a eip712.BurnAttestation, vaultBase58 string) TypedDataDoc {
	return TypedDataDoc{
		Chain:       "solana",
		PrimaryType: "BurnAttestation",
		Domain: TypedDataDomain{
			Name: eip712.DomainName, Version: eip712.DomainVersion,
			Cluster: domain.Cluster, Program: domain.Program, Config: domain.Config,
		},
		Message: TypedDataMessage{
			Auditor:        a.Auditor.Hex(),
			ProfileDigest:  "0x" + hex.EncodeToString(a.ProfileDigest[:]),
			OperationID:    "0x" + hex.EncodeToString(a.OperationID[:]),
			MetadataDigest: "0x" + hex.EncodeToString(a.MetadataDigest[:]),
			Amount:         strconv.FormatUint(a.Amount, 10),
			Nonce:          "0x" + hex.EncodeToString(a.Nonce[:]),
			ValidUntil:     a.ValidUntil,
			Vault:          vaultBase58,
		},
	}
}

// base58Encode is a small helper so callers holding only the raw
// 32-byte form (e.g. RecordService's configured vault) can render a
// DomainView/vaultBase58 without importing mr-tron/base58 themselves.
func base58Encode(b [32]byte) string { return base58.Encode(b[:]) }
