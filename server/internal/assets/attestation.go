package assets

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/mr-tron/base58"

	"github.com/rwa-platform/server/internal/auditpkg"
	"github.com/rwa-platform/server/internal/dal/models"
	"github.com/rwa-platform/server/internal/dal/repository"
	"github.com/rwa-platform/server/internal/eip712"
)

// NewRecordService constructs a RecordService.
// CreateRecord/ReissueRecord (and everything downstream of them — profile
// validation, metadata canonicalization/pinning, IPFS publish) build the
// .rwa evidence package and project the on-chain Minted event onto record
// status (ReconcileMinted). BuildPackage calls buildPackage (see
// service.go), which calls BuildMintAttestation below to get a
// correctly-digested Solana mint attestation request before embedding it in
// the .rwa package.
//
// clusterGenesis/supplyProgram/supplyConfig/vault are all base58 Solana
// pubkeys/hashes: clusterGenesis is the target cluster's genesis hash (the
// Solana analogue of chainId — see eip712.Domain.Cluster's doc
// comment), supplyProgram is the rwa-supply-controller program id,
// supplyConfig is its config PDA (the analogue of verifyingContract), and
// vault is the Vault authority's pubkey the attestation binds to. All four
// MUST be sourced from the bootstrap deployment manifest / config — this
// function does no PDA derivation, matching the rest of this codebase's
// "never derive PDAs in Go" rule (see the frozen solana-chainevent-mapping
// contract).
func NewRecordService(
	records repository.AssetRecordRepository, packages repository.AuditPackageRepository, attestations repository.AttestationRepository,
	ipfsClient ipfsPinner,
	clusterGenesis, supplyProgram, supplyConfig, vault string,
	auditor common.Address,
) (*RecordService, error) {
	cluster, err := decodePubkey("chain.cluster_genesis", clusterGenesis)
	if err != nil {
		return nil, err
	}
	program, err := decodePubkey("contract.programs.supply_controller", supplyProgram)
	if err != nil {
		return nil, err
	}
	config, err := decodePubkey("contract.supply_config", supplyConfig)
	if err != nil {
		return nil, err
	}
	vaultBytes, err := decodePubkey("vault", vault)
	if err != nil {
		return nil, err
	}
	domain := eip712.Domain{Cluster: cluster, Program: program, Config: config}
	return &RecordService{
		records: records, packages: packages, attestations: attestations, ipfs: ipfsClient,
		domain: &domain,
		domainView: auditpkg.DomainView{
			Cluster: clusterGenesis, Program: supplyProgram, Config: supplyConfig,
		},
		vault: vaultBytes, vaultBase58: vault,
		auditor: auditor, baselineAuditor: auditor,
	}, nil
}

// decodePubkey base58-decodes s into a 32-byte pubkey, wrapping any
// error with field for a caller-identifiable message — config.Load already
// validates every one of these fields is a syntactically valid base58
// pubkey before this deployment can even boot (see
// isBase58Pubkey/isBase58Hash in internal/config), so a failure here would
// mean this constructor was called with a value that bypassed that gate.
func decodePubkey(field, s string) ([32]byte, error) {
	var out [32]byte
	b, err := base58.Decode(s)
	if err != nil {
		return out, fmt.Errorf("assets: %s: invalid base58: %w", field, err)
	}
	if len(b) != 32 {
		return out, fmt.Errorf("assets: %s: decodes to %d bytes, want 32", field, len(b))
	}
	copy(out[:], b)
	return out, nil
}

// errNotConfigured is returned by BuildMintAttestation when
// called on a zero-value RecordService (domain is nil) rather than
// one constructed via NewRecordService.
var errNotConfigured = errors.New("assets: BuildMintAttestation requires a RecordService built via NewRecordService")

// ErrAuditorUnknown is returned when no auditor identity is known yet, so no
// attestation (and therefore no .rwa package) can be built. Exported so the API
// can turn it into a 409 with an actionable message rather than a 500.
var ErrAuditorUnknown = errors.New(
	"assets: the deployment's auditor is not known yet — the supply-controller's auditor address " +
		"could not be read from the chain (is the deployment bootstrapped, and is the RPC reachable?). " +
		"A package built now would carry a zero auditor and could not be signed or minted")

// errAuditorUnknown is the unexported alias used internally.
var errAuditorUnknown = ErrAuditorUnknown

// BuildMintAttestation computes the Solana-shaped mint attestation
// request (auditpkg.TypedDataDoc) and the raw digest it commits the
// auditor to, for record — rebuilt deterministically from record's own
// persisted fields (recordKey, nonce, validUntil, amount, metadataDigest)
// plus this service's current auditor and configured vault.
//
// Unlike BuildPackage this returns the document + digest directly rather
// than a .rwa zip — it is the lower-level building block buildPackage
// (service.go) calls to assemble the actual package, and remains useful on
// its own wherever only the document/digest (not the zip) is needed; see
// TestBuildMintAttestationMatchesGoldenVector.
func (s *RecordService) BuildMintAttestation(record *models.AssetRecord, profileDigest [32]byte) (auditpkg.TypedDataDoc, [32]byte, error) {
	if s.domain == nil {
		return auditpkg.TypedDataDoc{}, [32]byte{}, errNotConfigured
	}
	recordKey, err := hexToBytes32Local(record.RecordKey)
	if err != nil {
		return auditpkg.TypedDataDoc{}, [32]byte{}, err
	}
	metadataDigest, err := hexToBytes32Local(record.MetadataDigest)
	if err != nil {
		return auditpkg.TypedDataDoc{}, [32]byte{}, err
	}
	amountBig, ok := new(big.Int).SetString(record.Amount, 10)
	if !ok {
		return auditpkg.TypedDataDoc{}, [32]byte{}, fmt.Errorf("assets: invalid stored amount %q", record.Amount)
	}
	amount, err := eip712.Amount(amountBig)
	if err != nil {
		return auditpkg.TypedDataDoc{}, [32]byte{}, err
	}
	nonceBig, ok := new(big.Int).SetString(record.Nonce, 10)
	if !ok {
		return auditpkg.TypedDataDoc{}, [32]byte{}, fmt.Errorf("assets: invalid stored nonce %q", record.Nonce)
	}
	// The stored nonce is the SAME 32 random bytes CreateRecord generated
	// (randomUint256), just persisted as a decimal string —
	// big.Int.Bytes() plus a left-pad to 32 recovers those exact
	// original bytes verbatim (no modular reduction was ever applied), which
	// is what the Solana encoding needs (bytes32, not an integer word — see
	// eip712.MintAttestation.Nonce's doc comment).
	var nonce [32]byte
	copy(nonce[:], common.LeftPadBytes(nonceBig.Bytes(), 32))

	// FAIL CLOSED on an unknown auditor. The auditor is the identity the
	// on-chain program recovers the secp256k1 signature to; a zero address
	// makes the package unsignable (the offline signer's policy check rejects
	// it) and, if it somehow were signed, unmintable. Emitting one anyway
	// produces a .rwa that looks complete and only fails after the whole
	// offline signing round-trip — the expensive place to discover it.
	//
	// It is reachable in normal operation: a server started BEFORE the chain
	// was bootstrapped has no auditor to read yet (see cmd/platform's
	// loadAuditorBaseline and the on-chain baseline refresh in
	// pollAndReconcile), so this is a "not ready yet" condition, not a bug.
	auditor := s.currentAuditor()
	if auditor == (common.Address{}) {
		return auditpkg.TypedDataDoc{}, [32]byte{}, errAuditorUnknown
	}

	attestation := eip712.MintAttestation{
		Auditor: auditor, ProfileDigest: profileDigest, RecordKey: recordKey, MetadataDigest: metadataDigest,
		Amount: amount, Nonce: nonce, ValidUntil: uint64(record.ValidUntil), Vault: s.vault,
	}
	doc := auditpkg.NewMintTypedDataDoc(s.domainView, record.RecordID, attestation, s.vaultBase58)
	digest := eip712.MintDigest(*s.domain, attestation)
	return doc, digest, nil
}
