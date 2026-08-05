package assets

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/rwa-platform/server/internal/auditpkg"
	"github.com/rwa-platform/server/internal/dal/models"
	"github.com/rwa-platform/server/internal/dal/repository"
	"github.com/rwa-platform/server/internal/eip712"
)

// ipfsPinner is the subset of internal/ipfs.Client this package needs,
// declared locally to avoid an import-cycle risk and to keep the workflow
// testable with a trivial stub.
type ipfsPinner interface {
	AddRaw(ctx context.Context, data []byte) (string, error)
}

// attestationValidUntil bounds how long a mint attestation remains signable
// after package creation — no more than 30 days.
const attestationValidUntilWindow = 30 * 24 * time.Hour

// CreateRecordRequest mirrors api Schemas.CreateRecordRequest.
type CreateRecordRequest struct {
	RecordID string
	Asset    json.RawMessage
	Amount   string
	Proofs   []ProofRecord
}

// RecordService creates and packages asset records.
// The auditor-signed mint is no longer relayed by the server — it is broadcast
// from the admin's wallet — so this service holds no relayer hot key; it only
// builds the .rwa evidence package and projects the on-chain Minted event onto
// record status (ReconcileMinted). Construct via NewRecordService
// (attestation.go).
type RecordService struct {
	records      repository.AssetRecordRepository
	packages     repository.AuditPackageRepository
	attestations repository.AttestationRepository
	ipfs         ipfsPinner

	// domain is set by NewRecordService and is what
	// BuildMintAttestation's digest is computed under — see that
	// method's doc comment. A nil domain (a zero-value RecordService)
	// makes BuildMintAttestation fail loudly (errNotConfigured)
	// rather than silently compute a digest under a zero-value domain.
	domain      *eip712.Domain
	domainView  auditpkg.DomainView
	vault       [32]byte
	vaultBase58 string

	// auditorMu guards auditor: it is set at construction from whatever was
	// known then, but that value can be empty (activation didn't source it
	// from the deployed project) or stale (an on-chain auditor rotation,
	// performed outside this server, otherwise never reaches a running
	// process). SetAuditor/ReconcileAuditor update it after construction,
	// concurrently with BuildPackage/RelaySignedResult reading it — hence
	// the lock rather than a plain field.
	auditorMu sync.RWMutex
	auditor   common.Address
	// baselineAuditor is the constructor's auditor value, held separately from
	// auditor and NEVER mutated after construction, so mutable authorities can
	// be reconciled from live contract calls or from this persisted deployment
	// baseline plus surviving events. ReconcileAuditor falls back to this when
	// no surviving AuditorChanged event exists (the rotation that set the
	// current auditor was itself rolled back by a reorg), rather than leaving
	// auditor stuck at an orphaned value with nothing left to restore it — see
	// ReconcileAuditor's doc comment.
	baselineAuditor common.Address
}

// SetAuditor updates the auditor address BuildPackage/RelaySignedResult use
// for every subsequent call. Safe to call concurrently with those.
func (s *RecordService) SetAuditor(addr common.Address) {
	s.auditorMu.Lock()
	defer s.auditorMu.Unlock()
	s.auditor = addr
}

// SetBaselineAuditor updates the fallback ReconcileAuditor resolves to when no
// AuditorChanged event exists.
//
// This is the normal case, not an edge case: no program's `initialize` emits an
// event, so a freshly bootstrapped deployment has no AuditorChanged at all and
// the auditor is only ever knowable by READING the supply-controller's config
// account. Without this the baseline stays frozen at whatever was in the
// database when the process started — zero for a server booted before the chain
// was bootstrapped — and ReconcileAuditor actively re-asserts that zero on
// every tick, so every .rwa package carries a zero auditor until a restart.
//
// It also updates the live value when it is currently unset, so a deployment
// that becomes readable mid-process starts producing signable packages without
// waiting for a rotation event that will never come.
func (s *RecordService) SetBaselineAuditor(addr common.Address) {
	s.auditorMu.Lock()
	defer s.auditorMu.Unlock()
	s.baselineAuditor = addr
	if s.auditor == (common.Address{}) {
		s.auditor = addr
	}
}

// currentAuditor returns the auditor address in effect right now.
func (s *RecordService) currentAuditor() common.Address {
	s.auditorMu.RLock()
	defer s.auditorMu.RUnlock()
	return s.auditor
}

// CreateRecord validates req against profile, canonicalizes+pins the
// metadata envelope, and persists a Pending asset record with a freshly
// generated nonce/recordKey/validUntil ready for package building.
func (s *RecordService) CreateRecord(ctx context.Context, profile *Profile, projectID string, req CreateRecordRequest) (*models.AssetRecord, error) {
	proofs := req.Proofs
	if proofs == nil {
		proofs = []ProofRecord{}
	}
	envelope := struct {
		PlatformVersion string          `json:"platformVersion"`
		ProjectID       string          `json:"projectId"`
		RecordID        string          `json:"recordId"`
		Asset           json.RawMessage `json:"asset"`
		Issuance        struct {
			Amount string `json:"amount"`
			Unit   string `json:"unit"`
		} `json:"issuance"`
		Proofs    []ProofRecord `json:"proofs,omitempty"`
		CreatedAt string        `json:"createdAt"`
	}{
		PlatformVersion: "1.0", ProjectID: projectID, RecordID: req.RecordID, Asset: req.Asset,
		Proofs: proofs, CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	envelope.Issuance.Amount = req.Amount
	envelope.Issuance.Unit = profile.TokenUnit

	raw, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("assets: marshal metadata envelope: %w", err)
	}

	result, meta := ValidateRecord(profile, raw, req.Amount, projectID)
	if !result.Valid {
		return nil, fmt.Errorf("assets: invalid record: %v", result.Errors)
	}

	nonce, err := randomUint256()
	if err != nil {
		return nil, err
	}
	recordKey := crypto.Keccak256Hash([]byte(req.RecordID))
	now := time.Now().UTC()

	record := &models.AssetRecord{
		RecordID: req.RecordID, ProjectID: projectID, Status: models.RecordStatusPending,
		AssetRaw: req.Asset, MetadataRaw: meta.Canonical, Amount: req.Amount, Unit: profile.TokenUnit,
		Proofs: toDomainProofs(proofs), MetadataDigest: meta.DigestHex(), CID: meta.CID,
		RecordKey: recordKey.Hex(), Nonce: nonce.String(), ValidUntil: now.Add(attestationValidUntilWindow).Unix(),
		CreatedAt: now, UpdatedAt: now,
	}
	// Reserve the immutable, create-once asset record BEFORE any external
	// publication. A duplicate create for an existing RecordID fails here
	// (ErrAlreadyExists) and never reaches Publish, so it can no longer
	// overwrite the durable-publication row's CID out from under the original
	// signed record. The record binds RecordID -> CID immutably, so
	// every subsequent publish for this id carries the same CID (which the
	// replication layer additionally enforces — see ipfs.ErrPublicationCIDConflict).
	if err := s.records.Create(ctx, record); err != nil {
		return nil, err
	}

	if s.ipfs != nil {
		// Prefer Publish (keyed by this record's own RecordID, a
		// meaningful lookup key) over the bare AddRaw(ctx,data) shape when
		// the configured client supports it (*ipfs.ReplicationManager
		// does; a plain Client/FakeClient does not). The mint gate looks up
		// durable-publication status by RecordID, so this is what makes that
		// lookup key exist in the first place.
		if p, ok := s.ipfs.(interface {
			Publish(ctx context.Context, id string, data []byte) (string, error)
		}); ok {
			if _, err := p.Publish(ctx, req.RecordID, meta.Canonical); err != nil {
				return nil, fmt.Errorf("assets: pin metadata: %w", err)
			}
		} else if _, err := s.ipfs.AddRaw(ctx, meta.Canonical); err != nil {
			return nil, fmt.Errorf("assets: pin metadata: %w", err)
		}
	}
	return record, nil
}

// ErrRecordNotFound is returned by ReissueRecord when no record exists for
// the given id, so the handler can map it to 404 rather than a generic 500.
var ErrRecordNotFound = errors.New("assets: record not found")

// ErrRecordNotReissuable is returned by ReissueRecord for a record that is
// not in Pending state. Reissue is audited recovery for a record whose
// attestation window lapsed BEFORE it was minted; once a record is Signed or
// Minted, rolling its nonce could strand or double-count a real on-chain mint,
// and Rejected/Draft records were never eligible to mint in the first place
// (see api/openapi.yaml reissueRecord).
var ErrRecordNotReissuable = errors.New("assets: record is not Pending; only a Pending record may be reissued")

// ReissueRecord assigns a fresh nonce and validUntil to an existing Pending
// record WITHOUT changing its immutable identity (recordId, metadata,
// digests, recordKey, amount, unit all unchanged), so a record whose
// attestation window lapsed before it was signed/relayed can be re-attested
// without violating record-ID uniqueness. Any previously built
// .rwa package or auditor signature was bound to the OLD nonce and no longer
// matches; the operator rebuilds the package and the auditor re-signs after
// this. Admin-only and idempotency-keyed at the HTTP layer.
func (s *RecordService) ReissueRecord(ctx context.Context, recordID string) (*models.AssetRecord, error) {
	record, err := s.records.Get(ctx, recordID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrRecordNotFound
		}
		return nil, err
	}
	if record.Status != models.RecordStatusPending {
		return nil, ErrRecordNotReissuable
	}

	nonce, err := randomUint256()
	if err != nil {
		return nil, err
	}
	expectedVersion := record.Version
	record.Status = models.RecordStatusPending
	record.Nonce = nonce.String()
	record.ValidUntil = time.Now().UTC().Add(attestationValidUntilWindow).Unix()
	record.UpdatedAt = time.Now().UTC()
	// Conditional on the version read above, so two concurrent reissues can't
	// both roll the nonce — the loser's conditional update simply fails
	// instead of clobbering.
	ok, err := s.records.UpdateConditional(ctx, record, expectedVersion)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrRecordConcurrentlyModified
	}
	record.Version = expectedVersion + 1
	return record, nil
}

// ErrRecordConcurrentlyModified is returned when a version-conditional record
// transition (reissue or relay) lost a race to a concurrent one. The caller
// should re-read the record and decide again rather than blindly retry.
var ErrRecordConcurrentlyModified = errors.New("assets: record was concurrently modified; re-read and retry")

func toDomainProofs(proofs []ProofRecord) []models.Proof {
	out := make([]models.Proof, len(proofs))
	for i, p := range proofs {
		out[i] = models.Proof{Type: p.Type, SHA256: p.SHA256, URI: p.URI}
	}
	return out
}

func randomUint256() (*big.Int, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("assets: generate nonce: %w", err)
	}
	return new(big.Int).SetBytes(b), nil
}

// BuildPackage assembles the .rwa audit package for record, using
// profileRaw (the project's canonicalized Asset Profile bytes) and the
// record's stored canonical metadata bytes. It rebuilds deterministically
// from the record's own persisted fields (recordKey, nonce, validUntil,
// amount, metadataDigest) plus the server's current auditor and vault, so a
// re-download always yields the same bytes for the same record state (see
// auditpkg.BuildPackage's determinism, TestBuildPackageIsDeterministic).
//
// this delegates to buildPackage, which embeds a
// Solana-shaped ("chain":"solana") typed-data.json.
func (s *RecordService) BuildPackage(ctx context.Context, record *models.AssetRecord, profileDigest [32]byte, profileRaw []byte) ([]byte, error) {
	return s.buildPackage(ctx, record, profileDigest, profileRaw)
}

// buildPackage is BuildPackage's implementation. It reuses
// BuildMintAttestation (internal/assets/attestation.go) purely for
// its OUTPUT — the already-proven Solana typed-data document and digest —
// and does no attestation math of its own; see that method's doc comment for
// the digest computation this builds on top of.
func (s *RecordService) buildPackage(ctx context.Context, record *models.AssetRecord, profileDigest [32]byte, profileRaw []byte) ([]byte, error) {
	doc, digest, err := s.BuildMintAttestation(record, profileDigest)
	if err != nil {
		return nil, err
	}
	metadataDigest, err := hexToBytes32Local(record.MetadataDigest)
	if err != nil {
		return nil, err
	}
	zipBytes, packageSHA256, err := auditpkg.BuildPackage("MintAttestation", profileDigest, metadataDigest, profileRaw, record.MetadataRaw, doc, nil)
	if err != nil {
		return nil, err
	}
	pkg := &models.AuditPackage{
		RecordID: record.RecordID, PackageSHA256: packageSHA256, Size: int64(len(zipBytes)),
		RecordVersion: record.Version, CID: record.CID,
		// Fields below are read straight off doc.Message — the exact bytes
		// just embedded in typed-data.json — rather than re-derived from
		// record/s.vault*, so this row can never drift from what the
		// package actually says: Vault/domain fields are base58 (not
		// 0x-hex) and Nonce is 0x-hex bytes32 (not a decimal string).
		Auditor: doc.Message.Auditor, ProfileDigest: doc.Message.ProfileDigest, MetadataDigest: doc.Message.MetadataDigest,
		RecordKey: doc.Message.RecordKey, Amount: doc.Message.Amount, Nonce: doc.Message.Nonce,
		ValidUntil: int64(doc.Message.ValidUntil), Vault: doc.Message.Vault,
		TypedDataDigest: "0x" + hex.EncodeToString(digest[:]),
		CreatedAt:       time.Now().UTC(),
	}
	if err := s.packages.Upsert(ctx, pkg); err != nil {
		return nil, err
	}
	return zipBytes, nil
}

func hexToBytes32Local(s string) ([32]byte, error) {
	var out [32]byte
	trimmed := s
	if len(trimmed) >= 2 && trimmed[0:2] == "0x" {
		trimmed = trimmed[2:]
	}
	if len(trimmed) != 64 {
		return out, fmt.Errorf("assets: expected 32-byte hex, got %d chars", len(trimmed))
	}
	b, err := hex.DecodeString(trimmed)
	if err != nil {
		return out, err
	}
	copy(out[:], b)
	return out, nil
}
