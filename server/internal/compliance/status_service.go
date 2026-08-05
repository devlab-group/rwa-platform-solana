package compliance

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/mr-tron/base58"

	"github.com/rwa-platform/server/internal/blockchain"
	"github.com/rwa-platform/server/internal/dal/models"
	"github.com/rwa-platform/server/internal/dal/repository"
)

// setStatusDiscriminator is Anchor's 8-byte instruction discriminator
// for rwa-compliance's set_status — sha256("global:set_status")[:8],
// verified against solana/target/idl/rwa_compliance.json (which pins the
// same 8 bytes literally) rather than computed at runtime, so a drift
// between this codebase and the deployed program's IDL fails loudly
// (a wrong discriminator is silently rejected on-chain as an
// unrecognized instruction, not a helpful error) — see
// TestSetStatusDiscriminatorMatchesIDL.
var setStatusDiscriminator = [8]byte{181, 184, 224, 203, 193, 29, 177, 224}

// systemProgramID is the well-known Solana System Program address
// (the all-zero 32-byte pubkey, base58-encoded) — set_status's
// system_program account, needed because the per-wallet compliance record
// PDA is created (init_if_needed) the first time a wallet's status is set.
const systemProgramID = "11111111111111111111111111111111"

// registrySeed / recordSeed are rwa-compliance's PDA seeds —
// see solana/target/idl/rwa_compliance.json's set_status account
// constraints. recordPDA additionally seeds on the target wallet's raw
// pubkey bytes.
const (
	registrySeed = "registry"
	recordSeed   = "record"
)

// StatusService submits rwa-compliance set_status instructions using
// the server's compliance-authority hot key. The same keypair plays
// BOTH the program's `authority` account (gated by the on-chain
// COMPLIANCE_ROLE-equivalent check) and `payer` (funds the compliance
// record PDA's rent on first write) — this server holds exactly one
// hot key, so there is no separate fee payer to configure.
//
// Confirmation model: a simple synchronous submit — build, sign, persist
// the record (idempotencyKey-keyed, BEFORE broadcasting — see SetStatus),
// sendTransaction, and — on a successful (non-error) RPC response —
// optimistically record the transaction as Confirmed. There is no
// confirmation-depth polling loop yet (see
// internal/blockchain.RPCClient.SendTransaction's doc comment on
// what "accepted" does and doesn't mean). This is a deliberate, flagged V1
// simplification, not an oversight: set_status is naturally idempotent
// on-chain (reapplying the same (wallet,status,validUntil) has no duplicate
// side effect), so a dropped/failed submission is safe to
// retry (SetStatus itself resubmits a TxFailed record found under the same
// idempotencyKey — see isStatusRetryable) on the next matching webhook
// tick or admin resubmission, but a genuinely-landed-then-reorged
// transaction would not currently un-confirm without that polling loop.
type StatusService struct {
	submitter    blockchain.Submitter
	transactions repository.TransactionRepository
	// complianceProgramID is the rwa-compliance program id (base58) —
	// Config.ProgramCompliance.
	complianceProgramID string
	// registryPDA is derived once at construction (fixed for the whole
	// deployment — the registry PDA never depends on the target wallet).
	registryPDA string
	signer      ed25519.PrivateKey
	signerBytes [32]byte // signer's public key, cached to avoid re-deriving it on every call
	commitment  string
}

// NewStatusService constructs a StatusService, deriving the
// registry PDA once up front. Returns an error if complianceProgramID
// isn't valid base58 or signer isn't a proper 64-byte ed25519 private key
// — both are config/loader-time failures (see cmd/platform's
// loadComplianceKey), never expected once construction succeeds.
func NewStatusService(submitter blockchain.Submitter, transactions repository.TransactionRepository, complianceProgramID string, signer ed25519.PrivateKey, commitment string) (*StatusService, error) {
	if len(signer) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("compliance: signer must be %d bytes, got %d", ed25519.PrivateKeySize, len(signer))
	}
	registryPDA, _, err := blockchain.FindProgramAddress([][]byte{[]byte(registrySeed)}, complianceProgramID)
	if err != nil {
		return nil, fmt.Errorf("compliance: deriving registry PDA: %w", err)
	}
	pub, ok := signer.Public().(ed25519.PublicKey)
	if !ok || len(pub) != 32 {
		return nil, fmt.Errorf("compliance: signer has an invalid public key")
	}
	var pubArr [32]byte
	copy(pubArr[:], pub)
	return &StatusService{
		submitter: submitter, transactions: transactions, complianceProgramID: complianceProgramID,
		registryPDA: registryPDA, signer: signer, signerBytes: pubArr, commitment: commitment,
	}, nil
}

// PublicKey returns the compliance authority's base58 pubkey — used for the
// boot-time "does this match the on-chain authority" check and log line
// (see cmd/platform's buildApp) and by tests.
func (s *StatusService) PublicKey() string { return base58.Encode(s.signerBytes[:]) }

// wordU64LE encodes n as 8 little-endian bytes — Borsh's u64
// encoding, per rwa-compliance's set_status args (status: u8, valid_until:
// u64) — NOT the big-endian right-aligned word the EVM/eip712 ABI encoding
// uses; these are two different wire formats for two different purposes
// (instruction args vs. an attestation digest), easy to conflate but must
// not be.
func wordU64LE(n uint64) [8]byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], n)
	return b
}

// SetStatus submits one set_status(status, validUntil) instruction for
// account — a base58 Solana wallet pubkey; see StatusWriter's doc comment.
// Implements StatusWriter, so WebhookReconciler/api's handler can drive it
// without knowing the concrete type.
//
// idempotencyKey handling: a non-empty key is looked up FIRST, and an
// existing non-retryable record is
// returned as-is instead of broadcasting again — the old version ignored
// the key entirely and unconditionally rebroadcast every call, which could
// waste the hot key's fees on a duplicate set_status whenever a caller
// retried (e.g. WebhookReconciler.submit on the next tick after an
// events.Update failure). The transaction record is also now persisted
// BEFORE SendTransaction (a hard error if that fails, not swallowed): the
// signature is already fully determined at this point (ed25519 signing is
// deterministic, so localSig below never changes), so persisting first
// means a crash between broadcast and the caller's own bookkeeping still
// leaves a durable, idempotencyKey-findable record of the attempt.
func (s *StatusService) SetStatus(ctx context.Context, idempotencyKey string, account string, status OnChainStatus, validUntil uint64) (*models.Transaction, error) {
	if idempotencyKey != "" && s.transactions != nil {
		existing, err := s.transactions.GetByIdempotencyKey(ctx, idempotencyKey)
		if err != nil && !errors.Is(err, repository.ErrNotFound) {
			return nil, fmt.Errorf("compliance: idempotency lookup for %q: %w", idempotencyKey, err)
		}
		if err == nil && !isStatusRetryable(existing) {
			return existing, nil // already broadcast (or ambiguously in flight) under this key
		}
	}

	walletBytes, err := base58.Decode(account)
	if err != nil {
		return nil, fmt.Errorf("compliance: account %q: invalid base58: %w", account, err)
	}
	if len(walletBytes) != 32 {
		return nil, fmt.Errorf("compliance: account %q decodes to %d bytes, want 32", account, len(walletBytes))
	}
	var wallet [32]byte
	copy(wallet[:], walletBytes)

	recordPDA, _, err := blockchain.FindProgramAddress([][]byte{[]byte(recordSeed), wallet[:]}, s.complianceProgramID)
	if err != nil {
		return nil, fmt.Errorf("compliance: deriving record PDA for %s: %w", account, err)
	}
	registryBytes, err := decode32(s.registryPDA)
	if err != nil {
		return nil, err
	}
	recordBytes, err := decode32(recordPDA)
	if err != nil {
		return nil, err
	}
	programBytes, err := decode32(s.complianceProgramID)
	if err != nil {
		return nil, err
	}
	systemProgramBytes, err := decode32(systemProgramID)
	if err != nil {
		return nil, err
	}

	validUntilLE := wordU64LE(validUntil)
	data := make([]byte, 0, 8+1+8)
	data = append(data, setStatusDiscriminator[:]...)
	data = append(data, byte(status))
	data = append(data, validUntilLE[:]...)

	// Account order MUST match rwa-compliance's set_status IDL exactly
	// (solana/target/idl/rwa_compliance.json): registry, authority, wallet,
	// record, payer, system_program. authority and payer are BOTH this
	// server's single compliance hot key — see the type doc comment.
	instr := blockchain.Instruction{
		ProgramID: programBytes,
		Accounts: []blockchain.AccountMeta{
			{Pubkey: registryBytes, IsSigner: false, IsWritable: false},
			{Pubkey: s.signerBytes, IsSigner: true, IsWritable: false}, // authority
			{Pubkey: wallet, IsSigner: false, IsWritable: false},
			{Pubkey: recordBytes, IsSigner: false, IsWritable: true},
			{Pubkey: s.signerBytes, IsSigner: true, IsWritable: true}, // payer
			{Pubkey: systemProgramBytes, IsSigner: false, IsWritable: false},
		},
		Data: data,
	}

	blockhash, _, err := s.submitter.GetLatestBlockhash(ctx, s.commitment)
	if err != nil {
		return nil, fmt.Errorf("compliance: getLatestBlockhash: %w", err)
	}
	message, err := blockchain.CompileLegacyMessage(s.signerBytes, blockhash, []blockchain.Instruction{instr})
	if err != nil {
		return nil, fmt.Errorf("compliance: compiling set_status message: %w", err)
	}
	base64Tx, localSig, err := blockchain.SignTransaction(message, s.signer)
	if err != nil {
		return nil, fmt.Errorf("compliance: signing set_status transaction: %w", err)
	}

	// localSig (the fee payer's ed25519 signature over the compiled
	// message) is fully determined at this point — signing is
	// deterministic, so it will not change no matter what SendTransaction
	// reports — which is what lets this record be persisted BEFORE
	// broadcasting: a durable, idempotencyKey-findable row exists from here
	// on, even if the process crashes mid-broadcast.
	now := time.Now().UTC()
	tx := &models.Transaction{
		ID: uuid.NewString(), IdempotencyKey: idempotencyKey, Kind: "compliance.setStatus",
		From: s.PublicKey(), To: s.complianceProgramID, TxHash: localSig,
		Status: models.TxPending, SubmittedAt: now, UpdatedAt: now,
	}
	if s.transactions != nil {
		// A hard error, unlike the old post-broadcast persist:
		// nothing has been broadcast yet, so failing here simply refuses to
		// send rather than sending an on-chain action this deployment can't
		// durably account for.
		if err := s.transactions.Create(ctx, tx); err != nil {
			return nil, fmt.Errorf("compliance: persist set_status transaction before broadcast: %w", err)
		}
	}

	rpcSig, err := s.submitter.SendTransaction(ctx, base64Tx, blockchain.SendTransactionOpts{})
	if err != nil {
		s.markFailed(ctx, tx)
		return nil, fmt.Errorf("compliance: sendTransaction: %w", err)
	}
	// The RPC-echoed signature should always equal the one we computed
	// locally (a Solana transaction's signature/id IS the fee payer's
	// signature — the node doesn't invent a different one); a mismatch
	// would mean this client's own signing/serialization is broken in a way
	// that happens to still be accepted, which is worth surfacing loudly
	// rather than silently trusting whichever value showed up.
	if rpcSig != "" && rpcSig != localSig {
		s.markFailed(ctx, tx)
		return nil, fmt.Errorf("compliance: sendTransaction returned signature %q, expected %q (local signing/serialization mismatch)", rpcSig, localSig)
	}

	tx.Status = models.TxConfirmed
	tx.UpdatedAt = time.Now().UTC()
	if s.transactions != nil {
		// Best-effort, logged rather than failing the call: the transaction
		// is ALREADY broadcast (and, per this type's optimistic-Confirmed
		// model, treated as landed) by this point — reporting an error here
		// would tell the caller a privileged on-chain action failed when it
		// didn't. A persistence failure here only costs WebhookReconciler
		// its ability to observe this record and advance Applying->Applied
		// for the KYC auto-allowlist path (see checkSubmitted); the
		// on-chain effect itself is unaffected, and the pre-broadcast
		// Create above already durably recorded the attempt under this
		// idempotencyKey (as TxPending) regardless.
		if err := s.transactions.Update(ctx, tx); err != nil {
			log.Printf("compliance: set_status transaction %s broadcast but confirmed status not persisted: %v", localSig, err)
		}
	}
	return tx, nil
}

// markFailed marks tx TxFailed after a broadcast attempt that did not land
// (SendTransaction itself erroring, or the signature-mismatch defensive
// check above), so a retry under the same idempotencyKey is recognized as
// retryable next time — see isStatusRetryable — instead of wedging a
// pre-broadcast TxPending record forever. Best-effort: the broadcast
// attempt already failed, so a further persistence failure here is logged,
// not propagated.
func (s *StatusService) markFailed(ctx context.Context, tx *models.Transaction) {
	if s.transactions == nil {
		return
	}
	tx.Status = models.TxFailed
	tx.UpdatedAt = time.Now().UTC()
	if err := s.transactions.Update(ctx, tx); err != nil {
		log.Printf("compliance: set_status transaction %s marked failed but not persisted: %v", tx.TxHash, err)
	}
}

// isStatusRetryable implements the status model's retry rule:
// SetStatus only ever persists TxPending (a
// broadcast attempt whose outcome isn't known yet — this call is still
// in-flight, or crashed between persisting and broadcasting), TxFailed (the
// broadcast attempt itself never landed), or TxConfirmed (broadcast
// succeeded, optimistically treated as landed — see the type doc comment).
// Only TxFailed is safe to retry under the same idempotencyKey: TxPending
// is deliberately treated as NOT retryable, since there is no
// confirmation-depth polling loop to later resolve it — resubmitting over
// an unresolved in-flight attempt risks a genuine duplicate broadcast, the
// exact hazard this fixes.
func isStatusRetryable(tx *models.Transaction) bool {
	return tx.Status == models.TxFailed
}

// decode32 base58-decodes s into a [32]byte, erroring on anything other
// than exactly 32 bytes.
func decode32(s string) ([32]byte, error) {
	var out [32]byte
	b, err := base58.Decode(s)
	if err != nil {
		return out, fmt.Errorf("compliance: %q: invalid base58: %w", s, err)
	}
	if len(b) != 32 {
		return out, fmt.Errorf("compliance: %q decodes to %d bytes, want 32", s, len(b))
	}
	copy(out[:], b)
	return out, nil
}
