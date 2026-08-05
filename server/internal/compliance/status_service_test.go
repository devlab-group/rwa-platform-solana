package compliance

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/mr-tron/base58"

	"github.com/rwa-platform/server/internal/blockchain"
	"github.com/rwa-platform/server/internal/dal/memory"
	"github.com/rwa-platform/server/internal/dal/models"
)

// TestSetStatusDiscriminatorMatchesIDL pins the hardcoded Anchor
// discriminator against its own definition (sha256("global:set_status")[:8])
// AND against the literal bytes solana/target/idl/rwa_compliance.json pins
// for set_status — a drift here is exactly the kind of silent, hard-to-debug
// failure (rejected on-chain as an unrecognized instruction) this test
// exists to catch loudly instead.
func TestSetStatusDiscriminatorMatchesIDL(t *testing.T) {
	sum := sha256.Sum256([]byte("global:set_status"))
	var want [8]byte
	copy(want[:], sum[:8])
	if setStatusDiscriminator != want {
		t.Errorf("setStatusDiscriminator = %v, want %v (sha256(\"global:set_status\")[:8])", setStatusDiscriminator, want)
	}
	// Literal bytes from solana/target/idl/rwa_compliance.json's set_status
	// entry, so a hand-edit of the discriminator constant that still
	// happens to satisfy the sha256 check above (impossible, but belt and
	// suspenders) is caught too.
	idlBytes := [8]byte{181, 184, 224, 203, 193, 29, 177, 224}
	if setStatusDiscriminator != idlBytes {
		t.Errorf("setStatusDiscriminator = %v, want the IDL's literal %v", setStatusDiscriminator, idlBytes)
	}
}

// fakeSubmitter is a minimal blockchain.Submitter test double that
// records the last transaction it was asked to send, so tests can decode
// and assert on the actual wire bytes StatusService produced.
type fakeSubmitter struct {
	blockhash         string
	lastRawTx         []byte // decoded from the last SendTransaction call's base64
	sendErr           error
	returnSigMismatch bool
}

func (f *fakeSubmitter) GetLatestBlockhash(ctx context.Context, commitment string) (string, uint64, error) {
	return f.blockhash, 12345, nil
}

func (f *fakeSubmitter) SendTransaction(ctx context.Context, base64Tx string, opts blockchain.SendTransactionOpts) (string, error) {
	if f.sendErr != nil {
		return "", f.sendErr
	}
	raw, err := base64.StdEncoding.DecodeString(base64Tx)
	if err != nil {
		return "", err
	}
	f.lastRawTx = raw
	sig := raw[1:65] // shortvec(1) + 64-byte signature + message
	if f.returnSigMismatch {
		return base58.Encode(append([]byte{0xFF}, sig[1:]...)), nil
	}
	return base58.Encode(sig), nil
}

func mustGenerateEd25519(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// TestStatusServiceSetStatusBuildsExpectedInstruction is the
// end-to-end wiring test: given a fake submitter, SetStatus derives the
// registry/record PDAs, compiles the set_status instruction with the exact
// account order and discriminator+args the on-chain program's IDL expects,
// signs it, and submits it — this decodes the actual bytes handed to
// SendTransaction and checks every one of those properties, not just that
// no error was returned.
func TestStatusServiceSetStatusBuildsExpectedInstruction(t *testing.T) {
	signer := mustGenerateEd25519(t)
	programID := "SuppLyCtR1111111111111111111111111111111111" // any valid-looking 32-byte base58 program id fixture
	wallet := "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi"

	txs := memory.NewTransactionRepository()
	submitter := &fakeSubmitter{blockhash: "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8"}

	svc, err := NewStatusService(submitter, txs, programID, signer, "finalized")
	if err != nil {
		t.Fatalf("NewStatusService: %v", err)
	}

	tx, err := svc.SetStatus(context.Background(), "idem-1", wallet, OnChainStatusAllowed, 1800000000)
	if err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	if tx.Status != models.TxConfirmed {
		t.Errorf("Status = %s, want %s (optimistic V1 model — see the type doc comment)", tx.Status, models.TxConfirmed)
	}
	if tx.Kind != "compliance.setStatus" {
		t.Errorf("Kind = %q", tx.Kind)
	}
	if tx.IdempotencyKey != "idem-1" {
		t.Errorf("IdempotencyKey = %q, want idem-1", tx.IdempotencyKey)
	}

	// The transaction record must be durably persisted (WebhookReconciler.
	// checkSubmitted looks it up by ID).
	stored, err := txs.Get(context.Background(), tx.ID)
	if err != nil {
		t.Fatalf("expected the transaction to be persisted: %v", err)
	}
	if stored.TxHash != tx.TxHash {
		t.Errorf("persisted TxHash = %q, want %q", stored.TxHash, tx.TxHash)
	}

	// Decode the actual wire message SendTransaction received and verify
	// the instruction shape.
	if submitter.lastRawTx == nil {
		t.Fatal("SendTransaction was never called")
	}
	message := submitter.lastRawTx[65:] // skip shortvec(1) + 64-byte signature

	registryPDA, _, err := blockchain.FindProgramAddress([][]byte{[]byte("registry")}, programID)
	if err != nil {
		t.Fatal(err)
	}
	walletBytes, _ := base58.Decode(wallet)
	recordPDA, _, err := blockchain.FindProgramAddress([][]byte{[]byte("record"), walletBytes}, programID)
	if err != nil {
		t.Fatal(err)
	}

	// header: numRequiredSignatures=1 (authority==payer==feePayer, deduped
	// to one signer), numReadonlySigned=0, numReadonlyUnsigned=4 (registry,
	// wallet, systemProgram, programID).
	if message[0] != 1 || message[1] != 0 || message[2] != 4 {
		t.Fatalf("header = %v, want [1,0,4]", message[0:3])
	}
	if message[3] != 6 {
		t.Fatalf("account_keys count = %d, want 6", message[3])
	}
	accountKeys := message[4 : 4+6*32]
	feePayerB58 := base58.Encode(accountKeys[0:32])
	if feePayerB58 != svc.PublicKey() {
		t.Errorf("account_keys[0] (fee payer) = %s, want the compliance signer's own pubkey %s", feePayerB58, svc.PublicKey())
	}
	recordB58 := base58.Encode(accountKeys[32:64])
	if recordB58 != recordPDA {
		t.Errorf("account_keys[1] (writable non-signer) = %s, want the record PDA %s", recordB58, recordPDA)
	}

	// The remaining 4 readonly-unsigned accounts (registry, wallet,
	// systemProgram, programID) are sorted by raw bytes — just check all
	// four are present somewhere in that segment, without over-specifying
	// the exact sub-order (see CompileLegacyMessage's doc comment).
	readonlySegment := accountKeys[64:192]
	for _, want := range []string{registryPDA, wallet, "11111111111111111111111111111111", programID} {
		wantBytes, _ := base58.Decode(want)
		found := false
		for i := 0; i+32 <= len(readonlySegment); i += 32 {
			if base58.Encode(readonlySegment[i:i+32]) == base58.Encode(wantBytes) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %s somewhere in the readonly-unsigned account segment", want)
		}
	}

	// Instruction data: discriminator + status(1) + validUntil(8 bytes LE).
	instrBytesStart := 4 + 6*32 + 32 // header+accountKeys+blockhash
	rest := message[instrBytesStart:]
	// rest = [instrCount(1)][programIdIndex(1)][accountsCount(1)][6 indices][dataLen(1)][17 data bytes]
	if rest[0] != 1 {
		t.Fatalf("instruction count = %d, want 1", rest[0])
	}
	accCount := rest[2]
	if accCount != 6 {
		t.Fatalf("instruction account count = %d, want 6", accCount)
	}
	dataStart := 3 + int(accCount) + 1 // +1 for the data-length shortvec byte
	dataLen := rest[3+int(accCount)]
	if dataLen != 17 {
		t.Fatalf("instruction data length = %d, want 17 (8-byte discriminator + 1-byte status + 8-byte validUntil)", dataLen)
	}
	data := rest[dataStart : dataStart+int(dataLen)]
	var gotDiscriminator [8]byte
	copy(gotDiscriminator[:], data[:8])
	if gotDiscriminator != setStatusDiscriminator {
		t.Errorf("instruction discriminator = %v, want %v", gotDiscriminator, setStatusDiscriminator)
	}
	if data[8] != byte(OnChainStatusAllowed) {
		t.Errorf("status arg = %d, want %d (Allowed)", data[8], OnChainStatusAllowed)
	}
	gotValidUntil := uint64(0)
	for i := 0; i < 8; i++ {
		gotValidUntil |= uint64(data[9+i]) << (8 * i)
	}
	if gotValidUntil != 1800000000 {
		t.Errorf("validUntil arg = %d, want 1800000000", gotValidUntil)
	}
}

func TestStatusServiceSetStatusRejectsMalformedAccount(t *testing.T) {
	signer := mustGenerateEd25519(t)
	svc, err := NewStatusService(&fakeSubmitter{blockhash: "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8"}, nil, "SuppLyCtR1111111111111111111111111111111111", signer, "finalized")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetStatus(context.Background(), "", "not-a-valid-address", OnChainStatusAllowed, 0); err == nil {
		t.Fatal("expected an error for a malformed account address")
	}
}

func TestStatusServiceSetStatusPropagatesSendError(t *testing.T) {
	signer := mustGenerateEd25519(t)
	submitter := &fakeSubmitter{blockhash: "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8", sendErr: context.DeadlineExceeded}
	svc, err := NewStatusService(submitter, nil, "SuppLyCtR1111111111111111111111111111111111", signer, "finalized")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetStatus(context.Background(), "", "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi", OnChainStatusAllowed, 0); err == nil {
		t.Fatal("expected an error propagated from SendTransaction")
	}
}

func TestStatusServiceSetStatusDetectsSignatureMismatch(t *testing.T) {
	signer := mustGenerateEd25519(t)
	submitter := &fakeSubmitter{blockhash: "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8", returnSigMismatch: true}
	svc, err := NewStatusService(submitter, nil, "SuppLyCtR1111111111111111111111111111111111", signer, "finalized")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetStatus(context.Background(), "", "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi", OnChainStatusAllowed, 0); err == nil {
		t.Fatal("expected an error when the RPC-echoed signature doesn't match the locally computed one")
	}
}

func TestNewStatusServiceRejectsMalformedProgramID(t *testing.T) {
	signer := mustGenerateEd25519(t)
	if _, err := NewStatusService(&fakeSubmitter{}, nil, "not-valid-base58-0OIl", signer, "finalized"); err == nil {
		t.Fatal("expected an error for a malformed compliance program id")
	}
}

func TestNewStatusServiceRejectsWrongSizedSigner(t *testing.T) {
	if _, err := NewStatusService(&fakeSubmitter{}, nil, "SuppLyCtR1111111111111111111111111111111111", []byte("too-short"), "finalized"); err == nil {
		t.Fatal("expected an error for a malformed signer key")
	}
}

// TestStatusServiceSetStatusIdempotentUnderSameKey pins the
// invariant that the old SetStatus violated by ignoring idempotencyKey
// entirely and unconditionally rebroadcasting on every call. Two SetStatus
// calls under the SAME idempotencyKey must broadcast exactly once — the
// second call finds the already-persisted TxConfirmed record and returns
// it directly.
func TestStatusServiceSetStatusIdempotentUnderSameKey(t *testing.T) {
	signer := mustGenerateEd25519(t)
	submitter := &fakeSubmitter{blockhash: "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8"}
	txs := memory.NewTransactionRepository()
	svc, err := NewStatusService(submitter, txs, "SuppLyCtR1111111111111111111111111111111111", signer, "finalized")
	if err != nil {
		t.Fatal(err)
	}

	wallet := "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi"
	tx1, err := svc.SetStatus(context.Background(), "idem-same", wallet, OnChainStatusAllowed, 0)
	if err != nil {
		t.Fatalf("SetStatus #1: %v", err)
	}
	if submitter.lastRawTx == nil {
		t.Fatal("SetStatus #1: expected a broadcast")
	}
	submitter.lastRawTx = nil // so the assertion below is unambiguous about call #2

	tx2, err := svc.SetStatus(context.Background(), "idem-same", wallet, OnChainStatusAllowed, 0)
	if err != nil {
		t.Fatalf("SetStatus #2: %v", err)
	}
	if submitter.lastRawTx != nil {
		t.Error("SetStatus #2: broadcast a SECOND transaction under the same idempotency key")
	}
	if tx2.ID != tx1.ID || tx2.TxHash != tx1.TxHash {
		t.Errorf("SetStatus #2 returned a different transaction (%+v) than #1 (%+v), want the same persisted record", tx2, tx1)
	}
	if tx2.Status != models.TxConfirmed {
		t.Errorf("SetStatus #2 Status = %s, want %s", tx2.Status, models.TxConfirmed)
	}

	// A DIFFERENT idempotency key must still broadcast normally.
	submitter.lastRawTx = nil
	tx3, err := svc.SetStatus(context.Background(), "idem-different", wallet, OnChainStatusAllowed, 0)
	if err != nil {
		t.Fatalf("SetStatus #3: %v", err)
	}
	if submitter.lastRawTx == nil {
		t.Error("SetStatus #3: expected a broadcast under a different idempotency key")
	}
	if tx3.ID == tx1.ID {
		t.Error("SetStatus #3 reused tx1's ID despite a different idempotency key")
	}
}

// TestStatusServiceSetStatusRetriesAfterFailedBroadcast proves a
// FAILED broadcast (SendTransaction error) under a given idempotencyKey
// leaves a TxFailed record that a later SetStatus call under the SAME key
// is allowed to retry — unlike a TxConfirmed/TxPending record, which must
// never be resubmitted (see isStatusRetryable).
func TestStatusServiceSetStatusRetriesAfterFailedBroadcast(t *testing.T) {
	signer := mustGenerateEd25519(t)
	submitter := &fakeSubmitter{blockhash: "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8", sendErr: context.DeadlineExceeded}
	txs := memory.NewTransactionRepository()
	svc, err := NewStatusService(submitter, txs, "SuppLyCtR1111111111111111111111111111111111", signer, "finalized")
	if err != nil {
		t.Fatal(err)
	}

	wallet := "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi"
	if _, err := svc.SetStatus(context.Background(), "idem-retry", wallet, OnChainStatusAllowed, 0); err == nil {
		t.Fatal("SetStatus #1: expected the injected send error")
	}

	// The failed attempt must have persisted a TxFailed record, not left
	// nothing behind or a permanently-stuck TxPending one.
	stored, err := txs.GetByIdempotencyKey(context.Background(), "idem-retry")
	if err != nil {
		t.Fatalf("expected a TxFailed record persisted despite the send error: %v", err)
	}
	if stored.Status != models.TxFailed {
		t.Fatalf("persisted status after a failed broadcast = %s, want %s", stored.Status, models.TxFailed)
	}

	// A retry under the SAME key, with the send error now cleared, must
	// succeed and broadcast (retrying a TxFailed record, not silently
	// short-circuiting to a non-existent success).
	submitter.sendErr = nil
	tx2, err := svc.SetStatus(context.Background(), "idem-retry", wallet, OnChainStatusAllowed, 0)
	if err != nil {
		t.Fatalf("SetStatus #2 (retry): %v", err)
	}
	if submitter.lastRawTx == nil {
		t.Error("SetStatus #2: expected a broadcast on retry")
	}
	if tx2.Status != models.TxConfirmed {
		t.Errorf("SetStatus #2 Status = %s, want %s", tx2.Status, models.TxConfirmed)
	}
}
