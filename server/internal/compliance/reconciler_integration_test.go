package compliance

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rwa-platform/server/internal/dal/memory"
	"github.com/rwa-platform/server/internal/dal/models"
)

// failNUpdatesEventRepo wraps a *memory.KYCEventRepository and fails the
// first n calls to Update, so a test can simulate exactly the hazard: a
// set_status broadcast that lands successfully on-chain, immediately
// followed by a durable-persistence failure recording that outcome
// against the KYC event itself.
type failNUpdatesEventRepo struct {
	*memory.KYCEventRepository
	remaining int
}

func (r *failNUpdatesEventRepo) Update(ctx context.Context, e *models.KYCEvent) error {
	if r.remaining > 0 {
		r.remaining--
		return errors.New("injected update failure")
	}
	return r.KYCEventRepository.Update(ctx, e)
}

// TestWebhookReconcilerSubmitDoesNotDoubleBroadcastOnUpdateFailure
// pins the invariant, exercised through the real WebhookReconciler
// + StatusService pairing: submit() calls status.SetStatus (which
// broadcasts a real Solana transaction) BEFORE persisting the event's own
// Accepted->Applying transition. If that events.Update call fails, the
// event is left durably Accepted (submit returns its error, unchanged), so
// the next Reconcile tick calls submit -> SetStatus again under the
// IDENTICAL idempotencyKey ("kyc-status:" + provider/eventID — see submit's
// doc comment). The old StatusService.SetStatus ignored
// idempotencyKey entirely and would broadcast a second, wasted transaction;
// the fix must recognize the already-broadcast (TxConfirmed) record and
// return it without a second SendTransaction call.
func TestWebhookReconcilerSubmitDoesNotDoubleBroadcastOnUpdateFailure(t *testing.T) {
	signer := mustGenerateEd25519(t)
	submitter := &fakeSubmitter{blockhash: "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8"}
	txs := memory.NewTransactionRepository()
	status, err := NewStatusService(submitter, txs, "SuppLyCtR1111111111111111111111111111111111", signer, "finalized")
	if err != nil {
		t.Fatal(err)
	}

	events := &failNUpdatesEventRepo{KYCEventRepository: memory.NewKYCEventRepository(), remaining: 1}
	r := NewWebhookReconciler(events, txs, status)

	ctx := context.Background()
	address := "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi"
	occurredAt := time.Now().UTC()
	won, err := events.ClaimLatestForAddress(ctx, address, occurredAt, kycEventIDKey("sumsub", "evt-1"))
	if err != nil || !won {
		t.Fatalf("claim: won=%v err=%v", won, err)
	}
	e := &models.KYCEvent{
		ID: "evt-1", Address: address, Provider: "sumsub", EventID: "evt-1",
		Status: "Allowed", Outcome: "Allowed", ApplyStatus: models.KYCApplyAccepted,
		OccurredAt: occurredAt, ReceivedAt: occurredAt, PayloadHash: "evt-1",
	}
	if err := events.Create(ctx, e); err != nil {
		t.Fatal(err)
	}

	// Tick #1: SetStatus broadcasts successfully, but the Accepted->Applying
	// events.Update is injected to fail — submit() must propagate that
	// error, leaving the event Accepted.
	if err := r.Reconcile(ctx); err == nil {
		t.Fatal("Reconcile #1: expected the injected Update failure to surface")
	}
	if submitter.lastRawTx == nil {
		t.Fatal("Reconcile #1: expected SetStatus to have broadcast once")
	}

	stillAccepted, err := events.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(stillAccepted) != 1 || stillAccepted[0].ApplyStatus != models.KYCApplyAccepted {
		t.Fatalf("event after failed Update = %+v, want ApplyStatus still Accepted", stillAccepted)
	}

	// Reset the fake submitter's observation so tick #2's assertion is
	// unambiguous about whether IT broadcast again.
	submitter.lastRawTx = nil

	// Tick #2: submit() runs again for the same still-Accepted event, under
	// the SAME idempotencyKey. SetStatus must recognize the TxConfirmed
	// record persisted during tick #1 and return it WITHOUT calling
	// SendTransaction again.
	if err := r.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile #2: %v", err)
	}
	if submitter.lastRawTx != nil {
		t.Error("Reconcile #2: SetStatus broadcast a SECOND transaction under the same idempotency key — duplicate broadcast")
	}

	final, err := events.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(final) != 1 || final[0].ApplyStatus != models.KYCApplyApplying {
		t.Fatalf("event after tick #2 = %+v, want ApplyStatus Applying (submit succeeded this time)", final)
	}
}

// TestWebhookReconcilerCheckSubmittedRecoversFromLostTransactionRecord pins
// checkSubmitted's missing ErrNotFound branch: an Applying event whose
// linked Transaction record has vanished (e.g. lost/never persisted) must
// reset to Accepted with TxID cleared — self-healing instead of wedging
// forever with nothing left to poll.
func TestWebhookReconcilerCheckSubmittedRecoversFromLostTransactionRecord(t *testing.T) {
	txs := memory.NewTransactionRepository()
	events := memory.NewKYCEventRepository()
	r := NewWebhookReconciler(events, txs, nil)

	ctx := context.Background()
	address := "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi"
	occurredAt := time.Now().UTC()
	won, err := events.ClaimLatestForAddress(ctx, address, occurredAt, kycEventIDKey("sumsub", "evt-2"))
	if err != nil || !won {
		t.Fatalf("claim: won=%v err=%v", won, err)
	}
	e := &models.KYCEvent{
		ID: "evt-2", Address: address, Provider: "sumsub", EventID: "evt-2",
		Status: "Allowed", Outcome: "Allowed", ApplyStatus: models.KYCApplyApplying,
		TxID: "does-not-exist", OccurredAt: occurredAt, ReceivedAt: occurredAt, PayloadHash: "evt-2",
	}
	if err := events.Create(ctx, e); err != nil {
		t.Fatal(err)
	}

	if err := r.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	all, err := events.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var got *models.KYCEvent
	for _, ev := range all {
		if ev.ID == "evt-2" {
			got = ev
		}
	}
	if got == nil {
		t.Fatal("evt-2 not found after Reconcile")
	}
	if got.ApplyStatus != models.KYCApplyAccepted {
		t.Errorf("ApplyStatus = %s, want %s (self-healed from a lost transaction record)", got.ApplyStatus, models.KYCApplyAccepted)
	}
	if got.TxID != "" {
		t.Errorf("TxID = %q, want cleared", got.TxID)
	}
}
