package compliance

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/rwa-platform/server/internal/dal/memory"
	"github.com/rwa-platform/server/internal/dal/models"
	"github.com/rwa-platform/server/internal/dal/repository"
)

// fakeStatusWriter is a minimal StatusWriter test double for exercising
// WebhookReconciler's own state machine (Accepted -> Applying ->
// Applied/Failed, retry-under-idempotency-key, supersede, reopen-on-reorg)
// independent of any concrete StatusWriter's own submission/retry policy
// (e.g. StatusService's — see its own tests for that). SetStatus
// always "succeeds": a fresh idempotencyKey creates a new TxConfirmed
// record; an idempotencyKey with an existing record reuses that SAME
// record's ID, resetting it to TxConfirmed — modeling a resubmission that
// lands under the identical transaction identity, which is what these
// tests assert on (TxID reuse across a retry).
type fakeStatusWriter struct {
	txs repository.TransactionRepository
}

func (f *fakeStatusWriter) SetStatus(ctx context.Context, idempotencyKey, account string, status OnChainStatus, validUntil uint64) (*models.Transaction, error) {
	if idempotencyKey != "" {
		existing, err := f.txs.GetByIdempotencyKey(ctx, idempotencyKey)
		if err == nil {
			existing.Status = models.TxConfirmed
			existing.UpdatedAt = time.Now().UTC()
			if err := f.txs.Update(ctx, existing); err != nil {
				return nil, err
			}
			return existing, nil
		} else if !errors.Is(err, repository.ErrNotFound) {
			return nil, err
		}
	}
	now := time.Now().UTC()
	tx := &models.Transaction{
		ID: uuid.NewString(), IdempotencyKey: idempotencyKey, Kind: "compliance.setStatus",
		From: account, To: account, TxHash: uuid.NewString(),
		Status: models.TxConfirmed, SubmittedAt: now, UpdatedAt: now,
	}
	if err := f.txs.Create(ctx, tx); err != nil {
		return nil, err
	}
	return tx, nil
}

// reconcilerFixture wires a WebhookReconciler against real (in-memory)
// KYCEventRepository/TransactionRepository implementations and a
// fakeStatusWriter, so tests can drive a submission all the way through
// Pending -> Confirmed the same way cmd/platform's background loop does.
type reconcilerFixture struct {
	r      *WebhookReconciler
	events *memory.KYCEventRepository
	txRepo *memory.TransactionRepository
	status *fakeStatusWriter
}

func newReconcilerFixture(t *testing.T) *reconcilerFixture {
	t.Helper()
	events := memory.NewKYCEventRepository()
	txRepo := memory.NewTransactionRepository()
	status := &fakeStatusWriter{txs: txRepo}
	return &reconcilerFixture{
		r:      NewWebhookReconciler(events, txRepo, status),
		events: events, txRepo: txRepo, status: status,
	}
}

// seedAccepted claims and durably stores an Accepted event, exactly the
// state WebhookService.Process leaves one in for the reconciler to pick
// up — used so these tests exercise the reconciler in isolation without
// going through the full HMAC/Process path.
func (f *reconcilerFixture) seedAccepted(t *testing.T, id, address, provider, eventID, outcome string, occurredAt time.Time) *models.KYCEvent {
	t.Helper()
	ctx := context.Background()
	won, err := f.events.ClaimLatestForAddress(ctx, address, occurredAt, kycEventIDKey(provider, eventID))
	if err != nil {
		t.Fatal(err)
	}
	if !won {
		t.Fatalf("seedAccepted: claim for %s/%s did not win", provider, eventID)
	}
	e := &models.KYCEvent{
		ID: id, Address: address, Provider: provider, EventID: eventID, Status: outcome, Outcome: outcome,
		ApplyStatus: models.KYCApplyAccepted, OccurredAt: occurredAt, ReceivedAt: occurredAt, PayloadHash: id,
	}
	if err := f.events.Create(ctx, e); err != nil {
		t.Fatal(err)
	}
	return e
}

func (f *reconcilerFixture) get(t *testing.T, id string) *models.KYCEvent {
	t.Helper()
	all, err := f.events.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range all {
		if e.ID == id {
			return e
		}
	}
	t.Fatalf("event %s not found", id)
	return nil
}

// TestWebhookReconcilerSubmitsThenConfirms is the happy path:
// Accepted -> Applying (a tx intent is submitted) -> Applied, ONLY once
// the linked transaction actually confirms on-chain.
func TestWebhookReconcilerSubmitsThenConfirms(t *testing.T) {
	f := newReconcilerFixture(t)
	ctx := context.Background()
	addr := "7porTR32j7zt69GG4AwoPQx3f3FL2RLpSDKGtPXWTeaQ"
	f.seedAccepted(t, "evt-d1", addr, "test-provider", "evt-d1", "Allowed", time.Now().UTC())

	if err := f.r.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile (submit): %v", err)
	}
	got := f.get(t, "evt-d1")
	if got.ApplyStatus != models.KYCApplyApplying || got.TxID == "" {
		t.Fatalf("got %+v, want Applying with a TxID", got)
	}

	if err := f.r.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile (confirm): %v", err)
	}
	got = f.get(t, "evt-d1")
	if got.ApplyStatus != models.KYCApplyApplied {
		t.Fatalf("ApplyStatus = %s, want Applied", got.ApplyStatus)
	}
}

// TestWebhookReconcilerRetriesAfterTxFailed covers idempotency-key reuse on
// retry: a broadcast that never reached the mempool (TxFailed) must
// go back to Accepted and resubmit under the SAME idempotency key next
// tick, not get stuck or double-submit under a new one.
func TestWebhookReconcilerRetriesAfterTxFailed(t *testing.T) {
	f := newReconcilerFixture(t)
	ctx := context.Background()
	addr := "7tj9biW3KRJ7EEWmVUGigHiouCTXhV2dzcyvwma7Cyu7"
	f.seedAccepted(t, "evt-d2", addr, "test-provider", "evt-d2", "Allowed", time.Now().UTC())

	if err := f.r.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile (submit): %v", err)
	}
	got := f.get(t, "evt-d2")
	firstTxID := got.TxID

	tx, err := f.txRepo.Get(ctx, firstTxID)
	if err != nil {
		t.Fatal(err)
	}
	tx.Status = models.TxFailed
	if err := f.txRepo.Update(ctx, tx); err != nil {
		t.Fatal(err)
	}

	if err := f.r.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile (detect failed): %v", err)
	}
	got = f.get(t, "evt-d2")
	if got.ApplyStatus != models.KYCApplyAccepted || got.TxID != "" {
		t.Fatalf("got %+v, want Accepted with TxID cleared after a TxFailed broadcast", got)
	}

	// Next tick resubmits — under the identical idempotency key, so the
	// status writer reuses the SAME transaction record id.
	if err := f.r.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile (resubmit): %v", err)
	}
	got = f.get(t, "evt-d2")
	if got.ApplyStatus != models.KYCApplyApplying || got.TxID != firstTxID {
		t.Fatalf("got %+v, want Applying reusing tx id %s", got, firstTxID)
	}
}

// TestWebhookReconcilerSupersedesStaleAcceptedEvent covers the "never apply a
// stale decision" case: an Accepted event that a NEWER decision
// for the same address has since claimed must never be submitted at all —
// it's marked Superseded instead.
func TestWebhookReconcilerSupersedesStaleAcceptedEvent(t *testing.T) {
	f := newReconcilerFixture(t)
	ctx := context.Background()
	addr := "82ZjtKS4W1tZWR1nN4vZG3GLPWsw3cQH7SKF4XfJheYX"
	t0 := time.Now().UTC().Add(-time.Hour)
	f.seedAccepted(t, "evt-d4-old", addr, "test-provider", "evt-d4-old", "Blocked", t0)
	// A newer decision for the SAME address claims it before the old one
	// is ever reconciled — simulating a second webhook delivery arriving
	// while the first is still queued.
	f.seedAccepted(t, "evt-d4-new", addr, "test-provider", "evt-d4-new", "Allowed", t0.Add(time.Minute))

	if err := f.r.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	old := f.get(t, "evt-d4-old")
	if old.ApplyStatus != models.KYCApplySuperseded {
		t.Fatalf("old event ApplyStatus = %s, want Superseded", old.ApplyStatus)
	}
	if old.TxID != "" {
		t.Fatalf("superseded event must never have been submitted, got TxID %q", old.TxID)
	}
	newer := f.get(t, "evt-d4-new")
	if newer.ApplyStatus != models.KYCApplyApplying {
		t.Fatalf("newer event ApplyStatus = %s, want Applying (it should have been the one submitted)", newer.ApplyStatus)
	}
}

func TestWebhookReconcilerLeavesAcceptedEventWithoutStatusService(t *testing.T) {
	events := memory.NewKYCEventRepository()
	txRepo := memory.NewTransactionRepository()
	r := NewWebhookReconciler(events, txRepo, nil)
	ctx := context.Background()
	addr := "8EKdKDq6GunEvgmJfxuK8fad7zWY4oTjnfKDEfo6weWe"
	occurredAt := time.Now().UTC()
	if _, err := events.ClaimLatestForAddress(ctx, addr, occurredAt, kycEventIDKey("test-provider", "evt-d5")); err != nil {
		t.Fatal(err)
	}
	if err := events.Create(ctx, &models.KYCEvent{
		ID: "evt-d5", Address: addr, Provider: "test-provider", EventID: "evt-d5", Outcome: "Allowed",
		ApplyStatus: models.KYCApplyAccepted, OccurredAt: occurredAt, ReceivedAt: occurredAt, PayloadHash: "evt-d5",
	}); err != nil {
		t.Fatal(err)
	}

	if err := r.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	all, err := events.List(ctx)
	if err != nil || len(all) != 1 {
		t.Fatalf("events = %v, err %v", all, err)
	}
	if all[0].ApplyStatus != models.KYCApplyAccepted {
		t.Fatalf("ApplyStatus = %s, want it to stay Accepted (never fabricate Applied without a signer)", all[0].ApplyStatus)
	}
}
