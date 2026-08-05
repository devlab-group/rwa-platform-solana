package compliance

import (
	"context"
	"errors"
	"fmt"

	"github.com/rwa-platform/server/internal/dal/models"
	"github.com/rwa-platform/server/internal/dal/repository"
)

// WebhookReconciler drives the outbox half of the webhook inbox/outbox
// state machine: it enqueues an idempotent transaction intent, retries and
// reconciles uncertain broadcasts, records the tx hash and confirmation, and
// sets Applied=true ONLY after the canonical on-chain event confirms.
// WebhookService.Process only ever gets an event as far as
// Accepted/Recorded — submitting the on-chain status transaction and
// advancing Accepted -> Applying -> Applied/Failed happens entirely here,
// on its own schedule, so a slow/failed relay can never block or corrupt
// the HTTP webhook response.
//
// Reconcile is idempotent and safe to call repeatedly — same pattern as
// project.Reconciler: a synchronous call at startup recovers whatever was
// Accepted/Applying when the process last stopped, then a ticker keeps
// advancing the queue (see cmd/platform/main.go's startBackgroundLoops).
type WebhookReconciler struct {
	events repository.KYCEventRepository
	txs    repository.TransactionRepository
	status StatusWriter
}

// NewWebhookReconciler constructs a WebhookReconciler. status may be nil —
// see submit's doc comment for what happens then. A production deployment
// with webhook ingestion enabled but no compliance signer configured is a
// startup-time configuration error the fail-closed startup checks are
// responsible for rejecting; this reconciler's job is only to never
// silently fabricate an Applied result when it cannot actually apply one.
// status is the StatusWriter interface rather than the concrete
// StatusService, so this reconciler stays testable against a fake and
// decoupled from how the status write is actually broadcast — see
// cmd/platform's buildApp.
func NewWebhookReconciler(events repository.KYCEventRepository, txs repository.TransactionRepository, status StatusWriter) *WebhookReconciler {
	return &WebhookReconciler{events: events, txs: txs, status: status}
}

// Reconcile advances every event still Accepted or Applying by one step.
// There is no deep-reorg reopen pass: transactions are read at a fixed
// commitment, so an event that reached Applied can never have its linked
// transaction walked back. One event's failure doesn't abort the batch —
// it's collected and returned (joined) at the end so every other address's
// queue still makes progress on this tick.
func (r *WebhookReconciler) Reconcile(ctx context.Context) error {
	pending, err := r.events.ListPending(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range pending {
		if err := r.reconcileOne(ctx, e); err != nil {
			errs = append(errs, fmt.Errorf("kyc event %s (%s): %w", e.ID, e.Address, err))
		}
	}
	return errors.Join(errs...)
}

func (r *WebhookReconciler) reconcileOne(ctx context.Context, e *models.KYCEvent) error {
	// A Claiming event was durably created but its claim was never
	// resolved — the Process request died at the claim/finalize boundary.
	// Resolve it here: finalizeClaim promotes it to Accepted/Recorded if it
	// (still) holds the per-address claim, else Superseded. This MUST run
	// before the generic supersede check below, whose currentKey compare
	// would otherwise wrongly supersede a legitimately-winning event whose
	// claim simply has not advanced yet.
	if e.ApplyStatus == models.KYCApplyClaiming {
		_, err := finalizeClaim(ctx, r.events, e)
		return err
	}

	// Never advance a decision the claim has since moved past: a newer
	// delivery for the same address may have won ClaimLatestForAddress
	// after this event was accepted but before it reached Applied.
	// Superseding must never let a stale decision be applied out of
	// order just because it happened to be queued first.
	currentKey, err := r.events.CurrentClaimEventKey(ctx, e.Address)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return err
	}
	if err == nil && currentKey != kycEventIDKey(e.Provider, e.EventID) {
		e.ApplyStatus = models.KYCApplySuperseded
		return r.events.Update(ctx, e)
	}

	switch e.ApplyStatus {
	case models.KYCApplyAccepted:
		return r.submit(ctx, e)
	case models.KYCApplyApplying:
		return r.checkSubmitted(ctx, e)
	default:
		return nil // Applied/Superseded/Failed/Recorded are terminal; ListPending never returns them anyway
	}
}

// submit enqueues the on-chain status transaction for an Accepted event.
func (r *WebhookReconciler) submit(ctx context.Context, e *models.KYCEvent) error {
	if r.status == nil {
		// No compliance hot key configured on this deployment: webhooks
		// can be durably accepted (Process already persisted this event)
		// but cannot be applied on-chain. Leaving it Accepted forever —
		// visible on the webhook-history screen as never-applied — is
		// deliberate: it must never silently report Applied for a
		// decision nothing actually relayed.
		return nil
	}
	statusVal, ok := StatusFromString(e.Outcome)
	if !ok {
		// Only reachable for a malformed/legacy record — Process() only
		// ever creates an Accepted event for "Allowed"/"Blocked".
		e.ApplyStatus = models.KYCApplyFailed
		return r.events.Update(ctx, e)
	}
	// The idempotency key is derived from the same (provider,eventId)
	// identity the claim uses, so a crash between SetStatus succeeding
	// and this Update persisting causes the next tick to resubmit under
	// the IDENTICAL TxManager-level idempotent intent instead of creating a
	// second transaction for the same decision.
	idemKey := "kyc-status:" + kycEventIDKey(e.Provider, e.EventID)
	tx, err := r.status.SetStatus(ctx, idemKey, e.Address, statusVal, uint64(e.ValidUntil))
	if err != nil {
		return err // ApplyStatus stays Accepted; retried next tick
	}
	e.TxID = tx.ID
	e.ApplyStatus = models.KYCApplyApplying
	return r.events.Update(ctx, e)
}

// checkSubmitted advances an Applying event once its linked transaction
// resolves.
func (r *WebhookReconciler) checkSubmitted(ctx context.Context, e *models.KYCEvent) error {
	if e.TxID == "" {
		// Applying is only ever set alongside TxID in submit — this
		// shouldn't happen, but fail safe by resetting to Accepted rather
		// than getting stuck forever with nothing to poll.
		e.ApplyStatus = models.KYCApplyAccepted
		return r.events.Update(ctx, e)
	}
	tx, err := r.txs.Get(ctx, e.TxID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			// The linked transaction record is gone — e.g. a Solana
			// StatusService.SetStatus call whose pre-broadcast Create
			// itself failed transiently, or any other lost record. Same
			// fail-safe reasoning as the e.TxID == "" branch above: reset to
			// Accepted with TxID cleared rather than leaving this event
			// wedged in Applying forever with nothing left to poll.
			e.ApplyStatus = models.KYCApplyAccepted
			e.TxID = ""
			return r.events.Update(ctx, e)
		}
		return err
	}
	switch tx.Status {
	case models.TxConfirmed:
		e.ApplyStatus = models.KYCApplyApplied
		return r.events.Update(ctx, e)
	case models.TxFailed:
		// Nothing took effect on-chain under this attempt — submission
		// errored, or the cluster reported an execution error. Retryable:
		// clear TxID and go back to Accepted so the next tick resubmits
		// under the SAME idempotency key (a TxFailed record's
		// Idempotency-Key is treated as "no prior record", never replayed
		// as an already-submitted result — see models.TxFailed's doc
		// comment).
		e.ApplyStatus = models.KYCApplyAccepted
		e.TxID = ""
		return r.events.Update(ctx, e)
	default:
		// Pending: still in flight — leave Applying alone this tick.
		return nil
	}
}
