package redemption

import (
	"context"
	"testing"

	"github.com/rwa-platform/server/internal/dal/memory"
	"github.com/rwa-platform/server/internal/dal/models"
)

func TestConfirmationsAndClaimable(t *testing.T) {
	pending := &models.RedemptionRequest{Status: models.RedemptionPending}
	if got := Confirmations(pending, 100); got != 0 {
		t.Errorf("Confirmations(pending) = %d, want 0", got)
	}
	if Claimable(pending, 100, 3) {
		t.Error("expected pending request to never be claimable")
	}

	funded := &models.RedemptionRequest{Status: models.RedemptionFunded, FundedAtBlock: 90}
	if got := Confirmations(funded, 95); got != 5 {
		t.Errorf("Confirmations(funded) = %d, want 5", got)
	}
	if Claimable(funded, 95, 10) {
		t.Error("expected not claimable below finality threshold")
	}
	if !Claimable(funded, 100, 10) {
		t.Error("expected claimable at/above finality threshold")
	}

	completed := &models.RedemptionRequest{Status: models.RedemptionCompleted, FundedAtBlock: 90}
	if Claimable(completed, 1000, 1) {
		t.Error("expected Completed request to never report claimable (already claimed)")
	}
}

// TestServeRepoBackedReads covers the wiring path (cmd/platform's
// buildApp): a Service built over a repository serves List/ListPage/
// Get off it directly.
func TestServeRepoBackedReads(t *testing.T) {
	repo := memory.NewRedemptionRequestRepository()
	svc := New(repo)
	ctx := context.Background()

	if err := repo.Upsert(ctx, &models.RedemptionRequest{ID: "1", Beneficiary: "pubkey111", Status: models.RedemptionPending}); err != nil {
		t.Fatal(err)
	}

	r, err := svc.Get(ctx, "1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if r.Beneficiary != "pubkey111" {
		t.Errorf("Beneficiary = %q", r.Beneficiary)
	}

	page, _, err := svc.ListPage(ctx, "", "", "", 10)
	if err != nil {
		t.Fatalf("ListPage: %v", err)
	}
	if len(page) != 1 {
		t.Fatalf("ListPage len = %d, want 1", len(page))
	}

	all, err := svc.List(ctx, "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("List len = %d, want 1", len(all))
	}
}
