package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/rwa-platform/server/internal/api/dto"
	"github.com/rwa-platform/server/internal/dal/models"
)

// TestGetRedemptionBeneficiaryAllowedUsesIndexedInvestorStatus covers
// the read path of App.beneficiaryAllowed (redemptions.go): there is no
// server-held chain client to read ComplianceRegistry.isAllowed from, so
// Schemas.Redemption.beneficiaryAllowed must come from the indexed investor
// record instead.
func TestGetRedemptionBeneficiaryAllowedUsesIndexedInvestorStatus(t *testing.T) {
	env := setupTestApp(t)
	seedFreshComplianceCheckpoint(t, env)
	const beneficiary = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi"

	if err := env.app.Repos.RedemptionRequests.Upsert(context.Background(), &models.RedemptionRequest{
		ID: "1", Beneficiary: beneficiary, Status: models.RedemptionPending, CreatedAt: time.Now().Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := env.app.Repos.Investors.Upsert(context.Background(), &models.Investor{
		Address: beneficiary, Status: models.ComplianceAllowed, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	w := doJSON(t, env.router, http.MethodGet, "/api/v1/redemptions/1", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	var got dto.RedemptionResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.BeneficiaryAllowed {
		t.Error("expected beneficiaryAllowed=true from the indexed investor record")
	}
}

// TestGetRedemptionBeneficiaryNotAllowedDefaultsFalse: a beneficiary
// with no indexed investor record must report beneficiaryAllowed=false, not
// a 500 or a panic.
func TestGetRedemptionBeneficiaryNotAllowedDefaultsFalse(t *testing.T) {
	env := setupTestApp(t)
	const beneficiary = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"

	if err := env.app.Repos.RedemptionRequests.Upsert(context.Background(), &models.RedemptionRequest{
		ID: "2", Beneficiary: beneficiary, Status: models.RedemptionPending, CreatedAt: time.Now().Unix(),
	}); err != nil {
		t.Fatal(err)
	}

	w := doJSON(t, env.router, http.MethodGet, "/api/v1/redemptions/2", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	var got dto.RedemptionResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.BeneficiaryAllowed {
		t.Error("expected beneficiaryAllowed=false with no indexed investor record")
	}
}

// TestBeneficiaryAllowedBlockedInvestorIsFalse: Investor compliance
// only has three states (Unknown/Allowed/Blocked — models.ComplianceStatus
// has no separate "Rejected" value), so the "not Allowed" case worth pinning
// here is Blocked: an investor the compliance program has explicitly
// blocked must never read as beneficiaryAllowed=true.
func TestBeneficiaryAllowedBlockedInvestorIsFalse(t *testing.T) {
	env := setupTestApp(t)
	const beneficiary = "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8"

	if err := env.app.Repos.Investors.Upsert(context.Background(), &models.Investor{
		Address: beneficiary, Status: models.ComplianceBlocked, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	allowed, err := env.app.beneficiaryAllowed(context.Background(), beneficiary)
	if err != nil {
		t.Fatalf("beneficiaryAllowed: %v", err)
	}
	if allowed {
		t.Error("expected beneficiaryAllowed=false for a Blocked investor")
	}
}

// TestInvestorAllowedValidUntil pins the expiry rule investorAllowed
// enforces, mirroring the on-chain semantics verified in both
// compliance-core::is_allowed (Solana) and ComplianceRegistry.isAllowed
// (EVM): Allowed + a still-future ValidUntil is eligible, Allowed + a past
// ValidUntil is not, and Allowed + ValidUntil==0 is eligible — 0 is the
// permanent-allow state (no expiry), not a sentinel for "expired". A
// Blocked/Unknown investor is never eligible regardless of ValidUntil.
func TestInvestorAllowedValidUntil(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name       string
		status     models.ComplianceStatus
		validUntil int64
		want       bool
	}{
		{"allowed, future validUntil", models.ComplianceAllowed, now.Add(time.Hour).Unix(), true},
		{"allowed, past validUntil", models.ComplianceAllowed, now.Add(-time.Hour).Unix(), false},
		{"allowed, validUntil==0 (no expiry)", models.ComplianceAllowed, 0, true},
		{"blocked, validUntil==0", models.ComplianceBlocked, 0, false},
		{"blocked, future validUntil", models.ComplianceBlocked, now.Add(time.Hour).Unix(), false},
		{"unknown, validUntil==0", models.ComplianceUnknown, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inv := &models.Investor{Address: "x", Status: tc.status, ValidUntil: tc.validUntil}
			if got := investorAllowed(inv, now); got != tc.want {
				t.Errorf("investorAllowed(status=%s, validUntil=%d) = %v, want %v", tc.status, tc.validUntil, got, tc.want)
			}
		})
	}
}

// TestBeneficiaryAllowedExpiredValidUntilIsFalse exercises the
// same rule through the full beneficiaryAllowed path, not just the
// investorAllowed helper: an investor Allowed on-chain but past its
// ValidUntil must not report eligible.
func TestBeneficiaryAllowedExpiredValidUntilIsFalse(t *testing.T) {
	env := setupTestApp(t)
	const beneficiary = "6dQoW6GRQfCPGYWJvVCScGgpvNJ2rNyLwF5FBrLR2R2Y"

	if err := env.app.Repos.Investors.Upsert(context.Background(), &models.Investor{
		Address: beneficiary, Status: models.ComplianceAllowed,
		ValidUntil: time.Now().Add(-time.Minute).Unix(),
		CreatedAt:  time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	allowed, err := env.app.beneficiaryAllowed(context.Background(), beneficiary)
	if err != nil {
		t.Fatalf("beneficiaryAllowed: %v", err)
	}
	if allowed {
		t.Error("expected beneficiaryAllowed=false for an investor past ValidUntil")
	}
}

// erroringInvestorRepository is a minimal repository.InvestorRepository stub
// whose Get always fails with a non-ErrNotFound error, exercising
// beneficiaryAllowed's error-propagation path — distinct from the
// no-record-yet path covered by
// TestGetRedemptionBeneficiaryNotAllowedDefaultsFalse above, which
// must NOT be treated as an error.
type erroringInvestorRepository struct{}

func (erroringInvestorRepository) Get(context.Context, string) (*models.Investor, error) {
	return nil, errors.New("boom: investor store unreachable")
}
func (erroringInvestorRepository) List(context.Context) ([]*models.Investor, error) { return nil, nil }
func (erroringInvestorRepository) Upsert(context.Context, *models.Investor) error   { return nil }
func (erroringInvestorRepository) ListPage(context.Context, string, int) ([]*models.Investor, string, error) {
	return nil, "", nil
}

// TestBeneficiaryAllowedRepoErrorPropagates: an investor-store error
// beyond "not found" must surface to the caller as (false, err) rather than
// being swallowed into an unqualified false. toRedemptionResponse is the one
// caller that chooses to discard that error (see its doc comment), but
// beneficiaryAllowed itself must still report it.
func TestBeneficiaryAllowedRepoErrorPropagates(t *testing.T) {
	env := setupTestApp(t)
	seedFreshComplianceCheckpoint(t, env)
	env.app.Repos.Investors = erroringInvestorRepository{}

	allowed, err := env.app.beneficiaryAllowed(context.Background(), "SomeAddress1111111111111111111111111111111")
	if err == nil {
		t.Fatal("expected beneficiaryAllowed to propagate the investor store error")
	}
	if allowed {
		t.Error("expected allowed=false alongside the error")
	}
}

// TestBeneficiaryAllowedFailsClosedOnStaleComplianceCheckpoint is a
// regression test: eligibility is served from
// repos.Investors, kept current by the compliance indexer — if that
// indexer wedges, the ONLY prior staleness mitigation was
// complianceReadinessCheck failing GET /health, an out-of-band
// signal a bypassed/misconfigured load balancer might not actually gate
// traffic on. beneficiaryAllowed must now itself fail closed once the
// compliance program's poll heartbeat exceeds MaxCheckpointAge, even
// though the underlying investor record still says Allowed.
func TestBeneficiaryAllowedFailsClosedOnStaleComplianceCheckpoint(t *testing.T) {
	env := setupTestApp(t)
	env.app.ChainID = 900001
	env.app.ProgramCompliance = "CompLiance111111111111111111111111111111111"
	env.app.MaxCheckpointAge = time.Minute
	const beneficiary = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi"

	if err := env.app.Repos.Investors.Upsert(context.Background(), &models.Investor{
		Address: beneficiary, Status: models.ComplianceAllowed, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := env.app.Repos.IndexerCheckpoints.Set(context.Background(), &models.IndexerCheckpoint{
		ChainID: env.app.ChainID, Address: env.app.ProgramCompliance,
		LastBlock: 500, LastSuccessfulPollAt: time.Now().Add(-time.Hour), // well past MaxCheckpointAge
	}); err != nil {
		t.Fatal(err)
	}

	allowed, err := env.app.beneficiaryAllowed(context.Background(), beneficiary)
	if err != nil {
		t.Fatalf("beneficiaryAllowed: %v", err)
	}
	if allowed {
		t.Error("expected beneficiaryAllowed=false — the compliance checkpoint heartbeat is stale, even though the investor record says Allowed")
	}
}

// TestBeneficiaryAllowedFailsClosedWithNoComplianceCheckpointYet
// covers the never-polled case: no IndexerCheckpoint row at all for the
// compliance program.
func TestBeneficiaryAllowedFailsClosedWithNoComplianceCheckpointYet(t *testing.T) {
	env := setupTestApp(t)
	env.app.ChainID = 900001
	env.app.ProgramCompliance = "CompLiance111111111111111111111111111111111"
	env.app.MaxCheckpointAge = time.Minute
	const beneficiary = "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR"

	if err := env.app.Repos.Investors.Upsert(context.Background(), &models.Investor{
		Address: beneficiary, Status: models.ComplianceAllowed, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	allowed, err := env.app.beneficiaryAllowed(context.Background(), beneficiary)
	if err != nil {
		t.Fatalf("beneficiaryAllowed: %v", err)
	}
	if allowed {
		t.Error("expected beneficiaryAllowed=false — the compliance program has never completed a poll")
	}
}

// TestBeneficiaryAllowedFreshCheckpointStillAllows proves the
// fix doesn't over-block: a fresh, recently-polled compliance checkpoint
// alongside an Allowed investor record must still report eligible.
func TestBeneficiaryAllowedFreshCheckpointStillAllows(t *testing.T) {
	env := setupTestApp(t)
	env.app.ChainID = 900001
	env.app.ProgramCompliance = "CompLiance111111111111111111111111111111111"
	env.app.MaxCheckpointAge = 5 * time.Minute
	const beneficiary = "6dQoW6GRQfCPGYWJvVCScGgpvNJ2rNyLwF5FBrLR2R2Y"

	if err := env.app.Repos.Investors.Upsert(context.Background(), &models.Investor{
		Address: beneficiary, Status: models.ComplianceAllowed, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := env.app.Repos.IndexerCheckpoints.Set(context.Background(), &models.IndexerCheckpoint{
		ChainID: env.app.ChainID, Address: env.app.ProgramCompliance,
		LastBlock: 500, LastSuccessfulPollAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	allowed, err := env.app.beneficiaryAllowed(context.Background(), beneficiary)
	if err != nil {
		t.Fatalf("beneficiaryAllowed: %v", err)
	}
	if !allowed {
		t.Error("expected beneficiaryAllowed=true with a fresh compliance checkpoint and an Allowed investor")
	}
}
