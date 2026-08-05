package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/rwa-platform/server/internal/api/dto"
	"github.com/rwa-platform/server/internal/dal/models"
	"github.com/rwa-platform/server/internal/dal/repository"
	"github.com/rwa-platform/server/internal/redemption"
)

// toRedemptionResponse computes the three enrichments the view mapper cannot
// derive from the record — claimable and confirmations against the indexer's
// block height and the configured finality depth, and whether the
// beneficiary currently passes compliance. A failed/absent lookup leaves
// beneficiaryAllowed false rather than failing the whole response, since it
// is an enrichment, not the request's primary data.
func (app *App) toRedemptionResponse(ctx context.Context, r *models.RedemptionRequest) dto.RedemptionResponse {
	currentBlock := app.lastIndexedBlock()
	allowed, _ := app.beneficiaryAllowed(ctx, r.Beneficiary)
	return dto.ToRedemptionResponse(r,
		redemption.Claimable(r, currentBlock, app.FinalityConfirmations),
		redemption.Confirmations(r, currentBlock),
		allowed,
	)
}

// listRedemptions implements GET /api/v1/redemptions (operationId
// listRedemptions).
// PUBLIC (redemption requests are on-chain-public data, so issuers can build
// their own investor UIs), keyset-paginated, with optional `status` and
// `address` filters — the latter narrowing to one beneficiary's requests
// (case-insensitive).
//
// Uses repository-level keyset pagination
// (RedemptionRequestRepository.ListPage) — see api.listPurchases' doc comment
// for the same reasoning (bounded query, X-Total-Count omitted).
func (app *App) listRedemptions(c *gin.Context) {
	if app.Redemptions == nil {
		fail(c, http.StatusNotImplemented, CodeNotImplemented, "redemptions is not configured on this server")
		return
	}
	status := c.Query("status")
	address := c.Query("address")
	cursor, limit := cursorLimitParams(c)
	page, next, err := app.Redemptions.ListPage(c.Request.Context(), status, address, cursor, limit)
	if err != nil {
		failErr(c, http.StatusInternalServerError, CodeInternal, err)
		return
	}
	out := make([]dto.RedemptionResponse, len(page))
	for i, r := range page {
		out[i] = app.toRedemptionResponse(c.Request.Context(), r)
	}
	setPaginationHeaders(c, -1, len(out), next)
	c.JSON(http.StatusOK, out)
}

// getRedemption implements GET /api/v1/redemptions/{id} (operationId
// getRedemption).
// PUBLIC: RedemptionEscrow.getRedemption(id) is itself an unauthenticated
// on-chain view call and ids are sequential, not a capability token.
func (app *App) getRedemption(c *gin.Context) {
	if app.Redemptions == nil {
		fail(c, http.StatusNotImplemented, CodeNotImplemented, "redemptions is not configured on this server")
		return
	}
	r, err := app.Redemptions.Get(c.Request.Context(), c.Param("id"))
	if err != nil {
		notFoundOrInternal(c, err)
		return
	}
	c.JSON(http.StatusOK, app.toRedemptionResponse(c.Request.Context(), r))
}

// beneficiaryAllowed reports whether address currently passes compliance,
// backing Schemas.Redemption.beneficiaryAllowed (toRedemptionResponse) and
// GET /api/v1/compliance/allowed/{address} (isAddressAllowed, wallet_session.go).
//
// There is no server-held chain client to read from (every business program
// is provisioned independently and observed only through the indexer — see
// buildApp in cmd/platform), so this consults the INDEXED investor
// record: compliance.Reconcile (cmd/platform's background loop) keeps
// repos.Investors current from the compliance program's StatusChanged
// events, so the answer is equally live, just event-sourced rather than a
// direct RPC call.
func (app *App) beneficiaryAllowed(ctx context.Context, address string) (bool, error) {
	if app.Repos == nil {
		return false, nil
	}
	if stale, err := app.complianceStale(ctx); err != nil {
		return false, err
	} else if stale {
		// Fail closed at the point of use: the only
		// prior staleness mitigation was complianceReadinessCheck
		// failing GET /health — an out-of-band signal a misconfigured
		// or bypassed load balancer might not actually gate traffic on.
		// Without this, a wedged indexer would keep this endpoint
		// answering allowed:true (or a stale Blocked) from
		// repos.Investors indefinitely.
		return false, nil
	}
	inv, err := app.Repos.Investors.Get(ctx, address)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return false, nil // no compliance decision on file yet — not an error
		}
		return false, err
	}
	return investorAllowed(inv, time.Now()), nil
}

// complianceStale reports whether the compliance program's indexer
// poll heartbeat (IndexerCheckpoint.LastSuccessfulPollAt) exceeds
// app.MaxCheckpointAge — the identical measure cmd/platform's
// complianceReadinessCheck uses for GET /health.
// ProgramCompliance=="" (no compliance program configured on this
// deployment at all) is treated as "nothing to gate" rather than
// unconditionally stale, mirroring complianceReadinessCheck's
// identical early return.
func (app *App) complianceStale(ctx context.Context) (bool, error) {
	if app.ProgramCompliance == "" {
		return false, nil
	}
	cp, err := app.Repos.IndexerCheckpoints.Get(ctx, app.ChainID, app.ProgramCompliance)
	switch {
	case errors.Is(err, repository.ErrNotFound):
		return true, nil // never polled yet — repos.Investors can't be vouched for
	case err != nil:
		return false, err
	case cp.LastSuccessfulPollAt.IsZero():
		return true, nil // a row exists (e.g. mid-backfill) but has never recorded a successful poll
	}
	return time.Since(cp.LastSuccessfulPollAt) > app.MaxCheckpointAge, nil
}

// investorAllowed reports whether an indexed investor record currently
// passes compliance, mirroring the on-chain eligibility rule the
// programs enforce (compliance-core::is_allowed): status must be Allowed,
// and ValidUntil is either 0 (no expiry — the
// permanent-allow state every pinned system address holds, and one an
// ordinary investor can be given too, see rwa-compliance::set_status /
// validate_status_change) or still in the future. Factored out as the one
// place that decides eligibility so this gate and any future DTO
// status view can't diverge on the expiry rule.
func investorAllowed(inv *models.Investor, now time.Time) bool {
	if inv.Status != models.ComplianceAllowed {
		return false
	}
	return inv.ValidUntil == 0 || inv.ValidUntil >= now.Unix()
}
