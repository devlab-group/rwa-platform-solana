package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/rwa-platform/server/internal/api/dto"
	"github.com/rwa-platform/server/internal/auth"
	"github.com/rwa-platform/server/internal/dal/models"
	"github.com/rwa-platform/server/internal/dal/repository"
)

// getMyWalletStatus implements GET /api/v1/me/wallet-status (operationId
// getMyWalletStatus).
// Returns the WalletStatus for ONLY the address bound to the presented
// X-Wallet-Session.
//
// auth.RequireWalletSession (wired ahead of this handler in api.go) has already
// validated the session and rejected with 401 before this handler ever runs, so
// there is no request parameter through which a caller could ask for a
// different address's status. This replaces the investor page's former
// dependency on the operator-only global wallet list.
func (app *App) getMyWalletStatus(c *gin.Context) {
	address, ok := auth.WalletSessionAddress(c)
	if !ok {
		// Unreachable given the route's middleware chain in api.go — fail
		// closed rather than silently proceeding if it somehow is.
		fail(c, http.StatusUnauthorized, CodeUnauthorized, "no wallet session")
		return
	}
	inv, err := app.Repos.Investors.Get(c.Request.Context(), address)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			// compliance.ChallengeService.VerifyOwnership (the only path
			// that mints a session) always upserts an Investor record
			// before returning, so this is not expected in practice — but
			// respond with the honest "nothing on file yet" status rather
			// than an internal error if it's ever reached (e.g. the record
			// was independently removed after the session was issued).
			c.JSON(http.StatusOK, dto.WalletStatus{Address: address, Status: string(models.ComplianceUnknown), OwnershipVerified: true})
			return
		}
		failErr(c, http.StatusInternalServerError, CodeInternal, err)
		return
	}
	c.JSON(http.StatusOK, dto.ToWalletStatus(inv))
}

// isAddressAllowed implements GET /api/v1/compliance/allowed/{address}
// (operationId isAddressAllowed).
// PUBLIC anonymous transfer-preflight lookup that discloses only {allowed}.
//
// Delegates to App.beneficiaryAllowed (redemptions.go), which reads the
// indexed investor record — there is no server-held chain client to read
// from.
func (app *App) isAddressAllowed(c *gin.Context) {
	addressParam := c.Param("address")
	if !auth.NewVerifier().ValidateAddress(addressParam) {
		fail(c, http.StatusBadRequest, CodeBadRequest, "address is not a valid solana public key")
		return
	}
	allowed, err := app.beneficiaryAllowed(c.Request.Context(), addressParam)
	if err != nil {
		failErr(c, http.StatusInternalServerError, CodeInternal, err)
		return
	}
	c.JSON(http.StatusOK, dto.AllowedResult{Allowed: allowed})
}
