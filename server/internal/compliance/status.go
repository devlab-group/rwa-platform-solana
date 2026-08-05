package compliance

import (
	"context"

	"github.com/rwa-platform/server/internal/dal/models"
)

// OnChainStatus mirrors rwa-compliance's on-chain compliance status enum:
// Unknown=0, Allowed=1, Blocked=2.
type OnChainStatus uint8

const (
	OnChainStatusUnknown OnChainStatus = 0
	OnChainStatusAllowed OnChainStatus = 1
	OnChainStatusBlocked OnChainStatus = 2
)

// StatusWriter is the capability api.App.Status and WebhookReconciler need:
// submit one compliance status write for account (a base58 Solana wallet
// pubkey) and return the submitted/broadcast transaction record. account is
// passed through verbatim, whatever wire format the caller already has it
// in (e.g. models.KYCEvent.Address, or the HTTP request body's address
// field); an implementation decodes it itself rather than the caller
// pre-parsing a chain-specific type.
type StatusWriter interface {
	SetStatus(ctx context.Context, idempotencyKey string, account string, status OnChainStatus, validUntil uint64) (*models.Transaction, error)
}

// StatusFromString maps the API's WalletStatus/SetStatusRequest string enum
// to the on-chain uint8 encoding.
func StatusFromString(s string) (OnChainStatus, bool) {
	switch s {
	case "Unknown":
		return OnChainStatusUnknown, true
	case "Allowed":
		return OnChainStatusAllowed, true
	case "Blocked":
		return OnChainStatusBlocked, true
	default:
		return 0, false
	}
}
