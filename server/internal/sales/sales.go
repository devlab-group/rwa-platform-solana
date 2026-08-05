// Package sales provides read models for the Vault program: inventory and
// the indexed purchase history. Per-amount purchase quotes are read straight
// from Vault.previewBuy by the client. It submits no
// transactions and builds none: an investor's Vault.buy and the issuer's
// treasury withdrawal are both assembled and signed by the wallet/multisig
// itself, never by a server hot key. The off-chain payment-distribution
// feature (Vault.distribute, the distributor hot key) has been removed
// from the platform — only on-chain purchases remain.
package sales

import (
	"context"
	"errors"

	"github.com/rwa-platform/server/internal/dal/repository"
)

// ErrNoChainClient is returned by GetInventory: this server holds no chain
// client to read Vault/quote-token/strategy state from — every business
// program is provisioned independently and observed only through the
// indexer. Callers should route around this rather than let it surface as a
// 500 — see internal/api's getInventory, which 501s before ever calling
// GetInventory.
var ErrNoChainClient = errors.New("sales: no chain client configured (read-only service)")

// Inventory mirrors api Schemas.Inventory.
type Inventory struct {
	Inventory       string `json:"inventory"`
	QuoteBalance    string `json:"quoteBalance"`
	PurchasePrice   string `json:"purchasePrice"`
	RedemptionPrice string `json:"redemptionPrice"`
}

// PurchaseView mirrors api Schemas.Purchase.
type PurchaseView struct {
	TxHash        string `json:"txHash"`
	Buyer         string `json:"buyer"`
	Recipient     string `json:"recipient"`
	TokenAmount   string `json:"tokenAmount"`
	QuoteAmount   string `json:"quoteAmount"`
	BlockNumber   uint64 `json:"blockNumber"`
	Confirmations uint64 `json:"confirmations"`
}

// Service reads the indexed purchase history. It submits no transactions
// itself: every Vault write (investor buy, treasury withdrawal) is a
// wallet/multisig transaction, never a server hot-key action.
type Service struct {
	purchases repository.PurchaseRepository
}

// New constructs a sales Service. purchases may be nil if the caller never
// calls ListPurchases.
func New(purchases repository.PurchaseRepository) *Service {
	return &Service{purchases: purchases}
}

// GetInventory always returns ErrNoChainClient: this server holds no chain
// client to read Vault inventory / quote-token balance / strategy prices
// from directly. Kept as a method (rather than removed) because
// cmd/platform's background loop calls it defensively and relies on this
// error to skip the inventory-gauge refresh.
func (s *Service) GetInventory(ctx context.Context) (Inventory, error) {
	return Inventory{}, ErrNoChainClient
}

// ListPurchases returns one bounded, newest-block-first page of indexed
// Vault.buy fills using repository-level keyset pagination (see
// repository.PurchaseRepository.ListPage's doc comment), with
// confirmations derived from currentBlock (typically the indexer's
// last-scanned block/slot). cursor is "" for the first page.
func (s *Service) ListPurchases(ctx context.Context, currentBlock uint64, cursor string, limit int) ([]PurchaseView, string, error) {
	items, next, err := s.purchases.ListPage(ctx, cursor, limit)
	if err != nil {
		return nil, "", err
	}
	out := make([]PurchaseView, len(items))
	for i, p := range items {
		out[i] = PurchaseView{
			TxHash: p.TxHash, Buyer: p.Buyer, Recipient: p.Recipient,
			TokenAmount: p.TokenAmount, QuoteAmount: p.QuoteAmount,
			BlockNumber: p.BlockNumber, Confirmations: confirmationsOf(currentBlock, p.BlockNumber),
		}
	}
	return out, next, nil
}

func confirmationsOf(currentBlock, blockNumber uint64) uint64 {
	if currentBlock < blockNumber {
		return 0
	}
	return currentBlock - blockNumber
}
