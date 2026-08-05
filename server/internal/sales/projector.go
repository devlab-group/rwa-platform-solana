package sales

import (
	"fmt"

	"github.com/rwa-platform/server/internal/dal/models"
)

// BuildPurchases converts decoded Vault Purchased chain events into
// models.Purchase records, one per event (each Purchased log is a
// self-contained fill, unlike redemption's multi-event lifecycle).
func BuildPurchases(events []*models.ChainEvent) []*models.Purchase {
	out := make([]*models.Purchase, 0, len(events))
	for _, e := range events {
		if e.Name != "Purchased" {
			continue
		}
		out = append(out, &models.Purchase{
			ID:          e.TxHash + fmt.Sprintf(":%d", e.LogIndex),
			Buyer:       toString(e.Data["buyer"]),
			Recipient:   toString(e.Data["recipient"]),
			TokenAmount: toString(e.Data["tokenAmount"]),
			QuoteAmount: toString(e.Data["quoteAmount"]),
			TxHash:      e.TxHash, BlockNumber: e.BlockNumber, CreatedAt: e.IndexedAt,
		})
	}
	return out
}

func toString(v any) string {
	s, _ := v.(string)
	return s
}
