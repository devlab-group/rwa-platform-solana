package dto

import (
	"github.com/rwa-platform/server/internal/dal/models"
)

// TransactionResponse mirrors components.schemas.Transaction.
//
// Sender is additive and omitempty, so the SPA can show which account signed a
// transaction rather than only a status badge, without changing the minimal
// payload for the common case. There is no replacement lineage to report: the
// server never fee-bumps or replaces a transaction (see models.TxStatus).
type TransactionResponse struct {
	TxHash      string `json:"txHash"`
	Kind        string `json:"kind"`
	Status      string `json:"status"`
	BlockNumber uint64 `json:"blockNumber,omitempty"`
	ExplorerURL string `json:"explorerUrl,omitempty"`
	Sender      string `json:"sender,omitempty"`
}

// ToTransactionResponse maps one transaction record onto its API view. Status
// is passed through raw, so a new models.TxStatus reaches clients without a
// change here.
func ToTransactionResponse(tx *models.Transaction) TransactionResponse {
	return TransactionResponse{
		TxHash: tx.TxHash, Kind: tx.Kind, Status: string(tx.Status),
		BlockNumber: tx.BlockNumber, Sender: tx.From,
	}
}
