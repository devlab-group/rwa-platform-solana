// Package memory provides in-memory implementations of every
// internal/dal/repository interface. It is used by unit tests (and MAY be used
// for local development without Mongo) so business logic never requires a
// live database to be exercised.
package memory

import (
	"github.com/rwa-platform/server/internal/dal/repository"
)

// New builds a fresh, empty repository.Repositories backed entirely by memory.
func New() *repository.Repositories {
	return &repository.Repositories{
		Projects:             NewProjectRepository(),
		AssetProfiles:        NewAssetProfileRepository(),
		AssetRecords:         NewAssetRecordRepository(),
		AuditPackages:        NewAuditPackageRepository(),
		Attestations:         NewAttestationRepository(),
		Investors:            NewInvestorRepository(),
		WalletChallenges:     NewWalletChallengeRepository(),
		KYCEvents:            NewKYCEventRepository(),
		KYCVerifications:     NewKYCVerificationRepository(),
		ComplianceOperations: NewComplianceOperationRepository(),
		Transactions:         NewTransactionRepository(),
		ChainEvents:          NewChainEventRepository(),
		Purchases:            NewPurchaseRepository(),
		RedemptionRequests:   NewRedemptionRequestRepository(),
		AuditLogs:            NewAuditLogRepository(),
		IndexerCheckpoints:   NewIndexerCheckpointRepository(),
		IndexerDeadLetters:   NewDeadLetterRepository(),
		Publications:         NewPublicationRepository(),
		Idempotency:          NewIdempotencyRepository(),
		WalletSessions:       NewWalletSessionRepository(),
		AdminChallenges:      NewAdminChallengeRepository(),
		Leases:               NewLeaseRepository(),
	}
}
