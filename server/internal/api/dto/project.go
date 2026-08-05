package dto

import (
	"time"

	"github.com/rwa-platform/server/internal/dal/models"
)

// ProgramIDs mirrors components.schemas.SolanaProgramIds: the six
// deployed Solana program addresses (base58).
type ProgramIDs struct {
	Compliance       string `json:"compliance,omitempty"`
	Vault            string `json:"vault,omitempty"`
	Pricing          string `json:"pricing,omitempty"`
	TransferHook     string `json:"transferHook,omitempty"`
	Redemption       string `json:"redemption,omitempty"`
	SupplyController string `json:"supplyController,omitempty"`
}

// BootstrapConfigResponse mirrors components.schemas.BootstrapConfig: the
// program/mint addresses the admin's web wallet needs to build
// calldata against directly (there is no on-chain factory to deploy from —
// every program/mint address is provisioned independently), and the
// operator-configured projectId the web builds its Asset Profile with.
// PUBLIC — it exposes only already-public bootstrap parameters.
type BootstrapConfigResponse struct {
	// ProjectID is the configured deployment projectId (UUID), or "" when the
	// server has none set — the web treats an empty value as "not configured"
	// and refuses to create a profile until the operator sets it.
	ProjectID string `json:"projectId"`

	ChainID    int64       `json:"solanaChainId,omitempty"`
	ProgramIDs *ProgramIDs `json:"programIds,omitempty"`
	RWAMint    string      `json:"rwaMint,omitempty"`
	QuoteMint  string      `json:"quoteMint,omitempty"`

	// ClusterGenesis/SupplyConfig/VaultConfig are the auditor attestation's
	// DOMAIN inputs, needed by the console to build the offline signer's policy
	// file. They are distinct from ProgramIDs above and must not be confused
	// with them: the policy's `config` is the supply-controller Config PDA (not
	// programIds.supplyController) and its `vault` is the vault Config PDA (not
	// programIds.vault). See api.App's doc comment on these three fields.
	ClusterGenesis string `json:"clusterGenesis,omitempty"`
	SupplyConfig   string `json:"supplyConfig,omitempty"`
	VaultConfig    string `json:"vaultConfig,omitempty"`
}

// NewBootstrapConfigResponse builds the bootstrap view from server
// configuration; unlike the other mappers here there is no model behind it.
func NewBootstrapConfigResponse(projectID string, solana Bootstrap) BootstrapConfigResponse {
	return BootstrapConfigResponse{
		ProjectID: projectID,
		ChainID:   solana.ChainID,
		ProgramIDs: &ProgramIDs{
			Compliance: solana.ProgramCompliance, Vault: solana.ProgramVault, Pricing: solana.ProgramPricing,
			TransferHook: solana.ProgramTransferHook, Redemption: solana.ProgramRedemption,
			SupplyController: solana.ProgramSupplyController,
		},
		RWAMint:        solana.RWAMint,
		QuoteMint:      solana.QuoteMint,
		ClusterGenesis: solana.ClusterGenesis,
		SupplyConfig:   solana.SupplyConfig,
		VaultConfig:    solana.VaultConfig,
	}
}

// Bootstrap bundles the bootstrap values
// NewBootstrapConfigResponse and ToProjectResponse need — kept as one struct
// so a caller (api.App) doesn't have to pass eight positional strings.
type Bootstrap struct {
	ChainID                 int64
	ProgramCompliance       string
	ProgramVault            string
	ProgramPricing          string
	ProgramTransferHook     string
	ProgramRedemption       string
	ProgramSupplyController string
	RWAMint                 string
	QuoteMint               string
	ClusterGenesis          string
	SupplyConfig            string
	VaultConfig             string
}

// ProjectResponse mirrors components.schemas.Project.
type ProjectResponse struct {
	ProjectID string `json:"projectId"`
	Version   string `json:"version"`
	// ChainID is the deployment's chain id (see
	// config.Config.ChainID). The browser's RPC endpoint is no
	// longer surfaced here: it is a build-time-only
	// value baked into the SPA, never known to or supplied by the server.
	ChainID       int64  `json:"chainId"`
	Decimals      uint8  `json:"decimals"`
	QuoteDecimals uint8  `json:"quoteDecimals,omitempty"`
	TokenUnit     string `json:"tokenUnit"`
	ProfileDigest string `json:"profileDigest"`
	// Status is the deployment lifecycle state (Undeployed/Deploying/
	// Verifying/Active/Failed) the admin UI polls for setup progress;
	// VerificationNote carries either the reason a deployment Failed or a
	// non-fatal verification gap on an otherwise-Active project (see
	// models.Project.VerificationNote).
	Status            string    `json:"status,omitempty"`
	VerificationNote  string    `json:"verificationNote,omitempty"`
	Addresses         Addresses `json:"addresses"`
	Paused            bool      `json:"paused"`
	Auditor           string    `json:"auditor"`
	Treasury          string    `json:"treasury"`
	RedemptionManager string    `json:"redemptionManager"`
	// PendingAdmin is the incoming DEFAULT_ADMIN of an in-progress two-step
	// admin transfer, event-sourced into Project.Security; empty when none is
	// pending (the deploy baseline never has one).
	PendingAdmin          string      `json:"pendingAdmin,omitempty"`
	FinalityConfirmations uint64      `json:"finalityConfirmations"`
	BytecodeVerified      bool        `json:"bytecodeVerified"`
	Roles                 RoleHolders `json:"roles,omitempty"`

	// PurchasePricePerWholeToken/RedemptionPricePerWholeToken are the live
	// on-chain prices (quote-token minimal units; the web scales by
	// quoteDecimals for display). Like the governance fields, they prefer the
	// event-sourced projection (Project.Security) and fall back to the
	// deploy-baseline, so they are present whenever a price is configured and
	// omitted only for a not-yet-deployed project.
	PurchasePricePerWholeToken   string `json:"purchasePricePerWholeToken,omitempty"`
	RedemptionPricePerWholeToken string `json:"redemptionPricePerWholeToken,omitempty"`

	// The security-authority fields above (Paused/Auditor/
	// Treasury/RedemptionManager/Roles) are the LIVE event-sourced
	// projection maintained by project.ReconcileSecurity — the indexer watches
	// the token, strategy, and every contract's AccessControl events and folds
	// them into models.Project.Security, so an out-of-band pause, role grant,
	// or auditor/treasury rotation IS reflected here. SecurityAsOfBlock/Time
	// report how current that projection is; SecurityStale is COMPUTED from
	// the gap between the projection and the indexer checkpoint (and the
	// indexer's own health) rather than hardcoded, so the UI can trust the
	// fields when it is false and label them "possibly stale" only when the
	// projection actually lags. When no projection has run yet (or governance
	// indexing is not wired) the response falls back to the deploy-config
	// snapshot and reports stale.
	SecurityAsOfBlock uint64 `json:"securityAsOfBlock,omitempty"`
	SecurityAsOfTime  string `json:"securityAsOfTime,omitempty"`
	SecurityStale     bool   `json:"securityStale"`
}

// Addresses mirrors components.schemas.Addresses.
type Addresses struct {
	Token            string `json:"token"`
	Compliance       string `json:"compliance"`
	SupplyController string `json:"supplyController"`
	Vault            string `json:"vault"`
	RedemptionEscrow string `json:"redemptionEscrow"`
	Strategy         string `json:"strategy"`
	QuoteToken       string `json:"quoteToken"`
}

// RoleHolders mirrors components.schemas.RoleHolders.
type RoleHolders map[string][]string

// ToProjectResponse maps the stored project record onto the API view, using the
// deploy-config snapshot as the baseline and overlaying the live governance
// projection (models.Project.Security) wherever it exists.
//
// tokenUnit, finalityConfirmations, and securityStale come from the caller
// because they are not on the record: tokenUnit is read from the live
// AssetProfile (nothing in the deploy flow carries it), finalityConfirmations
// is an operational server setting whose current value always wins over
// whatever was persisted, and securityStale is derived from the indexer
// checkpoint.
func ToProjectResponse(p *models.Project, tokenUnit string, finalityConfirmations uint64, securityStale bool) ProjectResponse {
	resp := ProjectResponse{
		ProjectID: p.ProjectID, Version: p.Version, ChainID: p.ChainID, ProfileDigest: p.ProfileDigest,
		Status: string(p.Status), VerificationNote: p.VerificationNote,
		Decimals: p.TokenDecimals, QuoteDecimals: p.QuoteDecimals, TokenUnit: tokenUnit,
		Addresses: Addresses{
			Token: p.Addresses.Token, Compliance: p.Addresses.Compliance, SupplyController: p.Addresses.SupplyController,
			Vault: p.Addresses.Vault, RedemptionEscrow: p.Addresses.RedemptionEscrow, Strategy: p.Addresses.Strategy,
			QuoteToken: p.Addresses.QuoteToken,
		},
		// Deploy-config snapshot as the fallback for a project that has not been
		// projected yet; overlaid with the live projection just below.
		Paused: p.Paused, Auditor: p.Auditor, Treasury: p.Treasury, RedemptionManager: p.RedemptionManager,
		FinalityConfirmations: finalityConfirmations, BytecodeVerified: p.BytecodeVerified, Roles: RoleHolders(p.Roles),
		PurchasePricePerWholeToken:   p.PurchasePricePerWholeToken,
		RedemptionPricePerWholeToken: p.RedemptionPricePerWholeToken,
		SecurityStale:                securityStale,
	}

	// Overlay the LIVE governance projection (project.ReconcileSecurity) when
	// present — the deploy-config fields above are only the fallback before the
	// first projection has run.
	if s := p.Security; s != nil {
		resp.Paused = s.Paused
		resp.Auditor = s.Auditor
		resp.Treasury = s.Treasury
		resp.RedemptionManager = s.RedemptionManager
		resp.PendingAdmin = s.PendingAdmin
		resp.Roles = RoleHolders(s.Roles)
		// Live prices overlay the deploy baseline only when the projection
		// actually carries one (a price may be legitimately unset).
		if s.PurchasePricePerWholeToken != "" {
			resp.PurchasePricePerWholeToken = s.PurchasePricePerWholeToken
		}
		if s.RedemptionPricePerWholeToken != "" {
			resp.RedemptionPricePerWholeToken = s.RedemptionPricePerWholeToken
		}
		resp.SecurityAsOfBlock = s.AsOfBlock
		if !s.AsOfTime.IsZero() {
			resp.SecurityAsOfTime = s.AsOfTime.UTC().Format(time.RFC3339)
		}
	}
	return resp
}
