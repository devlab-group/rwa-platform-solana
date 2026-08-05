package project

import (
	"context"
	"fmt"
	"time"

	"github.com/rwa-platform/server/internal/dal/models"
	"github.com/rwa-platform/server/internal/dal/repository"
)

// PlatformVersion is the value SeedProject writes to Project.Version, which
// GET /project reports and the admin console's Security screen displays.
//
// It is the SAME frozen "1.0" the rest of the platform already pins: metadata
// records carry `platformVersion: "1.0"` (assets/service.go, validated in
// assets/record.go) and Asset Profiles carry `profileVersion` 1.0. There is no
// on-chain version to read — the programs record none — and nothing was
// assigning this field at all, so GET /project reported an empty version on
// every deployment.
const PlatformVersion = "1.0"

// SeedParams is the config-derived input to SeedProject, kept as
// a plain struct (not the whole internal/config.Config) so seeding is
// testable without constructing a full server config. Every field EXCEPT
// ProfileDigest is a base58 Solana pubkey/program ID (or, for QuoteDecimals,
// the plain byte count) straight from the chain.*/contract.* config blocks —
// see internal/config.Config's Program*/RWAMint/QuoteMint/
// QuoteDecimals/AdminPubkey fields. ProfileDigest is the one value read back
// from the chain rather than configured; see its own doc comment.
type SeedParams struct {
	ChainID int64

	// ProjectID is contract.project_id — the UUID identifying this
	// deployment's single Asset Profile. It is what Project.ProjectID is keyed
	// to, and AssetProfileRepository.Get is a by-_id lookup on exactly that
	// value, so leaving it unset makes api.loadVerifiedProfile's
	// `AssetProfiles.Get(ctx, p.ProjectID)` a lookup for the empty string:
	// every record-creation and package-download request 404s on a deployment
	// that is otherwise perfectly healthy, and the profile cross-check those
	// paths exist to perform never runs at all. Optional outside production
	// (see Config.ProjectID) and, like ProfileDigest, only ever set here,
	// never cleared.
	ProjectID string

	RWAMint   string
	QuoteMint string

	ProgramVault            string
	ProgramCompliance       string
	ProgramSupplyController string
	ProgramRedemption       string
	ProgramPricing          string

	// RWADecimals is the RWA Token-2022 mint's decimals() — set onto
	// Project.TokenDecimals below so GET /project (dto's "decimals" field)
	// is authoritative without any SPA having to read the mint on-chain
	// itself. Config.Load requires this to be explicitly set (see its
	// "contract.rwa_decimals is required" check), so a config that reached
	// SeedProject at all already has a real value here — never the
	// zero-value placeholder.
	RWADecimals   uint8
	QuoteDecimals uint8
	AdminPubkey   string

	// ProfileDigest is the 0x-hex `profile_digest` read back from the
	// on-chain rwa-supply-controller Config account — the digest this
	// deployment permanently committed to at `initialize`. Unlike every other
	// field here it is NOT a config value: the operator commits to it in
	// bootstrap.config.json before the server ever runs, so reading it off the
	// chain is the only way the server learns what the deployment is actually
	// bound to. Persisting it is what makes the API's profile cross-checks
	// real (see api.createProfile and api.loadVerifiedProfile) — without it a
	// wrong Asset Profile is only caught on-chain at mint broadcast, after the
	// auditor has already signed the package.
	//
	// EMPTY MEANS "UNKNOWN", NEVER "NONE": the caller leaves it empty whenever
	// the account could not be fully verified (RPC down, pre-`initialize`
	// boot, cross-check failure), so SeedProject must not clear an already-
	// stored digest when it is empty. The value is immutable on-chain — the
	// program writes it once in `initialize` and exposes no setter — so a
	// non-empty value read on any later boot can only ever confirm what is
	// already stored.
	ProfileDigest string
}

// SeedProject makes the single-tenant Project record Active with the
// program/mint addresses from config. There is no on-chain factory and no
// signed deploy calldata for the server to bind a stored Asset Profile to
// and verify bytecode/roles against — every program is provisioned
// independently and its address is simply configuration, trusted directly
// rather than observed and verified from a deploy transaction. Downstream code
// (ReconcileSecurity, the reused compliance/redemption/sales
// reconcilers, the API) all gate on Project.Status==Active and read
// Project.Addresses, so this must run before any of them can do anything
// useful.
//
// Idempotent: safe to call on every boot/reconcile tick. It Upserts the
// singleton Project record (repository.ProjectRepository.Get/Upsert take no
// key — see models.Project's doc comment on the single-deployment
// invariant), preserving whatever already exists (CreatedAt, and critically
// any Security projection already folded by ReconcileSecurity) and
// only overwriting the config-sourced fields below. Calling it repeatedly
// with the same params is a no-op beyond bumping UpdatedAt.
func SeedProject(ctx context.Context, params SeedParams, projects repository.ProjectRepository) error {
	now := time.Now().UTC()

	p, err := projects.Get(ctx)
	if err != nil {
		if err != repository.ErrNotFound {
			return fmt.Errorf("project: load project for solana seed: %w", err)
		}
		p = &models.Project{CreatedAt: now}
	}

	p.ChainID = params.ChainID
	if params.ProjectID != "" {
		p.ProjectID = params.ProjectID
	}
	p.Version = PlatformVersion
	p.Status = models.ProjectStatusActive
	p.Addresses = models.Addresses{
		Token:            params.RWAMint,
		QuoteToken:       params.QuoteMint,
		Vault:            params.ProgramVault,
		Compliance:       params.ProgramCompliance,
		SupplyController: params.ProgramSupplyController,
		RedemptionEscrow: params.ProgramRedemption,
		Strategy:         params.ProgramPricing,
	}
	// TokenDecimals is the RWA mint's decimals, surfaced by
	// dto.ToProjectResponse as "decimals". Left unset here it would silently
	// report 0, which is what motivated making RWADecimals required in
	// Config.Load rather than optional like QuoteDecimals.
	p.TokenDecimals = params.RWADecimals
	p.QuoteDecimals = params.QuoteDecimals
	// Admin is the configured baseline ReconcileSecurity's admin fold
	// reads (see security.go's adminState) as the baseline
	// derive prefers. models.Project.Admin is a plain string field (no
	// format validation anywhere it's written), so a base58 pubkey fits it
	// directly.
	p.Admin = params.AdminPubkey
	// Only ever SET, never clear — see SeedParams.ProfileDigest's doc comment
	// on why empty means "this boot could not read it", not "there isn't one".
	// Overwriting an already-stored digest with "" would silently disarm every
	// profile cross-check for the rest of the process's life, and the most
	// likely time for that to happen is exactly when the chain is unreachable.
	if params.ProfileDigest != "" {
		p.ProfileDigest = params.ProfileDigest
	}
	p.UpdatedAt = now

	if err := projects.Upsert(ctx, p); err != nil {
		return fmt.Errorf("project: seed solana project: %w", err)
	}
	return nil
}
