package project

import (
	"context"
	"testing"

	"github.com/rwa-platform/server/internal/dal/memory"
	"github.com/rwa-platform/server/internal/dal/models"
)

func params() SeedParams {
	return SeedParams{
		ChainID:                 900001,
		RWAMint:                 "RWAMint111111111111111111111111111111111111",
		QuoteMint:               "QuoteMint11111111111111111111111111111111111",
		ProgramVault:            "VauLT1111111111111111111111111111111111111",
		ProgramCompliance:       "CompLiance111111111111111111111111111111111",
		ProgramSupplyController: "SuppLyCtR1111111111111111111111111111111111",
		ProgramRedemption:       "REdempT10n1111111111111111111111111111111",
		ProgramPricing:          "PriciNg111111111111111111111111111111111111",
		RWADecimals:             9,
		QuoteDecimals:           6,
		AdminPubkey:             "AdmiN1111111111111111111111111111111111111",
		ProjectID:               fxSeedProjectID,
		ProfileDigest:           fxSeedProfileDigest,
	}
}

const fxSeedProjectID = "4fd4224f-6e65-4d6b-9fa9-c5c2b3514e61"

// fxSeedProfileDigest stands in for the 0x-hex profile_digest
// cmd/platform reads off the on-chain supply-controller Config account.
const fxSeedProfileDigest = "0x" +
	"101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"

func TestSeedProjectCreatesActiveProject(t *testing.T) {
	repos := memory.New()
	ctx := context.Background()
	params := params()

	if err := SeedProject(ctx, params, repos.Projects); err != nil {
		t.Fatalf("SeedProject: %v", err)
	}

	p, err := repos.Projects.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if p.Status != models.ProjectStatusActive {
		t.Errorf("Status = %s, want Active", p.Status)
	}
	if p.ChainID != params.ChainID {
		t.Errorf("ChainID = %d, want %d", p.ChainID, params.ChainID)
	}
	wantAddrs := models.Addresses{
		Token: params.RWAMint, QuoteToken: params.QuoteMint,
		Vault: params.ProgramVault, Compliance: params.ProgramCompliance,
		SupplyController: params.ProgramSupplyController, RedemptionEscrow: params.ProgramRedemption,
		Strategy: params.ProgramPricing,
	}
	if p.Addresses != wantAddrs {
		t.Errorf("Addresses = %+v, want %+v", p.Addresses, wantAddrs)
	}
	if p.QuoteDecimals != params.QuoteDecimals {
		t.Errorf("QuoteDecimals = %d, want %d", p.QuoteDecimals, params.QuoteDecimals)
	}
	if p.TokenDecimals != params.RWADecimals {
		t.Errorf("TokenDecimals = %d, want %d (RWADecimals)", p.TokenDecimals, params.RWADecimals)
	}
	if p.Admin != params.AdminPubkey {
		t.Errorf("Admin = %q, want %q", p.Admin, params.AdminPubkey)
	}
	if p.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
	if p.ProfileDigest != params.ProfileDigest {
		t.Errorf("ProfileDigest = %q, want %q", p.ProfileDigest, params.ProfileDigest)
	}
	// ProjectID is what AssetProfileRepository.Get is keyed on. Left unset,
	// api.loadVerifiedProfile looks a profile up under the empty string and
	// every record/package request 404s — see SeedParams.ProjectID.
	if p.ProjectID != params.ProjectID {
		t.Errorf("ProjectID = %q, want %q", p.ProjectID, params.ProjectID)
	}
}

// TestSeedProjectKeepsProfileDigestWhenUnknown is the regression guard for
// the "empty means unknown, not none" rule in SeedParams.ProfileDigest's doc
// comment. A boot that cannot read the on-chain Config account — RPC down, a
// pre-`initialize` deployment, a failed cross-check — passes an empty digest,
// and that must NOT wipe the digest a previous boot successfully stored.
// Clearing it would silently disarm api.createProfile's and
// api.loadVerifiedProfile's cross-checks for the rest of the process's life,
// and it would do so at precisely the least convenient moment: when the chain
// is unreachable and nothing can re-derive the value.
func TestSeedProjectKeepsProfileDigestWhenUnknown(t *testing.T) {
	repos := memory.New()
	ctx := context.Background()

	if err := SeedProject(ctx, params(), repos.Projects); err != nil {
		t.Fatal(err)
	}

	unknown := params()
	unknown.ProfileDigest = ""
	if err := SeedProject(ctx, unknown, repos.Projects); err != nil {
		t.Fatalf("SeedProject (digest unknown): %v", err)
	}

	p, err := repos.Projects.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if p.ProfileDigest != fxSeedProfileDigest {
		t.Errorf("ProfileDigest = %q, want it preserved as %q", p.ProfileDigest, fxSeedProfileDigest)
	}
}

// TestSeedProjectStoresProfileDigestOnLaterBoot covers the reverse order: a
// deployment first seeded before `initialize` (no digest on record) must pick
// the digest up on the first boot that can actually read it, rather than
// staying permanently unverified until someone clears the database.
func TestSeedProjectStoresProfileDigestOnLaterBoot(t *testing.T) {
	repos := memory.New()
	ctx := context.Background()

	preInit := params()
	preInit.ProfileDigest = ""
	if err := SeedProject(ctx, preInit, repos.Projects); err != nil {
		t.Fatal(err)
	}
	if p, err := repos.Projects.Get(ctx); err != nil {
		t.Fatal(err)
	} else if p.ProfileDigest != "" {
		t.Fatalf("ProfileDigest = %q before initialize, want empty", p.ProfileDigest)
	}

	if err := SeedProject(ctx, params(), repos.Projects); err != nil {
		t.Fatalf("SeedProject (post-initialize boot): %v", err)
	}
	p, err := repos.Projects.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if p.ProfileDigest != fxSeedProfileDigest {
		t.Errorf("ProfileDigest = %q, want %q", p.ProfileDigest, fxSeedProfileDigest)
	}
}

// TestSeedProjectIsIdempotent: a second call with the same params
// doesn't lose CreatedAt or an already-folded Security projection.
func TestSeedProjectIsIdempotent(t *testing.T) {
	repos := memory.New()
	ctx := context.Background()
	params := params()

	if err := SeedProject(ctx, params, repos.Projects); err != nil {
		t.Fatal(err)
	}
	first, err := repos.Projects.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	firstCreatedAt := first.CreatedAt
	first.Security = &models.SecurityState{Paused: true}
	if err := repos.Projects.Upsert(ctx, first); err != nil {
		t.Fatal(err)
	}

	if err := SeedProject(ctx, params, repos.Projects); err != nil {
		t.Fatalf("SeedProject (second call): %v", err)
	}
	second, err := repos.Projects.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !second.CreatedAt.Equal(firstCreatedAt) {
		t.Errorf("CreatedAt changed across idempotent reseed: %v -> %v", firstCreatedAt, second.CreatedAt)
	}
	if second.Security == nil || !second.Security.Paused {
		t.Error("re-seeding must not clobber an already-folded Security projection")
	}
	if second.Status != models.ProjectStatusActive {
		t.Errorf("Status = %s, want Active", second.Status)
	}
}
