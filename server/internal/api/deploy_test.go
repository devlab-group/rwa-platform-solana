package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/rwa-platform/server/internal/api/dto"
)

// TestGetConfigReturnsBootstrap covers the PUBLIC GET /api/v1/config
// bootstrap endpoint: no factory (there is none to deploy from — every
// program/mint address is provisioned independently), just the program IDs,
// RPC URL, and mints the admin/investor web apps need to build calldata
// client-side (see dto.NewBootstrapConfigResponse).
func TestGetConfigReturnsBootstrap(t *testing.T) {
	env := setupTestApp(t)
	env.app.ProjectID = "11111111-2222-3333-4444-555555555555"
	env.app.ChainID = 103
	env.app.ProgramCompliance = "Comp11111111111111111111111111111111111111"
	env.app.ProgramVault = "Vaul11111111111111111111111111111111111111"
	env.app.ProgramPricing = "Pric11111111111111111111111111111111111111"
	env.app.ProgramTransferHook = "Hook11111111111111111111111111111111111111"
	env.app.ProgramRedemption = "Rdmp11111111111111111111111111111111111111"
	env.app.ProgramSupplyController = "Supp11111111111111111111111111111111111111"
	env.app.RWAMint = "RWAM11111111111111111111111111111111111111"
	env.app.QuoteMint = "USDC11111111111111111111111111111111111111"
	// The attestation domain inputs. VaultConfig is deliberately DIFFERENT
	// from ProgramVault above: the signer policy's `vault` is the vault Config
	// PDA, and conflating it with the vault program id yields signatures the
	// on-chain supply-controller rejects.
	env.app.ClusterGenesis = "Genn11111111111111111111111111111111111111"
	env.app.SupplyConfig = "SCfg11111111111111111111111111111111111111"
	env.app.VaultConfig = "VCfg11111111111111111111111111111111111111"

	// No auth header: /config is public.
	w := doJSON(t, env.router, http.MethodGet, "/api/v1/config", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("config status = %d, body=%s", w.Code, w.Body.String())
	}
	var got dto.BootstrapConfigResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ProjectID != env.app.ProjectID {
		t.Errorf("ProjectID = %q, want %q", got.ProjectID, env.app.ProjectID)
	}
	if got.ChainID != env.app.ChainID {
		t.Errorf("solanaChainId = %d, want %d", got.ChainID, env.app.ChainID)
	}
	if got.ProgramIDs == nil {
		t.Fatal("programIds is nil, want populated")
	}
	if got.ProgramIDs.Compliance != env.app.ProgramCompliance {
		t.Errorf("programIds.compliance = %q, want %q", got.ProgramIDs.Compliance, env.app.ProgramCompliance)
	}
	if got.ProgramIDs.Vault != env.app.ProgramVault {
		t.Errorf("programIds.vault = %q, want %q", got.ProgramIDs.Vault, env.app.ProgramVault)
	}
	if got.ProgramIDs.SupplyController != env.app.ProgramSupplyController {
		t.Errorf("programIds.supplyController = %q, want %q", got.ProgramIDs.SupplyController, env.app.ProgramSupplyController)
	}
	if got.RWAMint != env.app.RWAMint {
		t.Errorf("rwaMint = %q, want %q", got.RWAMint, env.app.RWAMint)
	}
	// Without these three the admin console cannot build a valid signer
	// policy at all — they are not derivable from anything else it is served.
	if got.ClusterGenesis != env.app.ClusterGenesis {
		t.Errorf("clusterGenesis = %q, want %q", got.ClusterGenesis, env.app.ClusterGenesis)
	}
	if got.SupplyConfig != env.app.SupplyConfig {
		t.Errorf("supplyConfig = %q, want %q", got.SupplyConfig, env.app.SupplyConfig)
	}
	if got.VaultConfig != env.app.VaultConfig {
		t.Errorf("vaultConfig = %q, want %q", got.VaultConfig, env.app.VaultConfig)
	}
	if got.VaultConfig == got.ProgramIDs.Vault {
		t.Error("vaultConfig must not be the vault program id — they are different pubkeys")
	}
	if got.QuoteMint != env.app.QuoteMint {
		t.Errorf("quoteMint = %q, want %q", got.QuoteMint, env.app.QuoteMint)
	}
}
