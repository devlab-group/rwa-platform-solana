package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/mr-tron/base58"

	"github.com/rwa-platform/server/internal/blockchain"
	"github.com/rwa-platform/server/internal/config"
	"github.com/rwa-platform/server/internal/dal/memory"
)

// TestBuildAppRegistersComplianceKeyCloser is a regression test: the
// pre-fix buildApp always returned a nil
// provider slice (see complianceKeyCloser's doc comment), so the raw
// ed25519 compliance key held in its closure was never
// zeroed at shutdown — onShutdown's providers.Close() loop had nothing to
// iterate. Configuring security.compliance_key must now yield exactly one
// registered keys.Provider whose Close() zeroes the key bytes.
func TestBuildAppRegistersComplianceKeyCloser(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.Config{
		ChainID:                 900002,
		Commitment:              "finalized",
		ProgramCompliance:       fxCompliance,
		ProgramVault:            fxVaultProgramID,
		ProgramPricing:          fxPricing,
		ProgramRedemption:       fxRedemption,
		ProgramSupplyController: fxSupplyController,
		RWAMint:                 fxRWAMint,
		QuoteMint:               fxQuoteMint,
		ClusterGenesis:          fxClusterGenesis,
		SupplyConfig:            fxSupplyConfig,
		VaultConfig:             fxVaultConfigPDA,
		ComplianceKey:           base58.Encode(priv),
	}
	repos := memory.New()
	client := blockchain.NewRPCClient("http://127.0.0.1:0") // never dialed — see the sibling vault-config test's comment
	app, providers := buildApp(cfg, repos, client, nil, common.Address{})

	if app.Status == nil {
		t.Fatal("app.Status is nil; StatusService failed to construct with a valid fixture key")
	}
	if len(providers) != 1 {
		t.Fatalf("buildApp returned %d key providers, want exactly 1 (the compliance key closer)", len(providers))
	}
	closer, ok := providers[0].(*complianceKeyCloser)
	if !ok {
		t.Fatalf("providers[0] is a %T, want *complianceKeyCloser", providers[0])
	}
	if len(closer.key) != ed25519.PrivateKeySize {
		t.Fatalf("closer.key has %d bytes, want %d", len(closer.key), ed25519.PrivateKeySize)
	}

	if err := closer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	for i, b := range closer.key {
		if b != 0 {
			t.Fatalf("closer.key[%d] = %d after Close, want 0 (key material must be zeroed)", i, b)
		}
	}
}
