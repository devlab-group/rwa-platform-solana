package blockchain

import (
	"crypto/sha256"
	"testing"
)

// TestEventDiscriminatorsMatchAnchorConvention proves the registry built
// from the embedded IDLs agrees with Anchor's own discriminator derivation
// (sha256("event:"+Name)[:8]) for every event in every program, so a
// mismatch (e.g. a stale/hand-edited IDL) fails loudly at test time rather
// than silently mis-dispatching at runtime.
func TestEventDiscriminatorsMatchAnchorConvention(t *testing.T) {
	if len(registryInstance) == 0 {
		t.Fatal("registryInstance is empty")
	}
	for role, schemas := range registryInstance {
		if len(schemas) == 0 {
			t.Errorf("role %s: no events parsed", role)
		}
		for disc, schema := range schemas {
			sum := sha256.Sum256([]byte("event:" + schema.Name))
			var want [8]byte
			copy(want[:], sum[:8])
			if want != disc {
				t.Errorf("role %s event %s: discriminator = %x, want %x (sha256(\"event:%s\")[:8])", role, schema.Name, disc, want, schema.Name)
			}
		}
	}
}

// TestRegistryCoversFrozenContractEvents spot-checks that every event name
// the frozen cross-worker contract lists is present for the expected role,
// so a future IDL regeneration that silently drops/renames an event is
// caught here instead of downstream in the indexer.
func TestRegistryCoversFrozenContractEvents(t *testing.T) {
	want := map[ProgramRole][]string{
		RoleCompliance:       {"AdminChanged", "AdminProposed", "AdminTransferCancelled", "Finalized", "PauseSet", "RoleChanged", "StatusChanged"},
		RoleVault:            {"AdminChanged", "AdminProposed", "AdminTransferCancelled", "ProceedsWithdrawn", "Purchased", "RoleChanged"},
		RolePricing:          {"AdminChanged", "AdminProposed", "AdminTransferCancelled", "PricerChanged", "PurchasePriceUpdated", "RedemptionPriceUpdated"},
		RoleRedemption:       {"AdminChanged", "AdminProposed", "AdminTransferCancelled", "RedemptionCancelled", "RedemptionCompleted", "RedemptionFunded", "RedemptionRejected", "RedemptionRequested", "RequestClosed", "RoleChanged"},
		RoleSupplyController: {"AdminChanged", "AdminProposed", "AdminTransferCancelled", "AuditorChanged", "Burned", "Finalized", "Minted"},
	}
	for role, names := range want {
		schemas, ok := registryInstance[role]
		if !ok {
			t.Fatalf("role %s: not registered", role)
		}
		got := map[string]bool{}
		for _, s := range schemas {
			got[s.Name] = true
		}
		for _, name := range names {
			if !got[name] {
				t.Errorf("role %s: missing expected event %q", role, name)
			}
		}
	}
}
