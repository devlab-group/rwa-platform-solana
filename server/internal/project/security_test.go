package project

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/rwa-platform/server/internal/dal/memory"
	"github.com/rwa-platform/server/internal/dal/models"
	"github.com/rwa-platform/server/internal/dal/repository"
)

// addr normalizes hex to its checksummed form — the auditor identity is a
// secp256k1 key rendered as a 20-byte 0x-hex address on both chains (see
// so this is not an EVM-only helper.
func addr(hex string) string { return common.HexToAddress(hex).Hex() }

const solChainID = int64(900001)

var solAddrs = ProgramAddrs{
	Vault:            "VauLT1111111111111111111111111111111111111",
	Compliance:       "CompLiance111111111111111111111111111111111",
	SupplyController: "SuppLyCtR1111111111111111111111111111111111",
	RedemptionEscrow: "REdempT10n1111111111111111111111111111111",
	Pricing:          "PriciNg111111111111111111111111111111111111",
}

const solAdminBaseline = "AdmiN1111111111111111111111111111111111111"

func solSetup(t *testing.T) *repository.Repositories {
	t.Helper()
	repos := memory.New()
	ctx := context.Background()
	if err := repos.Projects.Upsert(ctx, &models.Project{
		ProjectID: "sol-p1", ChainID: solChainID, Status: models.ProjectStatusActive,
		Addresses: models.Addresses{
			Token: "RWAMint111111111111111111111111111111111111", QuoteToken: "QuoteMint11111111111111111111111111111111111",
			Vault: solAddrs.Vault, Compliance: solAddrs.Compliance, SupplyController: solAddrs.SupplyController,
			RedemptionEscrow: solAddrs.RedemptionEscrow, Strategy: solAddrs.Pricing,
		},
		Admin: solAdminBaseline,
	}); err != nil {
		t.Fatal(err)
	}
	return repos
}

var solEvSeq int

func solEvent(t *testing.T, repos *repository.Repositories, address, name string, block uint64, logIndex uint, data map[string]any) {
	t.Helper()
	solEvSeq++
	e := &models.ChainEvent{
		ChainID: solChainID, Address: address, TxHash: fmt.Sprintf("sig%d-%s", solEvSeq, name),
		LogIndex: logIndex, BlockNumber: block, Name: name, Data: data,
	}
	if err := repos.ChainEvents.Create(context.Background(), e); err != nil {
		t.Fatal(err)
	}
}

// solAddRemovedEvent mirrors solEvent but marks the event Removed — a
// reorged-out row (see internal/project/security_test.go's addRemovedEvent
// for the EVM equivalent). latestRoleHolder/latestEvent/etc. must skip
// these.
func solAddRemovedEvent(t *testing.T, repos *repository.Repositories, address, name string, block uint64, logIndex uint, data map[string]any) {
	t.Helper()
	solEvSeq++
	e := &models.ChainEvent{
		ChainID: solChainID, Address: address, TxHash: fmt.Sprintf("sig%d-%s", solEvSeq, name),
		LogIndex: logIndex, BlockNumber: block, Name: name, Data: data, Removed: true,
	}
	if err := repos.ChainEvents.Create(context.Background(), e); err != nil {
		t.Fatal(err)
	}
}

// solReconcile drives ReconcileSecurity with NO on-chain baseline by default,
// so every existing case still exercises the pure event fold. Pass one
// explicitly to test the baseline path.
func solReconcile(t *testing.T, repos *repository.Repositories, baseline ...SecurityBaseline) *models.SecurityState {
	t.Helper()
	var b SecurityBaseline
	if len(baseline) > 0 {
		b = baseline[0]
	}
	if err := ReconcileSecurity(context.Background(), repos.Projects, repos.ChainEvents, repos.IndexerCheckpoints, solChainID, solAddrs, b); err != nil {
		t.Fatalf("ReconcileSecurity: %v", err)
	}
	p, err := repos.Projects.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p.Security == nil {
		t.Fatal("Security projection is nil after reconcile")
	}
	return p.Security
}

func TestReconcileSecurityBaseline(t *testing.T) {
	repos := solSetup(t)
	s := solReconcile(t, repos)

	if s.Paused {
		t.Error("Paused should default false")
	}
	if s.Admin != solAdminBaseline {
		t.Errorf("Admin = %q, want baseline %q", s.Admin, solAdminBaseline)
	}
	if s.Treasury != "" || s.Treasurer != "" || s.ComplianceOperator != "" || s.RedemptionManager != "" || s.Pricer != "" {
		t.Errorf("unset roles should stay empty with no events: %+v", s)
	}
}

func TestReconcileSecurityPauseSetLatestWins(t *testing.T) {
	repos := solSetup(t)
	solEvent(t, repos, solAddrs.Compliance, "PauseSet", 10, 0, map[string]any{"paused": true, "by": solAdminBaseline})
	solEvent(t, repos, solAddrs.Compliance, "PauseSet", 11, 0, map[string]any{"paused": false, "by": solAdminBaseline})

	s := solReconcile(t, repos)
	if s.Paused {
		t.Error("Paused should be false (the later PauseSet unpaused it)")
	}
}

// TestReconcileSecurityAuditorChanged feeds AuditorChanged with the
// exact previous/newAuditor shape the decoder produces — "0x"+
// lowercase hex, NOT EIP-55 checksummed — proving latestAddressField's reuse
// (via common.IsHexAddress, which is case-insensitive) tolerates it; the
// projected state.Auditor still comes out checksummed, same as EVM, since
// latestAddressField re-normalizes through common.HexToAddress(v).Hex().
func TestReconcileSecurityAuditorChanged(t *testing.T) {
	repos := solSetup(t)
	previous := addr("0x00000000000000000000000000000000000ad0")
	newAuditor := addr("0x00000000000000000000000000000000000aa0")
	solEvent(t, repos, solAddrs.SupplyController, "AuditorChanged", 10, 0, map[string]any{
		"previous": strings.ToLower(previous), "newAuditor": strings.ToLower(newAuditor), "by": solAdminBaseline,
	})
	s := solReconcile(t, repos)
	if s.Auditor != newAuditor {
		t.Errorf("Auditor = %q, want %q", s.Auditor, newAuditor)
	}
}

// TestReconcileSecurityVaultRoles verifies the vault program's role
// numbering against solana/programs/rwa-vault/src/lib.rs: 1=Treasury (a
// top-level field, no Roles entry) and 2=Treasurer (unioned with
// redemption's).
func TestReconcileSecurityVaultRoles(t *testing.T) {
	repos := solSetup(t)
	treasury := "Treasury1111111111111111111111111111111111"
	treasurer := "Treasurer111111111111111111111111111111111"
	solEvent(t, repos, solAddrs.Vault, "RoleChanged", 10, 0, map[string]any{"role": uint(1), "previous": "", "newValue": treasury, "by": solAdminBaseline})
	solEvent(t, repos, solAddrs.Vault, "RoleChanged", 11, 0, map[string]any{"role": uint(2), "previous": "", "newValue": treasurer, "by": solAdminBaseline})

	s := solReconcile(t, repos)
	if s.Treasury != treasury {
		t.Errorf("Treasury = %q, want %q", s.Treasury, treasury)
	}
	if s.Treasurer != treasurer {
		t.Errorf("Treasurer = %q, want %q", s.Treasurer, treasurer)
	}
	if got := s.Roles["TREASURER_ROLE"]; len(got) != 1 || got[0] != treasurer {
		t.Errorf("Roles[TREASURER_ROLE] = %v, want [%s]", got, treasurer)
	}
	if _, ok := s.Roles["TREASURY_ROLE"]; ok {
		t.Error("Treasury must not appear in the Roles map (matches EVM: it's a plain field, not an AccessControl role)")
	}
}

// TestReconcileSecurityRedemptionRoles verifies role numbering against
// rwa-redemption/src/lib.rs: 1=Treasurer (unioned with vault's), 2=
// RedemptionManager. Also proves a mismatched treasurer between vault and
// redemption produces a union of both in the Roles map.
func TestReconcileSecurityRedemptionRoles(t *testing.T) {
	repos := solSetup(t)
	vaultTreasurer := "VTreasurer111111111111111111111111111111111"
	redemptionTreasurer := "RTreasurer111111111111111111111111111111111"
	redemptionManager := "RedManager11111111111111111111111111111111"
	solEvent(t, repos, solAddrs.Vault, "RoleChanged", 10, 0, map[string]any{"role": uint(2), "previous": "", "newValue": vaultTreasurer, "by": solAdminBaseline})
	solEvent(t, repos, solAddrs.RedemptionEscrow, "RoleChanged", 10, 0, map[string]any{"role": uint(1), "previous": "", "newValue": redemptionTreasurer, "by": solAdminBaseline})
	solEvent(t, repos, solAddrs.RedemptionEscrow, "RoleChanged", 11, 0, map[string]any{"role": uint(2), "previous": "", "newValue": redemptionManager, "by": solAdminBaseline})

	s := solReconcile(t, repos)
	if s.RedemptionManager != redemptionManager {
		t.Errorf("RedemptionManager = %q, want %q", s.RedemptionManager, redemptionManager)
	}
	got := s.Roles["TREASURER_ROLE"]
	if len(got) != 2 {
		t.Fatalf("Roles[TREASURER_ROLE] = %v, want both vault and redemption treasurers", got)
	}
}

// TestReconcileSecurityComplianceRoles verifies role numbering against
// rwa-compliance/src/lib.rs: 1=ComplianceAuthority (top-level
// ComplianceOperator field + COMPLIANCE_ROLE), 2=Pauser (Roles-map only, no
// top-level field on either chain).
func TestReconcileSecurityComplianceRoles(t *testing.T) {
	repos := solSetup(t)
	authority := "ComplAuth111111111111111111111111111111111"
	pauser := "Pauser11111111111111111111111111111111111"
	solEvent(t, repos, solAddrs.Compliance, "RoleChanged", 10, 0, map[string]any{"role": uint(1), "previous": "", "newValue": authority, "by": solAdminBaseline})
	solEvent(t, repos, solAddrs.Compliance, "RoleChanged", 11, 0, map[string]any{"role": uint(2), "previous": "", "newValue": pauser, "by": solAdminBaseline})

	s := solReconcile(t, repos)
	if s.ComplianceOperator != authority {
		t.Errorf("ComplianceOperator = %q, want %q", s.ComplianceOperator, authority)
	}
	if got := s.Roles["COMPLIANCE_ROLE"]; len(got) != 1 || got[0] != authority {
		t.Errorf("Roles[COMPLIANCE_ROLE] = %v, want [%s]", got, authority)
	}
	if got := s.Roles["PAUSER_ROLE"]; len(got) != 1 || got[0] != pauser {
		t.Errorf("Roles[PAUSER_ROLE] = %v, want [%s]", got, pauser)
	}
}

// TestReconcileSecurityRoleChangedReorgRollback: a reorged-out
// (Removed) RoleChanged event must not win over an earlier surviving one,
// even though it is chronologically later by (block, logIndex) — mirrors
// EVM's TestReconcileSecurityReorgRemovesEvent, but for
// latestRoleHolder's e.Removed filter instead of roleDeltas'.
func TestReconcileSecurityRoleChangedReorgRollback(t *testing.T) {
	repos := solSetup(t)
	older := "OlderTreasury11111111111111111111111111111"
	newer := "NewerTreasury11111111111111111111111111111"
	solEvent(t, repos, solAddrs.Vault, "RoleChanged", 10, 0, map[string]any{"role": uint(1), "previous": "", "newValue": older, "by": solAdminBaseline})
	solAddRemovedEvent(t, repos, solAddrs.Vault, "RoleChanged", 11, 0, map[string]any{"role": uint(1), "previous": older, "newValue": newer, "by": solAdminBaseline})

	s := solReconcile(t, repos)
	if s.Treasury != older {
		t.Errorf("Treasury = %q, want %q (the later RoleChanged at block 11 was reorged out — Removed:true)", s.Treasury, older)
	}
}

// TestReconcileSecurityRoleChangedOrdersByBlockNotInsertion:
// latestRoleHolder must pick the winner by (block, logIndex) via
// earlier(), never by the order events happen to be inserted into (or
// iterated out of) the repository — inserting the chronologically-later
// event FIRST must not change the result.
func TestReconcileSecurityRoleChangedOrdersByBlockNotInsertion(t *testing.T) {
	repos := solSetup(t)
	early := "EarlyTreasury11111111111111111111111111111"
	late := "LateTreasury111111111111111111111111111111"
	// Insert the chronologically-LATER event (block 20) before the earlier
	// one (block 10).
	solEvent(t, repos, solAddrs.Vault, "RoleChanged", 20, 0, map[string]any{"role": uint(1), "previous": early, "newValue": late, "by": solAdminBaseline})
	solEvent(t, repos, solAddrs.Vault, "RoleChanged", 10, 0, map[string]any{"role": uint(1), "previous": "", "newValue": early, "by": solAdminBaseline})

	s := solReconcile(t, repos)
	if s.Treasury != late {
		t.Errorf("Treasury = %q, want %q (block 20 is later than block 10 regardless of insertion order)", s.Treasury, late)
	}
}

// TestReconcileSecuritySameSlotSameLogIndexIsDeterministic
// covers the Solana scenario BlockNumber-as-slot/per-transaction LogIndex
// makes possible: two RoleChanged events for the same role, from different
// transactions, landing at the exact same (BlockNumber, LogIndex). Without
// a deterministic tiebreak, latestRoleHolder's first-wins-on-tie loop
// could derive a different winner depending on repository iteration order.
// earlier() (security.go) now breaks such ties on TxHash, so the winner
// must be the same regardless of insertion order.
func TestReconcileSecuritySameSlotSameLogIndexIsDeterministic(t *testing.T) {
	holderA := "HolderA1111111111111111111111111111111111"
	holderB := "HolderB1111111111111111111111111111111111"
	// "bbb-tx" > "aaa-tx" lexicographically, so holderB must always win.
	mk := func(txHash, newValue string) *models.ChainEvent {
		return &models.ChainEvent{
			ChainID: solChainID, Address: solAddrs.Vault, TxHash: txHash,
			LogIndex: 0, BlockNumber: 10, Name: "RoleChanged",
			Data: map[string]any{"role": uint(1), "previous": "", "newValue": newValue, "by": solAdminBaseline},
		}
	}

	for _, order := range [][2]string{{"aaa-tx", "bbb-tx"}, {"bbb-tx", "aaa-tx"}} {
		repos := solSetup(t)
		vals := map[string]string{"aaa-tx": holderA, "bbb-tx": holderB}
		for _, tx := range order {
			if err := repos.ChainEvents.Create(context.Background(), mk(tx, vals[tx])); err != nil {
				t.Fatal(err)
			}
		}
		s := solReconcile(t, repos)
		if s.Treasury != holderB {
			t.Errorf("insertion order %v: Treasury = %q, want %q (deterministic TxHash tiebreak)", order, s.Treasury, holderB)
		}
	}
}

// TestReconcileSecurityBaselineUnderReportsNonAdminAuthorities (
// accepted gap — see foldSecurity's doc comment) pins the documented,
// safe-direction behavior: a freshly-seeded project (no governance
// events yet) reports Treasury/Treasurer/ComplianceOperator/Pricer/
// RedemptionManager/Auditor/prices all empty — only Admin (seeded from
// config) and Paused (defaults false) are populated — because neither the
// config surface nor any program's `initialize` instruction gives
// foldSecurity a baseline to seed them from (verified: no program
// emits a genesis event).
func TestReconcileSecurityBaselineUnderReportsNonAdminAuthorities(t *testing.T) {
	repos := solSetup(t)
	s := solReconcile(t, repos)

	if s.Admin != solAdminBaseline {
		t.Errorf("Admin = %q, want the seeded baseline %q", s.Admin, solAdminBaseline)
	}
	if s.Paused {
		t.Error("Paused should default false")
	}
	for name, got := range map[string]string{
		"Treasury": s.Treasury, "Treasurer": s.Treasurer, "ComplianceOperator": s.ComplianceOperator,
		"RedemptionManager": s.RedemptionManager, "Pricer": s.Pricer, "Auditor": s.Auditor,
		"PurchasePricePerWholeToken": s.PurchasePricePerWholeToken, "RedemptionPricePerWholeToken": s.RedemptionPricePerWholeToken,
	} {
		if got != "" {
			t.Errorf("%s = %q, want empty on a freshly-seeded project with no governance events yet", name, got)
		}
	}
}

// TestRoleU8 table-tests every numeric shape a ChainEvent.Data "role"
// value can arrive in — the exact set roleU8's doc comment claims to
// handle: the decoder's own in-process Go `uint`, plus every shape a real
// Mongo BSON round-trip can yield (int32/int64 always; int/uint8/uint64/
// float64 for robustness against other callers) — and confirms an
// unrecognized type falls back to 0 rather than panicking.
func TestRoleU8(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want uint8
	}{
		{"uint (the decoder's actual in-process type)", uint(2), 2},
		{"uint8", uint8(2), 2},
		{"int32 (Mongo BSON round-trip of a small int)", int32(2), 2},
		{"int64 (Mongo BSON round-trip of a large/unsigned int)", int64(2), 2},
		{"int", int(2), 2},
		{"uint64", uint64(2), 2},
		{"float64", float64(2), 2},
		{"unrecognized type (string) falls back to 0", "2", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := roleU8(c.in); got != c.want {
				t.Errorf("roleU8(%v) = %d, want %d", c.in, got, c.want)
			}
		})
	}
}

func TestReconcileSecurityPricingEvents(t *testing.T) {
	repos := solSetup(t)
	pricer := "Pricer11111111111111111111111111111111111"
	solEvent(t, repos, solAddrs.Pricing, "PricerChanged", 10, 0, map[string]any{"previous": "", "newPricer": pricer, "by": solAdminBaseline})
	solEvent(t, repos, solAddrs.Pricing, "PurchasePriceUpdated", 11, 0, map[string]any{"previous": "1000", "newPrice": "1100", "by": pricer})
	solEvent(t, repos, solAddrs.Pricing, "RedemptionPriceUpdated", 12, 0, map[string]any{"previous": "900", "newPrice": "950", "by": pricer})

	s := solReconcile(t, repos)
	if s.Pricer != pricer {
		t.Errorf("Pricer = %q, want %q", s.Pricer, pricer)
	}
	if s.PurchasePricePerWholeToken != "1100" {
		t.Errorf("PurchasePricePerWholeToken = %q, want 1100", s.PurchasePricePerWholeToken)
	}
	if s.RedemptionPricePerWholeToken != "950" {
		t.Errorf("RedemptionPricePerWholeToken = %q, want 950", s.RedemptionPricePerWholeToken)
	}
}

// TestReconcileSecurityAdminTwoStepTransfer walks propose->accept on
// one program (vault) and confirms Admin/PendingAdmin/DEFAULT_ADMIN_ROLE
// update, while the other 4 programs remain on the baseline admin — so the
// overall state.Admin (derived) still prefers the baseline since it's still
// the admin on 4 of 5 programs.
func TestReconcileSecurityAdminTwoStepTransfer(t *testing.T) {
	repos := solSetup(t)
	newAdmin := "NewAdmin11111111111111111111111111111111111"

	solEvent(t, repos, solAddrs.Vault, "AdminProposed", 10, 0, map[string]any{"newAdmin": newAdmin, "by": solAdminBaseline})
	s := solReconcile(t, repos)
	if s.PendingAdmin != newAdmin {
		t.Fatalf("PendingAdmin = %q, want %q after propose", s.PendingAdmin, newAdmin)
	}
	if s.Admin != solAdminBaseline {
		t.Fatalf("Admin = %q, want unchanged baseline %q mid-transfer", s.Admin, solAdminBaseline)
	}

	solEvent(t, repos, solAddrs.Vault, "AdminChanged", 11, 0, map[string]any{"previous": solAdminBaseline, "newAdmin": newAdmin})
	s = solReconcile(t, repos)
	if s.PendingAdmin != "" {
		t.Errorf("PendingAdmin = %q, want cleared after accept", s.PendingAdmin)
	}
	// Baseline is still admin on the other 4 programs, so it remains the
	// preferred single-value Admin (mirrors EVM's derive(): prefer the
	// configured value while it's still a current holder somewhere).
	if s.Admin != solAdminBaseline {
		t.Errorf("Admin = %q, want %q (still holding admin on 4/5 programs)", s.Admin, solAdminBaseline)
	}
	got := s.Roles["DEFAULT_ADMIN_ROLE"]
	if len(got) != 2 {
		t.Fatalf("Roles[DEFAULT_ADMIN_ROLE] = %v, want both the baseline and the vault's new admin", got)
	}
}

// TestReconcileSecurityAdminTransferCancelled confirms a cancel clears
// the pending transfer without changing the current admin.
func TestReconcileSecurityAdminTransferCancelled(t *testing.T) {
	repos := solSetup(t)
	newAdmin := "NewAdmin11111111111111111111111111111111111"
	solEvent(t, repos, solAddrs.Compliance, "AdminProposed", 10, 0, map[string]any{"newAdmin": newAdmin, "by": solAdminBaseline})
	solEvent(t, repos, solAddrs.Compliance, "AdminTransferCancelled", 11, 0, map[string]any{"cancelled": newAdmin, "by": solAdminBaseline})

	s := solReconcile(t, repos)
	if s.PendingAdmin != "" {
		t.Errorf("PendingAdmin = %q, want empty after cancel", s.PendingAdmin)
	}
	if s.Admin != solAdminBaseline {
		t.Errorf("Admin = %q, want unchanged baseline %q", s.Admin, solAdminBaseline)
	}
}

// TestReconcileSecurityAsOfFromCheckpoint pins the invariant that
// the projection's AsOfBlock/AsOfTime must be a coherent
// watermark folded from EVERY security-relevant program's OWN checkpoint —
// the MINIMUM LastBlock and the OLDEST LastSuccessfulPollAt heartbeat —
// never the first one found and never the old (never-written)
// synthetic "ALL" checkpoint row.
func TestReconcileSecurityAsOfFromCheckpoint(t *testing.T) {
	repos := solSetup(t)
	now := time.Now().UTC()
	progCheckpoints := []struct {
		addr   string
		block  uint64
		pollAt time.Time
	}{
		{solAddrs.Vault, 500, now},
		{solAddrs.Compliance, 600, now.Add(-30 * time.Second)}, // oldest heartbeat
		{solAddrs.SupplyController, 550, now.Add(10 * time.Second)},
		{solAddrs.RedemptionEscrow, 480, now.Add(5 * time.Second)}, // lowest block
		{solAddrs.Pricing, 700, now.Add(20 * time.Second)},
	}
	for _, pc := range progCheckpoints {
		if err := repos.IndexerCheckpoints.Set(context.Background(), &models.IndexerCheckpoint{
			ChainID: solChainID, Address: pc.addr, LastBlock: pc.block, LastSuccessfulPollAt: pc.pollAt, UpdatedAt: pc.pollAt,
		}); err != nil {
			t.Fatal(err)
		}
	}

	s := solReconcile(t, repos)
	if s.AsOfBlock != 480 {
		t.Errorf("AsOfBlock = %d, want 480 (the MINIMUM LastBlock across all 5 security-relevant programs)", s.AsOfBlock)
	}
	wantAsOfTime := now.Add(-30 * time.Second)
	if !s.AsOfTime.Equal(wantAsOfTime) {
		t.Errorf("AsOfTime = %v, want %v (the OLDEST LastSuccessfulPollAt across all 5 programs)", s.AsOfTime, wantAsOfTime)
	}
}

// TestReconcileSecurityAsOfZeroUntilEveryProgramHasPolled: the
// watermark must stay zero — never a partial/misleadingly-fresh value —
// until EVERY configured security-relevant program has both a checkpoint
// row and a non-zero poll-health heartbeat, even if some already do.
func TestReconcileSecurityAsOfZeroUntilEveryProgramHasPolled(t *testing.T) {
	repos := solSetup(t)
	now := time.Now().UTC()
	// 4 of the 5 required programs have a healthy checkpoint; Pricing has
	// never completed a poll (no row at all).
	for _, addr := range []string{solAddrs.Vault, solAddrs.Compliance, solAddrs.SupplyController, solAddrs.RedemptionEscrow} {
		if err := repos.IndexerCheckpoints.Set(context.Background(), &models.IndexerCheckpoint{
			ChainID: solChainID, Address: addr, LastBlock: 500, LastSuccessfulPollAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}

	s := solReconcile(t, repos)
	if s.AsOfBlock != 0 || !s.AsOfTime.IsZero() {
		t.Errorf("AsOfBlock=%d AsOfTime=%v, want both zero — Pricing has never completed a poll, so the watermark can't cover it yet", s.AsOfBlock, s.AsOfTime)
	}

	// A checkpoint row with a zero heartbeat (e.g. mid-first-sync, before
	// any successful poll) is treated the same as "no row at all".
	if err := repos.IndexerCheckpoints.Set(context.Background(), &models.IndexerCheckpoint{
		ChainID: solChainID, Address: solAddrs.Pricing, LastBlock: 0, BackfillCursor: "sig1",
	}); err != nil {
		t.Fatal(err)
	}
	s2 := solReconcile(t, repos)
	if s2.AsOfBlock != 0 || !s2.AsOfTime.IsZero() {
		t.Errorf("AsOfBlock=%d AsOfTime=%v, want both zero — Pricing's checkpoint has no heartbeat yet", s2.AsOfBlock, s2.AsOfTime)
	}
}

// TestReconcileSecurityNonActiveProjectIsNoOp pins
// ReconcileSecurity's early-return: a non-Active project has nothing
// verified to project onto.
func TestReconcileSecurityNonActiveProjectIsNoOp(t *testing.T) {
	repos := memory.New()
	ctx := context.Background()
	if err := repos.Projects.Upsert(ctx, &models.Project{
		ProjectID: "sol-p2", ChainID: solChainID, Status: models.ProjectStatusUndeployed,
	}); err != nil {
		t.Fatal(err)
	}
	if err := ReconcileSecurity(ctx, repos.Projects, repos.ChainEvents, repos.IndexerCheckpoints, solChainID, solAddrs, SecurityBaseline{}); err != nil {
		t.Fatalf("ReconcileSecurity: %v", err)
	}
	p, err := repos.Projects.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if p.Security != nil {
		t.Error("Security should stay nil for a non-Active project")
	}
}

// --- on-chain account baseline ---------------------------------------------

// solBaseline is a fully-populated baseline, standing in for what
// blockchain.ReadBaseline returns for a bootstrapped deployment that has never
// rotated anything.
func solBaseline() SecurityBaseline {
	return SecurityBaseline{
		Auditor:                      addr("0x00000000000000000000000000000000000ba5e"),
		Treasury:                     "BaseTreasury11111111111111111111111111111",
		Treasurer:                    "BaseTreasurer1111111111111111111111111111",
		Pricer:                       "BasePricer111111111111111111111111111111",
		ComplianceOperator:           "BaseCompliance111111111111111111111111111",
		Pauser:                       "BasePauser111111111111111111111111111111",
		RedemptionManager:            "BaseRedManager11111111111111111111111111",
		PurchasePricePerWholeToken:   "2000000",
		RedemptionPricePerWholeToken: "1950000",
		Paused:                       true,
	}
}

// TestReconcileSecurityUsesAccountBaseline is the regression test for the bug
// this baseline exists to fix: a freshly bootstrapped deployment emits NO
// events at all (no program's `initialize` emits one), so before this the
// projection reported empty auditor/treasury/prices/roles forever and
// re-indexing could not help — there was nothing on chain to re-read.
func TestReconcileSecurityUsesAccountBaseline(t *testing.T) {
	repos := solSetup(t)
	b := solBaseline()

	s := solReconcile(t, repos, b)

	for _, tc := range []struct{ field, got, want string }{
		{"Auditor", s.Auditor, b.Auditor},
		{"Treasury", s.Treasury, b.Treasury},
		{"Treasurer", s.Treasurer, b.Treasurer},
		{"Pricer", s.Pricer, b.Pricer},
		{"ComplianceOperator", s.ComplianceOperator, b.ComplianceOperator},
		{"RedemptionManager", s.RedemptionManager, b.RedemptionManager},
		{"PurchasePricePerWholeToken", s.PurchasePricePerWholeToken, b.PurchasePricePerWholeToken},
		{"RedemptionPricePerWholeToken", s.RedemptionPricePerWholeToken, b.RedemptionPricePerWholeToken},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q from the baseline", tc.field, tc.got, tc.want)
		}
	}
	if !s.Paused {
		t.Error("Paused = false, want true from the baseline")
	}
	// The Roles map must be seeded too — the Security screen reads holders
	// from it, not only from the top-level fields.
	for role, want := range map[string]string{
		"PRICER_ROLE":             b.Pricer,
		"COMPLIANCE_ROLE":         b.ComplianceOperator,
		"PAUSER_ROLE":             b.Pauser,
		"REDEMPTION_MANAGER_ROLE": b.RedemptionManager,
		"TREASURER_ROLE":          b.Treasurer,
	} {
		if got := s.Roles[role]; len(got) != 1 || got[0] != want {
			t.Errorf("Roles[%s] = %v, want [%s]", role, got, want)
		}
	}
	// Admin still comes from the config-seeded Project.Admin, unchanged.
	if s.Admin != solAdminBaseline {
		t.Errorf("Admin = %q, want the config baseline %q", s.Admin, solAdminBaseline)
	}
}

// TestReconcileSecurityEventsOverrideBaseline: once a real rotation lands, the
// event must win over the account state for that field — and ONLY that field.
// The account read happens every tick, so a baseline that could beat an event
// would make rotations invisible.
func TestReconcileSecurityEventsOverrideBaseline(t *testing.T) {
	repos := solSetup(t)
	b := solBaseline()

	rotatedTreasury := "NewTreasury11111111111111111111111111111"
	rotatedAuditor := addr("0x00000000000000000000000000000000000aa11")
	solEvent(t, repos, solAddrs.Vault, "RoleChanged", 20, 0,
		map[string]any{"role": uint(1), "previous": b.Treasury, "newValue": rotatedTreasury, "by": solAdminBaseline})
	solEvent(t, repos, solAddrs.SupplyController, "AuditorChanged", 21, 0,
		map[string]any{"previous": b.Auditor, "newAuditor": strings.ToLower(rotatedAuditor), "by": solAdminBaseline})
	solEvent(t, repos, solAddrs.Pricing, "PurchasePriceUpdated", 22, 0,
		map[string]any{"previous": "2000000", "newPrice": "3000000", "by": solAdminBaseline})

	s := solReconcile(t, repos, b)

	if s.Treasury != rotatedTreasury {
		t.Errorf("Treasury = %q, want the rotated %q", s.Treasury, rotatedTreasury)
	}
	if s.Auditor != rotatedAuditor {
		t.Errorf("Auditor = %q, want the rotated %q", s.Auditor, rotatedAuditor)
	}
	if s.PurchasePricePerWholeToken != "3000000" {
		t.Errorf("PurchasePrice = %q, want the updated 3000000", s.PurchasePricePerWholeToken)
	}
	// Untouched fields keep the baseline.
	if s.Pricer != b.Pricer || s.RedemptionManager != b.RedemptionManager {
		t.Errorf("un-rotated fields must keep the baseline: Pricer=%q RedemptionManager=%q", s.Pricer, s.RedemptionManager)
	}
	if s.RedemptionPricePerWholeToken != b.RedemptionPricePerWholeToken {
		t.Errorf("RedemptionPrice = %q, want the untouched baseline %q", s.RedemptionPricePerWholeToken, b.RedemptionPricePerWholeToken)
	}
}

// TestReconcileSecurityEmptyBaselineDoesNotBlank: a tick whose account read
// failed (RPC down mid-life) passes an empty baseline. That must not erase
// values the events already establish — the fold is a full replay, so the
// event-derived state has to survive a baseline outage untouched.
func TestReconcileSecurityEmptyBaselineDoesNotBlank(t *testing.T) {
	repos := solSetup(t)
	treasury := "EventTreasury111111111111111111111111111"
	solEvent(t, repos, solAddrs.Vault, "RoleChanged", 10, 0,
		map[string]any{"role": uint(1), "previous": "", "newValue": treasury, "by": solAdminBaseline})

	if s := solReconcile(t, repos, solBaseline()); s.Treasury != treasury {
		t.Fatalf("precondition: Treasury = %q, want %q", s.Treasury, treasury)
	}
	s := solReconcile(t, repos, SecurityBaseline{})
	if s.Treasury != treasury {
		t.Errorf("Treasury = %q, want the event-derived %q preserved across a failed account read", s.Treasury, treasury)
	}
}
