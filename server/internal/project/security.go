package project

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/rwa-platform/server/internal/dal/models"
	"github.com/rwa-platform/server/internal/dal/repository"
)

// ProgramAddrs is the set of Solana program IDs (base58, verbatim from
// config — see the ADDRESSING INVARIANT in the frozen event-mapping doc)
// ReconcileSecurity folds governance events from. It is passed
// explicitly rather than read off Project.Addresses so this reconciler does
// not depend on SeedProject having already run with the exact same
// values — the two are expected to agree (SeedProject sets
// Vault/Compliance/SupplyController/RedemptionEscrow/Strategy to these same
// program IDs) but are not coupled through the struct.
type ProgramAddrs struct {
	Vault            string
	Compliance       string
	SupplyController string
	RedemptionEscrow string
	Pricing          string
}

// SecurityBaseline is the governance state read from the programs' own config
// accounts, which foldSecurity starts from before replaying events over it.
//
// It exists because NO program's `initialize` emits an event: the authorities
// and prices chosen at bootstrap are written into the config PDAs and
// announced nowhere, so a fold over chain_events alone reports empty for every
// field on a deployment that has never rotated anything. Re-indexing cannot
// recover them — the events were never emitted, so there is nothing to
// re-read. cmd/platform fills this in from blockchain.ReadBaseline.
//
// Every field is optional. A zero value means "not readable" (mid-bootstrap,
// RPC down, a program not yet initialized), never "confirmed empty", and
// foldSecurity treats it as "no baseline for this field" — so an unreadable
// account degrades to exactly the old event-only behaviour rather than
// blanking a value an earlier pass established.
//
// It is deliberately NOT models.SecurityState: that type has no Pauser field
// (the pauser lives only in the Roles map) and carries projection outputs like
// AsOfBlock that an input has no business supplying.
type SecurityBaseline struct {
	Admin                        string
	Auditor                      string
	Treasury                     string
	Treasurer                    string
	Pricer                       string
	ComplianceOperator           string
	Pauser                       string
	RedemptionManager            string
	PurchasePricePerWholeToken   string
	RedemptionPricePerWholeToken string
	Paused                       bool
}

// ReconcileSecurity makes Project.Security the live, event-sourced
// view of Solana governance authority, by full replay over chain_events:
// reorg rollback deletes chain_events rows outright, so re-deriving from
// scratch on every tick is what makes an out-of-band change AND its later
// reorg both reflected correctly.
//
// The Solana programs expose single-holder authorities rotated via one
// RoleChanged{role:u8,previous,new_value,by} event per program (see
// solana/programs/*/src/lib.rs's `enum Role`) and base58 Pubkey values.
func ReconcileSecurity(ctx context.Context, projects repository.ProjectRepository, chainEvents repository.ChainEventRepository, checkpoints repository.IndexerCheckpointRepository, chainID int64, programIDs ProgramAddrs, baseline SecurityBaseline) error {
	p, err := projects.Get(ctx)
	if err != nil {
		if err == repository.ErrNotFound {
			return nil
		}
		return fmt.Errorf("project: load project for solana security reconcile: %w", err)
	}
	if p.Status != models.ProjectStatusActive {
		return nil
	}

	// Project.Admin is the config-seeded admin (seed.go) and remains the admin
	// baseline; the caller may override it with an on-chain read, but must not
	// blank it when the accounts were unreadable this tick.
	if baseline.Admin == "" {
		baseline.Admin = p.Admin
	}
	state, err := foldSecurity(ctx, chainEvents, chainID, programIDs, baseline)
	if err != nil {
		return err
	}

	asOfBlock, asOfTime, err := securityWatermark(ctx, checkpoints, chainID, programIDs)
	if err != nil {
		return err
	}
	state.AsOfBlock = asOfBlock
	state.AsOfTime = asOfTime

	p.Security = state
	p.UpdatedAt = time.Now().UTC()
	if err := projects.Upsert(ctx, p); err != nil {
		return fmt.Errorf("project: persist solana security projection: %w", err)
	}
	return nil
}

// securityWatermark computes the projection's AsOfBlock/AsOfTime.
// The old code looked up blockchain.CheckpointAddress — a synthetic "ALL"
// checkpoint row left over from an EVM-style single-checkpoint-per-chain
// model — which the indexer never writes (it keys one IndexerCheckpoint per
// program), so the lookup always missed and AsOfBlock/AsOfTime stayed zero
// forever, making api.securityStale report the security view stale
// permanently.
//
// The fix folds every security-relevant program's OWN checkpoint (Vault,
// Compliance, SupplyController, RedemptionEscrow, Pricing — the same set
// foldSecurity reads events from) into ONE coherent watermark: the
// MINIMUM LastBlock (the most-behind program bounds how current the whole
// projection can be, mirroring app.LastIndexedBlock's lastIndexedSlot)
// and the OLDEST LastSuccessfulPollAt (the poll-health heartbeat, not
// UpdatedAt — a program that is polling successfully but has
// nothing new to ingest must not make the watermark look stale). It
// deliberately does NOT use the first checkpoint found (the api package's
// securityCheckpoint does that, but only to answer "has SOMETHING run" for
// the ReconciliationRequired/existence check — a different question).
//
// The watermark stays zero (i.e. this reconcile leaves AsOfBlock/AsOfTime at
// their pre-projection zero values, which is what state starts as) until
// EVERY configured (non-empty) security-relevant program has both a
// checkpoint row AND a non-zero heartbeat — a partially-synced deployment
// must not report a watermark that some of its governance-relevant events
// haven't actually reached yet.
func securityWatermark(ctx context.Context, checkpoints repository.IndexerCheckpointRepository, chainID int64, pr ProgramAddrs) (asOfBlock uint64, asOfTime time.Time, err error) {
	programIDs := []string{pr.Vault, pr.Compliance, pr.SupplyController, pr.RedemptionEscrow, pr.Pricing}
	have := false
	for _, addr := range programIDs {
		if addr == "" {
			continue
		}
		cp, cerr := checkpoints.Get(ctx, chainID, addr)
		switch {
		case cerr == repository.ErrNotFound:
			// This program hasn't completed even its first poll yet — the
			// watermark can't honestly claim to cover it.
			return 0, time.Time{}, nil
		case cerr != nil:
			return 0, time.Time{}, fmt.Errorf("project: load indexer checkpoint %s for solana security reconcile: %w", addr, cerr)
		case cp.LastSuccessfulPollAt.IsZero():
			// A checkpoint row exists (e.g. mid-backfill) but has never
			// recorded a successful-poll heartbeat — same "can't cover this
			// program yet" reasoning as ErrNotFound above.
			return 0, time.Time{}, nil
		}
		if !have || cp.LastBlock < asOfBlock {
			asOfBlock = cp.LastBlock
		}
		if !have || cp.LastSuccessfulPollAt.Before(asOfTime) {
			asOfTime = cp.LastSuccessfulPollAt
		}
		have = true
	}
	if !have {
		return 0, time.Time{}, nil
	}
	return asOfBlock, asOfTime, nil
}

// Role numbers per program — verified against the Rust `enum Role` in each
// program's lib.rs (the IDL alone doesn't carry the numeric values), NOT
// just names, per the frozen contract's warning that role u8 is
// program-specific.
const (
	vaultRoleTreasury  uint8 = 1
	vaultRoleTreasurer uint8 = 2

	complianceRoleAuthority uint8 = 1
	compliancePauserRole    uint8 = 2

	redemptionRoleTreasurer         uint8 = 1
	redemptionRoleRedemptionManager uint8 = 2
)

// foldSecurity computes the live SecurityState from indexed Solana
// governance events. baselineAdmin is Project.Admin, the config-seeded
// admin pubkey (see seed.go) every program's admin fold starts from
// when it has never seen an AdminChanged event.
//
// The gap this baseline closes: NONE of
// rwa-vault::initialize, rwa-compliance::initialize, rwa-redemption::initialize,
// rwa-supply-controller::initialize, or rwa-pricing::initialize emits any event
// (verified against each program's lib.rs; `finalize` and
// `set_system_addresses` emit nothing either). Only AdminChanged is guaranteed
// on every program, via accept_admin, which is why the admin fold alone never
// had a gap.
//
// So a fold over chain_events ALONE reports empty Treasury, Treasurer,
// ComplianceOperator, Pricer, RedemptionManager, Auditor, and prices on every
// freshly bootstrapped deployment, and no amount of re-indexing fixes it: those
// events were never emitted, so there is nothing on chain to re-read. The
// original note here concluded the gap needed either new config keys or an
// indexer that decodes `initialize` instruction data. It needs neither — the
// values are sitting in the programs' config accounts, readable with an
// ordinary getAccountInfo, which is what SecurityBaseline carries in.
func foldSecurity(ctx context.Context, chainEvents repository.ChainEventRepository, chainID int64, pr ProgramAddrs, baseline SecurityBaseline) (*models.SecurityState, error) {
	baselineAdmin := baseline.Admin
	// Start from the on-chain account baseline rather than the zero value.
	// For a deployment that has never rotated an authority or moved a price —
	// i.e. every freshly bootstrapped one — these ARE the live values, and
	// there is no event anywhere on chain that says so. Each `if ok` below
	// then overwrites its own field from the latest surviving event, so a real
	// rotation still wins and a reorg that deletes the rotation correctly
	// falls back to the account state rather than to nothing.
	state := &models.SecurityState{
		Paused:                       baseline.Paused,
		Auditor:                      baseline.Auditor,
		Treasury:                     baseline.Treasury,
		RedemptionManager:            baseline.RedemptionManager,
		ComplianceOperator:           baseline.ComplianceOperator,
		Pricer:                       baseline.Pricer,
		PurchasePricePerWholeToken:   baseline.PurchasePricePerWholeToken,
		RedemptionPricePerWholeToken: baseline.RedemptionPricePerWholeToken,
	}
	roles := map[string][]string{}
	addRole := func(name string, holders ...string) {
		v := dedupSorted(holders)
		if len(v) > 0 {
			roles[name] = v
		}
	}
	// Baseline role holders go in first. addRole REPLACES an entry rather than
	// merging, and every event-sourced addRole below runs after these, so an
	// event holder always supersedes the account-state one for the same role.
	addRole("PRICER_ROLE", baseline.Pricer)
	addRole("COMPLIANCE_ROLE", baseline.ComplianceOperator)
	addRole("PAUSER_ROLE", baseline.Pauser)
	addRole("REDEMPTION_MANAGER_ROLE", baseline.RedemptionManager)

	// Paused: rwa-compliance's PauseSet carries the flag directly (unlike
	// EVM's Paused/Unpaused event pair), so the latest surviving event wins
	// outright; no event ever means the deploy baseline (unpaused).
	if pr.Compliance != "" {
		if v, ok, err := latestBoolField(ctx, chainEvents, chainID, pr.Compliance, "PauseSet", "paused"); err != nil {
			return nil, err
		} else if ok {
			state.Paused = v
		}
	}

	// Auditor: rwa-supply-controller's AuditorChanged.newAuditor is already
	// EVM-shaped 20-byte 0x-hex (SupplyController stores auditor_eth for
	// secp256k1 signature recovery, not a Pubkey) — latestAddressField's hex
	// validation is correct to reuse here unmodified.
	if pr.SupplyController != "" {
		if v, ok, err := latestAddressField(ctx, chainEvents, chainID, pr.SupplyController, "AuditorChanged", "newAuditor"); err != nil {
			return nil, err
		} else if ok {
			state.Auditor = v
		}
	}

	// Vault: role 1=Treasury (single top-level field, no Roles entry —
	// mirrors EVM, where Treasury is a plain address field, not an
	// AccessControl role), role 2=Treasurer (shared with redemption below).
	vaultTreasurer := baseline.Treasurer
	if pr.Vault != "" {
		if v, ok, err := latestRoleHolder(ctx, chainEvents, chainID, pr.Vault, vaultRoleTreasury); err != nil {
			return nil, err
		} else if ok {
			state.Treasury = v
		}
		if v, ok, err := latestRoleHolder(ctx, chainEvents, chainID, pr.Vault, vaultRoleTreasurer); err != nil {
			return nil, err
		} else if ok {
			vaultTreasurer = v
		}
	}

	// Redemption: role 1=Treasurer (unioned with Vault's), role
	// 2=RedemptionManager.
	var redemptionTreasurer string
	if pr.RedemptionEscrow != "" {
		if v, ok, err := latestRoleHolder(ctx, chainEvents, chainID, pr.RedemptionEscrow, redemptionRoleTreasurer); err != nil {
			return nil, err
		} else if ok {
			redemptionTreasurer = v
		}
		if v, ok, err := latestRoleHolder(ctx, chainEvents, chainID, pr.RedemptionEscrow, redemptionRoleRedemptionManager); err != nil {
			return nil, err
		} else if ok {
			state.RedemptionManager = v
			addRole("REDEMPTION_MANAGER_ROLE", v)
		}
	}
	treasurerHolders := dedupSorted([]string{vaultTreasurer, redemptionTreasurer})
	if len(treasurerHolders) > 0 {
		state.Treasurer = treasurerHolders[0]
		addRole("TREASURER_ROLE", treasurerHolders...)
	}

	// Compliance: role 1=ComplianceAuthority (EVM's COMPLIANCE_ROLE/
	// ComplianceOperator equivalent), role 2=Pauser (Roles-map only, like
	// EVM's PAUSER_ROLE — neither chain exposes a top-level Pauser field).
	if pr.Compliance != "" {
		if v, ok, err := latestRoleHolder(ctx, chainEvents, chainID, pr.Compliance, complianceRoleAuthority); err != nil {
			return nil, err
		} else if ok {
			state.ComplianceOperator = v
			addRole("COMPLIANCE_ROLE", v)
		}
		if v, ok, err := latestRoleHolder(ctx, chainEvents, chainID, pr.Compliance, compliancePauserRole); err != nil {
			return nil, err
		} else if ok {
			addRole("PAUSER_ROLE", v)
		}
	}

	// Pricing (== Project.Addresses.Strategy): PricerChanged and the two
	// price-update events. Field names (newPricer/newPrice) match the EVM
	// strategy events verbatim, so the existing latestStringField helper —
	// which does no hex validation, just "non-empty string" — is reused
	// as-is.
	if pr.Pricing != "" {
		if v, ok, err := latestStringField(ctx, chainEvents, chainID, pr.Pricing, "PricerChanged", "newPricer"); err != nil {
			return nil, err
		} else if ok {
			state.Pricer = v
			addRole("PRICER_ROLE", v)
		}
		if v, ok, err := latestStringField(ctx, chainEvents, chainID, pr.Pricing, "PurchasePriceUpdated", "newPrice"); err != nil {
			return nil, err
		} else if ok {
			state.PurchasePricePerWholeToken = v
		}
		if v, ok, err := latestStringField(ctx, chainEvents, chainID, pr.Pricing, "RedemptionPriceUpdated", "newPrice"); err != nil {
			return nil, err
		} else if ok {
			state.RedemptionPricePerWholeToken = v
		}
	}

	// Admin: all 5 business programs (vault, compliance, redemption,
	// supply-controller, pricing) share the AdminProposed/AdminChanged/
	// AdminTransferCancelled shape — the transfer-hook program emits no
	// events at all (see the frozen doc's V1 limitation note) so it is not
	// included. Unlike EVM's DEFAULT_ADMIN_ROLE fold (which has to infer
	// "already accepted" from role-holding because acceptDefaultAdminTransfer
	// emits no dedicated event), Solana's accept_admin ALWAYS emits
	// AdminChanged, so each program's current/pending admin is derived
	// directly from its own event stream with no role-holding cross-check
	// needed.
	adminPrograms := []string{pr.Vault, pr.Compliance, pr.RedemptionEscrow, pr.SupplyController, pr.Pricing}
	var currentAdmins []string
	for _, addr := range adminPrograms {
		if addr == "" {
			continue
		}
		current, pending, err := adminState(ctx, chainEvents, chainID, addr, baselineAdmin)
		if err != nil {
			return nil, err
		}
		if current != "" {
			currentAdmins = append(currentAdmins, current)
		}
		if pending != "" && state.PendingAdmin == "" {
			state.PendingAdmin = pending
		}
	}
	currentAdmins = dedupSorted(currentAdmins)
	state.Admin = derive(baselineAdmin, currentAdmins)
	addRole("DEFAULT_ADMIN_ROLE", currentAdmins...)

	if len(roles) > 0 {
		state.Roles = roles
	}
	return state, nil
}

// adminState replays one program's AdminProposed/AdminChanged/
// AdminTransferCancelled events in (slot, logIndex) order into its current
// admin (starting from baseline) and the still-pending transfer target, if
// any. AdminChanged both updates current AND clears pending in the same
// step — it is the sole "accept" event, always emitted, so there is no
// analog of the EVM fold's role-holding cross-check.
func adminState(ctx context.Context, chainEvents repository.ChainEventRepository, chainID int64, programID, baseline string) (current, pending string, err error) {
	var all []*models.ChainEvent
	for _, name := range []string{"AdminProposed", "AdminChanged", "AdminTransferCancelled"} {
		evs, e := chainEvents.ListByName(ctx, chainID, programID, name)
		if e != nil {
			return "", "", fmt.Errorf("project: list %s for %s: %w", name, programID, e)
		}
		for _, ev := range evs {
			if !ev.Removed {
				all = append(all, ev)
			}
		}
	}
	sort.SliceStable(all, func(i, j int) bool { return earlier(all[i], all[j]) })

	current = baseline
	for _, e := range all {
		switch e.Name {
		case "AdminProposed":
			if v, _ := e.Data["newAdmin"].(string); v != "" {
				pending = v
			}
		case "AdminChanged":
			if v, _ := e.Data["newAdmin"].(string); v != "" {
				current = v
			}
			pending = ""
		case "AdminTransferCancelled":
			pending = ""
		}
	}
	return current, pending, nil
}

// latestRoleHolder returns the newValue (base58 pubkey) of the most
// recent (non-reorged) RoleChanged event at programID whose role field
// equals want, or ok=false if no such event survives. Dispatch is by
// (programID, discriminator) already at the ChainEventRepository query
// level (chain_events are scoped by Address==programID), and by role u8
// here — the same "RoleChanged" name means different roles on different
// programs (per the frozen contract's CRITICAL decoding rules), so this
// must never be called with an address whose role numbering doesn't match
// want's intended program.
//
// "Most recent" is decided by earlier(), whose TxHash tiebreak
// makes this deterministic across runs even when two RoleChanged events for
// the same role land in the same Solana slot from different transactions —
// (BlockNumber, LogIndex) alone can collide there.
func latestRoleHolder(ctx context.Context, chainEvents repository.ChainEventRepository, chainID int64, programID string, want uint8) (string, bool, error) {
	events, err := chainEvents.ListByName(ctx, chainID, programID, "RoleChanged")
	if err != nil {
		return "", false, fmt.Errorf("project: list RoleChanged for %s: %w", programID, err)
	}
	var latest *models.ChainEvent
	for _, e := range events {
		if e.Removed || roleU8(e.Data["role"]) != want {
			continue
		}
		if latest == nil || earlier(latest, e) {
			latest = e
		}
	}
	if latest == nil {
		return "", false, nil
	}
	v, _ := latest.Data["newValue"].(string)
	if v == "" {
		return "", false, fmt.Errorf("project: RoleChanged event %s/%d (role %d) has no newValue", latest.TxHash, latest.LogIndex, want)
	}
	return v, true, nil
}

// latestBoolField returns the bool in field of the most recent
// (non-reorged) event named name at addr, ok=false when no such event
// survives.
func latestBoolField(ctx context.Context, chainEvents repository.ChainEventRepository, chainID int64, addr, name, field string) (bool, bool, error) {
	ev, err := latestEvent(ctx, chainEvents, chainID, addr, name)
	if err != nil {
		return false, false, err
	}
	if ev == nil {
		return false, false, nil
	}
	v, ok := ev.Data[field].(bool)
	return v, ok, nil
}

// roleU8 accepts every numeric shape a ChainEvent.Data "role" value
// can arrive in. The decoder (internal/blockchain) writes u8
// fields as Go `uint` in-process (confirmed against its actual output —
// NOT uint8, unlike what the equivalent helper in this codebase, e.g.
// internal/compliance/projector.go's toUint8, assumes), which then decodes
// back as int32/int64 once it has round-tripped through MongoDB's Go
// driver (BSON int32/int64 decode to exactly those two Go types regardless
// of the field's original width). uint8/uint64/int/float64 are accepted
// too for robustness against any caller/test that hands this a differently
// -typed literal.
func roleU8(v any) uint8 {
	switch t := v.(type) {
	case uint:
		return uint8(t)
	case uint8:
		return t
	case int32:
		return uint8(t)
	case int64:
		return uint8(t)
	case int:
		return uint8(t)
	case uint64:
		return uint8(t)
	case float64:
		return uint8(t)
	default:
		return 0
	}
}

// derive picks the live single-value authority: the configured/
// baseline pubkey if it's still one of the current holders (keeping the
// field stable across no-op reconciles, mirroring EVM's derive()), else the
// lexicographically-first current holder, else "" (never observed / role
// vacated). Unlike EVM's derive(), there is no hex validation — every
// Solana value here is an opaque base58 string.
func derive(configured string, holders []string) string {
	if configured != "" {
		for _, h := range holders {
			if h == configured {
				return configured
			}
		}
	}
	if len(holders) > 0 {
		return holders[0]
	}
	return ""
}

// dedupSorted returns the sorted, deduped, empty-string-dropped contents of
// vs.
func dedupSorted(vs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range vs {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// latestAddressField returns the address in field of the most recent
// (non-reorged) event named name at addr, and ok=false when no such event
// exists (leave the baseline in place). A malformed address in a surviving
// event is a decode/data error worth surfacing.
//
// rwa-supply-controller's AuditorChanged.newAuditor is already 20-byte
// 0x-hex (SupplyController stores auditor_eth for secp256k1 signature
// recovery, not a Pubkey), so this hex validation is correct
// to use for that field.
func latestAddressField(ctx context.Context, chainEvents repository.ChainEventRepository, chainID int64, addr, name, field string) (string, bool, error) {
	ev, err := latestEvent(ctx, chainEvents, chainID, addr, name)
	if err != nil {
		return "", false, err
	}
	if ev == nil {
		return "", false, nil
	}
	v, _ := ev.Data[field].(string)
	if v == "" || !common.IsHexAddress(v) {
		return "", false, fmt.Errorf("project: %s event %s/%d has no valid %s", name, ev.TxHash, ev.LogIndex, field)
	}
	return common.HexToAddress(v).Hex(), true, nil
}

// latestStringField returns the string in field of the most recent
// (non-reorged) event named name at addr — used for the strategy price
// events, whose values are already decimal strings.
func latestStringField(ctx context.Context, chainEvents repository.ChainEventRepository, chainID int64, addr, name, field string) (string, bool, error) {
	ev, err := latestEvent(ctx, chainEvents, chainID, addr, name)
	if err != nil {
		return "", false, err
	}
	if ev == nil {
		return "", false, nil
	}
	v, _ := ev.Data[field].(string)
	if v == "" {
		return "", false, fmt.Errorf("project: %s event %s/%d has no %s", name, ev.TxHash, ev.LogIndex, field)
	}
	return v, true, nil
}

// latestEvent returns the most recent non-reorged event named name at addr, or
// nil when none survives. Ordering is by (block, logIndex) so a same-block
// pair resolves deterministically.
func latestEvent(ctx context.Context, chainEvents repository.ChainEventRepository, chainID int64, addr, name string) (*models.ChainEvent, error) {
	events, err := chainEvents.ListByName(ctx, chainID, addr, name)
	if err != nil {
		return nil, fmt.Errorf("project: list %s for %s: %w", name, addr, err)
	}
	var latest *models.ChainEvent
	for _, e := range events {
		if e.Removed {
			continue
		}
		if latest == nil || earlier(latest, e) {
			latest = e
		}
	}
	return latest, nil
}

// earlier reports whether a precedes b in (block, logIndex, txHash) order.
//
// The TxHash tiebreak matters because BlockNumber is the slot and
// LogIndex resets per transaction, so two events from different
// transactions in the same slot can collide on (slot, logIndex) — without a
// deterministic final tiebreak, both this function's callers (latestEvent's
// first-wins-on-tie loop, and latestRoleHolder's sort.SliceStable)
// could derive a different "latest" event across runs from the same
// persisted events. True intra-slot cross-transaction ordering isn't
// recoverable from getSignaturesForAddress, so this picks a stable,
// documented total order instead.
func earlier(a, b *models.ChainEvent) bool {
	if a.BlockNumber != b.BlockNumber {
		return a.BlockNumber < b.BlockNumber
	}
	if a.LogIndex != b.LogIndex {
		return a.LogIndex < b.LogIndex
	}
	return a.TxHash < b.TxHash
}
