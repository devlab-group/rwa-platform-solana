package blockchain

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
)

// Baseline is the deployment's governance state as it exists in the programs'
// own config accounts, independent of any event.
//
// It exists because NONE of the five programs' `initialize` instructions emit
// an event (verified against solana/programs/*/src/lib.rs): the initial
// auditor, treasury, treasurer, redemption manager, pricer, compliance
// authority, pauser, pause flag, and both prices are written straight into the
// config PDAs and announced to nobody. project.ReconcileSecurity is otherwise
// a pure fold over chain_events, so on a freshly bootstrapped deployment —
// one that has never rotated a role or changed a price — that fold has
// literally nothing to read and every field projects empty. Re-indexing cannot
// help: the events are not merely unread, they were never emitted.
//
// So the account state IS the baseline, and events layer on top of it exactly
// as they already do for Admin (see project.foldSecurity's baselineAdmin).
// Every string here is produced by the same borshReader the event decoder uses,
// so a baseline value and the event value that later supersedes it are
// formatted identically (base58 pubkeys, 0x-hex eth addresses, decimal-string
// u64s) and compare equal when they represent the same thing.
//
// Fields are best-effort and independently optional: a deployment mid-bootstrap
// may legitimately have some accounts initialized and others not, so a zero
// value means "not readable yet", never "set to empty".
type Baseline struct {
	// From the rwa-supply-controller Config account.
	Auditor string // 0x-hex 20-byte eth address (secp256k1 attestation signer)

	// From the rwa-vault Config account.
	Treasury  string
	Treasurer string

	// From the rwa-pricing Strategy account.
	Pricer                       string
	PurchasePricePerWholeToken   string // decimal string, quote base units
	RedemptionPricePerWholeToken string

	// From the rwa-compliance Registry account.
	ComplianceOperator string // the registry's compliance_authority
	Pauser             string
	Paused             bool
	Finalized          bool

	// From the rwa-redemption Config account.
	RedemptionManager string
}

// accountDiscriminator is Anchor's account discriminator: the first 8 bytes of
// sha256("account:<TypeName>"). Note that the vault, redemption, and
// supply-controller accounts are ALL named `Config`, so they share a
// discriminator — it proves the account's declared type, never which program
// it belongs to. The owner check is what does that, and it runs first.
func accountDiscriminator(typeName string) [8]byte {
	sum := sha256.Sum256([]byte("account:" + typeName))
	var d [8]byte
	copy(d[:], sum[:8])
	return d
}

// errAccountAbsent marks "this account does not exist yet", which on a
// deployment that has not finished bootstrapping is an ordinary state rather
// than a failure. ReadBaseline turns it into "leave those fields unset".
var errAccountAbsent = errors.New("blockchain: account does not exist yet")

// zeroPubkey is base58(32 zero bytes) — what an unset Anchor `Pubkey` field
// decodes to. It is ALSO the System Program's id, so a zero field naively fed
// back into getAccountInfo returns a real, existing account owned by
// NativeLoader: without this check an escrow that set_system_addresses has not
// pinned yet would be reported as an owner mismatch (a loud, alarming, wrong
// error) instead of the ordinary "not wired yet" it actually is.
const zeroPubkey = "11111111111111111111111111111111"

// readAnchorAccount fetches an Anchor account and returns a borshReader
// positioned just past the 8-byte discriminator, after proving the account is
// owned by ownerProgram and carries typeName's discriminator.
//
// Both checks are mandatory and ordered owner-first: an account that merely
// decodes plausibly at the right offsets can otherwise feed attacker- or
// accident-chosen role holders straight into the security projection the admin
// console displays.
func readAnchorAccount(ctx context.Context, client *RPCClient, address, ownerProgram, typeName, commitment string) (*borshReader, error) {
	if address == "" || address == zeroPubkey || ownerProgram == "" {
		return nil, errAccountAbsent
	}
	info, err := client.GetAccountInfo(ctx, address, commitment)
	if err != nil {
		return nil, fmt.Errorf("blockchain: reading %s account %s: %w", typeName, address, err)
	}
	if info == nil {
		return nil, errAccountAbsent
	}
	if info.Owner != ownerProgram {
		return nil, fmt.Errorf("blockchain: %s account %s is owned by %q, want %q", typeName, address, info.Owner, ownerProgram)
	}
	if len(info.Data) < 8 {
		return nil, fmt.Errorf("blockchain: %s account %s is %d bytes, too short to hold a discriminator", typeName, address, len(info.Data))
	}
	want := accountDiscriminator(typeName)
	if [8]byte(info.Data[:8]) != want {
		return nil, fmt.Errorf("blockchain: %s account %s has discriminator %x, want %x", typeName, address, info.Data[:8], want)
	}
	return newBorshReader(info.Data[8:]), nil
}

// BaselinePrograms is the set of program ids and config-account addresses
// ReadBaseline needs from configuration. Only SupplyConfig and VaultConfig are
// operator-supplied addresses (contract.supply_config / contract.vault_config);
// the remaining three config accounts are discovered from on-chain fields
// rather than derived, because deriving a PDA in Go is explicitly out of bounds
// here (see the contract: block's note in server/README.md).
type BaselinePrograms struct {
	SupplyController string
	SupplyConfig     string
	Vault            string
	VaultConfig      string
	Pricing          string
	Compliance       string
	Redemption       string
}

// ReadBaseline reads every program's config account and returns the governance
// state recorded in them.
//
// Address discovery deliberately walks the on-chain graph instead of deriving
// PDAs: contract.supply_config and contract.vault_config come from config, the
// vault Config names the pricing Strategy and compliance Registry it was wired
// to, and the Registry names the redemption escrow pinned by
// set_system_addresses. Every hop is therefore a value the bootstrap already
// committed on-chain and that verifyVaultConfigOnChain has cross-checked the
// root of.
//
// Best-effort by construction: an unreadable account leaves its fields unset
// and does NOT fail the others, because a deployment can legitimately be
// partway through bootstrap (and because this runs on a repeating reconcile
// tick, not once at boot — the accounts routinely do not exist on the first
// few passes of the server-before-bootstrap flow). Errors are returned joined
// for logging, never to gate the fields that did decode.
func ReadBaseline(ctx context.Context, client *RPCClient, p BaselinePrograms, commitment string) (Baseline, error) {
	var b Baseline
	var problems []error

	// note records a real failure but ignores "not initialized yet", which is
	// an expected state, not a problem worth surfacing.
	note := func(err error) {
		if err != nil && !errors.Is(err, errAccountAbsent) {
			problems = append(problems, err)
		}
	}

	// --- supply-controller Config: the auditor ------------------------------
	// Layout: admin, pending_admin, auditor_eth[20], token_mint, vault,
	// registry, profile_digest[32], cluster[32], finalized, bump.
	if r, err := readAnchorAccount(ctx, client, p.SupplyConfig, p.SupplyController, "Config", commitment); err != nil {
		note(err)
	} else {
		note(readFields(r,
			skipPubkey, // admin
			skipPubkey, // pending_admin
			hexField(20, &b.Auditor),
		))
	}

	// --- vault Config: treasury/treasurer, and the strategy + registry ------
	// Layout: admin, pending_admin, treasurer, treasury, supply_controller,
	// rwa_mint, quote_mint, quote_decimals, strategy, registry, bump.
	var strategyAddr, registryAddr string
	if r, err := readAnchorAccount(ctx, client, p.VaultConfig, p.Vault, "Config", commitment); err != nil {
		note(err)
	} else {
		note(readFields(r,
			skipPubkey, // admin
			skipPubkey, // pending_admin
			pubkeyField(&b.Treasurer),
			pubkeyField(&b.Treasury),
			skipPubkey, // supply_controller
			skipPubkey, // rwa_mint
			skipPubkey, // quote_mint
			skipU8,     // quote_decimals
			pubkeyField(&strategyAddr),
			pubkeyField(&registryAddr),
		))
	}

	// --- pricing Strategy: pricer + both prices -----------------------------
	// Layout: admin, pending_admin, pricer, token_decimals, purchase_price,
	// redemption_price, bump.
	if r, err := readAnchorAccount(ctx, client, strategyAddr, p.Pricing, "Strategy", commitment); err != nil {
		note(err)
	} else {
		note(readFields(r,
			skipPubkey, // admin
			skipPubkey, // pending_admin
			pubkeyField(&b.Pricer),
			skipU8, // token_decimals
			u64Field(&b.PurchasePricePerWholeToken),
			u64Field(&b.RedemptionPricePerWholeToken),
		))
	}

	// --- compliance Registry: authority, pauser, paused, and the escrow -----
	// Layout: admin, pending_admin, compliance_authority, pauser, vault,
	// escrow, supply_controller, rwa_mint, system_set, paused, finalized, bump.
	var escrowAddr string
	if r, err := readAnchorAccount(ctx, client, registryAddr, p.Compliance, "Registry", commitment); err != nil {
		note(err)
	} else {
		note(readFields(r,
			skipPubkey, // admin
			skipPubkey, // pending_admin
			pubkeyField(&b.ComplianceOperator),
			pubkeyField(&b.Pauser),
			skipPubkey, // vault
			pubkeyField(&escrowAddr),
			skipPubkey, // supply_controller
			skipPubkey, // rwa_mint
			skipBool,   // system_set
			boolField(&b.Paused),
			boolField(&b.Finalized),
		))
	}

	// --- redemption Config: the redemption manager --------------------------
	// Layout: admin, pending_admin, treasurer, redemption_manager, vault, ...
	// The address is the Registry's `escrow`, pinned by set_system_addresses;
	// it is the zero pubkey until that has run, which readAnchorAccount treats
	// as an ordinary absent account.
	if r, err := readAnchorAccount(ctx, client, escrowAddr, p.Redemption, "Config", commitment); err != nil {
		note(err)
	} else {
		note(readFields(r,
			skipPubkey, // admin
			skipPubkey, // pending_admin
			skipPubkey, // treasurer (the vault's is authoritative; they are wired equal at bootstrap)
			pubkeyField(&b.RedemptionManager),
		))
	}

	return b, errors.Join(problems...)
}

// --- tiny field-reader combinators -----------------------------------------
//
// These exist so each account's layout above reads as a literal transcription
// of its Rust struct's field order, including the fields that are skipped.
// Spelling out the skips is the point: Borsh has no field names on the wire, so
// an omitted field silently shifts every subsequent read onto the wrong bytes,
// and a list that visibly matches the declaration is the only cheap defence.

type fieldReader func(*borshReader) error

func readFields(r *borshReader, fields ...fieldReader) error {
	for i, f := range fields {
		if err := f(r); err != nil {
			return fmt.Errorf("field %d: %w", i, err)
		}
	}
	return nil
}

func skipPubkey(r *borshReader) error { _, err := r.pubkey(); return err }
func skipU8(r *borshReader) error     { _, err := r.u8(); return err }
func skipBool(r *borshReader) error   { _, err := r.boolean(); return err }

func pubkeyField(dst *string) fieldReader {
	return func(r *borshReader) error {
		v, err := r.pubkey()
		if err != nil {
			return err
		}
		*dst = v
		return nil
	}
}

func hexField(n int, dst *string) fieldReader {
	return func(r *borshReader) error {
		v, err := r.hexBytes(n)
		if err != nil {
			return err
		}
		*dst = v
		return nil
	}
}

func u64Field(dst *string) fieldReader {
	return func(r *borshReader) error {
		v, err := r.u64String()
		if err != nil {
			return err
		}
		*dst = v
		return nil
	}
}

func boolField(dst *bool) fieldReader {
	return func(r *borshReader) error {
		v, err := r.boolean()
		if err != nil {
			return err
		}
		*dst = v
		return nil
	}
}
