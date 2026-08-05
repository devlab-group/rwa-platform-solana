//! rwa-compliance — wallet allowlist + KYC expiry + project-wide pause.
//!
//! Solana port of `contracts/src/ComplianceRegistry.sol`, plus the token's
//! project-wide pause flag (`ERC20Pausable` on RWAToken). Pause lives here
//! because the Token-2022 **transfer hook** is the single chokepoint that must
//! honour it on every transfer; keeping `paused` next to the allowlist the hook
//! already loads avoids a second cross-program read per transfer. Every other
//! program (supply-controller, vault, redemption) reads this `Registry` to gate
//! on pause and to resolve `is_allowed`.
//!
//! Parity notes:
//! - `is_allowed` / system-address invariant come from the shared, host-tested
//!   `compliance-core` crate (a pinned Vault/Escrow may only ever be `Allowed`
//!   with no expiry).
//! - Roles are single-holder authority pubkeys stored on the `Registry` (this is
//!   a single-tenant deployment), the Solana-idiomatic form of the Solidity
//!   `COMPLIANCE_ROLE` / `PAUSER_ROLE` / `DEFAULT_ADMIN_ROLE`. Admin rotation is a
//!   two-step propose/accept handshake echoing `AccessControlDefaultAdminRules`.

use anchor_lang::prelude::*;
use compliance_core::{is_allowed, validate_status_change, ComplianceStatus};

declare_id!("ECGfTwvG1JaAxJ11ub7HjgTB9KJFH4HSDUJR7reFeVVH");

pub const REGISTRY_SEED: &[u8] = b"registry";
pub const RECORD_SEED: &[u8] = b"record";

/// Seed of the supply-controller config PDA. The supply-controller *program
/// id* is deliberately NOT hard-coded here — a literal would go stale under
/// `anchor keys sync` (which rewrites `declare_id!`s but not a raw const) and could
/// not track a per-deployment program id. Instead the deployer pins the real
/// supply-controller id into the `Registry` at `set_system_addresses`; `finalize`
/// proves that pinned id equals the running supply controller (`crate::ID`); and
/// `set_finalized` derives this PDA from the pinned id to authenticate the finalize
/// CPI signer. A dependency on `rwa_supply_controller` would be a cycle (it depends
/// on this crate), so the id travels as data, not a compiled symbol.
pub const SUPPLY_CONFIG_SEED: &[u8] = b"supply-config";

#[program]
pub mod rwa_compliance {
    use super::*;

    /// Create the singleton `Registry`. `deployer` (signer) becomes the initial
    /// admin able to pin system addresses; roles are set explicitly.
    pub fn initialize(
        ctx: Context<Initialize>,
        admin: Pubkey,
        compliance_authority: Pubkey,
        pauser: Pubkey,
    ) -> Result<()> {
        require_keys_neq!(admin, Pubkey::default(), ComplianceError::ZeroAddress);
        require_keys_neq!(
            compliance_authority,
            Pubkey::default(),
            ComplianceError::ZeroAddress
        );
        require_keys_neq!(pauser, Pubkey::default(), ComplianceError::ZeroAddress);
        let r = &mut ctx.accounts.registry;
        r.admin = admin;
        r.pending_admin = Pubkey::default();
        r.compliance_authority = compliance_authority;
        r.pauser = pauser;
        r.vault = Pubkey::default();
        r.escrow = Pubkey::default();
        r.supply_controller = Pubkey::default();
        r.rwa_mint = Pubkey::default();
        r.system_set = false;
        r.paused = false;
        r.finalized = false;
        r.bump = ctx.bumps.registry;
        Ok(())
    }

    /// Flip the deployment's global `finalized` flag. Every asset-moving
    /// instruction (mint, burn, buy, redemption request/fund/reject/cancel/claim)
    /// reads this registry already and refuses to run until it is set, so nothing
    /// goes live before the cross-program wiring has been verified.
    ///
    /// This may ONLY be reached as a CPI from `rwa-supply-controller::finalize`,
    /// which signs as the supply config PDA (`supply_config`). We re-derive that PDA
    /// from the supply-controller id pinned in the Registry at `set_system_addresses`
    /// and require it to be the signer.
    ///
    /// Two further guards make the flag deployer-bound and un-brickable:
    /// - The `SetFinalized` context requires this compliance program's own upgrade
    ///   authority to equal the registry admin signer, so — regardless of what
    ///   supply-controller id was pinned — a registry admin who is *not* the deployer
    ///   cannot forge go-live by pinning a look-alike controller. That closes the
    ///   role-boundary gap when admin and deployer are separated.
    /// - The transition is idempotent: an already-set flag returns `Ok` rather than
    ///   erroring, so a stray pre-set can never brick the real `finalize` (which
    ///   keeps its own one-shot `Config.finalized` guard).
    pub fn set_finalized(ctx: Context<SetFinalized>) -> Result<()> {
        let (expected, _) = Pubkey::find_program_address(
            &[SUPPLY_CONFIG_SEED],
            &ctx.accounts.registry.supply_controller,
        );
        require_keys_eq!(
            ctx.accounts.supply_config.key(),
            expected,
            ComplianceError::NotSupplyController
        );
        let r = &mut ctx.accounts.registry;
        require!(r.system_set, ComplianceError::SystemAddressesNotSet);
        // Idempotent — never a hard error that could brick `finalize`.
        if r.finalized {
            return Ok(());
        }
        r.finalized = true;
        emit!(Finalized {
            by: ctx.accounts.admin.key()
        });
        Ok(())
    }

    /// Pin the Vault + RedemptionEscrow *authority* pubkeys, the supply-controller
    /// program id, and the RWA mint, **atomically**
    /// creating and permanently allowlisting both records (`Allowed`,
    /// `valid_until = 0`) in the same transaction. This closes the window where a
    /// pinned system address could already be Unknown/Blocked or expiring. After
    /// `set_status` can never give either a non-Allowed status or an expiry, and the
    /// transfer hook uses `escrow` for its pause bypass.
    ///
    /// Gated on `!finalized`, not `!system_set`, so a bootstrap typo in any of
    /// these permanent pins is correctable by re-running this instruction any time
    /// before go-live. `finalize` freezes everything, which is the property that
    /// actually matters. The supply-controller is taken as an *executable* account,
    /// so a non-program value cannot be pinned.
    pub fn set_system_addresses(ctx: Context<SetSystemAddresses>) -> Result<()> {
        let vault = ctx.accounts.vault.key();
        let escrow = ctx.accounts.escrow.key();
        let supply_controller = ctx.accounts.supply_controller_program.key();
        let rwa_mint = ctx.accounts.rwa_mint.key();
        let authority = ctx.accounts.admin.key();
        require!(
            !ctx.accounts.registry.finalized,
            ComplianceError::AlreadyFinalized
        );
        require_keys_neq!(vault, Pubkey::default(), ComplianceError::ZeroAddress);
        require_keys_neq!(escrow, Pubkey::default(), ComplianceError::ZeroAddress);
        require_keys_neq!(vault, escrow, ComplianceError::VaultEscrowMustDiffer);

        // Capture the pins being superseded *before* the registry is overwritten,
        // so a corrective re-run can atomically clear any old system address that
        // is no longer pinned (below).
        let old_vault = ctx.accounts.registry.vault;
        let old_escrow = ctx.accounts.registry.escrow;

        let allowed = ComplianceStatus::Allowed as u8;
        // Emit the record's REAL prior status/expiry, not an unconditional 0.
        // (`init_if_needed` zeroes a fresh record, so a first pin still reports 0/0;
        // a corrective re-pin of the same address reports what was actually there.)
        let vr = &mut ctx.accounts.vault_record;
        let prev_vault_status = vr.status;
        let prev_vault_valid = vr.valid_until;
        vr.wallet = vault;
        vr.status = allowed;
        vr.valid_until = 0;
        vr.bump = ctx.bumps.vault_record;
        let er = &mut ctx.accounts.escrow_record;
        let prev_escrow_status = er.status;
        let prev_escrow_valid = er.valid_until;
        er.wallet = escrow;
        er.status = allowed;
        er.valid_until = 0;
        er.bump = ctx.bumps.escrow_record;

        let r = &mut ctx.accounts.registry;
        r.system_set = true;
        r.vault = vault;
        r.escrow = escrow;
        r.supply_controller = supply_controller;
        r.rwa_mint = rwa_mint;

        emit!(StatusChanged {
            account: vault,
            previous_status: prev_vault_status,
            new_status: allowed,
            previous_valid_until: prev_vault_valid,
            new_valid_until: 0,
            authority,
        });
        emit!(StatusChanged {
            account: escrow,
            previous_status: prev_escrow_status,
            new_status: allowed,
            previous_valid_until: prev_escrow_valid,
            new_valid_until: 0,
            authority,
        });

        // On a corrective call, restore any superseded system address to
        // `Unknown` so a mistaken pin does not leave a wallet permanently
        // allowlisted after finalization. An old pin still present among the new
        // pins is left untouched. The caller MUST pass the superseded record when a
        // pin actually changes (enforced below); this instruction is deployer-only
        // and pre-finalize, so the added account is a bootstrap-time requirement,
        // not an operational burden.
        clear_superseded(
            &mut ctx.accounts.prev_vault_record,
            old_vault,
            vault,
            escrow,
            authority,
        )?;
        clear_superseded(
            &mut ctx.accounts.prev_escrow_record,
            old_escrow,
            vault,
            escrow,
            authority,
        )?;
        Ok(())
    }

    /// Set (or create) a wallet's compliance record. Gated to the compliance
    /// authority. `status`: 1=Allowed, 2=Blocked (0=Unknown clears to disallowed).
    pub fn set_status(ctx: Context<SetStatus>, status: u8, valid_until: u64) -> Result<()> {
        let r = &ctx.accounts.registry;
        require_keys_eq!(
            ctx.accounts.authority.key(),
            r.compliance_authority,
            ComplianceError::NotComplianceAuthority
        );
        let parsed = ComplianceStatus::from_u8(status).ok_or(ComplianceError::InvalidStatus)?;

        let wallet = ctx.accounts.wallet.key();
        let is_system = r.system_set && (wallet == r.vault || wallet == r.escrow);
        validate_status_change(is_system, parsed, valid_until)
            .map_err(|_| ComplianceError::SystemAddressCannotBeBlocked)?;

        let rec = &mut ctx.accounts.record;
        let prev_status = rec.status;
        let prev_valid = rec.valid_until;
        rec.wallet = wallet;
        rec.status = status;
        rec.valid_until = valid_until;
        rec.bump = ctx.bumps.record;

        emit!(StatusChanged {
            account: wallet,
            previous_status: prev_status,
            new_status: status,
            previous_valid_until: prev_valid,
            new_valid_until: valid_until,
            authority: ctx.accounts.authority.key(),
        });
        Ok(())
    }

    /// Project-wide emergency pause. Gated to the pauser.
    pub fn pause(ctx: Context<PauserOnly>) -> Result<()> {
        ctx.accounts.registry.paused = true;
        emit!(PauseSet {
            paused: true,
            by: ctx.accounts.pauser.key()
        });
        Ok(())
    }

    pub fn unpause(ctx: Context<PauserOnly>) -> Result<()> {
        ctx.accounts.registry.paused = false;
        emit!(PauseSet {
            paused: false,
            by: ctx.accounts.pauser.key()
        });
        Ok(())
    }

    pub fn set_compliance_authority(ctx: Context<AdminOnly>, new_authority: Pubkey) -> Result<()> {
        require_keys_neq!(
            new_authority,
            Pubkey::default(),
            ComplianceError::ZeroAddress
        );
        // Emit the role change so the indexer can source governance state
        // from events (parity with the EVM deployment), not only by polling.
        let previous = ctx.accounts.registry.compliance_authority;
        ctx.accounts.registry.compliance_authority = new_authority;
        emit!(RoleChanged {
            role: Role::ComplianceAuthority as u8,
            previous,
            new_value: new_authority,
            by: ctx.accounts.admin.key(),
        });
        Ok(())
    }

    pub fn set_pauser(ctx: Context<AdminOnly>, new_pauser: Pubkey) -> Result<()> {
        require_keys_neq!(new_pauser, Pubkey::default(), ComplianceError::ZeroAddress);
        let previous = ctx.accounts.registry.pauser;
        ctx.accounts.registry.pauser = new_pauser;
        emit!(RoleChanged {
            role: Role::Pauser as u8,
            previous,
            new_value: new_pauser,
            by: ctx.accounts.admin.key(),
        });
        Ok(())
    }

    /// Two-step admin rotation (propose) — mirrors AccessControlDefaultAdminRules.
    /// Rejects a zero pending admin (an unacceptable, unwithdrawable proposal on an
    /// otherwise-reversible handshake) and emits the proposal.
    pub fn propose_admin(ctx: Context<AdminOnly>, new_admin: Pubkey) -> Result<()> {
        require_keys_neq!(new_admin, Pubkey::default(), ComplianceError::ZeroAddress);
        ctx.accounts.registry.pending_admin = new_admin;
        emit!(AdminProposed {
            new_admin,
            by: ctx.accounts.admin.key(),
        });
        Ok(())
    }

    /// Two-step admin rotation (accept) — the pending admin claims the role.
    pub fn accept_admin(ctx: Context<AcceptAdmin>) -> Result<()> {
        let r = &mut ctx.accounts.registry;
        require_keys_neq!(
            r.pending_admin,
            Pubkey::default(),
            ComplianceError::NoPendingAdmin
        );
        require_keys_eq!(
            ctx.accounts.new_admin.key(),
            r.pending_admin,
            ComplianceError::NotPendingAdmin
        );
        let previous = r.admin;
        r.admin = r.pending_admin;
        r.pending_admin = Pubkey::default();
        emit!(AdminChanged {
            previous,
            new_admin: r.admin,
        });
        Ok(())
    }

    /// Withdraw a pending admin transfer (current admin only), so a fat-fingered
    /// `propose_admin` is recoverable state.
    pub fn cancel_admin_transfer(ctx: Context<AdminOnly>) -> Result<()> {
        let cancelled = ctx.accounts.registry.pending_admin;
        ctx.accounts.registry.pending_admin = Pubkey::default();
        emit!(AdminTransferCancelled {
            cancelled,
            by: ctx.accounts.admin.key(),
        });
        Ok(())
    }
}

/// Public helper so sibling programs can read a record account and evaluate the
/// exact same allowlist rule the hook uses.
pub fn record_is_allowed(rec: &ComplianceRecord, now: u64) -> bool {
    ComplianceStatus::from_u8(rec.status)
        .map(|s| is_allowed(s, rec.valid_until, now))
        .unwrap_or(false)
}

/// Reset a superseded system-address record to `Unknown`.
/// A no-op when `old` is unset (first pin) or is still a system address under the
/// new pins. Otherwise the caller MUST supply the old address's record (its
/// canonical PDA, enforced by the account `seeds`) so this can clear it and emit
/// the real previous values; omitting it is an error, so a corrected bootstrap
/// cannot silently leave the old wallet allowlisted.
fn clear_superseded(
    rec: &mut Option<Account<ComplianceRecord>>,
    old: Pubkey,
    new_vault: Pubkey,
    new_escrow: Pubkey,
    authority: Pubkey,
) -> Result<()> {
    if old == Pubkey::default() || old == new_vault || old == new_escrow {
        return Ok(());
    }
    let r = rec.as_mut().ok_or(ComplianceError::MissingPrevRecord)?;
    require_keys_eq!(r.wallet, old, ComplianceError::WrongPrevRecord);
    let prev_status = r.status;
    let prev_valid = r.valid_until;
    r.status = ComplianceStatus::Unknown as u8;
    r.valid_until = 0;
    emit!(StatusChanged {
        account: old,
        previous_status: prev_status,
        new_status: ComplianceStatus::Unknown as u8,
        previous_valid_until: prev_valid,
        new_valid_until: 0,
        authority,
    });
    Ok(())
}

#[account]
pub struct Registry {
    pub admin: Pubkey,
    pub pending_admin: Pubkey,
    pub compliance_authority: Pubkey,
    pub pauser: Pubkey,
    pub vault: Pubkey,
    pub escrow: Pubkey,
    /// Supply-controller program id, pinned at `set_system_addresses`; the
    /// authority behind the `finalize` CPI that flips `finalized`.
    pub supply_controller: Pubkey,
    /// The RWA mint, pinned at `set_system_addresses`. The transfer hook —
    /// the single compliance chokepoint — asserts the mint it is invoked for equals
    /// this, so the guarantee no longer depends only on the handler being
    /// side-effect-free for a foreign mint that points its hook extension here.
    pub rwa_mint: Pubkey,
    pub system_set: bool,
    pub paused: bool,
    /// Global go-live flag; set once cross-program wiring is verified.
    pub finalized: bool,
    pub bump: u8,
}

impl Registry {
    pub const SPACE: usize = 8 + 32 * 8 + 1 + 1 + 1 + 1;
}

#[account]
pub struct ComplianceRecord {
    pub wallet: Pubkey,
    /// 0=Unknown, 1=Allowed, 2=Blocked.
    pub status: u8,
    /// Unix seconds; 0 = no expiry.
    pub valid_until: u64,
    pub bump: u8,
}

impl ComplianceRecord {
    pub const SPACE: usize = 8 + 32 + 1 + 8 + 1;
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = payer,
        space = Registry::SPACE,
        seeds = [REGISTRY_SEED],
        bump
    )]
    pub registry: Account<'info, Registry>,
    #[account(mut)]
    pub payer: Signer<'info>,
    // Upgrade-authority gate: only the program's deployer may initialize
    // the singleton, so an observer can't win the race and take over the config.
    #[account(constraint = program.programdata_address()? == Some(program_data.key()) @ ComplianceError::NotUpgradeAuthority)]
    pub program: Program<'info, crate::program::RwaCompliance>,
    #[account(constraint = program_data.upgrade_authority_address == Some(payer.key()) @ ComplianceError::NotUpgradeAuthority)]
    pub program_data: Account<'info, ProgramData>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AdminOnly<'info> {
    #[account(
        mut,
        seeds = [REGISTRY_SEED],
        bump = registry.bump,
        has_one = admin @ ComplianceError::NotAdmin
    )]
    pub registry: Account<'info, Registry>,
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct SetSystemAddresses<'info> {
    #[account(
        mut,
        seeds = [REGISTRY_SEED],
        bump = registry.bump,
        has_one = admin @ ComplianceError::NotAdmin
    )]
    pub registry: Account<'info, Registry>,
    pub admin: Signer<'info>,
    /// CHECK: only used as the seed / stored key of the vault record.
    pub vault: UncheckedAccount<'info>,
    /// CHECK: only used as the seed / stored key of the escrow record.
    pub escrow: UncheckedAccount<'info>,
    /// The supply-controller program, pinned by id. Required executable so a
    /// non-program value (a typo) can never be stored as the controller.
    /// CHECK: only its key is stored; the executable flag is asserted here.
    #[account(constraint = supply_controller_program.executable @ ComplianceError::NotExecutable)]
    pub supply_controller_program: UncheckedAccount<'info>,
    /// The RWA mint, pinned by id for the transfer hook's mint check.
    /// CHECK: only its key is stored.
    pub rwa_mint: UncheckedAccount<'info>,
    #[account(
        init_if_needed,
        payer = payer,
        space = ComplianceRecord::SPACE,
        seeds = [RECORD_SEED, vault.key().as_ref()],
        bump
    )]
    pub vault_record: Account<'info, ComplianceRecord>,
    #[account(
        init_if_needed,
        payer = payer,
        space = ComplianceRecord::SPACE,
        seeds = [RECORD_SEED, escrow.key().as_ref()],
        bump
    )]
    pub escrow_record: Account<'info, ComplianceRecord>,
    /// The record of the vault pin being superseded, so a corrective call can
    /// atomically clear it. Seeded from the registry's CURRENT
    /// `vault` (the old pin, read before overwrite), so the caller cannot pass a
    /// look-alike. Optional: pass `None` on the first call, or when the vault pin is
    /// unchanged (`clear_superseded` requires it only when the pin actually moves to
    /// a non-system address).
    #[account(
        mut,
        seeds = [RECORD_SEED, registry.vault.as_ref()],
        bump
    )]
    pub prev_vault_record: Option<Account<'info, ComplianceRecord>>,
    /// The record of the escrow pin being superseded (see above).
    #[account(
        mut,
        seeds = [RECORD_SEED, registry.escrow.as_ref()],
        bump
    )]
    pub prev_escrow_record: Option<Account<'info, ComplianceRecord>>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AcceptAdmin<'info> {
    #[account(mut, seeds = [REGISTRY_SEED], bump = registry.bump)]
    pub registry: Account<'info, Registry>,
    pub new_admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct SetFinalized<'info> {
    #[account(
        mut,
        seeds = [REGISTRY_SEED],
        bump = registry.bump,
        has_one = admin @ ComplianceError::NotAdmin
    )]
    pub registry: Account<'info, Registry>,
    pub admin: Signer<'info>,
    /// The supply-controller config PDA, signing via `finalize`'s CPI seeds.
    /// Verified in-handler against the canonical PDA of the pinned supply-controller
    /// id, so this instruction is reachable only through `finalize`.
    pub supply_config: Signer<'info>,
    // Bind go-live to the deployer. This compliance program's upgrade authority
    // must be the registry admin signing here, so a registry admin who is not the
    // deployer cannot flip the flag by pinning a look-alike supply controller.
    #[account(constraint = program.programdata_address()? == Some(program_data.key()) @ ComplianceError::NotUpgradeAuthority)]
    pub program: Program<'info, crate::program::RwaCompliance>,
    #[account(constraint = program_data.upgrade_authority_address == Some(admin.key()) @ ComplianceError::NotUpgradeAuthority)]
    pub program_data: Account<'info, ProgramData>,
}

#[derive(Accounts)]
pub struct PauserOnly<'info> {
    #[account(
        mut,
        seeds = [REGISTRY_SEED],
        bump = registry.bump,
        has_one = pauser @ ComplianceError::NotPauser
    )]
    pub registry: Account<'info, Registry>,
    pub pauser: Signer<'info>,
}

#[derive(Accounts)]
pub struct SetStatus<'info> {
    #[account(seeds = [REGISTRY_SEED], bump = registry.bump)]
    pub registry: Account<'info, Registry>,
    pub authority: Signer<'info>,
    /// CHECK: only used as the seed / stored key of the record; never read or written.
    pub wallet: UncheckedAccount<'info>,
    #[account(
        init_if_needed,
        payer = payer,
        space = ComplianceRecord::SPACE,
        seeds = [RECORD_SEED, wallet.key().as_ref()],
        bump
    )]
    pub record: Account<'info, ComplianceRecord>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[event]
pub struct StatusChanged {
    pub account: Pubkey,
    pub previous_status: u8,
    pub new_status: u8,
    pub previous_valid_until: u64,
    pub new_valid_until: u64,
    pub authority: Pubkey,
}

#[event]
pub struct PauseSet {
    pub paused: bool,
    pub by: Pubkey,
}

#[event]
pub struct Finalized {
    pub by: Pubkey,
}

/// Role label for `RoleChanged`, so an indexer can distinguish which
/// single-holder authority moved without a per-role event type.
#[repr(u8)]
pub enum Role {
    ComplianceAuthority = 1,
    Pauser = 2,
}

#[event]
pub struct RoleChanged {
    pub role: u8,
    pub previous: Pubkey,
    pub new_value: Pubkey,
    pub by: Pubkey,
}

#[event]
pub struct AdminProposed {
    pub new_admin: Pubkey,
    pub by: Pubkey,
}

#[event]
pub struct AdminChanged {
    pub previous: Pubkey,
    pub new_admin: Pubkey,
}

#[event]
pub struct AdminTransferCancelled {
    pub cancelled: Pubkey,
    pub by: Pubkey,
}

#[error_code]
pub enum ComplianceError {
    #[msg("zero address")]
    ZeroAddress,
    #[msg("caller is not the admin")]
    NotAdmin,
    #[msg("caller is not the pending admin")]
    NotPendingAdmin,
    #[msg("no pending admin transfer to accept")]
    NoPendingAdmin,
    #[msg("caller is not the compliance authority")]
    NotComplianceAuthority,
    #[msg("set_finalized is only reachable via the supply-controller finalize CPI")]
    NotSupplyController,
    #[msg("caller is not the pauser")]
    NotPauser,
    #[msg("system addresses already set")]
    SystemAddressesAlreadySet,
    #[msg("a system address must stay permanently Allowed")]
    SystemAddressCannotBeBlocked,
    #[msg("invalid compliance status")]
    InvalidStatus,
    #[msg("caller is not the program upgrade authority")]
    NotUpgradeAuthority,
    #[msg("vault and escrow must be different addresses")]
    VaultEscrowMustDiffer,
    #[msg("system addresses must be pinned before finalizing")]
    SystemAddressesNotSet,
    #[msg("deployment is already finalized")]
    AlreadyFinalized,
    #[msg("pinned supply-controller account must be an executable program")]
    NotExecutable,
    #[msg("superseded system-address record must be supplied to correct a pin")]
    MissingPrevRecord,
    #[msg("supplied previous record does not match the superseded system address")]
    WrongPrevRecord,
}
