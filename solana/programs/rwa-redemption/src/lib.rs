//! rwa-redemption — cash redemption state machine: request → fund → claim.
//!
//! Solana port of `contracts/src/RedemptionEscrow.sol` /
//! `docs/spec/redemption-state-machine.md`. The Config PDA is the **escrow
//! authority** that owns the escrowed RWA and quote token accounts, and is the
//! `escrow` pinned as a compliance system address. Transition guards come from
//! the shared, host-tested `redemption-core` crate; the asset legs and the
//! spec's compliance re-checks are applied here at the required points.
//!
//! Pause parity (the load-bearing asymmetry): `claim` keeps its `!paused` guard;
//! `cancel` deliberately omits one, and its RWA-return leg still succeeds while
//! paused because the transfer hook grants the escrow authority the
//! `returnEscrowedRWA` carve-out (source == pinned escrow → allowed during pause,
//! recipient still checked). `claim` never re-checks the beneficiary's compliance.

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{
    transfer_checked, Mint, TokenAccount, TokenInterface, TransferChecked,
};
use redemption_core::{can_cancel, ensure_funded, ensure_pending, RedemptionStatus};
use rwa_compliance::{record_is_allowed, ComplianceRecord, Registry, RECORD_SEED};
use rwa_pricing::Strategy;
use rwa_transfer_hook::invoke_transfer_checked;
use rwa_transfer_hook::{validate_quote_mint, validate_rwa_mint};

declare_id!("32J24AMuuocveSVofvbqWS4HrspAKqsNp7xnrtWw1uFY");

pub const CONFIG_SEED: &[u8] = b"redemption-config";
pub const REQUEST_SEED: &[u8] = b"request";

/// Redemption-timeout bounds, mirroring `RWAFactory`'s
/// `MIN_REDEMPTION_TIMEOUT = 1 days` / `MAX_REDEMPTION_TIMEOUT = 365 days`.
pub const MIN_REDEMPTION_TIMEOUT: u64 = 86_400;
pub const MAX_REDEMPTION_TIMEOUT: u64 = 31_536_000;

#[program]
pub mod rwa_redemption {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    pub fn initialize(
        ctx: Context<Initialize>,
        admin: Pubkey,
        treasurer: Pubkey,
        redemption_manager: Pubkey,
        vault_authority: Pubkey,
        redemption_timeout: u64,
        quote_decimals: u8,
    ) -> Result<()> {
        for k in [admin, treasurer, redemption_manager, vault_authority] {
            require_keys_neq!(k, Pubkey::default(), RedemptionError::ZeroAddress);
        }
        // The RWA mint must be a Token-2022 mint using our compliance hook.
        validate_rwa_mint(&ctx.accounts.rwa_mint.to_account_info(), None, false, None)
            .map_err(|_| error!(RedemptionError::UnsafeMint))?;
        // The quote mint must be the legacy SPL Token or Token-2022 program
        // and carry no seize/fee/hook/amount-changing extension.
        validate_quote_mint(&ctx.accounts.quote_mint.to_account_info())
            .map_err(|_| error!(RedemptionError::UnsafeQuoteMint))?;
        // The RWA and quote mints must be distinct.
        require_keys_neq!(
            ctx.accounts.rwa_mint.key(),
            ctx.accounts.quote_mint.key(),
            RedemptionError::MintQuoteSame
        );
        // Pricing decimals must match the RWA mint.
        require!(
            ctx.accounts.strategy.token_decimals == ctx.accounts.rwa_mint.decimals,
            RedemptionError::DecimalsMismatch
        );
        // Bound the redemption timeout to [1 day, 365 days], matching
        // `RWAFactory`'s MIN/MAX_REDEMPTION_TIMEOUT. Like the EVM `immutable`,
        // there is no setter — the value is fixed for the life of the deployment, so
        // a rotation can never retroactively extend a live escrow's cancel deadline.
        require!(
            (MIN_REDEMPTION_TIMEOUT..=MAX_REDEMPTION_TIMEOUT).contains(&redemption_timeout),
            RedemptionError::InvalidTimeout
        );
        // Bind the quote mint's decimals to the price scale (see the vault).
        require!(
            ctx.accounts.quote_mint.decimals == quote_decimals,
            RedemptionError::QuoteDecimalsMismatch
        );
        let c = &mut ctx.accounts.config;
        c.admin = admin;
        c.pending_admin = Pubkey::default();
        c.treasurer = treasurer;
        c.redemption_manager = redemption_manager;
        c.vault = vault_authority;
        c.rwa_mint = ctx.accounts.rwa_mint.key();
        c.quote_mint = ctx.accounts.quote_mint.key();
        c.quote_decimals = quote_decimals;
        c.strategy = ctx.accounts.strategy.key();
        c.registry = ctx.accounts.registry.key();
        c.redemption_timeout = redemption_timeout;
        c.next_id = 0;
        c.bump = ctx.bumps.config;
        Ok(())
    }

    /// Rotate the treasurer.
    pub fn set_treasurer(ctx: Context<AdminOnly>, new_treasurer: Pubkey) -> Result<()> {
        require_keys_neq!(
            new_treasurer,
            Pubkey::default(),
            RedemptionError::ZeroAddress
        );
        let previous = ctx.accounts.config.treasurer;
        ctx.accounts.config.treasurer = new_treasurer;
        emit!(RoleChanged {
            role: Role::Treasurer as u8,
            previous,
            new_value: new_treasurer,
            by: ctx.accounts.admin.key(),
        });
        Ok(())
    }

    /// Rotate the redemption manager.
    pub fn set_redemption_manager(ctx: Context<AdminOnly>, new_manager: Pubkey) -> Result<()> {
        require_keys_neq!(new_manager, Pubkey::default(), RedemptionError::ZeroAddress);
        let previous = ctx.accounts.config.redemption_manager;
        ctx.accounts.config.redemption_manager = new_manager;
        emit!(RoleChanged {
            role: Role::RedemptionManager as u8,
            previous,
            new_value: new_manager,
            by: ctx.accounts.admin.key(),
        });
        Ok(())
    }

    /// Two-step admin rotation (propose). Rejects a zero pending admin
    /// and emits the proposal.
    pub fn propose_admin(ctx: Context<AdminOnly>, new_admin: Pubkey) -> Result<()> {
        require_keys_neq!(new_admin, Pubkey::default(), RedemptionError::ZeroAddress);
        ctx.accounts.config.pending_admin = new_admin;
        emit!(AdminProposed {
            new_admin,
            by: ctx.accounts.admin.key()
        });
        Ok(())
    }

    /// Two-step admin rotation (accept).
    pub fn accept_admin(ctx: Context<AcceptAdmin>) -> Result<()> {
        let c = &mut ctx.accounts.config;
        require_keys_neq!(
            c.pending_admin,
            Pubkey::default(),
            RedemptionError::NoPendingAdmin
        );
        require_keys_eq!(
            ctx.accounts.new_admin.key(),
            c.pending_admin,
            RedemptionError::NotPendingAdmin
        );
        let previous = c.admin;
        c.admin = c.pending_admin;
        c.pending_admin = Pubkey::default();
        emit!(AdminChanged {
            previous,
            new_admin: c.admin
        });
        Ok(())
    }

    /// Withdraw a pending admin transfer (current admin only).
    pub fn cancel_admin_transfer(ctx: Context<AdminOnly>) -> Result<()> {
        let cancelled = ctx.accounts.config.pending_admin;
        ctx.accounts.config.pending_admin = Pubkey::default();
        emit!(AdminTransferCancelled {
            cancelled,
            by: ctx.accounts.admin.key()
        });
        Ok(())
    }

    pub fn request_redemption<'info>(
        ctx: Context<'info, RequestRedemption<'info>>,
        rwa_amount: u64,
        min_quote_out: u64,
        deadline: u64,
    ) -> Result<()> {
        let now = Clock::get()?.unix_timestamp as u64;
        // No redemption activity until the deployment wiring is finalized.
        require!(
            ctx.accounts.registry.finalized,
            RedemptionError::NotFinalized
        );
        require!(
            !ctx.accounts.registry.paused,
            RedemptionError::ProjectPaused
        );
        require!(
            load_allowed(
                &ctx.accounts.beneficiary_record,
                &ctx.accounts.beneficiary.key(),
                now
            )?,
            RedemptionError::CallerNotAllowed
        );
        require!(rwa_amount != 0, RedemptionError::ZeroAmount);
        require!(deadline >= now, RedemptionError::DeadlineExpired);

        // Direct pricing-math call (not the boxed Account<Strategy> method, whose
        // auto-deref dispatch faults under this toolchain).
        let quote = pricing_math::quote_redemption(
            rwa_amount,
            ctx.accounts.strategy.redemption_price,
            ctx.accounts.strategy.token_decimals,
        )
        .map_err(|_| error!(RedemptionError::PricingFailed))?;
        require!(quote != 0, RedemptionError::ZeroQuote);
        require!(quote >= min_quote_out, RedemptionError::QuoteBelowMin);

        // Pull exact RWA from the beneficiary into escrow (fires the hook).
        // Record the liability against what escrow ACTUALLY received, so a
        // balance-affecting mint (already rejected at initialize, defense in depth
        // here) can never make escrow record more than it holds.
        let escrow_before = ctx.accounts.escrow_token.amount;
        transfer_rwa(
            &ctx.accounts.rwa_token_program,
            &ctx.accounts.beneficiary_token.to_account_info(),
            &ctx.accounts.rwa_mint,
            &ctx.accounts.escrow_token.to_account_info(),
            &ctx.accounts.beneficiary.to_account_info(),
            ctx.remaining_accounts,
            rwa_amount,
            &[],
        )?;
        ctx.accounts.escrow_token.reload()?;
        let received = ctx
            .accounts
            .escrow_token
            .amount
            .checked_sub(escrow_before)
            .ok_or(RedemptionError::RwaDeltaMismatch)?;
        require!(received == rwa_amount, RedemptionError::RwaDeltaMismatch);

        let c = &mut ctx.accounts.config;
        let id = c.next_id;
        c.next_id = c.next_id.checked_add(1).ok_or(RedemptionError::Overflow)?;

        let r = &mut ctx.accounts.request;
        r.id = id;
        r.beneficiary = ctx.accounts.beneficiary.key();
        r.rwa_amount = rwa_amount;
        r.quote_amount = quote;
        r.created_at = now;
        r.status = RedemptionStatus::Pending as u8;
        r.bump = ctx.bumps.request;

        emit!(RedemptionRequested {
            id,
            beneficiary: r.beneficiary,
            rwa_amount,
            quote_amount: quote,
            created_at: now
        });
        Ok(())
    }

    pub fn fund_redemption(ctx: Context<FundRedemption>, _id: u64) -> Result<()> {
        let now = Clock::get()?.unix_timestamp as u64;
        // No redemption activity until the deployment wiring is finalized.
        require!(
            ctx.accounts.registry.finalized,
            RedemptionError::NotFinalized
        );
        require!(
            !ctx.accounts.registry.paused,
            RedemptionError::ProjectPaused
        );
        let status = RedemptionStatus::from_u8(ctx.accounts.request.status)
            .ok_or(RedemptionError::BadStatus)?;
        ensure_pending(status).map_err(map_core)?;
        require!(
            load_allowed(
                &ctx.accounts.beneficiary_record,
                &ctx.accounts.request.beneficiary,
                now
            )?,
            RedemptionError::BeneficiaryNotAllowed
        );

        let quote_amount = ctx.accounts.request.quote_amount;
        let before = ctx.accounts.escrow_quote.amount;
        transfer_checked(
            CpiContext::new(
                ctx.accounts.quote_token_program.key(),
                TransferChecked {
                    from: ctx.accounts.treasurer_quote.to_account_info(),
                    mint: ctx.accounts.quote_mint.to_account_info(),
                    to: ctx.accounts.escrow_quote.to_account_info(),
                    authority: ctx.accounts.treasurer.to_account_info(),
                },
            ),
            quote_amount,
            ctx.accounts.quote_mint.decimals,
        )?;
        ctx.accounts.escrow_quote.reload()?;
        // checked_sub matches the file's convention and cannot panic under
        // `overflow-checks = true` if the quote allowlist is ever widened.
        require!(
            ctx.accounts.escrow_quote.amount.checked_sub(before) == Some(quote_amount),
            RedemptionError::QuoteDeltaMismatch
        );

        ctx.accounts.request.status = RedemptionStatus::Funded as u8;
        emit!(RedemptionFunded {
            id: ctx.accounts.request.id,
            funder: ctx.accounts.treasurer.key(),
            quote_amount
        });
        Ok(())
    }

    pub fn reject_redemption<'info>(
        ctx: Context<'info, RejectRedemption<'info>>,
        _id: u64,
        reason_code: [u8; 32],
    ) -> Result<()> {
        let now = Clock::get()?.unix_timestamp as u64;
        // No redemption activity until the deployment wiring is finalized.
        require!(
            ctx.accounts.registry.finalized,
            RedemptionError::NotFinalized
        );
        require!(
            !ctx.accounts.registry.paused,
            RedemptionError::ProjectPaused
        );
        require!(reason_code != [0u8; 32], RedemptionError::ZeroReasonCode);
        let status = RedemptionStatus::from_u8(ctx.accounts.request.status)
            .ok_or(RedemptionError::BadStatus)?;
        ensure_pending(status).map_err(map_core)?;
        require!(
            load_allowed(
                &ctx.accounts.beneficiary_record,
                &ctx.accounts.request.beneficiary,
                now
            )?,
            RedemptionError::BeneficiaryNotAllowed
        );

        ctx.accounts.request.status = RedemptionStatus::Rejected as u8;
        let rwa_amount = ctx.accounts.request.rwa_amount;
        let dest_before = ctx.accounts.beneficiary_token.amount;
        return_escrowed_rwa(
            &ctx.accounts.config,
            &ctx.accounts.rwa_token_program,
            &ctx.accounts.escrow_token.to_account_info(),
            &ctx.accounts.rwa_mint,
            &ctx.accounts.beneficiary_token.to_account_info(),
            ctx.remaining_accounts,
            rwa_amount,
        )?;
        ctx.accounts.beneficiary_token.reload()?;
        require!(
            ctx.accounts
                .beneficiary_token
                .amount
                .checked_sub(dest_before)
                == Some(rwa_amount),
            RedemptionError::RwaDeltaMismatch
        );
        emit!(RedemptionRejected {
            id: ctx.accounts.request.id,
            reason_code,
            by: ctx.accounts.redemption_manager.key()
        });
        Ok(())
    }

    /// No `!paused` guard (deliberate) — the escrow-only hook bypass lets this
    /// complete during an emergency pause. Beneficiary must still be allowed.
    pub fn cancel_redemption<'info>(
        ctx: Context<'info, CancelRedemption<'info>>,
        _id: u64,
    ) -> Result<()> {
        let now = Clock::get()?.unix_timestamp as u64;
        // Gate the pause-bypass path on finalization too (nothing is escrowed
        // before finalize, so this only blocks pre-go-live calls).
        require!(
            ctx.accounts.registry.finalized,
            RedemptionError::NotFinalized
        );
        let status = RedemptionStatus::from_u8(ctx.accounts.request.status)
            .ok_or(RedemptionError::BadStatus)?;
        let caller_is_beneficiary =
            ctx.accounts.beneficiary.key() == ctx.accounts.request.beneficiary;
        can_cancel(
            status,
            caller_is_beneficiary,
            ctx.accounts.request.created_at,
            ctx.accounts.config.redemption_timeout,
            now,
        )
        .map_err(map_core)?;
        require!(
            load_allowed(
                &ctx.accounts.beneficiary_record,
                &ctx.accounts.request.beneficiary,
                now
            )?,
            RedemptionError::BeneficiaryNotAllowed
        );

        ctx.accounts.request.status = RedemptionStatus::Cancelled as u8;
        let rwa_amount = ctx.accounts.request.rwa_amount;
        let dest_before = ctx.accounts.beneficiary_token.amount;
        return_escrowed_rwa(
            &ctx.accounts.config,
            &ctx.accounts.rwa_token_program,
            &ctx.accounts.escrow_token.to_account_info(),
            &ctx.accounts.rwa_mint,
            &ctx.accounts.beneficiary_token.to_account_info(),
            ctx.remaining_accounts,
            rwa_amount,
        )?;
        ctx.accounts.beneficiary_token.reload()?;
        require!(
            ctx.accounts
                .beneficiary_token
                .amount
                .checked_sub(dest_before)
                == Some(rwa_amount),
            RedemptionError::RwaDeltaMismatch
        );
        emit!(RedemptionCancelled {
            id: ctx.accounts.request.id,
            beneficiary: ctx.accounts.request.beneficiary
        });
        Ok(())
    }

    /// Permissionless. Keeps its `!paused` guard; never re-checks compliance.
    pub fn claim_redemption<'info>(
        ctx: Context<'info, ClaimRedemption<'info>>,
        _id: u64,
    ) -> Result<()> {
        // No redemption activity until the deployment wiring is finalized.
        require!(
            ctx.accounts.registry.finalized,
            RedemptionError::NotFinalized
        );
        require!(
            !ctx.accounts.registry.paused,
            RedemptionError::ProjectPaused
        );
        let status = RedemptionStatus::from_u8(ctx.accounts.request.status)
            .ok_or(RedemptionError::BadStatus)?;
        ensure_funded(status).map_err(map_core)?;

        ctx.accounts.request.status = RedemptionStatus::Completed as u8;
        let rwa_amount = ctx.accounts.request.rwa_amount;
        let quote_amount = ctx.accounts.request.quote_amount;

        // Snapshot the beneficiary quote balance BEFORE the RWA CPI, so the
        // quote delta check below never spans the intervening RWA transfer + hook.
        let before = ctx.accounts.beneficiary_quote.amount;

        // RWA back to the Vault inventory (escrow-authority signed; hook fires).
        let vault_before = ctx.accounts.vault_token.amount;
        return_escrowed_rwa(
            &ctx.accounts.config,
            &ctx.accounts.rwa_token_program,
            &ctx.accounts.escrow_token.to_account_info(),
            &ctx.accounts.rwa_mint,
            &ctx.accounts.vault_token.to_account_info(),
            ctx.remaining_accounts,
            rwa_amount,
        )?;
        ctx.accounts.vault_token.reload()?;
        require!(
            ctx.accounts.vault_token.amount.checked_sub(vault_before) == Some(rwa_amount),
            RedemptionError::RwaDeltaMismatch
        );

        // Funded quote to the recorded beneficiary, exact-delta checked (`before`
        // was snapshotted above, ahead of the RWA CPI).
        let seeds: &[&[&[u8]]] = &[&[CONFIG_SEED, &[ctx.accounts.config.bump]]];
        transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.quote_token_program.key(),
                TransferChecked {
                    from: ctx.accounts.escrow_quote.to_account_info(),
                    mint: ctx.accounts.quote_mint.to_account_info(),
                    to: ctx.accounts.beneficiary_quote.to_account_info(),
                    authority: ctx.accounts.config.to_account_info(),
                },
                seeds,
            ),
            quote_amount,
            ctx.accounts.quote_mint.decimals,
        )?;
        ctx.accounts.beneficiary_quote.reload()?;
        // checked_sub, matching the file's convention.
        require!(
            ctx.accounts.beneficiary_quote.amount.checked_sub(before) == Some(quote_amount),
            RedemptionError::QuoteDeltaMismatch
        );

        emit!(RedemptionCompleted {
            id: ctx.accounts.request.id,
            beneficiary: ctx.accounts.request.beneficiary,
            rwa_amount,
            quote_amount
        });
        Ok(())
    }

    /// Reclaim the rent of a request that has reached a terminal state
    /// (`Completed` / `Rejected` / `Cancelled`), returning the lamports to the
    /// beneficiary who paid for it. Request PDAs are seeded on a monotonic counter,
    /// so a closed id is never reused — closing introduces no replay surface.
    /// Permissionless: the only effect is refunding rent to the recorded
    /// beneficiary, and a still-open request is rejected by the status check.
    pub fn close_request(ctx: Context<CloseRequest>, _id: u64) -> Result<()> {
        let status = RedemptionStatus::from_u8(ctx.accounts.request.status)
            .ok_or(RedemptionError::BadStatus)?;
        require!(
            matches!(
                status,
                RedemptionStatus::Completed
                    | RedemptionStatus::Rejected
                    | RedemptionStatus::Cancelled
            ),
            RedemptionError::RequestNotTerminal
        );
        emit!(RequestClosed {
            id: ctx.accounts.request.id,
            beneficiary: ctx.accounts.request.beneficiary,
        });
        Ok(())
    }
}

fn map_core(e: redemption_core::RedemptionError) -> Error {
    use redemption_core::RedemptionError as E;
    match e {
        E::NotPending => error!(RedemptionError::NotPending),
        E::NotFunded => error!(RedemptionError::NotFunded),
        E::NotBeneficiary => error!(RedemptionError::NotBeneficiary),
        E::TimeoutNotReached => error!(RedemptionError::TimeoutNotReached),
    }
}

fn load_allowed(record: &UncheckedAccount, wallet: &Pubkey, now: u64) -> Result<bool> {
    let (expected, _) =
        Pubkey::find_program_address(&[RECORD_SEED, wallet.as_ref()], &rwa_compliance::ID);
    require_keys_eq!(record.key(), expected, RedemptionError::RecordMismatch);
    let info = record.to_account_info();
    if info.owner != &rwa_compliance::ID {
        return Ok(false);
    }
    let data = info.try_borrow_data()?;
    if data.len() < 8 + 32 + 1 + 8 + 1 {
        return Ok(false);
    }
    let rec = ComplianceRecord::try_deserialize(&mut &data[..])
        .map_err(|_| error!(RedemptionError::RecordMismatch))?;
    Ok(record_is_allowed(&rec, now))
}

/// Escrow-authority-signed RWA transfer out of escrow (reject/cancel/claim legs).
#[allow(clippy::too_many_arguments)]
fn return_escrowed_rwa<'info>(
    config: &Account<'info, Config>,
    token_program: &UncheckedAccount<'info>,
    escrow_token: &AccountInfo<'info>,
    mint: &InterfaceAccount<'info, Mint>,
    destination: &AccountInfo<'info>,
    remaining: &'info [AccountInfo<'info>],
    amount: u64,
) -> Result<()> {
    let seeds: &[&[&[u8]]] = &[&[CONFIG_SEED, &[config.bump]]];
    transfer_rwa(
        token_program,
        escrow_token,
        mint,
        destination,
        &config.to_account_info(),
        remaining,
        amount,
        seeds,
    )
}

/// Hook-aware Token-2022 RWA transfer. `seeds` empty = `authority` is a signer.
#[allow(clippy::too_many_arguments)]
fn transfer_rwa<'info>(
    token_program: &UncheckedAccount<'info>,
    source: &AccountInfo<'info>,
    mint: &InterfaceAccount<'info, Mint>,
    destination: &AccountInfo<'info>,
    authority: &AccountInfo<'info>,
    remaining: &'info [AccountInfo<'info>],
    amount: u64,
    seeds: &[&[&[u8]]],
) -> Result<()> {
    invoke_transfer_checked(
        &token_program.key(),
        source.clone(),
        mint.to_account_info(),
        destination.clone(),
        authority.clone(),
        remaining,
        amount,
        mint.decimals,
        seeds,
    )?;
    Ok(())
}

#[account]
pub struct Config {
    pub admin: Pubkey,
    pub pending_admin: Pubkey,
    pub treasurer: Pubkey,
    pub redemption_manager: Pubkey,
    pub vault: Pubkey,
    pub rwa_mint: Pubkey,
    pub quote_mint: Pubkey,
    /// The quote mint's decimals, bound at `initialize` to the price scale.
    pub quote_decimals: u8,
    pub strategy: Pubkey,
    pub registry: Pubkey,
    pub redemption_timeout: u64,
    pub next_id: u64,
    pub bump: u8,
}

impl Config {
    pub const SPACE: usize = 8 + 32 * 9 + 1 + 8 + 8 + 1;
}

#[account]
pub struct RedemptionRequest {
    pub id: u64,
    pub beneficiary: Pubkey,
    pub rwa_amount: u64,
    pub quote_amount: u64,
    pub created_at: u64,
    /// redemption_core::RedemptionStatus as u8.
    pub status: u8,
    pub bump: u8,
}

impl RedemptionRequest {
    pub const SPACE: usize = 8 + 8 + 32 + 8 + 8 + 8 + 1 + 1;
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = payer, space = Config::SPACE, seeds = [CONFIG_SEED], bump)]
    pub config: Box<Account<'info, Config>>,
    /// CHECK: validated by validate_rwa_mint (Token-2022 + our hook).
    pub rwa_mint: Box<InterfaceAccount<'info, Mint>>,
    /// CHECK: validated by validate_quote_mint (program + safe extensions).
    pub quote_mint: Box<InterfaceAccount<'info, Mint>>,
    /// Pinned to the canonical pricing `Strategy` PDA.
    #[account(seeds = [rwa_pricing::STRATEGY_SEED], bump = strategy.bump, seeds::program = rwa_pricing::ID)]
    pub strategy: Box<Account<'info, Strategy>>,
    pub registry: Box<Account<'info, Registry>>,
    #[account(mut)]
    pub payer: Signer<'info>,
    // Upgrade-authority gate.
    #[account(constraint = program.programdata_address()? == Some(program_data.key()) @ RedemptionError::NotUpgradeAuthority)]
    pub program: Program<'info, crate::program::RwaRedemption>,
    #[account(constraint = program_data.upgrade_authority_address == Some(payer.key()) @ RedemptionError::NotUpgradeAuthority)]
    pub program_data: Account<'info, ProgramData>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AdminOnly<'info> {
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump, has_one = admin @ RedemptionError::NotAdmin)]
    pub config: Box<Account<'info, Config>>,
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct AcceptAdmin<'info> {
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,
    pub new_admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct RequestRedemption<'info> {
    #[account(
        mut,
        seeds = [CONFIG_SEED],
        bump = config.bump,
        has_one = registry @ RedemptionError::WrongRegistry,
        has_one = strategy @ RedemptionError::WrongStrategy,
    )]
    pub config: Box<Account<'info, Config>>,
    #[account(seeds = [rwa_compliance::REGISTRY_SEED], bump = registry.bump, seeds::program = rwa_compliance::ID)]
    pub registry: Box<Account<'info, Registry>>,
    /// Pinned to the canonical pricing `Strategy` PDA.
    #[account(seeds = [rwa_pricing::STRATEGY_SEED], bump = strategy.bump, seeds::program = rwa_pricing::ID)]
    pub strategy: Box<Account<'info, Strategy>>,
    /// Read-only — `transfer_checked` takes the mint read-only, so a write
    /// lock here would needlessly serialize every redemption against the mint.
    #[account(address = config.rwa_mint @ RedemptionError::WrongMint)]
    pub rwa_mint: Box<InterfaceAccount<'info, Mint>>,
    #[account(
        init,
        payer = beneficiary,
        space = RedemptionRequest::SPACE,
        seeds = [REQUEST_SEED, config.next_id.to_le_bytes().as_ref()],
        bump
    )]
    pub request: Box<Account<'info, RedemptionRequest>>,
    #[account(mut)]
    pub beneficiary: Signer<'info>,
    #[account(mut, token::mint = rwa_mint, token::authority = beneficiary)]
    pub beneficiary_token: Box<InterfaceAccount<'info, TokenAccount>>,
    /// Pinned to the canonical escrow ATA of the redemption PDA.
    #[account(
        mut,
        token::mint = rwa_mint,
        token::authority = config,
        address = anchor_spl::associated_token::get_associated_token_address_with_program_id(
            &config.key(), &rwa_mint.key(), rwa_mint.to_account_info().owner
        ) @ RedemptionError::NotCanonicalAta,
    )]
    pub escrow_token: Box<InterfaceAccount<'info, TokenAccount>>,
    /// CHECK: beneficiary's compliance record, verified in-handler.
    pub beneficiary_record: UncheckedAccount<'info>,
    /// CHECK: pinned to the Token-2022 program id; further validated by invoke.
    #[account(address = anchor_spl::token_2022::ID @ RedemptionError::WrongTokenProgram)]
    pub rwa_token_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(id: u64)]
pub struct FundRedemption<'info> {
    #[account(
        seeds = [CONFIG_SEED],
        bump = config.bump,
        has_one = registry @ RedemptionError::WrongRegistry,
        has_one = treasurer @ RedemptionError::NotTreasurer,
    )]
    pub config: Box<Account<'info, Config>>,
    #[account(seeds = [rwa_compliance::REGISTRY_SEED], bump = registry.bump, seeds::program = rwa_compliance::ID)]
    pub registry: Box<Account<'info, Registry>>,
    #[account(mut, seeds = [REQUEST_SEED, id.to_le_bytes().as_ref()], bump = request.bump)]
    pub request: Box<Account<'info, RedemptionRequest>>,
    #[account(address = config.quote_mint @ RedemptionError::WrongMint)]
    pub quote_mint: Box<InterfaceAccount<'info, Mint>>,
    pub treasurer: Signer<'info>,
    #[account(mut, token::mint = quote_mint, token::authority = treasurer)]
    pub treasurer_quote: Box<InterfaceAccount<'info, TokenAccount>>,
    /// Pinned to the canonical escrow-quote ATA of the redemption PDA.
    #[account(
        mut,
        token::mint = quote_mint,
        token::authority = config,
        address = anchor_spl::associated_token::get_associated_token_address_with_program_id(
            &config.key(), &quote_mint.key(), quote_mint.to_account_info().owner
        ) @ RedemptionError::NotCanonicalAta,
    )]
    pub escrow_quote: Box<InterfaceAccount<'info, TokenAccount>>,
    /// CHECK: beneficiary's compliance record, verified in-handler.
    pub beneficiary_record: UncheckedAccount<'info>,
    /// Pinned to the quote mint's own owning program.
    #[account(address = *quote_mint.to_account_info().owner @ RedemptionError::WrongTokenProgram)]
    pub quote_token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
#[instruction(id: u64)]
pub struct RejectRedemption<'info> {
    #[account(
        seeds = [CONFIG_SEED],
        bump = config.bump,
        has_one = registry @ RedemptionError::WrongRegistry,
        has_one = redemption_manager @ RedemptionError::NotRedemptionManager,
    )]
    pub config: Box<Account<'info, Config>>,
    #[account(seeds = [rwa_compliance::REGISTRY_SEED], bump = registry.bump, seeds::program = rwa_compliance::ID)]
    pub registry: Box<Account<'info, Registry>>,
    #[account(mut, seeds = [REQUEST_SEED, id.to_le_bytes().as_ref()], bump = request.bump)]
    pub request: Box<Account<'info, RedemptionRequest>>,
    /// Read-only (see `RequestRedemption`).
    #[account(address = config.rwa_mint @ RedemptionError::WrongMint)]
    pub rwa_mint: Box<InterfaceAccount<'info, Mint>>,
    /// Pinned to the canonical escrow ATA of the redemption PDA.
    #[account(
        mut,
        token::mint = rwa_mint,
        token::authority = config,
        address = anchor_spl::associated_token::get_associated_token_address_with_program_id(
            &config.key(), &rwa_mint.key(), rwa_mint.to_account_info().owner
        ) @ RedemptionError::NotCanonicalAta,
    )]
    pub escrow_token: Box<InterfaceAccount<'info, TokenAccount>>,
    // Pays only the recorded beneficiary — bound to request.beneficiary.
    #[account(mut, token::mint = rwa_mint, token::authority = request.beneficiary)]
    pub beneficiary_token: Box<InterfaceAccount<'info, TokenAccount>>,
    /// CHECK: beneficiary's compliance record, verified in-handler.
    pub beneficiary_record: UncheckedAccount<'info>,
    pub redemption_manager: Signer<'info>,
    /// CHECK: pinned to the Token-2022 program id; further validated by invoke.
    #[account(address = anchor_spl::token_2022::ID @ RedemptionError::WrongTokenProgram)]
    pub rwa_token_program: UncheckedAccount<'info>,
}

#[derive(Accounts)]
#[instruction(id: u64)]
pub struct CancelRedemption<'info> {
    #[account(
        seeds = [CONFIG_SEED],
        bump = config.bump,
        has_one = registry @ RedemptionError::WrongRegistry,
    )]
    pub config: Box<Account<'info, Config>>,
    #[account(seeds = [rwa_compliance::REGISTRY_SEED], bump = registry.bump, seeds::program = rwa_compliance::ID)]
    pub registry: Box<Account<'info, Registry>>,
    #[account(mut, seeds = [REQUEST_SEED, id.to_le_bytes().as_ref()], bump = request.bump)]
    pub request: Box<Account<'info, RedemptionRequest>>,
    /// Read-only (see `RequestRedemption`).
    #[account(address = config.rwa_mint @ RedemptionError::WrongMint)]
    pub rwa_mint: Box<InterfaceAccount<'info, Mint>>,
    /// Pinned to the canonical escrow ATA of the redemption PDA.
    #[account(
        mut,
        token::mint = rwa_mint,
        token::authority = config,
        address = anchor_spl::associated_token::get_associated_token_address_with_program_id(
            &config.key(), &rwa_mint.key(), rwa_mint.to_account_info().owner
        ) @ RedemptionError::NotCanonicalAta,
    )]
    pub escrow_token: Box<InterfaceAccount<'info, TokenAccount>>,
    // Pays only the recorded beneficiary — bound to request.beneficiary, not
    // the caller. `can_cancel` already forces caller == request.beneficiary, so this
    // is behaviour-preserving today and removes the dependency on that off-file
    // invariant (matching `reject` / `claim`).
    #[account(mut, token::mint = rwa_mint, token::authority = request.beneficiary)]
    pub beneficiary_token: Box<InterfaceAccount<'info, TokenAccount>>,
    /// CHECK: beneficiary's compliance record, verified in-handler.
    pub beneficiary_record: UncheckedAccount<'info>,
    pub beneficiary: Signer<'info>,
    /// CHECK: pinned to the Token-2022 program id; further validated by invoke.
    #[account(address = anchor_spl::token_2022::ID @ RedemptionError::WrongTokenProgram)]
    pub rwa_token_program: UncheckedAccount<'info>,
}

#[derive(Accounts)]
#[instruction(id: u64)]
pub struct ClaimRedemption<'info> {
    #[account(
        seeds = [CONFIG_SEED],
        bump = config.bump,
        has_one = registry @ RedemptionError::WrongRegistry,
    )]
    pub config: Box<Account<'info, Config>>,
    #[account(seeds = [rwa_compliance::REGISTRY_SEED], bump = registry.bump, seeds::program = rwa_compliance::ID)]
    pub registry: Box<Account<'info, Registry>>,
    #[account(mut, seeds = [REQUEST_SEED, id.to_le_bytes().as_ref()], bump = request.bump)]
    pub request: Box<Account<'info, RedemptionRequest>>,
    /// Read-only (see `RequestRedemption`).
    #[account(address = config.rwa_mint @ RedemptionError::WrongMint)]
    pub rwa_mint: Box<InterfaceAccount<'info, Mint>>,
    #[account(address = config.quote_mint @ RedemptionError::WrongMint)]
    pub quote_mint: Box<InterfaceAccount<'info, Mint>>,
    /// Pinned to the canonical escrow ATA of the redemption PDA.
    #[account(
        mut,
        token::mint = rwa_mint,
        token::authority = config,
        address = anchor_spl::associated_token::get_associated_token_address_with_program_id(
            &config.key(), &rwa_mint.key(), rwa_mint.to_account_info().owner
        ) @ RedemptionError::NotCanonicalAta,
    )]
    pub escrow_token: Box<InterfaceAccount<'info, TokenAccount>>,
    /// Pinned to the canonical escrow-quote ATA of the redemption PDA.
    #[account(
        mut,
        token::mint = quote_mint,
        token::authority = config,
        address = anchor_spl::associated_token::get_associated_token_address_with_program_id(
            &config.key(), &quote_mint.key(), quote_mint.to_account_info().owner
        ) @ RedemptionError::NotCanonicalAta,
    )]
    pub escrow_quote: Box<InterfaceAccount<'info, TokenAccount>>,
    /// Vault inventory account — RWA returns here. Pinned to the canonical
    /// inventory ATA of the pinned vault authority.
    #[account(
        mut,
        token::mint = rwa_mint,
        token::authority = config.vault,
        address = anchor_spl::associated_token::get_associated_token_address_with_program_id(
            &config.vault, &rwa_mint.key(), rwa_mint.to_account_info().owner
        ) @ RedemptionError::NotCanonicalAta,
    )]
    pub vault_token: Box<InterfaceAccount<'info, TokenAccount>>,
    // Pays only the recorded beneficiary, and only into their *canonical*
    // quote ATA. Without the address pin this is the protocol's one custody account
    // that is neither ATA-pinned nor covered by the hook's ImmutableOwner rule (the
    // quote leg fires no hook), so a permissionless `claim` could otherwise steer
    // the payout into any attacker-crafted account satisfying mint+authority — the
    // reconciler would then see a legitimate payment as missing, and a PDA
    // beneficiary could be paid into an unrecoverable account.
    #[account(
        mut,
        token::mint = quote_mint,
        token::authority = request.beneficiary,
        address = anchor_spl::associated_token::get_associated_token_address_with_program_id(
            &request.beneficiary, &quote_mint.key(), quote_mint.to_account_info().owner
        ) @ RedemptionError::NotCanonicalAta,
    )]
    pub beneficiary_quote: Box<InterfaceAccount<'info, TokenAccount>>,
    /// CHECK: pinned to the Token-2022 program id; further validated by invoke.
    #[account(address = anchor_spl::token_2022::ID @ RedemptionError::WrongTokenProgram)]
    pub rwa_token_program: UncheckedAccount<'info>,
    /// Pinned to the quote mint's own owning program.
    #[account(address = *quote_mint.to_account_info().owner @ RedemptionError::WrongTokenProgram)]
    pub quote_token_program: Interface<'info, TokenInterface>,
}

/// Accounts to close a terminal request and refund its rent to the beneficiary.
#[derive(Accounts)]
#[instruction(id: u64)]
pub struct CloseRequest<'info> {
    #[account(
        seeds = [CONFIG_SEED],
        bump = config.bump,
        has_one = registry @ RedemptionError::WrongRegistry,
    )]
    pub config: Box<Account<'info, Config>>,
    #[account(seeds = [rwa_compliance::REGISTRY_SEED], bump = registry.bump, seeds::program = rwa_compliance::ID)]
    pub registry: Box<Account<'info, Registry>>,
    /// Refunds rent to `beneficiary`, which must be the request's recorded
    /// beneficiary (the original rent payer).
    #[account(
        mut,
        seeds = [REQUEST_SEED, id.to_le_bytes().as_ref()],
        bump = request.bump,
        has_one = beneficiary @ RedemptionError::NotBeneficiary,
        close = beneficiary,
    )]
    pub request: Box<Account<'info, RedemptionRequest>>,
    /// CHECK: rent destination; constrained to `request.beneficiary` via `has_one`.
    #[account(mut)]
    pub beneficiary: UncheckedAccount<'info>,
}

#[event]
pub struct RedemptionRequested {
    pub id: u64,
    pub beneficiary: Pubkey,
    pub rwa_amount: u64,
    pub quote_amount: u64,
    pub created_at: u64,
}

#[event]
pub struct RedemptionFunded {
    pub id: u64,
    pub funder: Pubkey,
    pub quote_amount: u64,
}

#[event]
pub struct RedemptionRejected {
    pub id: u64,
    pub reason_code: [u8; 32],
    pub by: Pubkey,
}

#[event]
pub struct RedemptionCancelled {
    pub id: u64,
    pub beneficiary: Pubkey,
}

#[event]
pub struct RedemptionCompleted {
    pub id: u64,
    pub beneficiary: Pubkey,
    pub rwa_amount: u64,
    pub quote_amount: u64,
}

#[event]
pub struct RequestClosed {
    pub id: u64,
    pub beneficiary: Pubkey,
}

/// Role label for `RoleChanged`.
#[repr(u8)]
pub enum Role {
    Treasurer = 1,
    RedemptionManager = 2,
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
pub enum RedemptionError {
    #[msg("zero address")]
    ZeroAddress,
    #[msg("project is paused")]
    ProjectPaused,
    #[msg("caller is not allowed")]
    CallerNotAllowed,
    #[msg("beneficiary is not allowed")]
    BeneficiaryNotAllowed,
    #[msg("amount must be non-zero")]
    ZeroAmount,
    #[msg("deadline expired")]
    DeadlineExpired,
    #[msg("quote is zero")]
    ZeroQuote,
    #[msg("quote below min")]
    QuoteBelowMin,
    #[msg("reason code must be non-zero")]
    ZeroReasonCode,
    #[msg("request is not pending")]
    NotPending,
    #[msg("request is not funded")]
    NotFunded,
    #[msg("caller is not the beneficiary")]
    NotBeneficiary,
    #[msg("redemption timeout not reached")]
    TimeoutNotReached,
    #[msg("quote delta mismatch")]
    QuoteDeltaMismatch,
    #[msg("pricing failed")]
    PricingFailed,
    #[msg("id overflow")]
    Overflow,
    #[msg("bad status byte")]
    BadStatus,
    #[msg("redemption timeout must be within [1 day, 365 days]")]
    InvalidTimeout,
    #[msg("request is not in a terminal state")]
    RequestNotTerminal,
    #[msg("compliance record account does not match its owner")]
    RecordMismatch,
    #[msg("wrong registry account")]
    WrongRegistry,
    #[msg("wrong strategy account")]
    WrongStrategy,
    #[msg("wrong mint account")]
    WrongMint,
    #[msg("caller is not the treasurer")]
    NotTreasurer,
    #[msg("caller is not the redemption manager")]
    NotRedemptionManager,
    #[msg("caller is not the admin")]
    NotAdmin,
    #[msg("caller is not the pending admin")]
    NotPendingAdmin,
    #[msg("no pending admin transfer to accept")]
    NoPendingAdmin,
    #[msg("caller is not the program upgrade authority")]
    NotUpgradeAuthority,
    #[msg("deployment is not finalized")]
    NotFinalized,
    #[msg("configured RWA mint is unsafe (not Token-2022 / wrong hook / disallowed extension)")]
    UnsafeMint,
    #[msg("configured quote mint is unsafe (wrong program / disallowed extension)")]
    UnsafeQuoteMint,
    #[msg("RWA mint and quote mint must be different")]
    MintQuoteSame,
    #[msg("token account is not the canonical ATA")]
    NotCanonicalAta,
    #[msg("wrong token program for the RWA leg")]
    WrongTokenProgram,
    #[msg("pricing decimals do not match the RWA mint")]
    DecimalsMismatch,
    #[msg("quote mint decimals do not match the configured price scale")]
    QuoteDecimalsMismatch,
    #[msg("RWA transfer delta mismatch")]
    RwaDeltaMismatch,
}
