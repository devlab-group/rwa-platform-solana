//! rwa-vault — holds RWA inventory, sells it for one quote token, withdraws proceeds.
//!
//! Solana port of `contracts/src/Vault.sol`. The Vault **config PDA** is the
//! authority that owns the inventory RWA token account and the quote token
//! account (it is the `vault` pinned as a compliance system address and named in
//! the SupplyController attestation). `buy` is the only path that moves inventory
//! out; it mirrors `Vault.buy`: not paused, buyer + recipient allowed, deadline
//! ok, non-zero amount, sufficient inventory, quote ≤ max, exact quote pulled in,
//! then RWA sent to the recipient.
//!
//! The RWA leg is a Token-2022 `transfer_checked` that fires the compliance
//! transfer hook (so the recipient is re-checked on-chain there too); we forward
//! the hook's accounts via `remaining_accounts`. The quote leg is a plain
//! SPL/Token-2022 `transfer_checked` with an exact received-amount delta check,
//! since the quote mint is an arbitrary configured token.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke_signed;
use anchor_spl::token_interface::{
    transfer_checked, Mint, TokenAccount, TokenInterface, TransferChecked,
};
use rwa_compliance::{record_is_allowed, ComplianceRecord, Registry, RECORD_SEED};
use rwa_pricing::Strategy;
use rwa_transfer_hook::{build_permissioned_burn_checked_ix, invoke_transfer_checked};
use rwa_transfer_hook::{validate_quote_mint, validate_rwa_mint};

declare_id!("2XnocgeBA5iT4mUEvuMCkbNPBscs9n7A2MdYL2zPBVjT");

pub const CONFIG_SEED: &[u8] = b"vault-config";

#[program]
pub mod rwa_vault {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    pub fn initialize(
        ctx: Context<Initialize>,
        admin: Pubkey,
        treasurer: Pubkey,
        treasury: Pubkey,
        supply_controller: Pubkey,
        quote_decimals: u8,
    ) -> Result<()> {
        for k in [admin, treasurer, treasury, supply_controller] {
            require_keys_neq!(k, Pubkey::default(), VaultError::ZeroAddress);
        }
        // The RWA mint must be a Token-2022 mint using our compliance hook.
        validate_rwa_mint(&ctx.accounts.rwa_mint.to_account_info(), None, false, None)
            .map_err(|_| error!(VaultError::UnsafeMint))?;
        // The quote mint must be the legacy SPL Token or Token-2022 program and
        // carry no extension that breaks the exact-delta quote accounting, runs
        // code on transfer, or seizes proceeds out of the vault PDA.
        validate_quote_mint(&ctx.accounts.quote_mint.to_account_info())
            .map_err(|_| error!(VaultError::UnsafeQuoteMint))?;
        // The RWA and quote mints must be distinct, or the delta checks below
        // could measure overlapping balances.
        require_keys_neq!(
            ctx.accounts.rwa_mint.key(),
            ctx.accounts.quote_mint.key(),
            VaultError::MintQuoteSame
        );
        // Pricing decimals must match the RWA mint, or quotes are off by powers
        // of ten.
        require!(
            ctx.accounts.strategy.token_decimals == ctx.accounts.rwa_mint.decimals,
            VaultError::DecimalsMismatch
        );
        // Bind the quote mint's decimals to the price scale the operator
        // priced against. `Strategy.purchase_price` is expressed in quote base units
        // per whole RWA token; nothing else ties that convention to the deployed
        // quote mint, so a decimals mismatch would silently mis-scale every trade by
        // powers of ten. Requiring the deployer to restate the scale independently
        // (as an argument) forces the two to agree at bootstrap.
        require!(
            ctx.accounts.quote_mint.decimals == quote_decimals,
            VaultError::QuoteDecimalsMismatch
        );
        let c = &mut ctx.accounts.config;
        c.admin = admin;
        c.pending_admin = Pubkey::default();
        c.treasurer = treasurer;
        c.treasury = treasury;
        // The supply controller PDA that may call `controller_burn`.
        c.supply_controller = supply_controller;
        c.rwa_mint = ctx.accounts.rwa_mint.key();
        c.quote_mint = ctx.accounts.quote_mint.key();
        c.quote_decimals = quote_decimals;
        c.strategy = ctx.accounts.strategy.key();
        c.registry = ctx.accounts.registry.key();
        c.bump = ctx.bumps.config;
        Ok(())
    }

    /// Burn inventory on behalf of the supply controller. The
    /// Vault PDA owns the inventory account, so only it can sign the Token-2022
    /// burn; the caller must be the stored supply-controller PDA (a signer via
    /// CPI seeds). This replaces a standing unlimited burn delegate.
    pub fn controller_burn(ctx: Context<ControllerBurn>, amount: u64) -> Result<()> {
        require_keys_eq!(
            ctx.accounts.supply_controller.key(),
            ctx.accounts.config.supply_controller,
            VaultError::NotSupplyController
        );
        let bump = ctx.accounts.config.bump;
        let decimals = ctx.accounts.mint.decimals;
        let before = ctx.accounts.vault_token.amount;

        // Burn through the Token-2022 PermissionedBurnChecked instruction.
        // It requires BOTH the permissioned-burn authority (the supply-controller
        // config PDA — a signer here via the propagated privilege from the
        // supply→vault CPI) AND the token-account owner (this Vault config PDA,
        // signed below via seeds). A plain holder `Burn`/`BurnChecked` is rejected
        // by the mint's permissioned-burn extension, so supply can only change
        // through this attested handshake.
        let ix = build_permissioned_burn_checked_ix(
            &ctx.accounts.token_program.key(),
            &ctx.accounts.vault_token.key(),
            &ctx.accounts.mint.key(),
            &ctx.accounts.supply_controller.key(),
            &ctx.accounts.config.key(),
            amount,
            decimals,
        )?;
        let seeds: &[&[&[u8]]] = &[&[CONFIG_SEED, &[bump]]];
        invoke_signed(
            &ix,
            &[
                ctx.accounts.vault_token.to_account_info(),
                ctx.accounts.mint.to_account_info(),
                ctx.accounts.supply_controller.to_account_info(),
                ctx.accounts.config.to_account_info(),
                ctx.accounts.token_program.to_account_info(),
            ],
            seeds,
        )?;
        ctx.accounts.vault_token.reload()?;
        require!(
            before - ctx.accounts.vault_token.amount == amount,
            VaultError::BurnDeltaMismatch
        );
        Ok(())
    }

    pub fn buy<'info>(
        ctx: Context<'info, Buy<'info>>,
        token_amount: u64,
        max_quote_amount: u64,
        deadline: u64,
    ) -> Result<()> {
        let c = &ctx.accounts.config;
        // Nothing is buyable until the deployment wiring is finalized.
        require!(ctx.accounts.registry.finalized, VaultError::NotFinalized);
        require!(!ctx.accounts.registry.paused, VaultError::ProjectPaused);
        let now = Clock::get()?.unix_timestamp as u64;
        require!(deadline >= now, VaultError::DeadlineExpired);
        require!(token_amount != 0, VaultError::ZeroAmount);

        // The recipient RWA account may not be the vault's own inventory ATA.
        // Token-2022 short-circuits a self-transfer *before* invoking the hook, so on
        // that single path the compliance hook never runs; the post-CPI delta check
        // would still catch it, but this rejects the aliasing outright rather than
        // leaning on one arithmetic line for the one case where the hook is bypassed.
        require_keys_neq!(
            ctx.accounts.recipient_token.key(),
            ctx.accounts.vault_token.key(),
            VaultError::SelfTransfer
        );

        // Buyer + recipient must be allowed (recipient is also re-checked by the hook).
        require!(
            load_allowed(&ctx.accounts.buyer_record, &ctx.accounts.buyer.key(), now)?,
            VaultError::CallerNotAllowed
        );
        require!(
            load_allowed(
                &ctx.accounts.recipient_record,
                &ctx.accounts.recipient_token.owner,
                now
            )?,
            VaultError::RecipientNotAllowed
        );

        let inventory = ctx.accounts.vault_token.amount;
        require!(token_amount <= inventory, VaultError::InsufficientInventory);
        let quote = pricing_math::quote_purchase(
            token_amount,
            ctx.accounts.strategy.purchase_price,
            ctx.accounts.strategy.token_decimals,
        )
        .map_err(|_| error!(VaultError::PricingFailed))?;
        require!(quote <= max_quote_amount, VaultError::QuoteAboveMax);

        // Snapshot the RWA balances BEFORE the quote CPI, not after, so the
        // delta check below never spans an intervening transfer. (These are RWA
        // accounts and the quote leg touches only quote accounts, so aliasing is
        // impossible anyway now that the mints are required distinct — belt and
        // braces.)
        let vault_before = ctx.accounts.vault_token.amount;
        let recipient_before = ctx.accounts.recipient_token.amount;

        // Pull exact quote from the buyer, verifying the received delta.
        let before = ctx.accounts.vault_quote.amount;
        transfer_checked(
            CpiContext::new(
                ctx.accounts.quote_token_program.key(),
                TransferChecked {
                    from: ctx.accounts.buyer_quote.to_account_info(),
                    mint: ctx.accounts.quote_mint.to_account_info(),
                    to: ctx.accounts.vault_quote.to_account_info(),
                    authority: ctx.accounts.buyer.to_account_info(),
                },
            ),
            quote,
            ctx.accounts.quote_mint.decimals,
        )?;
        ctx.accounts.vault_quote.reload()?;
        let received = ctx.accounts.vault_quote.amount - before;
        require!(received == quote, VaultError::QuoteDeltaMismatch);

        // Send RWA to the recipient (fires the compliance hook via remaining_accounts).
        // Verify the exact amount was debited from the vault and credited to the
        // recipient (defense in depth beyond the no-fee-extension gate).
        let bump = c.bump;
        let seeds: &[&[&[u8]]] = &[&[CONFIG_SEED, &[bump]]];
        invoke_transfer_checked(
            &ctx.accounts.rwa_token_program.key(),
            ctx.accounts.vault_token.to_account_info(),
            ctx.accounts.rwa_mint.to_account_info(),
            ctx.accounts.recipient_token.to_account_info(),
            ctx.accounts.config.to_account_info(),
            ctx.remaining_accounts,
            token_amount,
            ctx.accounts.rwa_mint.decimals,
            seeds,
        )?;
        ctx.accounts.vault_token.reload()?;
        ctx.accounts.recipient_token.reload()?;
        require!(
            vault_before - ctx.accounts.vault_token.amount == token_amount
                && ctx.accounts.recipient_token.amount - recipient_before == token_amount,
            VaultError::RwaDeltaMismatch
        );

        emit!(Purchased {
            buyer: ctx.accounts.buyer.key(),
            recipient: ctx.accounts.recipient_token.owner,
            token_amount,
            quote_amount: quote,
        });
        Ok(())
    }

    pub fn withdraw_proceeds(ctx: Context<WithdrawProceeds>, amount: u64) -> Result<()> {
        let c = &ctx.accounts.config;
        // Gate on finalization for consistency with `buy` and the redemption
        // legs (there are no proceeds before go-live, so this only rejects premature
        // calls).
        require!(ctx.accounts.registry.finalized, VaultError::NotFinalized);
        require!(!ctx.accounts.registry.paused, VaultError::ProjectPaused);

        let before = ctx.accounts.treasury_quote.amount;
        let seeds: &[&[&[u8]]] = &[&[CONFIG_SEED, &[c.bump]]];
        transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.quote_token_program.key(),
                TransferChecked {
                    from: ctx.accounts.vault_quote.to_account_info(),
                    mint: ctx.accounts.quote_mint.to_account_info(),
                    to: ctx.accounts.treasury_quote.to_account_info(),
                    authority: ctx.accounts.config.to_account_info(),
                },
                seeds,
            ),
            amount,
            ctx.accounts.quote_mint.decimals,
        )?;
        ctx.accounts.treasury_quote.reload()?;
        let received = ctx.accounts.treasury_quote.amount - before;
        require!(received == amount, VaultError::QuoteDeltaMismatch);

        emit!(ProceedsWithdrawn {
            treasury: c.treasury,
            amount,
            by: ctx.accounts.treasurer.key()
        });
        Ok(())
    }

    pub fn set_treasury(ctx: Context<AdminOnly>, new_treasury: Pubkey) -> Result<()> {
        require_keys_neq!(new_treasury, Pubkey::default(), VaultError::ZeroAddress);
        let previous = ctx.accounts.config.treasury;
        ctx.accounts.config.treasury = new_treasury;
        emit!(RoleChanged {
            role: Role::Treasury as u8,
            previous,
            new_value: new_treasury,
            by: ctx.accounts.admin.key(),
        });
        Ok(())
    }

    /// Rotate the treasurer.
    pub fn set_treasurer(ctx: Context<AdminOnly>, new_treasurer: Pubkey) -> Result<()> {
        require_keys_neq!(new_treasurer, Pubkey::default(), VaultError::ZeroAddress);
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

    /// Two-step admin rotation (propose). Rejects a zero pending admin and emits
    /// the proposal.
    pub fn propose_admin(ctx: Context<AdminOnly>, new_admin: Pubkey) -> Result<()> {
        require_keys_neq!(new_admin, Pubkey::default(), VaultError::ZeroAddress);
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
            VaultError::NoPendingAdmin
        );
        require_keys_eq!(
            ctx.accounts.new_admin.key(),
            c.pending_admin,
            VaultError::NotPendingAdmin
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
}

/// Verify `record` is the canonical PDA for `wallet` and evaluate the allowlist.
fn load_allowed(record: &UncheckedAccount, wallet: &Pubkey, now: u64) -> Result<bool> {
    let (expected, _) =
        Pubkey::find_program_address(&[RECORD_SEED, wallet.as_ref()], &rwa_compliance::ID);
    require_keys_eq!(record.key(), expected, VaultError::RecordMismatch);
    let info = record.to_account_info();
    if info.owner != &rwa_compliance::ID {
        return Ok(false);
    }
    let data = info.try_borrow_data()?;
    if data.len() < 8 + 32 + 1 + 8 + 1 {
        return Ok(false);
    }
    let rec = ComplianceRecord::try_deserialize(&mut &data[..])
        .map_err(|_| error!(VaultError::RecordMismatch))?;
    Ok(record_is_allowed(&rec, now))
}

#[account]
pub struct Config {
    pub admin: Pubkey,
    pub pending_admin: Pubkey,
    pub treasurer: Pubkey,
    pub treasury: Pubkey,
    /// supply-controller config PDA allowed to call `controller_burn`.
    pub supply_controller: Pubkey,
    pub rwa_mint: Pubkey,
    pub quote_mint: Pubkey,
    /// the quote mint's decimals, bound at `initialize` to the price scale.
    pub quote_decimals: u8,
    pub strategy: Pubkey,
    pub registry: Pubkey,
    pub bump: u8,
}

impl Config {
    pub const SPACE: usize = 8 + 32 * 9 + 1 + 1;
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
    #[account(constraint = program.programdata_address()? == Some(program_data.key()) @ VaultError::NotUpgradeAuthority)]
    pub program: Program<'info, crate::program::RwaVault>,
    #[account(constraint = program_data.upgrade_authority_address == Some(payer.key()) @ VaultError::NotUpgradeAuthority)]
    pub program_data: Account<'info, ProgramData>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ControllerBurn<'info> {
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,
    #[account(mut, address = config.rwa_mint @ VaultError::WrongMint)]
    pub mint: Box<InterfaceAccount<'info, Mint>>,
    /// Pinned to the canonical inventory ATA of the vault PDA.
    #[account(
        mut,
        token::mint = mint,
        token::authority = config,
        address = anchor_spl::associated_token::get_associated_token_address_with_program_id(
            &config.key(), &mint.key(), mint.to_account_info().owner
        ) @ VaultError::NotCanonicalAta,
    )]
    pub vault_token: Box<InterfaceAccount<'info, TokenAccount>>,
    /// The supply-controller config PDA, signing via CPI seeds.
    pub supply_controller: Signer<'info>,
    /// The RWA leg is always Token-2022; pin the program so the hand-built
    /// permissioned-burn CPI can never be delivered to a substituted program.
    #[account(address = anchor_spl::token_2022::ID @ VaultError::WrongTokenProgram)]
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct AcceptAdmin<'info> {
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,
    pub new_admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct Buy<'info> {
    #[account(
        seeds = [CONFIG_SEED],
        bump = config.bump,
        has_one = registry @ VaultError::WrongRegistry,
        has_one = strategy @ VaultError::WrongStrategy,
    )]
    // Boxed to keep the anchor-1.1 `try_accounts` frame under the 4 KB SBF stack.
    pub config: Box<Account<'info, Config>>,
    #[account(seeds = [rwa_compliance::REGISTRY_SEED], bump = registry.bump, seeds::program = rwa_compliance::ID)]
    pub registry: Box<Account<'info, Registry>>,
    /// Pinned to the canonical pricing `Strategy` PDA.
    #[account(seeds = [rwa_pricing::STRATEGY_SEED], bump = strategy.bump, seeds::program = rwa_pricing::ID)]
    pub strategy: Box<Account<'info, Strategy>>,
    /// Read-only — `transfer_checked` takes the mint read-only, so a write
    /// lock would needlessly serialize every buy against the mint.
    #[account(address = config.rwa_mint @ VaultError::WrongMint)]
    pub rwa_mint: Box<InterfaceAccount<'info, Mint>>,
    #[account(address = config.quote_mint @ VaultError::WrongMint)]
    pub quote_mint: Box<InterfaceAccount<'info, Mint>>,
    /// Pinned to the canonical inventory ATA of the vault PDA.
    #[account(
        mut,
        token::mint = rwa_mint,
        token::authority = config,
        address = anchor_spl::associated_token::get_associated_token_address_with_program_id(
            &config.key(), &rwa_mint.key(), rwa_mint.to_account_info().owner
        ) @ VaultError::NotCanonicalAta,
    )]
    pub vault_token: Box<InterfaceAccount<'info, TokenAccount>>,
    /// Pinned to the canonical quote-proceeds ATA of the vault PDA.
    #[account(
        mut,
        token::mint = quote_mint,
        token::authority = config,
        address = anchor_spl::associated_token::get_associated_token_address_with_program_id(
            &config.key(), &quote_mint.key(), quote_mint.to_account_info().owner
        ) @ VaultError::NotCanonicalAta,
    )]
    pub vault_quote: Box<InterfaceAccount<'info, TokenAccount>>,
    pub buyer: Signer<'info>,
    #[account(mut, token::mint = quote_mint, token::authority = buyer)]
    pub buyer_quote: Box<InterfaceAccount<'info, TokenAccount>>,
    #[account(mut, token::mint = rwa_mint)]
    pub recipient_token: Box<InterfaceAccount<'info, TokenAccount>>,
    /// CHECK: buyer's compliance record, verified in-handler.
    pub buyer_record: UncheckedAccount<'info>,
    /// CHECK: recipient's compliance record, verified in-handler.
    pub recipient_record: UncheckedAccount<'info>,
    /// Pinned to the quote mint's own owning program, consistent with the
    /// `rwa_token_program` pin. (The quote ATA addresses are derived from this
    /// owner, so a mismatch already fails closed; this makes it explicit.)
    #[account(address = *quote_mint.to_account_info().owner @ VaultError::WrongTokenProgram)]
    pub quote_token_program: Interface<'info, TokenInterface>,
    /// CHECK: pinned to the Token-2022 program id (the RWA leg is always
    /// Token-2022); further validated by invoke.
    #[account(address = anchor_spl::token_2022::ID @ VaultError::WrongTokenProgram)]
    pub rwa_token_program: UncheckedAccount<'info>,
    // remaining_accounts: the transfer-hook program + its extra accounts
    // (extra-meta-list PDA, compliance program, registry, source & dest records).
}

#[derive(Accounts)]
pub struct WithdrawProceeds<'info> {
    #[account(
        seeds = [CONFIG_SEED],
        bump = config.bump,
        has_one = registry @ VaultError::WrongRegistry,
        has_one = treasurer @ VaultError::NotTreasurer,
    )]
    pub config: Box<Account<'info, Config>>,
    #[account(seeds = [rwa_compliance::REGISTRY_SEED], bump = registry.bump, seeds::program = rwa_compliance::ID)]
    pub registry: Box<Account<'info, Registry>>,
    #[account(address = config.quote_mint @ VaultError::WrongMint)]
    pub quote_mint: Box<InterfaceAccount<'info, Mint>>,
    /// Pinned to the canonical quote-proceeds ATA of the vault PDA.
    #[account(
        mut,
        token::mint = quote_mint,
        token::authority = config,
        address = anchor_spl::associated_token::get_associated_token_address_with_program_id(
            &config.key(), &quote_mint.key(), quote_mint.to_account_info().owner
        ) @ VaultError::NotCanonicalAta,
    )]
    pub vault_quote: Box<InterfaceAccount<'info, TokenAccount>>,
    /// Proceeds land in the treasury's canonical ATA, not any account it owns.
    #[account(
        mut,
        token::mint = quote_mint,
        token::authority = config.treasury,
        address = anchor_spl::associated_token::get_associated_token_address_with_program_id(
            &config.treasury, &quote_mint.key(), quote_mint.to_account_info().owner
        ) @ VaultError::NotCanonicalAta,
    )]
    pub treasury_quote: Box<InterfaceAccount<'info, TokenAccount>>,
    pub treasurer: Signer<'info>,
    /// Pinned to the quote mint's own owning program.
    #[account(address = *quote_mint.to_account_info().owner @ VaultError::WrongTokenProgram)]
    pub quote_token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct AdminOnly<'info> {
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump, has_one = admin @ VaultError::NotAdmin)]
    pub config: Box<Account<'info, Config>>,
    pub admin: Signer<'info>,
}

#[event]
pub struct Purchased {
    pub buyer: Pubkey,
    pub recipient: Pubkey,
    pub token_amount: u64,
    pub quote_amount: u64,
}

#[event]
pub struct ProceedsWithdrawn {
    pub treasury: Pubkey,
    pub amount: u64,
    pub by: Pubkey,
}

/// Role label for `RoleChanged`.
#[repr(u8)]
pub enum Role {
    Treasury = 1,
    Treasurer = 2,
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
pub enum VaultError {
    #[msg("zero address")]
    ZeroAddress,
    #[msg("project is paused")]
    ProjectPaused,
    #[msg("deadline expired")]
    DeadlineExpired,
    #[msg("amount must be non-zero")]
    ZeroAmount,
    #[msg("buyer is not allowed")]
    CallerNotAllowed,
    #[msg("recipient is not allowed")]
    RecipientNotAllowed,
    #[msg("insufficient inventory")]
    InsufficientInventory,
    #[msg("quote above max")]
    QuoteAboveMax,
    #[msg("quote delta mismatch")]
    QuoteDeltaMismatch,
    #[msg("pricing failed")]
    PricingFailed,
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
    #[msg("caller is not the admin")]
    NotAdmin,
    #[msg("caller is not the pending admin")]
    NotPendingAdmin,
    #[msg("no pending admin transfer to accept")]
    NoPendingAdmin,
    #[msg("caller is not the authorized supply controller")]
    NotSupplyController,
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
    #[msg("recipient RWA account must not be the vault inventory account")]
    SelfTransfer,
    #[msg("RWA transfer delta mismatch")]
    RwaDeltaMismatch,
    #[msg("burn delta mismatch")]
    BurnDeltaMismatch,
}
