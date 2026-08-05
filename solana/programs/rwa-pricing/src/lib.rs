//! rwa-pricing — admin/pricer-updatable fixed purchase & redemption prices.
//!
//! Solana port of `contracts/src/pricing/FixedPriceStrategy.sol`. This program
//! owns the `Strategy` account; the Vault and RedemptionEscrow programs read it
//! (importing this crate with `no-entrypoint`) and apply the shared, host-tested
//! `pricing-math` rounding (purchase = Ceil, redemption = Floor). Swapping the
//! strategy = pointing Vault/Escrow config at a different `Strategy` PDA, the
//! parallel to `Vault.setStrategy`.

use anchor_lang::prelude::*;
use pricing_math::{quote_purchase, quote_redemption};

declare_id!("B8a1y3LHPUwv95vSHBhcU6F2Fg4BzmrU17aSoKC5EjDh");

pub const STRATEGY_SEED: &[u8] = b"strategy";

#[program]
pub mod rwa_pricing {
    use super::*;

    pub fn initialize(
        ctx: Context<Initialize>,
        token_decimals: u8,
        purchase_price: u64,
        redemption_price: u64,
        admin: Pubkey,
        pricer: Pubkey,
    ) -> Result<()> {
        require!(
            purchase_price != 0 && redemption_price != 0,
            PricingErr::ZeroPrice
        );
        require!(
            token_decimals <= pricing_math::MAX_DECIMALS,
            PricingErr::DecimalsTooLarge
        );
        require_keys_neq!(admin, Pubkey::default(), PricingErr::ZeroAddress);
        require_keys_neq!(pricer, Pubkey::default(), PricingErr::ZeroAddress);
        let s = &mut ctx.accounts.strategy;
        s.admin = admin;
        s.pending_admin = Pubkey::default();
        s.pricer = pricer;
        s.token_decimals = token_decimals;
        s.purchase_price = purchase_price;
        s.redemption_price = redemption_price;
        s.bump = ctx.bumps.strategy;
        Ok(())
    }

    /// Rotate the pricer. Admin-gated.
    pub fn set_pricer(ctx: Context<AdminOnly>, new_pricer: Pubkey) -> Result<()> {
        require_keys_neq!(new_pricer, Pubkey::default(), PricingErr::ZeroAddress);
        let previous = ctx.accounts.strategy.pricer;
        ctx.accounts.strategy.pricer = new_pricer;
        emit!(PricerChanged {
            previous,
            new_pricer,
            by: ctx.accounts.admin.key()
        });
        Ok(())
    }

    /// Two-step admin rotation (propose). Rejects a zero pending admin and emits
    /// the proposal.
    pub fn propose_admin(ctx: Context<AdminOnly>, new_admin: Pubkey) -> Result<()> {
        require_keys_neq!(new_admin, Pubkey::default(), PricingErr::ZeroAddress);
        ctx.accounts.strategy.pending_admin = new_admin;
        emit!(AdminProposed {
            new_admin,
            by: ctx.accounts.admin.key()
        });
        Ok(())
    }

    /// Two-step admin rotation (accept).
    pub fn accept_admin(ctx: Context<AcceptAdmin>) -> Result<()> {
        let s = &mut ctx.accounts.strategy;
        require_keys_neq!(
            s.pending_admin,
            Pubkey::default(),
            PricingErr::NoPendingAdmin
        );
        require_keys_eq!(
            ctx.accounts.new_admin.key(),
            s.pending_admin,
            PricingErr::NotPendingAdmin
        );
        let previous = s.admin;
        s.admin = s.pending_admin;
        s.pending_admin = Pubkey::default();
        emit!(AdminChanged {
            previous,
            new_admin: s.admin
        });
        Ok(())
    }

    /// Withdraw a pending admin transfer (current admin only).
    pub fn cancel_admin_transfer(ctx: Context<AdminOnly>) -> Result<()> {
        let cancelled = ctx.accounts.strategy.pending_admin;
        ctx.accounts.strategy.pending_admin = Pubkey::default();
        emit!(AdminTransferCancelled {
            cancelled,
            by: ctx.accounts.admin.key()
        });
        Ok(())
    }

    pub fn set_purchase_price(ctx: Context<PricerOnly>, new_price: u64) -> Result<()> {
        require!(new_price != 0, PricingErr::ZeroPrice);
        let s = &mut ctx.accounts.strategy;
        let previous = s.purchase_price;
        s.purchase_price = new_price;
        emit!(PurchasePriceUpdated {
            previous,
            new_price,
            by: ctx.accounts.pricer.key()
        });
        Ok(())
    }

    pub fn set_redemption_price(ctx: Context<PricerOnly>, new_price: u64) -> Result<()> {
        require!(new_price != 0, PricingErr::ZeroPrice);
        let s = &mut ctx.accounts.strategy;
        let previous = s.redemption_price;
        s.redemption_price = new_price;
        emit!(RedemptionPriceUpdated {
            previous,
            new_price,
            by: ctx.accounts.pricer.key()
        });
        Ok(())
    }
}

#[account]
pub struct Strategy {
    pub admin: Pubkey,
    pub pending_admin: Pubkey,
    pub pricer: Pubkey,
    pub token_decimals: u8,
    pub purchase_price: u64,
    pub redemption_price: u64,
    pub bump: u8,
}

impl Strategy {
    pub const SPACE: usize = 8 + 32 + 32 + 32 + 1 + 8 + 8 + 1;

    /// Quote a buyer pays (rounds up) — used by the Vault program.
    pub fn quote_purchase(&self, token_amount: u64) -> std::result::Result<u64, PricingErr> {
        quote_purchase(token_amount, self.purchase_price, self.token_decimals)
            .map_err(map_pricing_err)
    }

    /// Quote a redeemer receives (rounds down) — used by the RedemptionEscrow program.
    pub fn quote_redemption(&self, token_amount: u64) -> std::result::Result<u64, PricingErr> {
        quote_redemption(token_amount, self.redemption_price, self.token_decimals)
            .map_err(map_pricing_err)
    }
}

fn map_pricing_err(e: pricing_math::PricingError) -> PricingErr {
    match e {
        pricing_math::PricingError::ZeroPrice => PricingErr::ZeroPrice,
        pricing_math::PricingError::DecimalsTooLarge => PricingErr::DecimalsTooLarge,
        pricing_math::PricingError::Overflow => PricingErr::Overflow,
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = payer, space = Strategy::SPACE, seeds = [STRATEGY_SEED], bump)]
    pub strategy: Account<'info, Strategy>,
    #[account(mut)]
    pub payer: Signer<'info>,
    // Only the program's deployer (upgrade authority) may bootstrap it.
    #[account(constraint = program.programdata_address()? == Some(program_data.key()) @ PricingErr::NotUpgradeAuthority)]
    pub program: Program<'info, crate::program::RwaPricing>,
    #[account(constraint = program_data.upgrade_authority_address == Some(payer.key()) @ PricingErr::NotUpgradeAuthority)]
    pub program_data: Account<'info, ProgramData>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct PricerOnly<'info> {
    #[account(mut, seeds = [STRATEGY_SEED], bump = strategy.bump, has_one = pricer @ PricingErr::NotPricer)]
    pub strategy: Account<'info, Strategy>,
    pub pricer: Signer<'info>,
}

#[derive(Accounts)]
pub struct AdminOnly<'info> {
    #[account(mut, seeds = [STRATEGY_SEED], bump = strategy.bump, has_one = admin @ PricingErr::NotAdmin)]
    pub strategy: Account<'info, Strategy>,
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct AcceptAdmin<'info> {
    #[account(mut, seeds = [STRATEGY_SEED], bump = strategy.bump)]
    pub strategy: Account<'info, Strategy>,
    pub new_admin: Signer<'info>,
}

#[event]
pub struct PurchasePriceUpdated {
    pub previous: u64,
    pub new_price: u64,
    pub by: Pubkey,
}

#[event]
pub struct RedemptionPriceUpdated {
    pub previous: u64,
    pub new_price: u64,
    pub by: Pubkey,
}

#[event]
pub struct PricerChanged {
    pub previous: Pubkey,
    pub new_pricer: Pubkey,
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
pub enum PricingErr {
    #[msg("zero address")]
    ZeroAddress,
    #[msg("price must be non-zero")]
    ZeroPrice,
    #[msg("token decimals too large")]
    DecimalsTooLarge,
    #[msg("quote overflow")]
    Overflow,
    #[msg("caller is not the pricer")]
    NotPricer,
    #[msg("caller is not the admin")]
    NotAdmin,
    #[msg("caller is not the pending admin")]
    NotPendingAdmin,
    #[msg("no pending admin transfer to accept")]
    NoPendingAdmin,
    #[msg("caller is not the program upgrade authority")]
    NotUpgradeAuthority,
}
