//! rwa-supply-controller — auditor-attested mint/burn.
//!
//! Solana port of `contracts/src/SupplyController.sol`. Enforces the platform's
//! non-negotiable invariant: **every supply increase requires a valid auditor
//! signature** bound to this deployment, one record, one amount, one Vault, one
//! unused nonce — and **all minting targets the Vault, never investors**.
//!
//! Signatures stay **secp256k1 / ECDSA** so the *same offline signer and auditor
//! key* secure Solidity and Solana. Verification uses the `secp256k1_recover`
//! syscall over the Solana-bound digest from the `attestation` crate (domain =
//! cluster + this program id + this config PDA, replacing chainId +
//! verifyingContract). Recovered eth address must equal the stored `auditor_eth`.
//!
//! Replay protection uses PDA *markers*: `mint` inits a nonce marker and a
//! record-key marker; `burn` inits a nonce marker and an operation marker. `init`
//! fails if the marker already exists (the used-nonce / used-key check), and — as
//! with every Anchor `init` — is rolled back if the handler later errors, so a
//! rejected attestation never consumes a nonce.
//!
//! Token custody: the mint's mint-authority is this config PDA (so only this
//! program can mint), and the Vault inventory token account delegates burn rights
//! to this config PDA at bootstrap (so this program can burn returned inventory
//! without the Vault program's involvement, mirroring `controllerBurn`).

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{mint_to, Mint, MintTo, TokenAccount, TokenInterface};
use attestation::{BurnAttestation, Domain, MintAttestation};
use rwa_compliance::Registry;
use rwa_transfer_hook::{validate_extra_account_meta_list, validate_rwa_mint};
use solana_secp256k1_recover::secp256k1_recover;

// Sibling configs read (typed, PDA-pinned) during `finalize` to cross-check
// every stored trust edge before the deployment is allowed to go live.
use rwa_pricing::Strategy as PricingStrategy;
use rwa_redemption::Config as RedemptionConfig;
use rwa_vault::Config as VaultConfig;

declare_id!("FtiSEvVU51FBuXuD5fBK1JDqeyAayJwuNSJx7vXGPQBT");

pub const CONFIG_SEED: &[u8] = b"supply-config";
pub const NONCE_SEED: &[u8] = b"nonce";
pub const RECORD_KEY_SEED: &[u8] = b"record-key";
pub const OPERATION_SEED: &[u8] = b"operation";

#[program]
pub mod rwa_supply_controller {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    pub fn initialize(
        ctx: Context<Initialize>,
        admin: Pubkey,
        auditor_eth: [u8; 20],
        profile_digest: [u8; 32],
        cluster: [u8; 32],
    ) -> Result<()> {
        require_keys_neq!(admin, Pubkey::default(), SupplyError::ZeroAddress);
        require!(auditor_eth != [0u8; 20], SupplyError::ZeroAuditor);
        // Reject an all-zero cluster. `cluster` is the only per-deployment
        // entropy separating two deployments that reuse program keypairs (its
        // config PDA, program id and vault are all pure functions of the program
        // id), so an unset value would collapse the domain separator toward a shared
        // value. It is re-asserted, independently restated, at `finalize`.
        require!(cluster != [0u8; 32], SupplyError::ZeroCluster);

        // The RWA mint must be a Token-2022 mint whose transfer hook is our
        // compliance hook, whose mint authority is THIS config PDA, and whose hook
        // update authority is already revoked (immutable hook) — and it must carry
        // no balance-affecting / seize extension. Without this a deployment could
        // wire a legacy or hookless mint and bypass compliance entirely.
        let config_key = ctx.accounts.config.key();
        validate_rwa_mint(
            &ctx.accounts.mint.to_account_info(),
            Some(config_key),
            true,
            Some(config_key),
        )
        .map_err(|_| error!(SupplyError::UnsafeMint))?;

        let c = &mut ctx.accounts.config;
        c.admin = admin;
        c.pending_admin = Pubkey::default();
        c.auditor_eth = auditor_eth;
        c.token_mint = ctx.accounts.mint.key();
        c.vault = ctx.accounts.vault_authority.key();
        c.registry = ctx.accounts.registry.key();
        c.profile_digest = profile_digest;
        // `cluster` is the 32-byte cluster genesis hash, supplied by the
        // (upgrade-authority-gated) deployer. It binds every attestation to this
        // cluster; deployment tooling MUST pass the real base58-decoded genesis
        // hash and verify the stored domain off-chain before trusting signatures.
        c.cluster = cluster;
        c.finalized = false;
        c.bump = ctx.bumps.config;
        Ok(())
    }

    /// Verify the whole singleton stack is wired correctly, then flip the
    /// global go-live flag. Gated on the config admin + the registry admin; the
    /// deployer-binding lives in the `set_finalized` CPI, which requires the
    /// compliance program's upgrade authority. `finalize` no longer
    /// carries the supply-controller's own upgrade-authority gate, so revoking that
    /// authority or rotating the config admin before go-live no longer bricks it —
    /// but the deployer must still finalize BEFORE any such change. Runnable only
    /// after every program has been initialized and the compliance system
    /// addresses pinned. The sibling configs are passed as typed, PDA-pinned
    /// accounts (`seeds::program` = the compiled sibling program id), so a caller
    /// cannot substitute look-alikes; every stored cross-program address is then
    /// cross-checked in both directions. On success it sets its own `finalized`
    /// flag (gating mint/burn) and CPIs `rwa_compliance::set_finalized` to set the
    /// registry flag that gates buy and every redemption leg. Nothing is
    /// mint/buy/redeem-able before this passes, so a bootstrap typo is caught
    /// while it is still recoverable rather than after assets exist.
    pub fn finalize(ctx: Context<Finalize>, cluster: [u8; 32]) -> Result<()> {
        let sc = ctx.accounts.config.key();
        let v = ctx.accounts.vault_config.key();
        let r = ctx.accounts.redemption_config.key();
        let reg = ctx.accounts.registry.key();
        let strat = ctx.accounts.strategy.key();
        let mint = ctx.accounts.mint.key();

        require!(
            !ctx.accounts.config.finalized,
            SupplyError::AlreadyFinalized
        );

        // The deployer must independently restate the cluster genesis
        // hash at go-live; it must equal the value pinned at `initialize`. Solana
        // exposes no genesis-hash syscall, so the binding cannot be checked against
        // the runtime — but forcing the deployer to derive and pass it a second time
        // catches a mistyped `initialize` cluster while the deployment is still
        // recoverable (nothing is minted before `finalize`).
        require!(
            ctx.accounts.config.cluster == cluster,
            SupplyError::ClusterMismatch
        );

        // This controller's own wiring.
        require_keys_eq!(ctx.accounts.config.vault, v, SupplyError::WiringMismatch);
        require_keys_eq!(
            ctx.accounts.config.registry,
            reg,
            SupplyError::WiringMismatch
        );
        require_keys_eq!(
            ctx.accounts.config.token_mint,
            mint,
            SupplyError::WiringMismatch
        );

        // Vault points back at THIS controller (blocks a rogue `supply_controller`
        // that could otherwise drive `controller_burn`) and shares mint/registry.
        require_keys_eq!(
            ctx.accounts.vault_config.supply_controller,
            sc,
            SupplyError::WiringMismatch
        );
        require_keys_eq!(
            ctx.accounts.vault_config.rwa_mint,
            mint,
            SupplyError::WiringMismatch
        );
        require_keys_eq!(
            ctx.accounts.vault_config.registry,
            reg,
            SupplyError::WiringMismatch
        );
        require_keys_eq!(
            ctx.accounts.vault_config.strategy,
            strat,
            SupplyError::WiringMismatch
        );

        // Redemption shares the Vault, mint, registry, quote mint, and strategy.
        require_keys_eq!(
            ctx.accounts.redemption_config.vault,
            v,
            SupplyError::WiringMismatch
        );
        require_keys_eq!(
            ctx.accounts.redemption_config.rwa_mint,
            mint,
            SupplyError::WiringMismatch
        );
        require_keys_eq!(
            ctx.accounts.redemption_config.registry,
            reg,
            SupplyError::WiringMismatch
        );
        require_keys_eq!(
            ctx.accounts.redemption_config.quote_mint,
            ctx.accounts.vault_config.quote_mint,
            SupplyError::WiringMismatch
        );
        require_keys_eq!(
            ctx.accounts.redemption_config.strategy,
            strat,
            SupplyError::WiringMismatch
        );

        // The RWA mint and the quote mint must be distinct, or the
        // exact-delta accounting on every quote leg could measure overlapping
        // balances. Rejected at each initializer; re-asserted here.
        require_keys_neq!(
            mint,
            ctx.accounts.vault_config.quote_mint,
            SupplyError::MintQuoteSame
        );

        // Compliance pins the canonical Vault + escrow (= redemption config) PDAs.
        require!(
            ctx.accounts.registry.system_set,
            SupplyError::WiringMismatch
        );
        require_keys_eq!(ctx.accounts.registry.vault, v, SupplyError::WiringMismatch);
        require_keys_eq!(ctx.accounts.registry.escrow, r, SupplyError::WiringMismatch);
        // The supply-controller id the registry pinned must be THIS program,
        // so the `set_finalized` CPI signer check authenticates the real controller.
        require_keys_eq!(
            ctx.accounts.registry.supply_controller,
            crate::ID,
            SupplyError::WiringMismatch
        );
        // The registry's pinned RWA mint — the one field the
        // transfer hook treats as authoritative (`require_keys_eq!(mint,
        // registry.rwa_mint)` on every transfer) — must equal the mint the whole
        // mesh is wired to. Without this a bootstrap typo in the `rwa_mint` passed
        // to `set_system_addresses` could finalize (and even accept an
        // auditor-attested mint, which skips the hook) while every ordinary RWA
        // transfer fails `WrongMint` — a finalized-but-non-transferable deployment.
        require_keys_eq!(
            ctx.accounts.registry.rwa_mint,
            mint,
            SupplyError::WiringMismatch
        );

        // Pricing decimals still match the mint, and the mint is still a
        // safe Token-2022 + our-hook mint with THIS controller as mint authority
        // and no freeze authority / disallowed extension.
        require!(
            ctx.accounts.strategy.token_decimals == ctx.accounts.mint.decimals,
            SupplyError::DecimalsMismatch
        );
        // The vault and escrow must agree on the quote mint's decimals
        // (each bound it to its own price scale at `initialize`; `finalize` already
        // proved they share the same quote mint, so the scales must match too).
        require!(
            ctx.accounts.vault_config.quote_decimals
                == ctx.accounts.redemption_config.quote_decimals,
            SupplyError::QuoteDecimalsMismatch
        );
        validate_rwa_mint(
            &ctx.accounts.mint.to_account_info(),
            Some(sc),
            true,
            Some(sc),
        )
        .map_err(|_| error!(SupplyError::UnsafeMint))?;

        // Prove the transfer-hook's `ExtraAccountMetaList`
        // resolution PDA for this mint exists, is hook-owned, and carries the
        // canonical entries. `validate_rwa_mint` only proves the mint's hook
        // extension points at our program; it says nothing about the separate
        // account Token-2022 needs to resolve the compliance program + records for
        // each transfer. Checking it here means a finalized deployment can actually
        // move RWA on the first real transfer, not merely mint stuck inventory.
        validate_extra_account_meta_list(
            &ctx.accounts.extra_account_meta_list.to_account_info(),
            &mint,
        )
        .map_err(|_| error!(SupplyError::MetaListInvalid))?;

        let bump = ctx.accounts.config.bump;
        ctx.accounts.config.finalized = true;

        // Flip the global flag every other program reads. We sign the CPI as
        // THIS config PDA (`supply_config`), which `rwa_compliance::set_finalized`
        // verifies against its compiled-in supply-controller id — so the registry
        // flag can only ever be set here, after the wiring checks above, and never
        // by a direct call. The registry admin co-signs as before.
        let sc_seeds: &[&[u8]] = &[CONFIG_SEED, &[bump]];
        rwa_compliance::cpi::set_finalized(CpiContext::new_with_signer(
            ctx.accounts.compliance_program.key(),
            rwa_compliance::cpi::accounts::SetFinalized {
                registry: ctx.accounts.registry.to_account_info(),
                admin: ctx.accounts.registry_admin.to_account_info(),
                supply_config: ctx.accounts.config.to_account_info(),
                // The compliance program + its ProgramData, so `set_finalized`
                // can bind go-live to the compliance deployer (== registry admin).
                program: ctx.accounts.compliance_program.to_account_info(),
                program_data: ctx.accounts.compliance_program_data.to_account_info(),
            },
            &[sc_seeds],
        ))?;

        emit!(Finalized {
            supply: sc,
            vault: v,
            escrow: r,
            registry: reg,
            strategy: strat,
            mint,
        });
        Ok(())
    }

    /// Verify a mint attestation and mint `amount` to the Vault inventory account.
    #[allow(clippy::too_many_arguments)]
    pub fn mint(
        ctx: Context<MintSupply>,
        record_key: [u8; 32],
        metadata_digest: [u8; 32],
        amount: u64,
        nonce: [u8; 32],
        valid_until: u64,
        signature: [u8; 64],
        recovery_id: u8,
    ) -> Result<()> {
        let c = &ctx.accounts.config;
        require!(c.finalized, SupplyError::NotFinalized);
        require!(!ctx.accounts.registry.paused, SupplyError::ProjectPaused);
        require!(valid_until >= now()?, SupplyError::AttestationExpired);
        require!(amount != 0, SupplyError::ZeroAmount);

        let att = MintAttestation {
            auditor: c.auditor_eth,
            profile_digest: c.profile_digest,
            record_key,
            metadata_digest,
            amount,
            nonce,
            valid_until,
            vault: c.vault.to_bytes(),
        };
        verify_signature(
            &att.digest(&domain(c)),
            &signature,
            recovery_id,
            &c.auditor_eth,
        )?;

        // markers (nonce + record_key) are init'd via the accounts context; reaching
        // here means neither existed. Now perform the mint.
        let seeds: &[&[u8]] = &[CONFIG_SEED, &[c.bump]];
        mint_to(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.key(),
                MintTo {
                    mint: ctx.accounts.mint.to_account_info(),
                    to: ctx.accounts.vault_token.to_account_info(),
                    authority: ctx.accounts.config.to_account_info(),
                },
                &[seeds],
            ),
            amount,
        )?;

        emit!(Minted {
            record_key,
            metadata_digest,
            vault: c.vault,
            amount,
            nonce
        });
        Ok(())
    }

    /// Verify a burn attestation and burn `amount` of returned Vault inventory.
    #[allow(clippy::too_many_arguments)]
    pub fn burn_supply(
        ctx: Context<BurnSupply>,
        operation_id: [u8; 32],
        metadata_digest: [u8; 32],
        amount: u64,
        nonce: [u8; 32],
        valid_until: u64,
        signature: [u8; 64],
        recovery_id: u8,
    ) -> Result<()> {
        let c = &ctx.accounts.config;
        require!(c.finalized, SupplyError::NotFinalized);
        require!(!ctx.accounts.registry.paused, SupplyError::ProjectPaused);
        require!(valid_until >= now()?, SupplyError::AttestationExpired);
        require!(amount != 0, SupplyError::ZeroAmount);
        require!(
            ctx.accounts.vault_token.amount >= amount,
            SupplyError::InsufficientVaultInventory
        );

        let att = BurnAttestation {
            auditor: c.auditor_eth,
            profile_digest: c.profile_digest,
            operation_id,
            metadata_digest,
            amount,
            nonce,
            valid_until,
            vault: c.vault.to_bytes(),
        };
        verify_signature(
            &att.digest(&domain(c)),
            &signature,
            recovery_id,
            &c.auditor_eth,
        )?;

        // The Vault PDA owns the inventory account, so it must sign the burn.
        // We CPI a narrowly-scoped Vault `controller_burn`, authenticating this
        // supply-controller config PDA (a signer via seeds) that the Vault checks
        // against its stored `supply_controller`. No standing unlimited delegate.
        let bump = c.bump;
        let seeds: &[&[u8]] = &[CONFIG_SEED, &[bump]];
        rwa_vault::cpi::controller_burn(
            CpiContext::new_with_signer(
                ctx.accounts.vault_program.key(),
                rwa_vault::cpi::accounts::ControllerBurn {
                    config: ctx.accounts.vault_config.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                    vault_token: ctx.accounts.vault_token.to_account_info(),
                    supply_controller: ctx.accounts.config.to_account_info(),
                    token_program: ctx.accounts.token_program.to_account_info(),
                },
                &[seeds],
            ),
            amount,
        )?;

        emit!(Burned {
            operation_id,
            metadata_digest,
            vault: ctx.accounts.config.vault,
            amount,
            nonce
        });
        Ok(())
    }

    pub fn set_auditor(ctx: Context<AdminOnly>, new_auditor_eth: [u8; 20]) -> Result<()> {
        require!(new_auditor_eth != [0u8; 20], SupplyError::ZeroAuditor);
        let c = &mut ctx.accounts.config;
        let previous = c.auditor_eth;
        c.auditor_eth = new_auditor_eth;
        emit!(AuditorChanged {
            previous,
            new_auditor: new_auditor_eth,
            by: ctx.accounts.admin.key()
        });
        Ok(())
    }

    /// Two-step admin rotation (propose). Rejects a zero pending admin and emits
    /// the proposal.
    pub fn propose_admin(ctx: Context<AdminOnly>, new_admin: Pubkey) -> Result<()> {
        require_keys_neq!(new_admin, Pubkey::default(), SupplyError::ZeroAddress);
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
            SupplyError::NoPendingAdmin
        );
        require_keys_eq!(
            ctx.accounts.new_admin.key(),
            c.pending_admin,
            SupplyError::NotPendingAdmin
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

fn now() -> Result<u64> {
    Ok(Clock::get()?.unix_timestamp as u64)
}

fn domain(c: &Config) -> Domain {
    Domain {
        cluster: c.cluster,
        program: crate::ID.to_bytes(),
        config: config_pda().to_bytes(),
    }
}

fn config_pda() -> Pubkey {
    Pubkey::find_program_address(&[CONFIG_SEED], &crate::ID).0
}

/// Half the secp256k1 curve order (n/2), big-endian. A signature with `s` above
/// this is the malleable "high-S" encoding of an otherwise-valid signature.
const SECP256K1_HALF_ORDER: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
];

/// `secp256k1_recover` the signer of `digest` and require it equals `auditor_eth`.
fn verify_signature(
    digest: &[u8; 32],
    signature: &[u8; 64],
    recovery_id: u8,
    auditor_eth: &[u8; 20],
) -> Result<()> {
    // Reject malleable high-S signatures before recovery, matching the EVM
    // twin (OpenZeppelin `ECDSA.tryRecover`). `agave`'s `secp256k1_recover` accepts
    // either encoding of a signature, so without this the Solana port would accept a
    // signature the EVM deployment rejects — a parity break for a stack whose whole
    // premise is one auditor key for both chains — and could confuse any off-chain
    // component that dedupes attestations by signature bytes. `signature[32..64]` is
    // the 32-byte big-endian `s`.
    let s = &signature[32..64];
    require!(
        s <= &SECP256K1_HALF_ORDER[..],
        SupplyError::MalleableSignature
    );

    let recovered = secp256k1_recover(digest, recovery_id, signature)
        .map_err(|_| error!(SupplyError::InvalidSignature))?;
    let addr = attestation::eth_address_from_pubkey(&recovered.to_bytes());
    require!(addr == *auditor_eth, SupplyError::InvalidSignature);
    Ok(())
}

#[account]
pub struct Config {
    pub admin: Pubkey,
    pub pending_admin: Pubkey,
    pub auditor_eth: [u8; 20],
    pub token_mint: Pubkey,
    /// Vault inventory-account authority PDA (the attestation `vault` field).
    pub vault: Pubkey,
    pub registry: Pubkey,
    pub profile_digest: [u8; 32],
    pub cluster: [u8; 32],
    /// Set by `finalize` once cross-program wiring is verified; gates mint/burn.
    pub finalized: bool,
    pub bump: u8,
}

impl Config {
    pub const SPACE: usize = 8 + 32 + 32 + 20 + 32 + 32 + 32 + 32 + 32 + 1 + 1;
}

/// One-byte replay marker; existence == "already used".
#[account]
pub struct Marker {
    pub bump: u8,
}

impl Marker {
    pub const SPACE: usize = 8 + 1;
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = payer, space = Config::SPACE, seeds = [CONFIG_SEED], bump)]
    pub config: Box<Account<'info, Config>>,
    /// CHECK: parsed and validated by validate_rwa_mint (Token-2022 + our hook).
    pub mint: Box<InterfaceAccount<'info, Mint>>,
    /// CHECK: stored as the attestation `vault` field (Vault inventory authority).
    pub vault_authority: UncheckedAccount<'info>,
    pub registry: Box<Account<'info, Registry>>,
    #[account(mut)]
    pub payer: Signer<'info>,
    // Only the program's deployer (upgrade authority) may bootstrap it.
    #[account(constraint = program.programdata_address()? == Some(program_data.key()) @ SupplyError::NotUpgradeAuthority)]
    pub program: Program<'info, crate::program::RwaSupplyController>,
    #[account(constraint = program_data.upgrade_authority_address == Some(payer.key()) @ SupplyError::NotUpgradeAuthority)]
    pub program_data: Account<'info, ProgramData>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(record_key: [u8; 32], metadata_digest: [u8; 32], amount: u64, nonce: [u8; 32])]
pub struct MintSupply<'info> {
    #[account(
        seeds = [CONFIG_SEED],
        bump = config.bump,
        has_one = registry @ SupplyError::WrongRegistry,
    )]
    pub config: Box<Account<'info, Config>>,
    #[account(seeds = [rwa_compliance::REGISTRY_SEED], bump = registry.bump, seeds::program = rwa_compliance::ID)]
    pub registry: Box<Account<'info, Registry>>,
    #[account(mut, address = config.token_mint @ SupplyError::WrongMint)]
    pub mint: Box<InterfaceAccount<'info, Mint>>,
    /// The Vault inventory account is pinned to the *canonical ATA* of
    /// `config.vault` for `mint`, not merely to any account this PDA happens to
    /// own. This is the one field an attacker could otherwise choose freely while
    /// a leaked/front-run attestation still verifies; pinning it forces every mint
    /// to the single inventory account (which, being an ATA, also carries
    /// `ImmutableOwner`), so a redirect into an unspendable shadow account that
    /// permanently burns the record key is impossible.
    #[account(
        mut,
        token::mint = mint,
        token::authority = config.vault,
        address = anchor_spl::associated_token::get_associated_token_address_with_program_id(
            &config.vault, &mint.key(), mint.to_account_info().owner
        ) @ SupplyError::NotCanonicalAta,
    )]
    pub vault_token: Box<InterfaceAccount<'info, TokenAccount>>,
    #[account(init, payer = payer, space = Marker::SPACE, seeds = [NONCE_SEED, nonce.as_ref()], bump)]
    pub nonce_marker: Account<'info, Marker>,
    #[account(init, payer = payer, space = Marker::SPACE, seeds = [RECORD_KEY_SEED, record_key.as_ref()], bump)]
    pub record_marker: Account<'info, Marker>,
    #[account(mut)]
    pub payer: Signer<'info>,
    /// The RWA leg is always Token-2022; pin the program so a PDA-signed CPI
    /// (mint_to here, or the forwarded controller_burn) is never delivered to a
    /// caller-substituted program.
    #[account(address = anchor_spl::token_2022::ID @ SupplyError::WrongTokenProgram)]
    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(operation_id: [u8; 32], metadata_digest: [u8; 32], amount: u64, nonce: [u8; 32])]
pub struct BurnSupply<'info> {
    #[account(
        seeds = [CONFIG_SEED],
        bump = config.bump,
        has_one = registry @ SupplyError::WrongRegistry,
    )]
    pub config: Box<Account<'info, Config>>,
    #[account(seeds = [rwa_compliance::REGISTRY_SEED], bump = registry.bump, seeds::program = rwa_compliance::ID)]
    pub registry: Box<Account<'info, Registry>>,
    #[account(mut, address = config.token_mint @ SupplyError::WrongMint)]
    pub mint: Box<InterfaceAccount<'info, Mint>>,
    /// Vault program config (the inventory owner) — must be the pinned vault.
    #[account(address = config.vault @ SupplyError::WrongVault)]
    pub vault_config: Box<Account<'info, rwa_vault::Config>>,
    /// Pinned to the canonical inventory ATA (see `MintSupply`).
    #[account(
        mut,
        token::mint = mint,
        token::authority = config.vault,
        address = anchor_spl::associated_token::get_associated_token_address_with_program_id(
            &config.vault, &mint.key(), mint.to_account_info().owner
        ) @ SupplyError::NotCanonicalAta,
    )]
    pub vault_token: Box<InterfaceAccount<'info, TokenAccount>>,
    #[account(init, payer = payer, space = Marker::SPACE, seeds = [NONCE_SEED, nonce.as_ref()], bump)]
    pub nonce_marker: Account<'info, Marker>,
    #[account(init, payer = payer, space = Marker::SPACE, seeds = [OPERATION_SEED, operation_id.as_ref()], bump)]
    pub operation_marker: Account<'info, Marker>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub vault_program: Program<'info, rwa_vault::program::RwaVault>,
    /// The RWA leg is always Token-2022; pin the program so a PDA-signed CPI
    /// (mint_to here, or the forwarded controller_burn) is never delivered to a
    /// caller-substituted program.
    #[account(address = anchor_spl::token_2022::ID @ SupplyError::WrongTokenProgram)]
    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AdminOnly<'info> {
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump, has_one = admin @ SupplyError::NotAdmin)]
    pub config: Box<Account<'info, Config>>,
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct AcceptAdmin<'info> {
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,
    pub new_admin: Signer<'info>,
}

/// Finalize: all sibling configs are typed `Account<>`s pinned to their
/// canonical PDA (`seeds::program` = the compiled sibling program id), so the
/// caller cannot pass look-alike accounts. `Account<T>` also verifies each is
/// owned by its declaring program. The registry admin co-signs so the CPI that
/// flips the global flag is authorized.
#[derive(Accounts)]
pub struct Finalize<'info> {
    // Heavy accounts are `Box`ed so the generated `try_accounts` deserializes them
    // onto the heap, not the 4 KB SBF stack (anchor 1.1's try_accounts is stack-
    // hungry and this context would otherwise overflow → UB / access violation).
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump, has_one = admin @ SupplyError::NotAdmin)]
    pub config: Box<Account<'info, Config>>,
    pub admin: Signer<'info>,
    #[account(address = config.token_mint @ SupplyError::WrongMint)]
    pub mint: Box<InterfaceAccount<'info, Mint>>,
    #[account(
        mut,
        seeds = [rwa_compliance::REGISTRY_SEED],
        bump = registry.bump,
        seeds::program = rwa_compliance::ID
    )]
    pub registry: Box<Account<'info, Registry>>,
    #[account(
        seeds = [rwa_vault::CONFIG_SEED],
        bump = vault_config.bump,
        seeds::program = rwa_vault::ID
    )]
    pub vault_config: Box<Account<'info, VaultConfig>>,
    #[account(
        seeds = [rwa_redemption::CONFIG_SEED],
        bump = redemption_config.bump,
        seeds::program = rwa_redemption::ID
    )]
    pub redemption_config: Box<Account<'info, RedemptionConfig>>,
    #[account(
        seeds = [rwa_pricing::STRATEGY_SEED],
        bump = strategy.bump,
        seeds::program = rwa_pricing::ID
    )]
    pub strategy: Box<Account<'info, PricingStrategy>>,
    /// Registry admin, whose signature authorizes the `set_finalized` CPI.
    pub registry_admin: Signer<'info>,
    pub compliance_program: Program<'info, rwa_compliance::program::RwaCompliance>,
    // The compliance program's ProgramData, forwarded to `set_finalized` so it
    // can bind go-live to the compliance deployer (== registry admin). Validated on
    // the compliance side (its `SetFinalized` asserts `program.programdata_address()
    // == program_data` and `upgrade_authority == admin`).
    //
    // The supply-controller's OWN upgrade-authority gate has been removed from
    // `finalize`. It made go-live unreachable if the deployer revoked the upgrade
    // authority (the recommended hardening step) or rotated the config admin before
    // finalizing. Go-live is now gated by the config-admin signer + the registry
    // admin signer + the compliance-deployer binding above; the deployer must
    // finalize BEFORE any authority change (see the release checklist).
    pub compliance_program_data: Account<'info, ProgramData>,
    /// The mint's transfer-hook `ExtraAccountMetaList` PDA. It is
    /// NOT pinned by seeds here on purpose — `validate_extra_account_meta_list`
    /// re-derives the canonical key from `[EXTRA_META_SEED, mint]` and asserts the
    /// passed key, the hook-program owner, and the exact canonical contents, so a
    /// wrong/absent/stale account fails go-live. Passing an arbitrary account lets a
    /// negative test drive the failure path.
    /// CHECK: fully validated in-handler; never deserialized here.
    pub extra_account_meta_list: UncheckedAccount<'info>,
}

#[event]
pub struct Minted {
    pub record_key: [u8; 32],
    pub metadata_digest: [u8; 32],
    pub vault: Pubkey,
    pub amount: u64,
    pub nonce: [u8; 32],
}

#[event]
pub struct Burned {
    pub operation_id: [u8; 32],
    pub metadata_digest: [u8; 32],
    pub vault: Pubkey,
    pub amount: u64,
    pub nonce: [u8; 32],
}

#[event]
pub struct AuditorChanged {
    pub previous: [u8; 20],
    pub new_auditor: [u8; 20],
    pub by: Pubkey,
}

#[event]
pub struct Finalized {
    pub supply: Pubkey,
    pub vault: Pubkey,
    pub escrow: Pubkey,
    pub registry: Pubkey,
    pub strategy: Pubkey,
    pub mint: Pubkey,
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
pub enum SupplyError {
    #[msg("zero address")]
    ZeroAddress,
    #[msg("zero auditor address")]
    ZeroAuditor,
    #[msg("cluster genesis hash must be non-zero")]
    ZeroCluster,
    #[msg("restated cluster does not match the pinned cluster")]
    ClusterMismatch,
    #[msg("malleable (high-S) signature rejected")]
    MalleableSignature,
    #[msg("project is paused")]
    ProjectPaused,
    #[msg("attestation expired")]
    AttestationExpired,
    #[msg("amount must be non-zero")]
    ZeroAmount,
    #[msg("insufficient vault inventory to burn")]
    InsufficientVaultInventory,
    #[msg("invalid auditor signature")]
    InvalidSignature,
    #[msg("wrong registry account")]
    WrongRegistry,
    #[msg("wrong mint account")]
    WrongMint,
    #[msg("wrong vault config account")]
    WrongVault,
    #[msg("caller is not the admin")]
    NotAdmin,
    #[msg("caller is not the pending admin")]
    NotPendingAdmin,
    #[msg("no pending admin transfer to accept")]
    NoPendingAdmin,
    #[msg("caller is not the program upgrade authority")]
    NotUpgradeAuthority,
    #[msg("vault token account is not the canonical inventory ATA")]
    NotCanonicalAta,
    #[msg("RWA mint and quote mint must be different")]
    MintQuoteSame,
    #[msg("configured RWA mint is unsafe (not Token-2022 / wrong or mutable hook / disallowed extension)")]
    UnsafeMint,
    #[msg("cross-program wiring mismatch")]
    WiringMismatch,
    #[msg("transfer-hook ExtraAccountMetaList PDA is missing, mis-owned, or incorrect")]
    MetaListInvalid,
    #[msg("pricing decimals do not match the RWA mint")]
    DecimalsMismatch,
    #[msg("vault and escrow quote decimals disagree")]
    QuoteDecimalsMismatch,
    #[msg("wrong token program for the RWA leg")]
    WrongTokenProgram,
    #[msg("deployment is not finalized")]
    NotFinalized,
    #[msg("deployment is already finalized")]
    AlreadyFinalized,
}
