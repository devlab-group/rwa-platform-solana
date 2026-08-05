//! rwa-transfer-hook — Token-2022 transfer hook enforcing compliance + pause.
//!
//! This is the Solana equivalent of `RWAToken._update`'s allowlist gate *and*
//! `ERC20Pausable` / `returnEscrowedRWA`'s narrow pause bypass, all in one place:
//! Token-2022 invokes this hook on **every** transfer of the RWA mint (mint & burn
//! do NOT trigger it, so they are exempt exactly as in Solidity).
//!
//! On each transfer it loads, from the `rwa-compliance` program:
//! - the `Registry` (for `paused` and the pinned `escrow` authority), and
//! - the `ComplianceRecord` of the **source** and **destination** token-account
//!   owners.
//!
//! Rules (identical outcomes to the Solidity token):
//! - Not paused → both source and destination owners must be `is_allowed`
//!   (`SenderNotAllowed` / `RecipientNotAllowed`).
//! - Paused → transfers revert (`Paused`) EXCEPT when the source is the pinned
//!   RedemptionEscrow authority, which may still return escrowed RWA to an
//!   allowed recipient — the exact `returnEscrowedRWA` carve-out that lets a
//!   timed-out `cancelRedemption` complete during an emergency pause without
//!   opening a general backdoor. (`claimRedemption` keeps its own explicit
//!   `!paused` guard and therefore does NOT use this bypass.)
//!
//! The record accounts are re-derived and verified in-handler
//! (`find_program_address([b"record", owner])`), so even a direct (non-Token-2022)
//! invocation cannot smuggle in a mismatched record.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::program_option::COption;
use anchor_lang::solana_program::{
    instruction::{AccountMeta, Instruction},
    program::invoke_signed,
};
use anchor_spl::token::ID as LEGACY_TOKEN_ID;
use anchor_spl::token_2022::spl_token_2022::{
    extension::{
        immutable_owner::ImmutableOwner,
        transfer_hook::{
            get_program_id as get_hook_program_id, TransferHook as TransferHookExt,
            TransferHookAccount,
        },
        BaseStateWithExtensions, StateWithExtensions,
    },
    instruction::transfer_checked as spl_transfer_checked_ix,
    state::{Account as Token2022Account, Mint as MintState},
    ID as TOKEN_2022_ID,
};
use anchor_spl::token_interface::{Mint, TokenAccount};
use rwa_compliance::{record_is_allowed, ComplianceRecord, Registry, RECORD_SEED, REGISTRY_SEED};
use spl_tlv_account_resolution::{
    account::ExtraAccountMeta, seeds::Seed, state::ExtraAccountMetaList,
};
use spl_transfer_hook_interface::instruction::{ExecuteInstruction, TransferHookInstruction};
use spl_transfer_hook_interface::onchain::add_extra_accounts_for_execute_cpi;

declare_id!("3e6iktcwEnj2XvvSgpuscQvnDpnJ8uMHNZGxu4A3ioZU");

pub const EXTRA_META_SEED: &[u8] = b"extra-account-metas";
/// Number of extra accounts the hook resolves: compliance program, registry,
/// source record, destination record (see `extra_account_metas`).
pub const EXTRA_META_COUNT: usize = 4;

#[program]
pub mod rwa_transfer_hook {
    use super::*;

    /// Build the `ExtraAccountMetaList` PDA that tells Token-2022 which extra
    /// accounts to pass to `Execute`: the compliance program, its `Registry`, and
    /// the source + destination owner `ComplianceRecord` PDAs (derived from the
    /// token accounts' owner field at data offset 32).
    pub fn initialize_extra_account_meta_list(
        ctx: Context<InitializeExtraAccountMetaList>,
    ) -> Result<()> {
        // Only build a meta list for a mint that actually uses THIS hook.
        validate_rwa_mint(&ctx.accounts.mint.to_account_info(), None, false, None)?;
        let metas = extra_account_metas()?;
        ExtraAccountMetaList::init::<ExecuteInstruction>(
            &mut ctx.accounts.extra_account_meta_list.try_borrow_mut_data()?,
            &metas,
        )?;
        Ok(())
    }

    /// Rebuild the `ExtraAccountMetaList` in place. The list embeds
    /// `rwa_compliance::ID` and derives the registry + record PDAs from it, so if
    /// the compliance program is ever redeployed at a new address (a breaking
    /// migration — see the runbook) or the extra-account layout changes,
    /// this lets the deployer repair the list rather than being forced to replace
    /// the mint and migrate every holder. Upgrade-authority gated. The account is
    /// exact-fit for `EXTRA_META_COUNT`, so a same-count rebuild needs no realloc.
    pub fn update_extra_account_meta_list(ctx: Context<UpdateExtraAccountMetaList>) -> Result<()> {
        validate_rwa_mint(&ctx.accounts.mint.to_account_info(), None, false, None)?;
        let metas = extra_account_metas()?;
        ExtraAccountMetaList::update::<ExecuteInstruction>(
            &mut ctx.accounts.extra_account_meta_list.try_borrow_mut_data()?,
            &metas,
        )?;
        Ok(())
    }

    /// The Token-2022 `Execute` entrypoint (routed via `fallback`).
    pub fn transfer_hook(ctx: Context<TransferHook>, _amount: u64) -> Result<()> {
        let registry = &ctx.accounts.registry;
        let now = Clock::get()?.unix_timestamp as u64;

        // The mint this hook fires for must be the deployment's pinned RWA
        // mint. The handler is already read-only and re-derives both record PDAs, so
        // a foreign mint pointing its hook extension here fails closed regardless;
        // this makes that guarantee explicit rather than resting on side-effect
        // freedom. (rwa_mint is pinned at `set_system_addresses`, before any
        // hook-firing transfer — every RWA movement requires a finalized
        // deployment.)
        require_keys_eq!(
            ctx.accounts.mint.key(),
            registry.rwa_mint,
            HookError::WrongMint
        );

        let src_owner = ctx.accounts.source_token.owner;
        let dst_owner = ctx.accounts.destination_token.owner;

        // Prove this `Execute` is part of an in-flight Token-2022 transfer,
        // not a forged direct call. Token-2022 sets the source account's
        // `TransferHookAccount.transferring` flag only for the duration of a real
        // transfer, so a standalone invocation reads `false` here.
        require!(
            source_is_transferring(&ctx.accounts.source_token.to_account_info())?,
            HookError::NotTransferring
        );

        // Both RWA token accounts must carry `ImmutableOwner` (canonical
        // Token-2022 ATAs have it by default). Without it a holder could fund a
        // mutable account, then hand its `AccountOwner` authority to an unallowed
        // key with `SetAuthority` — a control transfer the hook never sees. This
        // is the chokepoint for every RWA movement (buy receipt, escrow, claim),
        // so enforcing it here rejects receipt into a mutable account too.
        require_immutable_owner(&ctx.accounts.source_token.to_account_info())?;
        require_immutable_owner(&ctx.accounts.destination_token.to_account_info())?;

        // Strict per-wallet policy: the transfer authority (Execute index 3)
        // must be the source token account's own owner. Delegates are disallowed,
        // so the actor moving RWA is always the KYC'd owner itself — stricter than
        // the EVM `RWAToken._update`, which checks only `from`/`to`. PDA-signed
        // vault/escrow legs still pass: their authority *is* the source owner PDA.
        require_keys_eq!(
            ctx.accounts.owner.key(),
            src_owner,
            HookError::DelegateNotAllowed
        );

        // Defence-in-depth: the passed record accounts must be the canonical PDAs
        // for these owners, so a direct call can't pass a permissive record.
        verify_record_pda(&ctx.accounts.source_record.key(), &src_owner)?;
        verify_record_pda(&ctx.accounts.destination_record.key(), &dst_owner)?;

        let dst_allowed = account_is_allowed(&ctx.accounts.destination_record, now)?;

        if registry.paused {
            // Escrow-only bypass: only the pinned RedemptionEscrow may move RWA
            // while paused, and only to a still-allowed recipient.
            require!(
                registry.system_set && src_owner == registry.escrow,
                HookError::Paused
            );
            require!(dst_allowed, HookError::RecipientNotAllowed);
        } else {
            let src_allowed = account_is_allowed(&ctx.accounts.source_record, now)?;
            require!(src_allowed, HookError::SenderNotAllowed);
            require!(dst_allowed, HookError::RecipientNotAllowed);
        }
        Ok(())
    }

    /// Route the raw SPL transfer-hook `Execute` instruction to `transfer_hook`.
    pub fn fallback<'info>(
        program_id: &'info Pubkey,
        accounts: &'info [AccountInfo<'info>],
        data: &[u8],
    ) -> Result<()> {
        let instruction = TransferHookInstruction::unpack(data)
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        match instruction {
            TransferHookInstruction::Execute { amount } => {
                // Anchor 1.1's generated global handler borrows the instruction
                // data for `'info`, so the re-encoded amount must outlive the call.
                // `Box::leak` is fine in an SBF program: the whole heap is reclaimed
                // when the instruction returns, so this frees at invocation end.
                let amount_bytes: &'info [u8] = Box::leak(Box::new(amount.to_le_bytes()));
                __private::__global::transfer_hook(program_id, accounts, amount_bytes)
            }
            _ => Err(ProgramError::InvalidInstructionData.into()),
        }
    }
}

/// The extra accounts (beyond source/mint/destination/owner/meta-list) Token-2022
/// must resolve and pass to `Execute`, in order.
fn extra_account_metas() -> Result<Vec<ExtraAccountMeta>> {
    Ok(vec![
        // index 5: the compliance program id (needed to derive external PDAs below).
        ExtraAccountMeta::new_with_pubkey(&rwa_compliance::ID, false, false)?,
        // index 6: Registry PDA of the compliance program (seeds = ["registry"]).
        ExtraAccountMeta::new_external_pda_with_seeds(
            5,
            &[Seed::Literal {
                bytes: REGISTRY_SEED.to_vec(),
            }],
            false,
            false,
        )?,
        // index 7: source owner's record — seeds ["record", source_token.owner].
        // source_token is Execute account index 0; its owner is at data offset 32.
        ExtraAccountMeta::new_external_pda_with_seeds(
            5,
            &[
                Seed::Literal {
                    bytes: RECORD_SEED.to_vec(),
                },
                Seed::AccountData {
                    account_index: 0,
                    data_index: 32,
                    length: 32,
                },
            ],
            false,
            false,
        )?,
        // index 8: destination owner's record — destination_token is index 2.
        ExtraAccountMeta::new_external_pda_with_seeds(
            5,
            &[
                Seed::Literal {
                    bytes: RECORD_SEED.to_vec(),
                },
                Seed::AccountData {
                    account_index: 2,
                    data_index: 32,
                    length: 32,
                },
            ],
            false,
            false,
        )?,
    ])
}

/// Read-only proof that a mint's canonical `ExtraAccountMetaList`
/// PDA exists, is owned by THIS hook program, and holds exactly the entries
/// `extra_account_metas()` produces. The supply-controller `finalize` gate calls
/// this so go-live proves Token-2022 can actually resolve the hook's required
/// accounts for a real transfer — not merely that the mint's hook extension points
/// at this program (which `validate_rwa_mint` already covers). Without it a
/// deployment whose `initialize_extra_account_meta_list` was skipped, failed, or
/// left stale could finalize and mint inventory that is then non-transferable
/// (minting skips the hook; the first real transfer cannot resolve its accounts).
///
/// The check is exact: re-encode the canonical list into a scratch buffer with the
/// very writer `initialize_extra_account_meta_list` uses and compare byte-for-byte,
/// so a missing/extra/reordered/mutated entry — or a wrong-sized account — fails.
/// `size_of` is exact-fit, so a correct account's data length equals `want_len`.
pub fn validate_extra_account_meta_list(meta_list_ai: &AccountInfo, mint: &Pubkey) -> Result<()> {
    let (expected_key, _) =
        Pubkey::find_program_address(&[EXTRA_META_SEED, mint.as_ref()], &crate::ID);
    require_keys_eq!(*meta_list_ai.key, expected_key, HookError::WrongMetaList);
    require!(meta_list_ai.owner == &crate::ID, HookError::WrongMetaList);

    let metas = extra_account_metas()?;
    let want_len =
        ExtraAccountMetaList::size_of(metas.len()).map_err(|_| error!(HookError::WrongMetaList))?;
    let data = meta_list_ai.try_borrow_data()?;
    require!(data.len() == want_len, HookError::WrongMetaList);
    let mut scratch = vec![0u8; want_len];
    ExtraAccountMetaList::init::<ExecuteInstruction>(&mut scratch, &metas)
        .map_err(|_| error!(HookError::WrongMetaList))?;
    require!(data[..] == scratch[..], HookError::WrongMetaList);
    Ok(())
}

/// Shared RWA-mint safety gate, used by every program's authenticated bootstrap
/// (supply-controller, vault, redemption) so a deployment can never wire a mint
/// that would bypass compliance. Requires: owned by Token-2022, a `TransferHook`
/// extension pointing at THIS hook program, and no balance-affecting / seize
/// extension (transfer fee, permanent delegate). Optionally pins the mint
/// authority and requires the hook update authority to be revoked (immutable
/// hook). `program_id`/`authority` are `OptionalNonZeroPubkey`; `mint_authority`
/// is a `COption` on the base state.
pub fn validate_rwa_mint(
    mint_ai: &AccountInfo,
    required_mint_authority: Option<Pubkey>,
    require_hook_authority_none: bool,
    require_permissioned_burn_authority: Option<Pubkey>,
) -> Result<()> {
    require!(mint_ai.owner == &TOKEN_2022_ID, HookError::NotToken2022Mint);
    let data = mint_ai.try_borrow_data()?;
    let state = StateWithExtensions::<MintState>::unpack(&data)
        .map_err(|_| error!(HookError::InvalidMint))?;

    let hook = state
        .get_extension::<TransferHookExt>()
        .map_err(|_| error!(HookError::MissingTransferHook))?;
    require!(
        Option::<Pubkey>::from(hook.program_id) == Some(crate::ID),
        HookError::WrongTransferHook
    );
    if require_hook_authority_none {
        require!(
            Option::<Pubkey>::from(hook.authority).is_none(),
            HookError::HookAuthorityNotRevoked
        );
    }

    // The freeze authority must be revoked. A retained freeze authority sits
    // entirely outside the compliance/pauser roles and could freeze Vault
    // inventory, redemption escrow, or investor accounts directly through
    // Token-2022 — stranding pooled assets and bypassing the pause/recovery model.
    require!(
        matches!(state.base.freeze_authority, COption::None),
        HookError::FreezeAuthoritySet
    );

    // Allowlist mint extensions, and (when required) validate the
    // permissioned-burn authority — by walking the Token-2022 TLV extension list
    // directly. We deliberately do NOT link spl-token-2022-interface 3 (the crate
    // that knows the PermissionedBurn extension type): it is built on a *second*
    // `solana-address` major, and two `solana-address` versions linked into one SBF
    // program corrupt the runtime (a null-deref crash at program entry). Token-2022
    // extension layout: base mint (82 bytes) padded to BASE_ACCOUNT_LENGTH (165),
    // then account_type (1 = Mint), then TLV entries `[type: u16 LE][len: u16 LE]
    // [value: len]`. Allowed extension types are exactly TransferHook (14) and
    // PermissionedBurn (28); PermissionedBurnConfig's value is a 32-byte authority.
    {
        const BASE_ACCOUNT_LENGTH: usize = 165;
        const ACCOUNT_TYPE_MINT: u8 = 1;
        const EXT_TRANSFER_HOOK: u16 = 14;
        const EXT_PERMISSIONED_BURN: u16 = 28;

        require!(
            data.len() > BASE_ACCOUNT_LENGTH && data[BASE_ACCOUNT_LENGTH] == ACCOUNT_TYPE_MINT,
            HookError::InvalidMint
        );
        let mut permissioned_burn_authority: Option<[u8; 32]> = None;
        let mut saw_transfer_hook = false;
        let mut off = BASE_ACCOUNT_LENGTH + 1;
        while off + 4 <= data.len() {
            let ext_type = u16::from_le_bytes([data[off], data[off + 1]]);
            if ext_type == 0 {
                break; // Uninitialized -> end of the TLV list
            }
            let len = u16::from_le_bytes([data[off + 2], data[off + 3]]) as usize;
            let val_start = off + 4;
            let val_end = val_start
                .checked_add(len)
                .filter(|e| *e <= data.len())
                .ok_or_else(|| error!(HookError::InvalidMint))?;
            require!(
                ext_type == EXT_TRANSFER_HOOK || ext_type == EXT_PERMISSIONED_BURN,
                HookError::DisallowedMintExtension
            );
            // Reject a *second* entry of either type rather than "last wins".
            // Token-2022 reads the FIRST match, so a hand-crafted mint with a benign
            // first entry and a hostile second could otherwise pass validation here
            // while the live authority differs. Duplicates are unreachable through
            // Token-2022 today (it errors ExtensionAlreadyInitialized), but the
            // hand-rolled parser must not disagree with the authoritative one.
            if ext_type == EXT_TRANSFER_HOOK {
                require!(!saw_transfer_hook, HookError::InvalidMint);
                saw_transfer_hook = true;
            }
            if ext_type == EXT_PERMISSIONED_BURN {
                require!(
                    permissioned_burn_authority.is_none(),
                    HookError::InvalidMint
                );
                require!(len >= 32, HookError::InvalidMint);
                let mut a = [0u8; 32];
                a.copy_from_slice(&data[val_start..val_start + 32]);
                permissioned_burn_authority = Some(a);
            }
            off = val_end;
        }
        if let Some(expected) = require_permissioned_burn_authority {
            let auth = permissioned_burn_authority
                .ok_or_else(|| error!(HookError::MissingPermissionedBurn))?;
            // A null (all-zero) authority means the extension is unconfigured.
            require!(
                auth == expected.to_bytes(),
                HookError::WrongPermissionedBurnAuthority
            );
        }
    }

    if let Some(expected) = required_mint_authority {
        let ma = match state.base.mint_authority {
            COption::Some(k) => Some(k),
            COption::None => None,
        };
        require!(ma == Some(expected), HookError::WrongMintAuthority);
    }
    Ok(())
}

/// Validate the configured quote mint. The quote mint is an arbitrary
/// configured token (typically a fiat-backed stablecoin), so — unlike the RWA
/// mint — we do not require our hook or a revoked freeze authority (a real
/// stablecoin cannot give the latter up). But we must reject a mint whose owning
/// program, or Token-2022 extensions, would break the exact-delta accounting
/// every quote leg depends on, run code on transfer, or seize balances straight
/// out of the PDA-owned custody accounts.
///
/// Accept the legacy SPL Token program (which has no extensions) or Token-2022
/// carrying **only** transfer-neutral metadata/group extensions. Everything else
/// on a mint — transfer fees, a transfer hook, a permanent delegate,
/// interest-bearing / scaled-ui amounts, default-account-state, pause, close
/// authority, non-transferable, and the confidential-balance extensions — is
/// rejected. We do this by *allowlisting* the benign extension type numbers and
/// rejecting every other, so a newly-introduced dangerous extension is refused by
/// default. Raw TLV parse (no interface-3 link), mirroring `validate_rwa_mint`.
///
/// A retained freeze authority is deliberately NOT rejected here: real stablecoins
/// keep one. It is recorded in the deployment manifest and accepted on the release
/// checklist. A frozen beneficiary quote account therefore strands a `Funded`
/// position with no on-chain unwind — exact parity with the EVM RedemptionEscrow,
/// where a blacklisted beneficiary's `claim` reverts and the funded quote is never
/// withdrawable. See the operator runbook.
pub fn validate_quote_mint(mint_ai: &AccountInfo) -> Result<()> {
    let owner = mint_ai.owner;
    if owner == &LEGACY_TOKEN_ID {
        // Legacy SPL Token mints carry no extensions — nothing further to check.
        return Ok(());
    }
    require!(
        owner == &TOKEN_2022_ID,
        HookError::UnsupportedQuoteMintProgram
    );

    const BASE_ACCOUNT_LENGTH: usize = 165;
    const ACCOUNT_TYPE_MINT: u8 = 1;
    // Transfer-neutral extensions a real stablecoin may legitimately carry.
    // MetadataPointer(18), TokenMetadata(19), GroupPointer(20), TokenGroup(21),
    // GroupMemberPointer(22), TokenGroupMember(23).
    const ALLOWED_QUOTE_EXTENSIONS: [u16; 6] = [18, 19, 20, 21, 22, 23];

    let data = mint_ai.try_borrow_data()?;
    // A base-length Token-2022 mint (82 bytes) has no extensions and is safe.
    if data.len() <= BASE_ACCOUNT_LENGTH {
        return Ok(());
    }
    require!(
        data[BASE_ACCOUNT_LENGTH] == ACCOUNT_TYPE_MINT,
        HookError::InvalidMint
    );
    let mut off = BASE_ACCOUNT_LENGTH + 1;
    while off + 4 <= data.len() {
        let ext_type = u16::from_le_bytes([data[off], data[off + 1]]);
        if ext_type == 0 {
            break; // Uninitialized -> end of the TLV list
        }
        let len = u16::from_le_bytes([data[off + 2], data[off + 3]]) as usize;
        let val_end = (off + 4)
            .checked_add(len)
            .filter(|e| *e <= data.len())
            .ok_or_else(|| error!(HookError::InvalidMint))?;
        require!(
            ALLOWED_QUOTE_EXTENSIONS.contains(&ext_type),
            HookError::DisallowedQuoteMintExtension
        );
        off = val_end;
    }
    Ok(())
}

/// Build a Token-2022 `PermissionedBurnChecked` instruction, hand-encoded
/// with anchor's own `solana-address 1` types (so we never link the interface-3
/// crate / a second `solana-address`). Wire format:
/// `TokenInstruction::PermissionedBurnExtension` (46) then
/// `PermissionedBurnInstruction::BurnChecked` (2), then
/// `BurnCheckedInstructionData { amount: u64 LE, decimals: u8 }`. Accounts:
/// source(w), mint(w), permissioned-burn authority(signer), owner(signer) — so
/// BOTH the burn authority and the token-account owner must sign, and a plain
/// holder `Burn`/`BurnChecked` can no longer reduce supply. Verified against
/// spl-token-2022-interface 3.1.1's `permissioned_burn::instruction::burn_checked`.
#[allow(clippy::too_many_arguments)]
pub fn build_permissioned_burn_checked_ix(
    token_program_id: &Pubkey,
    account: &Pubkey,
    mint: &Pubkey,
    burn_authority: &Pubkey,
    owner: &Pubkey,
    amount: u64,
    decimals: u8,
) -> Result<Instruction> {
    // This instruction is Token-2022-specific (the PermissionedBurn
    // extension). The hand-built instruction below performs no program-id check of
    // its own, so assert it here — a PDA-signed CPI must never be delivered to an
    // attacker-chosen program with the Vault token account writable.
    require!(
        token_program_id == &TOKEN_2022_ID,
        HookError::WrongTokenProgram
    );
    const PERMISSIONED_BURN_EXTENSION: u8 = 46;
    const BURN_CHECKED: u8 = 2;
    let mut data = Vec::with_capacity(11);
    data.push(PERMISSIONED_BURN_EXTENSION);
    data.push(BURN_CHECKED);
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    Ok(Instruction {
        program_id: *token_program_id,
        accounts: vec![
            AccountMeta::new(*account, false),
            AccountMeta::new(*mint, false),
            AccountMeta::new_readonly(*burn_authority, true),
            AccountMeta::new_readonly(*owner, true),
        ],
        data,
    })
}

/// Hook-aware Token-2022 `transfer_checked` CPI. Ported from the removed
/// `spl_token_2022::onchain::invoke_transfer_checked` (anchor-spl 1.1 depends on
/// `spl-token-2022-interface`, which drops the `onchain` module). Builds the
/// `TransferChecked` instruction, threads through any multisig signer accounts,
/// then resolves the mint's transfer-hook `ExtraAccountMetaList` and appends the
/// hook's extra accounts before `invoke_signed`. Public so the Vault and
/// redemption programs can move RWA through the compliance hook.
#[allow(clippy::too_many_arguments)]
pub fn invoke_transfer_checked<'a>(
    token_program_id: &Pubkey,
    source_info: AccountInfo<'a>,
    mint_info: AccountInfo<'a>,
    destination_info: AccountInfo<'a>,
    authority_info: AccountInfo<'a>,
    additional_accounts: &[AccountInfo<'a>],
    amount: u64,
    decimals: u8,
    seeds: &[&[&[u8]]],
) -> Result<()> {
    let mut cpi_instruction = spl_transfer_checked_ix(
        token_program_id,
        source_info.key,
        mint_info.key,
        destination_info.key,
        authority_info.key,
        &[], // extra accounts appended below, to avoid unnecessary clones
        amount,
        decimals,
    )?;

    let mut cpi_account_infos = vec![
        source_info.clone(),
        mint_info.clone(),
        destination_info.clone(),
        authority_info.clone(),
    ];

    // If any forwarded account is itself a signer (multisig), thread it through.
    additional_accounts
        .iter()
        .filter(|ai| ai.is_signer)
        .for_each(|ai| {
            cpi_account_infos.push(ai.clone());
            cpi_instruction
                .accounts
                .push(AccountMeta::new_readonly(*ai.key, true));
        });

    // Scope the mint borrow so it is released before the CPI.
    {
        let mint_data = mint_info.try_borrow_data()?;
        let mint = StateWithExtensions::<MintState>::unpack(&mint_data)
            .map_err(|_| error!(HookError::InvalidMint))?;
        if let Some(hook_program_id) = get_hook_program_id(&mint) {
            add_extra_accounts_for_execute_cpi(
                &mut cpi_instruction,
                &mut cpi_account_infos,
                &hook_program_id,
                source_info,
                mint_info.clone(),
                destination_info,
                authority_info,
                amount,
                additional_accounts,
            )
            .map_err(|_| error!(HookError::HookCpiFailed))?;
        }
    }

    invoke_signed(&cpi_instruction, &cpi_account_infos, seeds).map_err(Into::into)
}

/// Require a Token-2022 token account to carry the `ImmutableOwner`
/// extension, so its `AccountOwner` authority can never be reassigned with
/// `SetAuthority`. Public so the Vault/redemption programs can reuse the exact
/// same rule on their custody accounts if needed.
pub fn require_immutable_owner(ai: &AccountInfo) -> Result<()> {
    let data = ai.try_borrow_data()?;
    let state = StateWithExtensions::<Token2022Account>::unpack(&data)
        .map_err(|_| error!(HookError::InvalidTokenAccount))?;
    state
        .get_extension::<ImmutableOwner>()
        .map_err(|_| error!(HookError::MutableTokenAccount))?;
    Ok(())
}

/// True when the source token account's `TransferHookAccount.transferring`
/// flag is set — Token-2022 sets it only while a genuine transfer is executing.
fn source_is_transferring(ai: &AccountInfo) -> Result<bool> {
    let data = ai.try_borrow_data()?;
    let state = StateWithExtensions::<Token2022Account>::unpack(&data)
        .map_err(|_| error!(HookError::InvalidTokenAccount))?;
    let ext = state
        .get_extension::<TransferHookAccount>()
        .map_err(|_| error!(HookError::InvalidTokenAccount))?;
    Ok(bool::from(ext.transferring))
}

fn verify_record_pda(passed: &Pubkey, owner: &Pubkey) -> Result<()> {
    let (expected, _) =
        Pubkey::find_program_address(&[RECORD_SEED, owner.as_ref()], &rwa_compliance::ID);
    require_keys_eq!(*passed, expected, HookError::RecordMismatch);
    Ok(())
}

/// Read a (possibly uninitialized) record account and evaluate the allowlist. A
/// missing/foreign account = not allowed (matches a zeroed Solidity record).
fn account_is_allowed(acc: &UncheckedAccount, now: u64) -> Result<bool> {
    let info = acc.to_account_info();
    if info.owner != &rwa_compliance::ID {
        return Ok(false);
    }
    let data = info.try_borrow_data()?;
    // 8-byte Anchor discriminator + ComplianceRecord.
    if data.len() < 8 + ComplianceRecord::SPACE - 8 {
        return Ok(false);
    }
    let rec = ComplianceRecord::try_deserialize(&mut &data[..])
        .map_err(|_| error!(HookError::RecordMismatch))?;
    Ok(record_is_allowed(&rec, now))
}

#[derive(Accounts)]
pub struct InitializeExtraAccountMetaList<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: PDA allocated here (init) and written by ExtraAccountMetaList::init.
    #[account(
        init,
        payer = payer,
        space = ExtraAccountMetaList::size_of(EXTRA_META_COUNT).unwrap(),
        seeds = [EXTRA_META_SEED, mint.key().as_ref()],
        bump
    )]
    pub extra_account_meta_list: AccountInfo<'info>,
    pub mint: InterfaceAccount<'info, Mint>,
    // Upgrade-authority gate: only the program's deployer may bootstrap it.
    #[account(constraint = program.programdata_address()? == Some(program_data.key()) @ HookError::NotUpgradeAuthority)]
    pub program: Program<'info, crate::program::RwaTransferHook>,
    #[account(constraint = program_data.upgrade_authority_address == Some(payer.key()) @ HookError::NotUpgradeAuthority)]
    pub program_data: Account<'info, ProgramData>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateExtraAccountMetaList<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: PDA validated by seeds; rewritten by ExtraAccountMetaList::update.
    #[account(mut, seeds = [EXTRA_META_SEED, mint.key().as_ref()], bump)]
    pub extra_account_meta_list: UncheckedAccount<'info>,
    pub mint: InterfaceAccount<'info, Mint>,
    // Upgrade-authority gate: only the program's deployer may rebuild the list.
    #[account(constraint = program.programdata_address()? == Some(program_data.key()) @ HookError::NotUpgradeAuthority)]
    pub program: Program<'info, crate::program::RwaTransferHook>,
    #[account(constraint = program_data.upgrade_authority_address == Some(payer.key()) @ HookError::NotUpgradeAuthority)]
    pub program_data: Account<'info, ProgramData>,
}

/// Account order dictated by the SPL transfer-hook `Execute` interface, followed
/// by the extra accounts declared in `extra_account_metas()`.
#[derive(Accounts)]
pub struct TransferHook<'info> {
    #[account(token::mint = mint)]
    pub source_token: InterfaceAccount<'info, TokenAccount>,
    pub mint: InterfaceAccount<'info, Mint>,
    #[account(token::mint = mint)]
    pub destination_token: InterfaceAccount<'info, TokenAccount>,
    /// CHECK: the transfer authority (source owner/delegate); not trusted here.
    pub owner: UncheckedAccount<'info>,
    /// CHECK: ExtraAccountMetaList PDA validated by seeds.
    #[account(seeds = [EXTRA_META_SEED, mint.key().as_ref()], bump)]
    pub extra_account_meta_list: UncheckedAccount<'info>,
    /// CHECK: compliance program id (extra meta index 5).
    #[account(address = rwa_compliance::ID)]
    pub compliance_program: UncheckedAccount<'info>,
    #[account(seeds = [REGISTRY_SEED], bump = registry.bump, seeds::program = rwa_compliance::ID)]
    pub registry: Account<'info, Registry>,
    /// CHECK: source owner's record PDA, verified against find_program_address.
    pub source_record: UncheckedAccount<'info>,
    /// CHECK: destination owner's record PDA, verified against find_program_address.
    pub destination_record: UncheckedAccount<'info>,
}

#[error_code]
pub enum HookError {
    #[msg("transfer sender is not allowed")]
    SenderNotAllowed,
    #[msg("transfer recipient is not allowed")]
    RecipientNotAllowed,
    #[msg("project is paused")]
    Paused,
    #[msg("compliance record account does not match its owner")]
    RecordMismatch,
    #[msg("caller is not the program upgrade authority")]
    NotUpgradeAuthority,
    #[msg("mint is not owned by the Token-2022 program")]
    NotToken2022Mint,
    #[msg("mint could not be parsed")]
    InvalidMint,
    #[msg("mint has no transfer hook extension")]
    MissingTransferHook,
    #[msg("mint transfer hook points at a different program")]
    WrongTransferHook,
    #[msg("hook invoked for a mint other than the pinned RWA mint")]
    WrongMint,
    #[msg("mint ExtraAccountMetaList PDA is missing, mis-owned, or has unexpected contents")]
    WrongMetaList,
    #[msg("mint transfer hook update authority is not revoked")]
    HookAuthorityNotRevoked,
    #[msg("mint has a disallowed extension (only the transfer hook is permitted)")]
    DisallowedMintExtension,
    #[msg("mint authority is not the expected supply-controller PDA")]
    WrongMintAuthority,
    #[msg("mint retains a freeze authority")]
    FreezeAuthoritySet,
    #[msg("token account could not be parsed")]
    InvalidTokenAccount,
    #[msg("token account is not immutable-owner (use a canonical ATA)")]
    MutableTokenAccount,
    #[msg("transfer authority must be the source token account owner (no delegates)")]
    DelegateNotAllowed,
    #[msg("hook invoked outside an active Token-2022 transfer")]
    NotTransferring,
    #[msg("transfer-hook CPI account resolution failed")]
    HookCpiFailed,
    #[msg("mint is missing the required permissioned-burn extension")]
    MissingPermissionedBurn,
    #[msg("mint permissioned-burn authority is not the supply-controller PDA")]
    WrongPermissionedBurnAuthority,
    #[msg("permissioned burn must target the Token-2022 program")]
    WrongTokenProgram,
    #[msg("quote mint program must be the legacy SPL Token or Token-2022 program")]
    UnsupportedQuoteMintProgram,
    #[msg("quote mint carries a disallowed Token-2022 extension")]
    DisallowedQuoteMintExtension,
}
