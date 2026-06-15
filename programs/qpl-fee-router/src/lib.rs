// `unexpected_cfgs` warnings originate from Anchor 0.30's macro expansion
// (`custom-heap`, `solana`, `anchor-debug`, ...) when checked by newer rustc;
// they are not produced by code in this crate. Allow only this lint so the
// `-D warnings` clippy gate stays meaningful for everything else.
#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;
use anchor_lang::AccountDeserialize;
use anchor_lang::AccountSerialize;
use solana_security_txt::security_txt;

security_txt! {
    name: "QPL Fee Router",
    project_url: "https://qpl.network",
    contacts: "email:security@qpl.network",
    policy: "https://github.com/ryana-sol/qpl/blob/main/SECURITY.md",
    preferred_languages: "en",
    source_code: "https://github.com/ryana-sol/qpl/tree/main/programs/qpl-fee-router"
}

// Force linker to retain security.txt static (macro lacks #[used])
#[used]
static SECURITY_TXT_KEEP: &str = SECURITY_TXT;

declare_id!("71U4cD7FpKz9epyFNMd4hZLUnY2Qe7WfQzQdrZgmyHrW");

/// Fee split constants (must sum to 100)
pub const COORDINATOR_SHARE_PCT: u8 = 40;
pub const PARTICIPANT_SHARE_PCT: u8 = 50;
pub const TREASURY_SHARE_PCT: u8 = 10;

/// Minimum fee to prevent dust attacks (in lamports, ~$0.025 at $150/SOL)
pub const MIN_FEE_LAMPORTS: u64 = 166_667; // ~$0.025

#[program]
pub mod qpl_fee_router {
    use super::*;

    /// Initialize the fee router configuration.
    pub fn initialize(ctx: Context<Initialize>, treasury: Pubkey) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.governance = ctx.accounts.governance.key();
        config.treasury = treasury;
        config.total_fees_collected = 0;
        config.total_fees_distributed = 0;
        config.bump = ctx.bumps.config;
        Ok(())
    }

    /// Initialize the fee vault PDA.
    /// Must be called once after `initialize`, before any deposit or charge can
    /// route lamports through `[b"fee-vault"]`. Restricted to the configured
    /// `governance` authority and enforced single-shot via Anchor's `init`.
    pub fn initialize_vault(ctx: Context<InitializeVault>) -> Result<()> {
        let vault = &mut ctx.accounts.fee_vault;
        vault.bump = ctx.bumps.fee_vault;

        emit!(FeeVaultInitialized {
            vault: vault.key(),
            bump: vault.bump,
        });

        Ok(())
    }

    /// Protocol deposits a prepaid fee balance.
    /// Protocols pre-fund to avoid per-operation transaction overhead.
    pub fn deposit_balance(ctx: Context<DepositBalance>, amount: u64) -> Result<()> {
        require!(amount > 0, QplFeeError::ZeroAmount);

        // Transfer SOL from protocol to fee vault
        let transfer_ix = anchor_lang::system_program::Transfer {
            from: ctx.accounts.protocol.to_account_info(),
            to: ctx.accounts.fee_vault.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            transfer_ix,
        );
        anchor_lang::system_program::transfer(cpi_ctx, amount)?;

        let balance = &mut ctx.accounts.protocol_balance;
        balance.protocol = ctx.accounts.protocol.key();
        balance.balance = balance
            .balance
            .checked_add(amount)
            .ok_or(QplFeeError::Overflow)?;

        emit!(BalanceDeposited {
            protocol: ctx.accounts.protocol.key(),
            amount,
            new_balance: balance.balance,
        });

        Ok(())
    }

    /// Deduct fee from a protocol's prepaid balance and distribute to all parties.
    /// Called by governance/coordinator after an operation completes.
    ///
    /// Participant `OperatorEarnings` PDAs must be passed via `remaining_accounts`
    /// in the same order as the `participants` vector.
    pub fn charge_fee(
        ctx: Context<ChargeFee>,
        amount: u64,
        coordinator: Pubkey,
        participants: Vec<Pubkey>,
    ) -> Result<()> {
        require!(amount >= MIN_FEE_LAMPORTS, QplFeeError::FeeBelowMinimum);
        require!(!participants.is_empty(), QplFeeError::NoParticipants);

        let balance = &mut ctx.accounts.protocol_balance;
        require!(balance.balance >= amount, QplFeeError::InsufficientBalance);

        // Validate remaining_accounts matches participants length
        let remaining = ctx.remaining_accounts;
        require!(
            remaining.len() == participants.len(),
            QplFeeError::ParticipantAccountMismatch
        );

        // Deduct from protocol balance (checked for defense-in-depth)
        balance.balance = balance
            .balance
            .checked_sub(amount)
            .ok_or(QplFeeError::InsufficientBalance)?;

        // Calculate split with checked arithmetic
        let (coordinator_amount, treasury_amount, per_participant, remainder) =
            compute_fee_split(amount, participants.len() as u64)?;

        // Record coordinator earnings (base share + integer division dust)
        let coordinator_earnings = &mut ctx.accounts.coordinator_earnings;
        coordinator_earnings.operator = coordinator;
        let coord_total = coordinator_amount
            .checked_add(remainder)
            .ok_or(QplFeeError::Overflow)?;
        coordinator_earnings.claimable = coordinator_earnings
            .claimable
            .checked_add(coord_total)
            .ok_or(QplFeeError::Overflow)?;

        // Distribute participant shares via remaining_accounts
        for (i, participant_key) in participants.iter().enumerate() {
            let (expected_pda, _bump) = Pubkey::find_program_address(
                &[b"earnings", participant_key.as_ref()],
                ctx.program_id,
            );
            let account_info = &remaining[i];
            require!(
                account_info.key() == expected_pda,
                QplFeeError::InvalidParticipantAccount
            );
            require!(
                account_info.owner == ctx.program_id,
                QplFeeError::InvalidParticipantAccount
            );

            // Deserialize, increment, re-serialize
            let mut data = account_info.try_borrow_mut_data()?;
            let mut earnings =
                OperatorEarnings::try_deserialize(&mut &data[..])
                    .map_err(|_| QplFeeError::InvalidParticipantAccount)?;
            earnings.claimable = earnings
                .claimable
                .checked_add(per_participant)
                .ok_or(QplFeeError::Overflow)?;
            earnings
                .try_serialize(&mut &mut data[..])
                .map_err(|_| QplFeeError::InvalidParticipantAccount)?;
        }

        // Transfer treasury share immediately (checked arithmetic)
        let vault_info = ctx.accounts.fee_vault.to_account_info();
        **vault_info.try_borrow_mut_lamports()? = vault_info
            .lamports()
            .checked_sub(treasury_amount)
            .ok_or(QplFeeError::InsufficientVaultBalance)?;
        let treasury_info = ctx.accounts.treasury.to_account_info();
        **treasury_info.try_borrow_mut_lamports()? = treasury_info
            .lamports()
            .checked_add(treasury_amount)
            .ok_or(QplFeeError::Overflow)?;

        // Update config totals (checked arithmetic)
        let config = &mut ctx.accounts.config;
        config.total_fees_collected = config
            .total_fees_collected
            .checked_add(amount)
            .ok_or(QplFeeError::Overflow)?;
        let participants_total = per_participant
            .checked_mul(participants.len() as u64)
            .ok_or(QplFeeError::Overflow)?;
        let distributed_delta = treasury_amount
            .checked_add(coordinator_amount)
            .and_then(|v| v.checked_add(remainder))
            .and_then(|v| v.checked_add(participants_total))
            .ok_or(QplFeeError::Overflow)?;
        config.total_fees_distributed = config
            .total_fees_distributed
            .checked_add(distributed_delta)
            .ok_or(QplFeeError::Overflow)?;

        emit!(FeeCharged {
            protocol: balance.protocol,
            total_fee: amount,
            coordinator_amount: coordinator_amount + remainder,
            per_participant,
            treasury_amount,
            participant_count: participants.len() as u8,
        });

        Ok(())
    }

    /// Operator claims their accumulated fee earnings.
    pub fn claim(ctx: Context<Claim>) -> Result<()> {
        let earnings = &mut ctx.accounts.earnings;
        let amount = earnings.claimable;
        require!(amount > 0, QplFeeError::NothingToClaim);

        earnings.claimable = 0;
        earnings.total_claimed = earnings
            .total_claimed
            .checked_add(amount)
            .ok_or(QplFeeError::Overflow)?;

        // Transfer from fee vault to operator (checked arithmetic)
        let vault_info = ctx.accounts.fee_vault.to_account_info();
        **vault_info.try_borrow_mut_lamports()? = vault_info
            .lamports()
            .checked_sub(amount)
            .ok_or(QplFeeError::InsufficientVaultBalance)?;
        let operator_info = ctx.accounts.operator.to_account_info();
        **operator_info.try_borrow_mut_lamports()? = operator_info
            .lamports()
            .checked_add(amount)
            .ok_or(QplFeeError::Overflow)?;

        emit!(FeesClaimed {
            operator: ctx.accounts.operator.key(),
            amount,
        });

        Ok(())
    }

    /// Initialize an earnings PDA for a participant operator.
    /// Must be called before `charge_fee` can credit a participant.
    pub fn init_participant_earnings(ctx: Context<InitParticipantEarnings>) -> Result<()> {
        let earnings = &mut ctx.accounts.earnings;
        earnings.operator = ctx.accounts.operator.key();
        earnings.claimable = 0;
        earnings.total_claimed = 0;
        Ok(())
    }
}

// ─── Accounts ────────────────────────────────────────────────────────────────

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub governance: Signer<'info>,

    #[account(
        init,
        payer = governance,
        space = FeeRouterConfig::SPACE,
        seeds = [b"fee-config"],
        bump
    )]
    pub config: Account<'info, FeeRouterConfig>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitializeVault<'info> {
    #[account(mut)]
    pub governance: Signer<'info>,

    #[account(
        seeds = [b"fee-config"],
        bump = config.bump,
        constraint = governance.key() == config.governance @ QplFeeError::Unauthorized
    )]
    pub config: Account<'info, FeeRouterConfig>,

    #[account(
        init,
        payer = governance,
        space = FeeVault::SPACE,
        seeds = [b"fee-vault"],
        bump
    )]
    pub fee_vault: Account<'info, FeeVault>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct DepositBalance<'info> {
    #[account(mut)]
    pub protocol: Signer<'info>,

    #[account(
        init_if_needed,
        payer = protocol,
        space = ProtocolBalance::SPACE,
        seeds = [b"balance", protocol.key().as_ref()],
        bump
    )]
    pub protocol_balance: Account<'info, ProtocolBalance>,

    #[account(
        mut,
        seeds = [b"fee-vault"],
        bump = fee_vault.bump
    )]
    pub fee_vault: Account<'info, FeeVault>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ChargeFee<'info> {
    #[account(mut)]
    pub governance: Signer<'info>,

    #[account(
        mut,
        seeds = [b"fee-config"],
        bump = config.bump,
        constraint = governance.key() == config.governance @ QplFeeError::Unauthorized
    )]
    pub config: Account<'info, FeeRouterConfig>,

    #[account(mut)]
    pub protocol_balance: Account<'info, ProtocolBalance>,

    #[account(
        init_if_needed,
        payer = governance,
        space = OperatorEarnings::SPACE,
        seeds = [b"earnings", protocol_balance.protocol.as_ref()],
        bump
    )]
    pub coordinator_earnings: Account<'info, OperatorEarnings>,

    #[account(
        mut,
        seeds = [b"fee-vault"],
        bump = fee_vault.bump
    )]
    pub fee_vault: Account<'info, FeeVault>,

    /// CHECK: Treasury receives its share
    #[account(mut, constraint = treasury.key() == config.treasury)]
    pub treasury: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Claim<'info> {
    #[account(mut)]
    pub operator: Signer<'info>,

    #[account(
        mut,
        constraint = earnings.operator == operator.key() @ QplFeeError::Unauthorized
    )]
    pub earnings: Account<'info, OperatorEarnings>,

    #[account(
        mut,
        seeds = [b"fee-vault"],
        bump = fee_vault.bump
    )]
    pub fee_vault: Account<'info, FeeVault>,
}

#[derive(Accounts)]
pub struct InitParticipantEarnings<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: Operator identity for PDA derivation
    pub operator: UncheckedAccount<'info>,

    #[account(
        init,
        payer = payer,
        space = OperatorEarnings::SPACE,
        seeds = [b"earnings", operator.key().as_ref()],
        bump
    )]
    pub earnings: Account<'info, OperatorEarnings>,

    pub system_program: Program<'info, System>,
}

// ─── State ───────────────────────────────────────────────────────────────────

#[account]
pub struct FeeRouterConfig {
    pub governance: Pubkey,
    pub treasury: Pubkey,
    pub total_fees_collected: u64,
    pub total_fees_distributed: u64,
    pub bump: u8,
}

impl FeeRouterConfig {
    pub const SPACE: usize = 8 + 32 + 32 + 8 + 8 + 1;
}

#[account]
pub struct ProtocolBalance {
    pub protocol: Pubkey,
    pub balance: u64,
}

impl ProtocolBalance {
    pub const SPACE: usize = 8 + 32 + 8;
}

#[account]
pub struct OperatorEarnings {
    pub operator: Pubkey,
    pub claimable: u64,
    pub total_claimed: u64,
}

impl OperatorEarnings {
    pub const SPACE: usize = 8 + 32 + 8 + 8;
}

#[account]
pub struct FeeVault {
    pub bump: u8,
}

impl FeeVault {
    // 8 (discriminator) + 1 (bump)
    pub const SPACE: usize = 8 + 1;
}

// ─── Events ──────────────────────────────────────────────────────────────────

#[event]
pub struct BalanceDeposited {
    pub protocol: Pubkey,
    pub amount: u64,
    pub new_balance: u64,
}

#[event]
pub struct FeeCharged {
    pub protocol: Pubkey,
    pub total_fee: u64,
    pub coordinator_amount: u64,
    pub per_participant: u64,
    pub treasury_amount: u64,
    pub participant_count: u8,
}

#[event]
pub struct FeesClaimed {
    pub operator: Pubkey,
    pub amount: u64,
}

#[event]
pub struct FeeVaultInitialized {
    pub vault: Pubkey,
    pub bump: u8,
}

// ─── Errors ──────────────────────────────────────────────────────────────────

#[error_code]
pub enum QplFeeError {
    #[msg("Amount must be greater than zero")]
    ZeroAmount,
    #[msg("Fee below minimum threshold")]
    FeeBelowMinimum,
    #[msg("Insufficient prepaid balance")]
    InsufficientBalance,
    #[msg("No participants specified")]
    NoParticipants,
    #[msg("Nothing to claim")]
    NothingToClaim,
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Remaining accounts length must match participants length")]
    ParticipantAccountMismatch,
    #[msg("Participant account does not match expected PDA")]
    InvalidParticipantAccount,
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("Vault has insufficient balance")]
    InsufficientVaultBalance,
}

// ─── Internal helpers ────────────────────────────────────────────────────────

/// Compute the 40/50/10 fee split with fully-checked arithmetic.
///
/// Returns `(coordinator_amount, treasury_amount, per_participant, remainder)`.
/// `remainder` is the integer-division dust from splitting the participant pool
/// and is awarded to the coordinator (matches the existing economic policy).
fn compute_fee_split(amount: u64, num_participants: u64) -> Result<(u64, u64, u64, u64)> {
    require!(num_participants > 0, QplFeeError::NoParticipants);

    let coordinator_amount = amount
        .checked_mul(COORDINATOR_SHARE_PCT as u64)
        .ok_or(QplFeeError::Overflow)?
        .checked_div(100)
        .ok_or(QplFeeError::Overflow)?;
    let treasury_amount = amount
        .checked_mul(TREASURY_SHARE_PCT as u64)
        .ok_or(QplFeeError::Overflow)?
        .checked_div(100)
        .ok_or(QplFeeError::Overflow)?;
    let participant_pool = amount
        .checked_sub(coordinator_amount)
        .ok_or(QplFeeError::Overflow)?
        .checked_sub(treasury_amount)
        .ok_or(QplFeeError::Overflow)?;
    let per_participant = participant_pool
        .checked_div(num_participants)
        .ok_or(QplFeeError::Overflow)?;
    let remainder = participant_pool
        .checked_rem(num_participants)
        .ok_or(QplFeeError::Overflow)?;

    Ok((coordinator_amount, treasury_amount, per_participant, remainder))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fee_vault_space_is_discriminator_plus_bump() {
        // initialize_vault allocates exactly this many bytes.
        assert_eq!(FeeVault::SPACE, 8 + 1);
    }

    #[test]
    fn split_distributes_min_fee_correctly() {
        let (c, t, p, r) = compute_fee_split(MIN_FEE_LAMPORTS, 3).unwrap();
        // 40 % coordinator, 10 % treasury, 50 % participants split 3 ways.
        assert_eq!(c, MIN_FEE_LAMPORTS * 40 / 100);
        assert_eq!(t, MIN_FEE_LAMPORTS * 10 / 100);
        let pool = MIN_FEE_LAMPORTS - c - t;
        assert_eq!(p, pool / 3);
        assert_eq!(r, pool % 3);
        // Conservation of value: coordinator + treasury + per*N + remainder = amount.
        assert_eq!(c + t + p * 3 + r, MIN_FEE_LAMPORTS);
    }

    #[test]
    fn split_round_amount_no_remainder() {
        let amount = 10_000u64; // divisible by 100 and by 5 participants
        let (c, t, p, r) = compute_fee_split(amount, 5).unwrap();
        assert_eq!(c, 4_000);
        assert_eq!(t, 1_000);
        assert_eq!(p, 1_000);
        assert_eq!(r, 0);
    }

    #[test]
    fn split_rejects_zero_participants() {
        let err = compute_fee_split(MIN_FEE_LAMPORTS, 0).unwrap_err();
        // Anchor wraps our QplFeeError; just assert it errored.
        let msg = format!("{err:?}");
        assert!(msg.contains("NoParticipants"), "unexpected error: {msg}");
    }

    #[test]
    fn split_overflow_is_caught() {
        // amount * 50 must overflow u64.
        let huge = u64::MAX / 10;
        let err = compute_fee_split(huge, 3).unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("Overflow"), "unexpected error: {msg}");
    }

    #[test]
    fn checked_add_overflow_protects_balance() {
        // Mirrors deposit_balance's checked_add path.
        let current: u64 = u64::MAX - 10;
        assert!(current.checked_add(11).is_none());
        assert_eq!(current.checked_add(10), Some(u64::MAX));
    }

    #[test]
    fn checked_sub_underflow_protects_lamports() {
        // Mirrors charge_fee / claim's vault checked_sub path.
        let vault_lamports: u64 = 100;
        assert!(vault_lamports.checked_sub(101).is_none());
        assert_eq!(vault_lamports.checked_sub(100), Some(0));
    }
}
