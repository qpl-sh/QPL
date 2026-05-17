use anchor_lang::prelude::*;

declare_id!("QPLFee1111111111111111111111111111111111111");

/// Fee split constants (must sum to 100)
pub const COORDINATOR_SHARE_PCT: u8 = 40;
pub const PARTICIPANT_SHARE_PCT: u8 = 50;
pub const TREASURY_SHARE_PCT: u8 = 10;

/// Minimum fee to prevent dust attacks (in lamports, ~$0.001 at $150/SOL)
pub const MIN_FEE_LAMPORTS: u64 = 6_667; // ~$0.001

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
        balance.balance = balance.balance.checked_add(amount).unwrap();

        emit!(BalanceDeposited {
            protocol: ctx.accounts.protocol.key(),
            amount,
            new_balance: balance.balance,
        });

        Ok(())
    }

    /// Deduct fee from a protocol's prepaid balance and record for distribution.
    /// Called by governance/coordinator after an operation completes.
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

        // Deduct from protocol balance
        balance.balance -= amount;

        // Calculate split
        let coordinator_amount = amount * COORDINATOR_SHARE_PCT as u64 / 100;
        let treasury_amount = amount * TREASURY_SHARE_PCT as u64 / 100;
        let participant_pool = amount - coordinator_amount - treasury_amount;
        let per_participant = participant_pool / participants.len() as u64;

        // Record coordinator earnings
        let coordinator_earnings = &mut ctx.accounts.coordinator_earnings;
        coordinator_earnings.operator = coordinator;
        coordinator_earnings.claimable += coordinator_amount;

        // Transfer treasury share immediately
        let vault_bump = ctx.accounts.fee_vault.bump;
        **ctx.accounts.fee_vault.to_account_info().try_borrow_mut_lamports()? -= treasury_amount;
        **ctx.accounts.treasury.to_account_info().try_borrow_mut_lamports()? += treasury_amount;

        // Update config totals
        let config = &mut ctx.accounts.config;
        config.total_fees_collected += amount;
        config.total_fees_distributed += treasury_amount;

        emit!(FeeCharged {
            protocol: balance.protocol,
            total_fee: amount,
            coordinator_amount,
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
        earnings.total_claimed += amount;

        // Transfer from fee vault to operator
        **ctx.accounts.fee_vault.to_account_info().try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.operator.to_account_info().try_borrow_mut_lamports()? += amount;

        emit!(FeesClaimed {
            operator: ctx.accounts.operator.key(),
            amount,
        });

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
}
