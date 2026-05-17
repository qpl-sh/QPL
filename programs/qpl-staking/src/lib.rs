use anchor_lang::prelude::*;

declare_id!("QPLStk1111111111111111111111111111111111111");

/// Minimum stake: 1 SOL (in lamports)
pub const MIN_STAKE_LAMPORTS: u64 = 1_000_000_000;

/// Unbonding period: 7 days in seconds
pub const UNBOND_PERIOD_SECS: i64 = 7 * 24 * 3600;

#[program]
pub mod qpl_staking {
    use super::*;

    /// Register as an operator by staking SOL.
    /// Transfers `amount` lamports from the operator to the stake vault.
    pub fn stake(
        ctx: Context<Stake>,
        operator_id: [u8; 32],
        endpoint: String,
        services_bitmask: u32,
        amount: u64,
    ) -> Result<()> {
        require!(amount >= MIN_STAKE_LAMPORTS, QplStakingError::InsufficientStake);
        require!(services_bitmask > 0, QplStakingError::NoServicesSelected);
        require!(endpoint.len() <= 128, QplStakingError::EndpointTooLong);

        // Transfer SOL from operator to vault
        let transfer_ix = anchor_lang::system_program::Transfer {
            from: ctx.accounts.operator.to_account_info(),
            to: ctx.accounts.stake_vault.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            transfer_ix,
        );
        anchor_lang::system_program::transfer(cpi_ctx, amount)?;

        // Initialize operator account
        let operator_account = &mut ctx.accounts.operator_account;
        operator_account.operator_id = operator_id;
        operator_account.authority = ctx.accounts.operator.key();
        operator_account.staked_amount = amount;
        operator_account.endpoint = endpoint;
        operator_account.services_bitmask = services_bitmask;
        operator_account.active = true;
        operator_account.unstake_time = 0;
        operator_account.registered_at = Clock::get()?.unix_timestamp;
        operator_account.bump = ctx.bumps.operator_account;

        emit!(OperatorStaked {
            operator_id,
            authority: ctx.accounts.operator.key(),
            amount,
        });

        Ok(())
    }

    /// Initiate unstaking — begins the 7-day unbonding period.
    pub fn initiate_unstake(ctx: Context<InitiateUnstake>) -> Result<()> {
        let operator_account = &mut ctx.accounts.operator_account;

        require!(operator_account.active, QplStakingError::NotActive);
        require!(operator_account.unstake_time == 0, QplStakingError::AlreadyUnstaking);

        let clock = Clock::get()?;
        operator_account.active = false;
        operator_account.unstake_time = clock.unix_timestamp + UNBOND_PERIOD_SECS;

        emit!(UnstakeInitiated {
            operator_id: operator_account.operator_id,
            unstake_time: operator_account.unstake_time,
        });

        Ok(())
    }

    /// Withdraw stake after unbonding period has elapsed.
    pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
        let operator_account = &mut ctx.accounts.operator_account;

        require!(operator_account.unstake_time > 0, QplStakingError::NotUnstaking);
        let clock = Clock::get()?;
        require!(
            clock.unix_timestamp >= operator_account.unstake_time,
            QplStakingError::UnbondingNotElapsed
        );

        let amount = operator_account.staked_amount;
        operator_account.staked_amount = 0;

        // Transfer SOL from vault back to operator
        let vault_bump = ctx.accounts.stake_vault.bump;
        let seeds = &[b"vault".as_ref(), &[vault_bump]];
        let signer_seeds = &[&seeds[..]];

        **ctx.accounts.stake_vault.to_account_info().try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.operator.to_account_info().try_borrow_mut_lamports()? += amount;

        emit!(StakeWithdrawn {
            operator_id: operator_account.operator_id,
            amount,
        });

        Ok(())
    }

    /// Governance slashes an operator's stake for protocol violations.
    pub fn slash(
        ctx: Context<Slash>,
        amount: u64,
        reason: String,
    ) -> Result<()> {
        let operator_account = &mut ctx.accounts.operator_account;

        require!(
            operator_account.staked_amount >= amount,
            QplStakingError::SlashExceedsStake
        );

        operator_account.staked_amount -= amount;

        // Deactivate if below minimum
        if operator_account.staked_amount < MIN_STAKE_LAMPORTS && operator_account.active {
            operator_account.active = false;
        }

        // Transfer slashed amount to treasury
        **ctx.accounts.stake_vault.to_account_info().try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.treasury.to_account_info().try_borrow_mut_lamports()? += amount;

        emit!(OperatorSlashed {
            operator_id: operator_account.operator_id,
            amount,
            reason,
        });

        Ok(())
    }
}

// ─── Accounts ────────────────────────────────────────────────────────────────

#[derive(Accounts)]
#[instruction(operator_id: [u8; 32])]
pub struct Stake<'info> {
    #[account(mut)]
    pub operator: Signer<'info>,

    #[account(
        init,
        payer = operator,
        space = OperatorAccount::SPACE,
        seeds = [b"operator", operator_id.as_ref()],
        bump
    )]
    pub operator_account: Account<'info, OperatorAccount>,

    #[account(
        mut,
        seeds = [b"vault"],
        bump = stake_vault.bump
    )]
    pub stake_vault: Account<'info, StakeVault>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitiateUnstake<'info> {
    #[account(mut)]
    pub operator: Signer<'info>,

    #[account(
        mut,
        has_one = authority @ QplStakingError::Unauthorized,
        constraint = operator.key() == operator_account.authority
    )]
    pub operator_account: Account<'info, OperatorAccount>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub operator: Signer<'info>,

    #[account(
        mut,
        has_one = authority @ QplStakingError::Unauthorized,
        constraint = operator.key() == operator_account.authority
    )]
    pub operator_account: Account<'info, OperatorAccount>,

    #[account(
        mut,
        seeds = [b"vault"],
        bump = stake_vault.bump
    )]
    pub stake_vault: Account<'info, StakeVault>,
}

#[derive(Accounts)]
pub struct Slash<'info> {
    #[account(mut)]
    pub governance: Signer<'info>,

    #[account(
        mut,
        constraint = governance.key() == config.governance @ QplStakingError::Unauthorized
    )]
    pub operator_account: Account<'info, OperatorAccount>,

    #[account(
        mut,
        seeds = [b"vault"],
        bump = stake_vault.bump
    )]
    pub stake_vault: Account<'info, StakeVault>,

    /// CHECK: Treasury receives slashed funds
    #[account(mut, constraint = treasury.key() == config.treasury)]
    pub treasury: UncheckedAccount<'info>,

    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, StakingConfig>,
}

// ─── State ───────────────────────────────────────────────────────────────────

#[account]
pub struct OperatorAccount {
    /// Operator identity (SHA-256 of ML-DSA public key)
    pub operator_id: [u8; 32],
    /// Wallet authority that can unstake/withdraw
    pub authority: Pubkey,
    /// Amount of SOL staked (lamports)
    pub staked_amount: u64,
    /// Network endpoint (IP:port or DNS)
    pub endpoint: String,
    /// Bitmask of supported services
    pub services_bitmask: u32,
    /// Whether operator is actively serving requests
    pub active: bool,
    /// Unix timestamp when unbonding completes (0 = not unstaking)
    pub unstake_time: i64,
    /// When the operator registered
    pub registered_at: i64,
    /// PDA bump seed
    pub bump: u8,
}

impl OperatorAccount {
    // 8 (discriminator) + 32 + 32 + 8 + (4 + 128) + 4 + 1 + 8 + 8 + 1 = 234
    pub const SPACE: usize = 8 + 32 + 32 + 8 + (4 + 128) + 4 + 1 + 8 + 8 + 1;
}

#[account]
pub struct StakeVault {
    pub bump: u8,
}

#[account]
pub struct StakingConfig {
    pub governance: Pubkey,
    pub treasury: Pubkey,
    pub bump: u8,
}

// ─── Events ──────────────────────────────────────────────────────────────────

#[event]
pub struct OperatorStaked {
    pub operator_id: [u8; 32],
    pub authority: Pubkey,
    pub amount: u64,
}

#[event]
pub struct UnstakeInitiated {
    pub operator_id: [u8; 32],
    pub unstake_time: i64,
}

#[event]
pub struct StakeWithdrawn {
    pub operator_id: [u8; 32],
    pub amount: u64,
}

#[event]
pub struct OperatorSlashed {
    pub operator_id: [u8; 32],
    pub amount: u64,
    pub reason: String,
}

// ─── Errors ──────────────────────────────────────────────────────────────────

#[error_code]
pub enum QplStakingError {
    #[msg("Insufficient stake: minimum 1 SOL required")]
    InsufficientStake,
    #[msg("Must support at least one service")]
    NoServicesSelected,
    #[msg("Endpoint too long (max 128 chars)")]
    EndpointTooLong,
    #[msg("Operator is not active")]
    NotActive,
    #[msg("Already unstaking")]
    AlreadyUnstaking,
    #[msg("Not currently unstaking")]
    NotUnstaking,
    #[msg("Unbonding period has not elapsed")]
    UnbondingNotElapsed,
    #[msg("Slash amount exceeds staked amount")]
    SlashExceedsStake,
    #[msg("Unauthorized")]
    Unauthorized,
}
