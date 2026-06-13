use anchor_lang::prelude::*;

declare_id!("QPLStk1111111111111111111111111111111111111");

/// Minimum stake: 10 SOL (in lamports) — ~$680 at $68/SOL
/// Provides meaningful Sybil resistance and skin-in-the-game for operators.
/// At 10K sigs/day revenue (~$210/day), 10 SOL ≈ 3.2 days of revenue at risk.
pub const MIN_STAKE_LAMPORTS: u64 = 10_000_000_000;

/// Unbonding period: 7 days in seconds
pub const UNBOND_PERIOD_SECS: i64 = 7 * 24 * 3600;

#[program]
pub mod qpl_staking {
    use super::*;

    /// Initialize the staking configuration PDA.
    /// Must be called once before any slashing can occur.
    /// Sets the governance authority and treasury address.
    pub fn initialize_config(
        ctx: Context<InitializeConfig>,
        treasury: Pubkey,
    ) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.governance = ctx.accounts.governance.key();
        config.treasury = treasury;
        config.bump = ctx.bumps.config;

        emit!(ConfigInitialized {
            governance: config.governance,
            treasury: config.treasury,
        });

        Ok(())
    }

    /// Initialize the stake vault PDA.
    /// Must be called once before operators can stake.
    pub fn initialize_vault(ctx: Context<InitializeVault>) -> Result<()> {
        let vault = &mut ctx.accounts.stake_vault;
        vault.bump = ctx.bumps.stake_vault;

        emit!(VaultInitialized {
            authority: ctx.accounts.authority.key(),
        });

        Ok(())
    }

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
    /// Can be called by active operators OR slashed (inactive) operators
    /// to recover remaining funds.
    pub fn initiate_unstake(ctx: Context<InitiateUnstake>) -> Result<()> {
        let operator_account = &mut ctx.accounts.operator_account;

        require!(operator_account.staked_amount > 0, QplStakingError::NothingStaked);
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

        // Transfer SOL from vault back to operator (checked arithmetic for defense-in-depth)
        let vault_info = ctx.accounts.stake_vault.to_account_info();
        **vault_info.try_borrow_mut_lamports()? = vault_info
            .lamports()
            .checked_sub(amount)
            .ok_or(QplStakingError::InsufficientVaultBalance)?;
        **ctx.accounts.operator.to_account_info().try_borrow_mut_lamports()? = ctx
            .accounts
            .operator
            .to_account_info()
            .lamports()
            .checked_add(amount)
            .ok_or(QplStakingError::Overflow)?;

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

        operator_account.staked_amount = operator_account
            .staked_amount
            .checked_sub(amount)
            .ok_or(QplStakingError::SlashExceedsStake)?;

        // Deactivate if below minimum
        if operator_account.staked_amount < MIN_STAKE_LAMPORTS && operator_account.active {
            operator_account.active = false;
        }

        // Transfer slashed amount to treasury (checked arithmetic)
        let vault_info = ctx.accounts.stake_vault.to_account_info();
        **vault_info.try_borrow_mut_lamports()? = vault_info
            .lamports()
            .checked_sub(amount)
            .ok_or(QplStakingError::InsufficientVaultBalance)?;
        let treasury_info = ctx.accounts.treasury.to_account_info();
        **treasury_info.try_borrow_mut_lamports()? = treasury_info
            .lamports()
            .checked_add(amount)
            .ok_or(QplStakingError::Overflow)?;

        emit!(OperatorSlashed {
            operator_id: operator_account.operator_id,
            amount,
            reason,
        });

        Ok(())
    }

    /// Deposit additional stake to an existing operator account.
    /// Allows operators to top up after partial slashing or increase their collateral.
    /// Reactivates the operator if stake rises above MIN_STAKE_LAMPORTS.
    pub fn deposit_stake(ctx: Context<DepositStake>, amount: u64) -> Result<()> {
        require!(amount > 0, QplStakingError::InsufficientStake);

        let operator_account = &mut ctx.accounts.operator_account;
        require!(
            operator_account.unstake_time == 0,
            QplStakingError::CannotDepositWhileUnstaking
        );

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

        operator_account.staked_amount += amount;

        // Reactivate if above minimum and not in unbonding
        if operator_account.staked_amount >= MIN_STAKE_LAMPORTS {
            operator_account.active = true;
        }

        emit!(StakeDeposited {
            operator_id: operator_account.operator_id,
            amount,
            new_total: operator_account.staked_amount,
            reactivated: operator_account.active,
        });

        Ok(())
    }
}

// ─── Accounts ────────────────────────────────────────────────────────────────

#[derive(Accounts)]
pub struct InitializeConfig<'info> {
    #[account(mut)]
    pub governance: Signer<'info>,

    #[account(
        init,
        payer = governance,
        space = 8 + 32 + 32 + 1, // discriminator + governance + treasury + bump
        seeds = [b"config"],
        bump
    )]
    pub config: Account<'info, StakingConfig>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitializeVault<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init,
        payer = authority,
        space = 8 + 1, // discriminator + bump
        seeds = [b"vault"],
        bump
    )]
    pub stake_vault: Account<'info, StakeVault>,

    pub system_program: Program<'info, System>,
}

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

#[derive(Accounts)]
pub struct DepositStake<'info> {
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

    pub system_program: Program<'info, System>,
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
pub struct ConfigInitialized {
    pub governance: Pubkey,
    pub treasury: Pubkey,
}

#[event]
pub struct VaultInitialized {
    pub authority: Pubkey,
}

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

#[event]
pub struct StakeDeposited {
    pub operator_id: [u8; 32],
    pub amount: u64,
    pub new_total: u64,
    pub reactivated: bool,
}

// ─── Errors ──────────────────────────────────────────────────────────────────

#[error_code]
pub enum QplStakingError {
    #[msg("Insufficient stake: minimum 10 SOL required")]
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
    #[msg("No staked amount to unstake")]
    NothingStaked,
    #[msg("Cannot deposit while unstaking is in progress")]
    CannotDepositWhileUnstaking,
    #[msg("Vault has insufficient balance")]
    InsufficientVaultBalance,
    #[msg("Arithmetic overflow")]
    Overflow,
}