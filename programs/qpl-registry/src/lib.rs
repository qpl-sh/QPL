use anchor_lang::prelude::*;

declare_id!("QPLReg1111111111111111111111111111111111111");

/// Service type bitmask values (matches qpl-network/src/types.rs)
pub const SERVICE_SIGNING: u32 = 1 << 1;  // 0x02
pub const SERVICE_PROVING: u32 = 1 << 2;  // 0x04

#[program]
pub mod qpl_registry {
    use super::*;

    /// Register an operator's endpoint and capabilities for on-chain discovery.
    /// Typically called during staking, but can be updated independently.
    pub fn register(
        ctx: Context<Register>,
        operator_id: [u8; 32],
        endpoint: String,
        services_bitmask: u32,
    ) -> Result<()> {
        require!(services_bitmask > 0, QplRegistryError::NoServicesSelected);
        require!(!endpoint.is_empty(), QplRegistryError::EmptyEndpoint);
        require!(endpoint.len() <= 128, QplRegistryError::EndpointTooLong);

        let entry = &mut ctx.accounts.registry_entry;
        entry.operator_id = operator_id;
        entry.authority = ctx.accounts.operator.key();
        entry.endpoint = endpoint.clone();
        entry.services_bitmask = services_bitmask;
        entry.active = true;
        entry.registered_at = Clock::get()?.unix_timestamp;
        entry.last_updated = Clock::get()?.unix_timestamp;
        entry.bump = ctx.bumps.registry_entry;

        emit!(OperatorRegistered {
            operator_id,
            endpoint,
            services_bitmask,
        });

        Ok(())
    }

    /// Update an operator's endpoint or service capabilities.
    pub fn update(
        ctx: Context<Update>,
        endpoint: Option<String>,
        services_bitmask: Option<u32>,
    ) -> Result<()> {
        let entry = &mut ctx.accounts.registry_entry;

        if let Some(ep) = endpoint {
            require!(!ep.is_empty(), QplRegistryError::EmptyEndpoint);
            require!(ep.len() <= 128, QplRegistryError::EndpointTooLong);
            entry.endpoint = ep;
        }

        if let Some(mask) = services_bitmask {
            require!(mask > 0, QplRegistryError::NoServicesSelected);
            entry.services_bitmask = mask;
        }

        entry.last_updated = Clock::get()?.unix_timestamp;

        emit!(OperatorUpdated {
            operator_id: entry.operator_id,
            endpoint: entry.endpoint.clone(),
            services_bitmask: entry.services_bitmask,
        });

        Ok(())
    }

    /// Deactivate an operator entry (e.g., when draining or exiting).
    pub fn deactivate(ctx: Context<Deactivate>) -> Result<()> {
        let entry = &mut ctx.accounts.registry_entry;
        entry.active = false;
        entry.last_updated = Clock::get()?.unix_timestamp;

        emit!(OperatorDeactivated {
            operator_id: entry.operator_id,
        });

        Ok(())
    }
}

// ─── Accounts ────────────────────────────────────────────────────────────────

#[derive(Accounts)]
#[instruction(operator_id: [u8; 32])]
pub struct Register<'info> {
    #[account(mut)]
    pub operator: Signer<'info>,

    #[account(
        init,
        payer = operator,
        space = RegistryEntry::SPACE,
        seeds = [b"registry", operator_id.as_ref()],
        bump
    )]
    pub registry_entry: Account<'info, RegistryEntry>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Update<'info> {
    #[account(mut)]
    pub operator: Signer<'info>,

    #[account(
        mut,
        constraint = operator.key() == registry_entry.authority @ QplRegistryError::Unauthorized
    )]
    pub registry_entry: Account<'info, RegistryEntry>,
}

#[derive(Accounts)]
pub struct Deactivate<'info> {
    #[account(mut)]
    pub operator: Signer<'info>,

    #[account(
        mut,
        constraint = operator.key() == registry_entry.authority @ QplRegistryError::Unauthorized
    )]
    pub registry_entry: Account<'info, RegistryEntry>,
}

// ─── State ───────────────────────────────────────────────────────────────────

#[account]
pub struct RegistryEntry {
    /// Operator identity (SHA-256 of ML-DSA public key)
    pub operator_id: [u8; 32],
    /// Wallet authority
    pub authority: Pubkey,
    /// Network endpoint for SDK discovery
    pub endpoint: String,
    /// Bitmask of supported services (Signing=0x02, Proving=0x04)
    pub services_bitmask: u32,
    /// Whether this operator is currently active
    pub active: bool,
    /// Registration timestamp
    pub registered_at: i64,
    /// Last update timestamp
    pub last_updated: i64,
    /// PDA bump
    pub bump: u8,
}

impl RegistryEntry {
    // 8 + 32 + 32 + (4 + 128) + 4 + 1 + 8 + 8 + 1 = 226
    pub const SPACE: usize = 8 + 32 + 32 + (4 + 128) + 4 + 1 + 8 + 8 + 1;
}

// ─── Events ──────────────────────────────────────────────────────────────────

#[event]
pub struct OperatorRegistered {
    pub operator_id: [u8; 32],
    pub endpoint: String,
    pub services_bitmask: u32,
}

#[event]
pub struct OperatorUpdated {
    pub operator_id: [u8; 32],
    pub endpoint: String,
    pub services_bitmask: u32,
}

#[event]
pub struct OperatorDeactivated {
    pub operator_id: [u8; 32],
}

// ─── Errors ──────────────────────────────────────────────────────────────────

#[error_code]
pub enum QplRegistryError {
    #[msg("Must support at least one service")]
    NoServicesSelected,
    #[msg("Endpoint cannot be empty")]
    EmptyEndpoint,
    #[msg("Endpoint too long (max 128 chars)")]
    EndpointTooLong,
    #[msg("Unauthorized")]
    Unauthorized,
}
