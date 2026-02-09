//! Policy instruction handlers.

#![allow(clippy::too_many_arguments)]

use anchor_lang::prelude::*;

use crate::error::CatalystError;
use crate::state::policy::*;

// ── InitPolicy ──────────────────────────────────────────────────

#[derive(Accounts)]
pub struct InitPolicy<'info> {
    #[account(
        init,
        payer = authority,
        space = Policy::FIXED_SPACE,
        seeds = [POLICY_SEED, authority.key().as_ref(), drift_sub_account.key().as_ref()],
        bump,
    )]
    pub policy: Account<'info, Policy>,

    #[account(mut)]
    pub authority: Signer<'info>,

    /// CHECK: The Drift sub-account this policy governs. Validated at
    /// execution time when CPI-ing to Drift.
    pub drift_sub_account: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handle_init_policy(
    ctx: Context<InitPolicy>,
    allowed_markets: Vec<u16>,
    max_base_amount: u64,
    oracle_deviation_bps: u16,
    min_time_window: i64,
    max_time_window: i64,
    rate_limit_per_window: u16,
    reduce_only: bool,
) -> Result<()> {
    require!(
        allowed_markets.len() <= MAX_ALLOWED_MARKETS,
        CatalystError::TooManyMarkets
    );
    require!(
        oracle_deviation_bps <= 10_000,
        CatalystError::OracleDeviationTooLarge
    );
    require!(
        min_time_window > 0 && max_time_window >= min_time_window,
        CatalystError::InvalidTimeWindow
    );

    let clock = Clock::get()?;
    let policy = &mut ctx.accounts.policy;

    policy.authority = ctx.accounts.authority.key();
    policy.drift_sub_account = ctx.accounts.drift_sub_account.key();
    policy.bump = ctx.bumps.policy;
    policy.paused = false;
    policy.allowed_markets = allowed_markets;
    policy.max_base_amount = max_base_amount;
    policy.oracle_deviation_bps = oracle_deviation_bps;
    policy.min_time_window = min_time_window;
    policy.max_time_window = max_time_window;
    policy.rate_limit_per_window = rate_limit_per_window;
    policy.reduce_only = reduce_only;
    policy.ticket_count = 0;
    policy.executed_count = 0;
    policy.created_at = clock.unix_timestamp;
    policy.updated_at = clock.unix_timestamp;
    policy.last_executed_at = 0;

    msg!(
        "Policy initialized for sub-account {}",
        policy.drift_sub_account
    );
    Ok(())
}

// ── UpdatePolicy ────────────────────────────────────────────────

#[derive(Accounts)]
pub struct UpdatePolicy<'info> {
    #[account(
        mut,
        has_one = authority @ CatalystError::Unauthorized,
    )]
    pub policy: Account<'info, Policy>,

    pub authority: Signer<'info>,
}

pub fn handle_update_policy(
    ctx: Context<UpdatePolicy>,
    allowed_markets: Option<Vec<u16>>,
    max_base_amount: Option<u64>,
    oracle_deviation_bps: Option<u16>,
    reduce_only: Option<bool>,
) -> Result<()> {
    let policy = &mut ctx.accounts.policy;
    let clock = Clock::get()?;

    if let Some(markets) = allowed_markets {
        require!(
            markets.len() <= MAX_ALLOWED_MARKETS,
            CatalystError::TooManyMarkets
        );
        policy.allowed_markets = markets;
    }

    if let Some(amount) = max_base_amount {
        policy.max_base_amount = amount;
    }

    if let Some(bps) = oracle_deviation_bps {
        require!(bps <= 10_000, CatalystError::OracleDeviationTooLarge);
        policy.oracle_deviation_bps = bps;
    }

    if let Some(ro) = reduce_only {
        policy.reduce_only = ro;
    }

    policy.updated_at = clock.unix_timestamp;
    msg!("Policy updated");
    Ok(())
}

// ── PausePolicy ─────────────────────────────────────────────────

#[derive(Accounts)]
pub struct PausePolicy<'info> {
    #[account(
        mut,
        has_one = authority @ CatalystError::Unauthorized,
    )]
    pub policy: Account<'info, Policy>,

    pub authority: Signer<'info>,
}

pub fn handle_pause_policy(ctx: Context<PausePolicy>, paused: bool) -> Result<()> {
    let policy = &mut ctx.accounts.policy;
    let clock = Clock::get()?;

    policy.paused = paused;
    policy.updated_at = clock.unix_timestamp;

    msg!(
        "Policy {} {}",
        policy.key(),
        if paused { "paused" } else { "unpaused" }
    );
    Ok(())
}
