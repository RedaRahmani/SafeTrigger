// Anchor / Solana macros emit cfg checks and use deprecated APIs that our
// toolchain warns about. These are NOT our code — suppress only these
// known macro-generated warnings so that clippy -D warnings passes.
#![allow(unexpected_cfgs)]
#![allow(deprecated)]

use anchor_lang::prelude::*;

use drift_cpi::instructions::OrderParams;

// This program is intentionally loaded at the real Drift program ID in localnet
// integration tests (via genesis), so CatalystGuard can CPI to the pinned ID.
declare_id!("dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH");

#[program]
pub mod drift_stub {
    use super::*;

    pub fn init_state(ctx: Context<InitState>) -> Result<()> {
        let state = &mut ctx.accounts.state;
        state.admin = ctx.accounts.admin.key();
        state.bump = ctx.bumps.state;
        Ok(())
    }

    pub fn init_user(ctx: Context<InitUser>, sub_account_id: u16) -> Result<()> {
        let user = &mut ctx.accounts.user;
        user.authority = ctx.accounts.authority.key();
        user.delegate = Pubkey::default();
        user.sub_account_id = sub_account_id;
        user.bump = ctx.bumps.user;
        Ok(())
    }

    pub fn init_user_stats(ctx: Context<InitUserStats>) -> Result<()> {
        let stats = &mut ctx.accounts.user_stats;
        stats.authority = ctx.accounts.authority.key();
        stats.bump = ctx.bumps.user_stats;
        Ok(())
    }

    pub fn update_user_delegate(ctx: Context<UpdateUserDelegate>, delegate: Pubkey) -> Result<()> {
        let user = &mut ctx.accounts.user;
        user.delegate = delegate;
        Ok(())
    }

    pub fn init_spot_market(
        ctx: Context<InitSpotMarket>,
        market_index: u16,
        oracle: Pubkey,
    ) -> Result<()> {
        let market_key = ctx.accounts.spot_market.key();
        let market = &mut ctx.accounts.spot_market;
        market.pubkey = market_key;
        market.oracle = oracle;
        market.market_index = market_index;
        market.bump = ctx.bumps.spot_market;
        Ok(())
    }

    pub fn init_perp_market(
        ctx: Context<InitPerpMarket>,
        market_index: u16,
        oracle: Pubkey,
    ) -> Result<()> {
        let market_key = ctx.accounts.perp_market.key();
        let market = &mut ctx.accounts.perp_market;
        market.pubkey = market_key;
        market.oracle = oracle;
        market.market_index = market_index;
        market.bump = ctx.bumps.perp_market;
        Ok(())
    }

    /// Stub implementation of Drift's `place_perp_order`.
    ///
    /// Enforces the delegate authority model:
    /// - `authority` signer must equal `user.authority` OR `user.delegate` (non-default)
    ///
    /// The instruction intentionally does NOT implement Drift risk/margin logic.
    pub fn place_perp_order(ctx: Context<PlacePerpOrder>, _params: OrderParams) -> Result<()> {
        let user = &ctx.accounts.user;
        let signer = ctx.accounts.authority.key();

        let can_sign = signer == user.authority
            || (signer == user.delegate && user.delegate != Pubkey::default());
        require!(can_sign, DriftStubError::Unauthorized);

        Ok(())
    }
}

// ── Accounts ────────────────────────────────────────────────────

#[derive(Accounts)]
pub struct InitState<'info> {
    #[account(
        init,
        payer = admin,
        space = DriftState::SPACE,
        seeds = [drift_cpi::DRIFT_STATE_SEED],
        bump,
    )]
    pub state: Account<'info, DriftState>,

    #[account(mut)]
    pub admin: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(sub_account_id: u16)]
pub struct InitUser<'info> {
    #[account(
        init,
        payer = authority,
        space = DriftUser::SPACE,
        seeds = [drift_cpi::DRIFT_USER_SEED, authority.key().as_ref(), &sub_account_id.to_le_bytes()],
        bump,
    )]
    pub user: Account<'info, DriftUser>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitUserStats<'info> {
    #[account(
        init,
        payer = authority,
        space = DriftUserStats::SPACE,
        seeds = [drift_cpi::DRIFT_USER_STATS_SEED, authority.key().as_ref()],
        bump,
    )]
    pub user_stats: Account<'info, DriftUserStats>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateUserDelegate<'info> {
    #[account(mut, has_one = authority)]
    pub user: Account<'info, DriftUser>,

    pub authority: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(market_index: u16)]
pub struct InitSpotMarket<'info> {
    #[account(
        init,
        payer = admin,
        space = DriftSpotMarket::SPACE,
        seeds = [drift_cpi::DRIFT_SPOT_MARKET_SEED, &market_index.to_le_bytes()],
        bump,
    )]
    pub spot_market: Account<'info, DriftSpotMarket>,

    #[account(mut)]
    pub admin: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(market_index: u16)]
pub struct InitPerpMarket<'info> {
    #[account(
        init,
        payer = admin,
        space = DriftPerpMarket::SPACE,
        seeds = [drift_cpi::DRIFT_PERP_MARKET_SEED, &market_index.to_le_bytes()],
        bump,
    )]
    pub perp_market: Account<'info, DriftPerpMarket>,

    #[account(mut)]
    pub admin: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct PlacePerpOrder<'info> {
    pub state: Account<'info, DriftState>,

    #[account(mut)]
    pub user: Account<'info, DriftUser>,

    pub authority: Signer<'info>,
}

// ── State Types ─────────────────────────────────────────────────

#[account]
#[derive(Debug)]
pub struct DriftState {
    pub admin: Pubkey,
    pub bump: u8,
}

impl DriftState {
    pub const SPACE: usize = 8 + 32 + 1;
}

#[account]
#[derive(Debug)]
pub struct DriftUser {
    pub authority: Pubkey,
    pub delegate: Pubkey,
    pub sub_account_id: u16,
    pub bump: u8,
}

impl DriftUser {
    pub const SPACE: usize = 8 + 32 + 32 + 2 + 1;
}

#[account]
#[derive(Debug)]
pub struct DriftUserStats {
    pub authority: Pubkey,
    pub bump: u8,
}

impl DriftUserStats {
    pub const SPACE: usize = 8 + 32 + 1;
}

/// Minimal spot market account that preserves the first two fields of Drift's real SpotMarket:
/// - `pubkey`
/// - `oracle`
///
/// This allows CatalystGuard to validate `oracle` by reading bytes at offset 40.
#[account]
#[derive(Debug)]
pub struct DriftSpotMarket {
    pub pubkey: Pubkey,
    pub oracle: Pubkey,
    pub market_index: u16,
    pub bump: u8,
}

impl DriftSpotMarket {
    pub const SPACE: usize = 8 + 32 + 32 + 2 + 1;
}

/// Minimal perp market account that preserves the first two fields of Drift's real PerpMarket:
/// - `pubkey`
/// - `amm.oracle` (represented here as `oracle`)
///
/// This allows CatalystGuard to validate `oracle` by reading bytes at offset 40.
#[account]
#[derive(Debug)]
pub struct DriftPerpMarket {
    pub pubkey: Pubkey,
    pub oracle: Pubkey,
    pub market_index: u16,
    pub bump: u8,
}

impl DriftPerpMarket {
    pub const SPACE: usize = 8 + 32 + 32 + 2 + 1;
}

// ── Errors ─────────────────────────────────────────────────────

#[error_code]
pub enum DriftStubError {
    #[msg("Unauthorized signer for drift user")]
    Unauthorized,
}
