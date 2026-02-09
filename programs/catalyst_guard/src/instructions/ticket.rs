//! Ticket instruction handlers.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke_signed;
use sha2::{Digest, Sha256};

use crate::error::CatalystError;
use crate::events::{TicketCancelled, TicketCreated, TicketExecuted, TicketExpired};
use crate::state::oracle::PriceFeed;
use crate::state::payload::HedgePayloadV1;
use crate::state::policy::{Policy, POLICY_SEED};
use crate::state::ticket::*;
use drift_cpi::instructions::{
    build_place_perp_order_accounts, build_place_perp_order_data, MarketType, OrderParams,
    OrderTriggerCondition, PostOnlyParam,
};

/// Domain separator for commitment preimage (version 0.2).
pub const COMMITMENT_DOMAIN: &[u8] = b"CSv0.2";

/// Maximum ticket expiry: 7 days from now.
pub const MAX_EXPIRY_WINDOW: i64 = 7 * 24 * 60 * 60;

/// CatalystGuard MVP: only Drift sub-account id 0 is supported.
pub const DRIFT_SUB_ACCOUNT_ID: u16 = 0;

// ── CreateTicket ────────────────────────────────────────────────

#[derive(Accounts)]
#[instruction(commitment: [u8; 32], ticket_id: [u8; 32])]
pub struct CreateTicket<'info> {
    #[account(
        init,
        payer = owner,
        space = Ticket::SPACE,
        seeds = [TICKET_SEED, policy.key().as_ref(), &ticket_id],
        bump,
    )]
    pub ticket: Account<'info, Ticket>,

    #[account(
        mut,
        constraint = !policy.paused @ CatalystError::PolicyPaused,
        constraint = policy.authority == owner.key() @ CatalystError::Unauthorized,
    )]
    pub policy: Account<'info, Policy>,

    #[account(mut)]
    pub owner: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handle_create_ticket(
    ctx: Context<CreateTicket>,
    commitment: [u8; 32],
    ticket_id: [u8; 32],
    expiry: i64,
) -> Result<()> {
    let clock = Clock::get()?;

    require!(expiry > clock.unix_timestamp, CatalystError::ExpiryInPast);
    require!(
        expiry
            <= clock
                .unix_timestamp
                .checked_add(MAX_EXPIRY_WINDOW)
                .ok_or(CatalystError::MathOverflow)?,
        CatalystError::ExpiryTooFar
    );

    let ticket = &mut ctx.accounts.ticket;
    ticket.owner = ctx.accounts.owner.key();
    ticket.policy = ctx.accounts.policy.key();
    ticket.commitment = commitment;
    ticket.ticket_id = ticket_id;
    ticket.bump = ctx.bumps.ticket;
    ticket.status = TicketStatus::Open;
    ticket.expiry = expiry;
    ticket.created_slot = clock.slot;
    ticket.created_at = clock.unix_timestamp;
    ticket.updated_at = clock.unix_timestamp;
    ticket.executed_slot = 0;

    // Increment policy ticket count
    let policy = &mut ctx.accounts.policy;
    policy.ticket_count = policy
        .ticket_count
        .checked_add(1)
        .ok_or(CatalystError::MathOverflow)?;

    msg!(
        "Ticket created: commitment={:?}, expiry={}",
        &commitment[..8],
        expiry
    );

    emit!(TicketCreated {
        policy: ctx.accounts.policy.key(),
        ticket: ctx.accounts.ticket.key(),
        owner: ctx.accounts.owner.key(),
        ticket_id,
        expiry,
        slot: clock.slot,
    });

    Ok(())
}

// ── CancelTicket ────────────────────────────────────────────────

#[derive(Accounts)]
pub struct CancelTicket<'info> {
    #[account(
        mut,
        has_one = owner @ CatalystError::NotTicketOwner,
        constraint = ticket.is_open() @ CatalystError::TicketAlreadyConsumed,
    )]
    pub ticket: Account<'info, Ticket>,

    pub owner: Signer<'info>,
}

pub fn handle_cancel_ticket(ctx: Context<CancelTicket>) -> Result<()> {
    let ticket = &mut ctx.accounts.ticket;
    let clock = Clock::get()?;

    ticket.status = TicketStatus::Cancelled;
    ticket.updated_at = clock.unix_timestamp;

    emit!(TicketCancelled {
        ticket: ctx.accounts.ticket.key(),
        owner: ctx.accounts.owner.key(),
        slot: clock.slot,
    });

    msg!("Ticket cancelled");
    Ok(())
}

// ── ExpireTicket ────────────────────────────────────────────────

#[derive(Accounts)]
pub struct ExpireTicket<'info> {
    #[account(
        mut,
        constraint = ticket.is_open() @ CatalystError::TicketAlreadyConsumed,
        constraint = ticket.is_expired(Clock::get()?.unix_timestamp) @ CatalystError::TicketNotExpired,
    )]
    pub ticket: Account<'info, Ticket>,

    /// Permissionless: anyone can expire a ticket after its expiry time.
    pub cranker: Signer<'info>,
}

pub fn handle_expire_ticket(ctx: Context<ExpireTicket>) -> Result<()> {
    let ticket = &mut ctx.accounts.ticket;
    let clock = Clock::get()?;

    ticket.status = TicketStatus::Expired;
    ticket.updated_at = clock.unix_timestamp;

    emit!(TicketExpired {
        ticket: ctx.accounts.ticket.key(),
        cranker: ctx.accounts.cranker.key(),
        slot: clock.slot,
    });

    msg!("Ticket expired");
    Ok(())
}

// ── ExecuteTicket ───────────────────────────────────────────────

#[derive(Accounts)]
pub struct ExecuteTicket<'info> {
    #[account(
        mut,
        has_one = policy @ CatalystError::PolicyMismatch,
        constraint = ticket.is_open() @ CatalystError::TicketAlreadyConsumed,
        constraint = !ticket.is_expired(Clock::get()?.unix_timestamp) @ CatalystError::TicketExpired,
        seeds = [TICKET_SEED, ticket.policy.as_ref(), ticket.ticket_id.as_ref()],
        bump = ticket.bump,
    )]
    pub ticket: Account<'info, Ticket>,

    #[account(
        mut,
        constraint = !policy.paused @ CatalystError::PolicyPaused,
        seeds = [POLICY_SEED, policy.authority.as_ref(), policy.drift_sub_account.as_ref()],
        bump = policy.bump,
    )]
    pub policy: Account<'info, Policy>,

    /// The keeper executing the ticket. Permissionless (anyone may execute).
    pub keeper: Signer<'info>,

    /// CHECK: Oracle price feed account. Bound to the commitment via the
    /// revealed payload, and validated in the handler.
    pub oracle: UncheckedAccount<'info>,

    /// CHECK: Drift program account (must match hardcoded allowlist).
    pub drift_program: UncheckedAccount<'info>,

    /// CHECK: Drift state PDA.
    pub drift_state: UncheckedAccount<'info>,

    /// CHECK: Drift user (sub-account) PDA. Mutated by Drift when placing orders.
    #[account(mut)]
    pub drift_user: UncheckedAccount<'info>,

    /// CHECK: Drift user stats PDA (validated, but not required by Drift's IDL for place_perp_order).
    pub drift_user_stats: UncheckedAccount<'info>,

    /// CHECK: Drift quote spot market PDA (index 0).
    pub drift_spot_market: UncheckedAccount<'info>,

    /// CHECK: Drift perp market PDA (derived from payload.market_index).
    pub drift_perp_market: UncheckedAccount<'info>,
}

pub fn handle_execute_ticket(
    ctx: Context<ExecuteTicket>,
    secret_salt: [u8; 32],
    revealed_data: Vec<u8>,
) -> Result<()> {
    let ticket = &ctx.accounts.ticket;
    let policy = &ctx.accounts.policy;
    let clock = Clock::get()?;

    // ── P2: Verify commitment (domain-separated, owner/policy-bound) ──
    // commitment = SHA-256(b"CSv0.2" || owner || policy || ticket_id || secret_salt || revealed_data)
    let mut hasher = Sha256::new();
    hasher.update(COMMITMENT_DOMAIN);
    hasher.update(ticket.owner.as_ref());
    hasher.update(ticket.policy.as_ref());
    hasher.update(ticket.ticket_id);
    hasher.update(secret_salt);
    hasher.update(&revealed_data);
    let computed_hash: [u8; 32] = hasher.finalize().into();

    require!(
        computed_hash == ticket.commitment,
        CatalystError::CommitmentMismatch
    );

    // Receipt helper: hash only the revealed payload bytes, so clients can recompute
    // independent of secret_salt and commitment construction.
    let payload_hash: [u8; 32] = Sha256::digest(&revealed_data).into();

    // ── M1: Deserialize revealed payload ────────────────────────
    let payload = HedgePayloadV1::try_from_slice(&revealed_data)
        .map_err(|_| CatalystError::InvalidRevealData)?;

    // ── M1: Validate payload against policy bounds ──────────────
    payload.validate_against_policy(
        &policy.allowed_markets,
        policy.max_base_amount,
        policy.reduce_only,
        clock.unix_timestamp,
    )?;

    // ── M1: Rate limiting ───────────────────────────────────────
    // Simple rate limit: enforce minimum interval between executions.
    // min_interval = ceil(max_time_window / rate_limit_per_window)
    if policy.rate_limit_per_window > 0 && policy.last_executed_at > 0 {
        let per_window = policy.rate_limit_per_window as i64;
        let min_interval = policy
            .max_time_window
            .checked_add(per_window - 1)
            .ok_or(CatalystError::MathOverflow)?
            .checked_div(per_window)
            .ok_or(CatalystError::MathOverflow)?;
        let elapsed = clock
            .unix_timestamp
            .checked_sub(policy.last_executed_at)
            .ok_or(CatalystError::MathOverflow)?;
        require!(elapsed >= min_interval, CatalystError::RateLimitExceeded);
    }

    // ── M1: Oracle freshness + predicate gating ─────────────────
    // The oracle program/account are commitment-bound via the revealed payload,
    // preventing executors from swapping in a different price feed.
    require!(
        payload.oracle == ctx.accounts.oracle.key(),
        CatalystError::InvalidOracleAccount
    );
    require!(
        payload.oracle_program == *ctx.accounts.oracle.to_account_info().owner,
        CatalystError::InvalidOracleAccount
    );

    let mut oracle_data: &[u8] = &ctx.accounts.oracle.try_borrow_data()?;
    let feed = PriceFeed::try_deserialize(&mut oracle_data)
        .map_err(|_| CatalystError::InvalidOracleAccount)?;

    require!(policy.min_time_window > 0, CatalystError::InvalidTimeWindow);
    let max_staleness_slots = policy.min_time_window as u64;
    let age_slots = clock
        .slot
        .checked_sub(feed.last_updated_slot)
        .ok_or(CatalystError::InvalidOracleAccount)?;
    require!(age_slots <= max_staleness_slots, CatalystError::OracleStale);

    require!(
        payload.is_trigger_met(feed.price),
        CatalystError::PredicateNotMet
    );

    // ── P4: Drift CPI firewall + strict account validation ──────
    // Hard-allowlist Drift program ID and require it's executable.
    require!(
        ctx.accounts.drift_program.key() == drift_cpi::DRIFT_PROGRAM_ID,
        CatalystError::InvalidDriftProgram
    );
    require!(
        ctx.accounts.drift_program.to_account_info().executable,
        CatalystError::InvalidDriftProgram
    );

    // Validate Drift PDAs + ownership. MVP pins sub_account_id = 0.
    let drift_program_id = drift_cpi::DRIFT_PROGRAM_ID;

    let (expected_state, _) = drift_cpi::derive_drift_state_pda();
    require!(
        ctx.accounts.drift_state.key() == expected_state,
        CatalystError::InvalidDriftState
    );
    require!(
        *ctx.accounts.drift_state.to_account_info().owner == drift_program_id,
        CatalystError::InvalidDriftState
    );

    let (expected_user, _) =
        drift_cpi::derive_drift_user_pda(&policy.authority, DRIFT_SUB_ACCOUNT_ID);
    require!(
        ctx.accounts.drift_user.key() == expected_user,
        CatalystError::InvalidDriftUser
    );
    require!(
        policy.drift_sub_account == expected_user,
        CatalystError::InvalidDriftUser
    );
    require!(
        *ctx.accounts.drift_user.to_account_info().owner == drift_program_id,
        CatalystError::InvalidDriftUser
    );

    let (expected_user_stats, _) = drift_cpi::derive_drift_user_stats_pda(&policy.authority);
    require!(
        ctx.accounts.drift_user_stats.key() == expected_user_stats,
        CatalystError::InvalidDriftUserStats
    );
    require!(
        *ctx.accounts.drift_user_stats.to_account_info().owner == drift_program_id,
        CatalystError::InvalidDriftUserStats
    );

    let (expected_quote_spot_market, _) =
        drift_cpi::derive_drift_spot_market_pda(drift_cpi::QUOTE_SPOT_MARKET_INDEX);
    require!(
        ctx.accounts.drift_spot_market.key() == expected_quote_spot_market,
        CatalystError::InvalidDriftSpotMarket
    );
    require!(
        *ctx.accounts.drift_spot_market.to_account_info().owner == drift_program_id,
        CatalystError::InvalidDriftSpotMarket
    );

    let (expected_perp_market, _) = drift_cpi::derive_drift_perp_market_pda(payload.market_index);
    require!(
        ctx.accounts.drift_perp_market.key() == expected_perp_market,
        CatalystError::InvalidDriftPerpMarket
    );
    require!(
        *ctx.accounts.drift_perp_market.to_account_info().owner == drift_program_id,
        CatalystError::InvalidDriftPerpMarket
    );

    // Defense-in-depth: ensure perp market's oracle matches the commitment-bound oracle.
    // Drift's real PerpMarket stores `amm.oracle` immediately after `pubkey`.
    // For MVP tests we ensure the stub market uses the same 32-byte slot.
    {
        let market_data = ctx.accounts.drift_perp_market.try_borrow_data()?;
        require!(
            market_data.len() >= 72,
            CatalystError::InvalidDriftPerpMarket
        );
        let oracle_bytes: [u8; 32] = market_data[40..72]
            .try_into()
            .map_err(|_| CatalystError::InvalidDriftPerpMarket)?;
        let market_oracle = Pubkey::new_from_array(oracle_bytes);
        require!(
            market_oracle == payload.oracle,
            CatalystError::InvalidOracleAccount
        );
    }

    // Construct Drift OrderParams (typed, deterministic, validated).
    // Only Market/Limit are supported by CatalystGuard MVP.
    let (order_type, price) = match payload.order_type {
        drift_cpi::instructions::OrderType::Market => {
            (drift_cpi::instructions::OrderType::Market, 0)
        }
        drift_cpi::instructions::OrderType::Limit => (
            drift_cpi::instructions::OrderType::Limit,
            payload.limit_price.unwrap_or(0),
        ),
        _ => return Err(error!(CatalystError::InvalidRevealData)),
    };

    let order_params = OrderParams {
        order_type,
        market_type: MarketType::Perp,
        direction: payload.side,
        user_order_id: 0,
        base_asset_amount: payload.base_amount,
        price,
        market_index: payload.market_index,
        reduce_only: payload.reduce_only,
        post_only: PostOnlyParam::None,
        bit_flags: 0,
        // Mirror payload deadline into Drift for additional safety.
        max_ts: Some(payload.deadline_ts),
        trigger_price: None,
        trigger_condition: OrderTriggerCondition::Above,
        oracle_price_offset: None,
        auction_duration: None,
        auction_start_price: None,
        auction_end_price: None,
    };

    // Instruction data (discriminator hardcoded in drift_cpi crate).
    let cpi_data = build_place_perp_order_data(&order_params);

    // Instruction account metas: declared accounts + explicit extra accounts in Drift's expected order:
    // oracles, spot markets, perp markets, then any optional accounts.
    let mut cpi_accounts = build_place_perp_order_accounts(
        ctx.accounts.drift_state.key(),
        ctx.accounts.drift_user.key(),
        ctx.accounts.policy.key(),
    );
    cpi_accounts.push(
        anchor_lang::solana_program::instruction::AccountMeta::new_readonly(
            ctx.accounts.oracle.key(),
            false,
        ),
    );
    cpi_accounts.push(
        anchor_lang::solana_program::instruction::AccountMeta::new_readonly(
            ctx.accounts.drift_spot_market.key(),
            false,
        ),
    );
    cpi_accounts.push(
        anchor_lang::solana_program::instruction::AccountMeta::new_readonly(
            ctx.accounts.drift_perp_market.key(),
            false,
        ),
    );
    // Optional account: user_stats is validated, and passed last so Drift's map loaders stop cleanly.
    cpi_accounts.push(
        anchor_lang::solana_program::instruction::AccountMeta::new_readonly(
            ctx.accounts.drift_user_stats.key(),
            false,
        ),
    );

    let cpi_ix = anchor_lang::solana_program::instruction::Instruction {
        program_id: drift_program_id,
        accounts: cpi_accounts,
        data: cpi_data,
    };

    // Sign as the Policy PDA (delegate) when invoking Drift.
    let policy_seeds: &[&[u8]] = &[
        POLICY_SEED,
        ctx.accounts.policy.authority.as_ref(),
        ctx.accounts.policy.drift_sub_account.as_ref(),
        &[ctx.accounts.policy.bump],
    ];

    let cpi_infos = [
        ctx.accounts.drift_state.to_account_info(),
        ctx.accounts.drift_user.to_account_info(),
        ctx.accounts.policy.to_account_info(), // authority (PDA delegate)
        ctx.accounts.oracle.to_account_info(),
        ctx.accounts.drift_spot_market.to_account_info(),
        ctx.accounts.drift_perp_market.to_account_info(),
        ctx.accounts.drift_user_stats.to_account_info(),
    ];

    invoke_signed(&cpi_ix, &cpi_infos, &[policy_seeds])?;

    // ── Commit state only AFTER CPI success (atomicity) ─────────
    let ticket = &mut ctx.accounts.ticket;
    let policy = &mut ctx.accounts.policy;

    ticket.status = TicketStatus::Executed;
    ticket.executed_slot = clock.slot;
    ticket.updated_at = clock.unix_timestamp;

    policy.executed_count = policy
        .executed_count
        .checked_add(1)
        .ok_or(CatalystError::MathOverflow)?;
    policy.last_executed_at = clock.unix_timestamp;

    emit!(TicketExecuted {
        policy: policy.key(),
        ticket: ticket.key(),
        keeper: ctx.accounts.keeper.key(),
        payload_hash,
        market_index: payload.market_index,
        base_amount: payload.base_amount,
        slot: clock.slot,
        timestamp: clock.unix_timestamp,
    });

    Ok(())
}
