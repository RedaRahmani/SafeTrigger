//! Ticket instruction handlers.

use anchor_lang::prelude::*;
use sha2::{Digest, Sha256};

use crate::error::CatalystError;
use crate::state::payload::HedgePayloadV1;
use crate::state::policy::{Policy, POLICY_SEED};
use crate::state::ticket::*;

/// Domain separator for commitment preimage (version 0.2).
pub const COMMITMENT_DOMAIN: &[u8] = b"CSv0.2";

/// Maximum ticket expiry: 7 days from now.
pub const MAX_EXPIRY_WINDOW: i64 = 7 * 24 * 60 * 60;

// ── CreateTicket ────────────────────────────────────────────────

#[derive(Accounts)]
#[instruction(commitment: [u8; 32], nonce: [u8; 32])]
pub struct CreateTicket<'info> {
    #[account(
        init,
        payer = owner,
        space = Ticket::SPACE,
        seeds = [TICKET_SEED, policy.key().as_ref(), &nonce],
        bump,
    )]
    pub ticket: Account<'info, Ticket>,

    #[account(
        mut,
        constraint = !policy.paused @ CatalystError::PolicyPaused,
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
}

pub fn handle_execute_ticket(
    ctx: Context<ExecuteTicket>,
    secret_salt: [u8; 32],
    revealed_data: Vec<u8>,
) -> Result<()> {
    let ticket = &mut ctx.accounts.ticket;
    let policy = &mut ctx.accounts.policy;
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
    // min_interval = max_time_window / rate_limit_per_window
    if policy.rate_limit_per_window > 0 && policy.last_executed_at > 0 {
        let min_interval = policy
            .max_time_window
            .checked_div(policy.rate_limit_per_window as i64)
            .unwrap_or(0);
        let elapsed = clock
            .unix_timestamp
            .checked_sub(policy.last_executed_at)
            .ok_or(CatalystError::MathOverflow)?;
        require!(elapsed >= min_interval, CatalystError::RateLimitExceeded);
    }

    // ── P3: Mark as consumed (replay protection) ────────────────
    ticket.status = TicketStatus::Executed;
    ticket.executed_slot = clock.slot;
    ticket.updated_at = clock.unix_timestamp;

    // ── Update policy counters ──────────────────────────────────
    policy.executed_count = policy
        .executed_count
        .checked_add(1)
        .ok_or(CatalystError::MathOverflow)?;
    policy.last_executed_at = clock.unix_timestamp;
    policy.updated_at = clock.unix_timestamp;

    // ── P4: Drift CPI ───────────────────────────────────────────
    // In a full deployment with Drift on-chain, we would CPI here.
    // For localnet without Drift, we validate the payload and log.
    // The actual CPI path is gated on having Drift accounts available
    // (added in feat(drift-cpi) step).
    msg!(
        "Ticket executed: market={}, side={:?}, amount={}, slot={}",
        payload.market_index,
        payload.side,
        payload.base_amount,
        clock.slot
    );

    Ok(())
}
