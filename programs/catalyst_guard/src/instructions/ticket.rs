//! Ticket instruction handlers.

use anchor_lang::prelude::*;
use sha2::{Digest, Sha256};

use crate::error::CatalystError;
use crate::state::policy::{Policy, POLICY_SEED};
use crate::state::ticket::*;

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
    nonce: [u8; 32],
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
    ticket.nonce = nonce;
    ticket.bump = ctx.bumps.ticket;
    ticket.status = TicketStatus::Open;
    ticket.expiry = expiry;
    ticket.created_slot = clock.slot;
    ticket.created_at = clock.unix_timestamp;
    ticket.updated_at = clock.unix_timestamp;
    ticket.executed_slot = 0;

    // Increment policy ticket count
    let policy = &mut ctx.accounts.policy.to_account_info();
    // NOTE: We read policy as immutable above (no `mut` in Accounts) to
    // keep it simple for M0. In M1 we will add mut + increment safely.
    let _ = policy;

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
        seeds = [TICKET_SEED, ticket.policy.as_ref(), ticket.nonce.as_ref()],
        bump = ticket.bump,
    )]
    pub ticket: Account<'info, Ticket>,

    #[account(
        constraint = !policy.paused @ CatalystError::PolicyPaused,
        seeds = [POLICY_SEED, policy.authority.as_ref(), policy.drift_sub_account.as_ref()],
        bump = policy.bump,
    )]
    pub policy: Account<'info, Policy>,

    /// The keeper executing the ticket. Permissionless (anyone may execute).
    pub keeper: Signer<'info>,
    // NOTE: Drift CPI accounts will be added in Milestone 1.
    // For M0, we verify the commitment and mark executed without CPI.
}

pub fn handle_execute_ticket(ctx: Context<ExecuteTicket>, revealed_data: Vec<u8>) -> Result<()> {
    let ticket = &mut ctx.accounts.ticket;
    let clock = Clock::get()?;

    // ── P2: Verify commitment ───────────────────────────────────
    // The revealed_data must hash (with the ticket's nonce) to the stored commitment.
    let mut hasher = Sha256::new();
    hasher.update(&revealed_data);
    hasher.update(ticket.nonce);
    let computed_hash: [u8; 32] = hasher.finalize().into();

    require!(
        computed_hash == ticket.commitment,
        CatalystError::CommitmentMismatch
    );

    // ── P3: Mark as consumed (replay protection) ────────────────
    ticket.status = TicketStatus::Executed;
    ticket.executed_slot = clock.slot;
    ticket.updated_at = clock.unix_timestamp;

    // ── P4: CPI to Drift (stubbed for M0) ───────────────────────
    // In Milestone 1, this will:
    //   1. Deserialize revealed_data into trigger params + BoundedOrderParams
    //   2. Validate params against policy bounds
    //   3. CPI to Drift with hardcoded program ID
    //   4. Verify Drift instruction discriminator is in allowlist
    msg!("Ticket executed: commitment verified, slot={}", clock.slot);

    Ok(())
}
