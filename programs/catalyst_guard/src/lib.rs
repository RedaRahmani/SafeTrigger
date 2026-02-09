//! CatalystGuard – Sealed Conditional Intent + PDA Capability Firewall
//!
//! On-chain program for commitment-based conditional execution on Drift Protocol.
//! See docs/INVARIANTS.md for P1–P5 security invariants.

#![allow(clippy::too_many_arguments)]
// Anchor / Solana macros emit cfg checks and use deprecated APIs that our
// toolchain warns about.  These are NOT our code — suppress only these
// known macro-generated warnings so that clippy -D warnings passes CI.
#![allow(unexpected_cfgs)]
#![allow(deprecated)]

use anchor_lang::prelude::*;

pub mod error;
pub mod instructions;
pub mod state;

use instructions::*;

declare_id!("2oUmUDgTvVFBDqNC2TpVLhtvaenKgiNnuvsPMUYT4yJq");

#[program]
pub mod catalyst_guard {
    use super::*;

    // ── Policy management ───────────────────────────────────────

    /// Initialize a new policy account.
    /// Only the authority can create policies.
    pub fn init_policy(
        ctx: Context<InitPolicy>,
        allowed_markets: Vec<u16>,
        max_base_amount: u64,
        oracle_deviation_bps: u16,
        min_time_window: i64,
        max_time_window: i64,
        rate_limit_per_window: u16,
        reduce_only: bool,
    ) -> Result<()> {
        instructions::policy::handle_init_policy(
            ctx,
            allowed_markets,
            max_base_amount,
            oracle_deviation_bps,
            min_time_window,
            max_time_window,
            rate_limit_per_window,
            reduce_only,
        )
    }

    /// Update an existing policy. Authority-only.
    pub fn update_policy(
        ctx: Context<UpdatePolicy>,
        allowed_markets: Option<Vec<u16>>,
        max_base_amount: Option<u64>,
        oracle_deviation_bps: Option<u16>,
        reduce_only: Option<bool>,
    ) -> Result<()> {
        instructions::policy::handle_update_policy(
            ctx,
            allowed_markets,
            max_base_amount,
            oracle_deviation_bps,
            reduce_only,
        )
    }

    /// Pause or unpause a policy.
    pub fn pause_policy(ctx: Context<PausePolicy>, paused: bool) -> Result<()> {
        instructions::policy::handle_pause_policy(ctx, paused)
    }

    // ── Ticket lifecycle ────────────────────────────────────────

    /// Create a new ticket with a commitment hash.
    /// Invariant P1: no plaintext trigger params stored.
    pub fn create_ticket(
        ctx: Context<CreateTicket>,
        commitment: [u8; 32],
        ticket_id: [u8; 32],
        expiry: i64,
    ) -> Result<()> {
        instructions::ticket::handle_create_ticket(ctx, commitment, ticket_id, expiry)
    }

    /// Cancel a ticket. Owner-only.
    pub fn cancel_ticket(ctx: Context<CancelTicket>) -> Result<()> {
        instructions::ticket::handle_cancel_ticket(ctx)
    }

    /// Expire a ticket. Permissionless, only works after expiry.
    pub fn expire_ticket(ctx: Context<ExpireTicket>) -> Result<()> {
        instructions::ticket::handle_expire_ticket(ctx)
    }

    /// Execute a ticket: verify commitment, evaluate predicate, CPI to Drift.
    /// Invariant P2: reveal is coupled to execution.
    /// Invariant P3: replay protection via consumed flag.
    /// Invariant P4: CPI is hard-allowlisted.
    pub fn execute_ticket(
        ctx: Context<ExecuteTicket>,
        secret_salt: [u8; 32],
        revealed_data: Vec<u8>,
    ) -> Result<()> {
        instructions::ticket::handle_execute_ticket(ctx, secret_salt, revealed_data)
    }
}
