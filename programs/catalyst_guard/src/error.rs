//! Custom error codes for CatalystGuard.

use anchor_lang::prelude::*;

#[error_code]
pub enum CatalystError {
    // ── Policy errors ───────────────────────────────────────────
    #[msg("Too many allowed markets (max 32)")]
    TooManyMarkets,

    #[msg("Oracle deviation bps must be ≤ 10_000")]
    OracleDeviationTooLarge,

    #[msg("Time window bounds invalid")]
    InvalidTimeWindow,

    #[msg("Policy is paused")]
    PolicyPaused,

    #[msg("Ticket does not belong to the provided policy")]
    PolicyMismatch,

    // ── Ticket errors ───────────────────────────────────────────
    #[msg("Commitment hash mismatch on reveal")]
    CommitmentMismatch,

    #[msg("Ticket has already been consumed")]
    TicketAlreadyConsumed,

    #[msg("Ticket has expired")]
    TicketExpired,

    #[msg("Ticket has not yet expired")]
    TicketNotExpired,

    #[msg("Ticket nonce already used")]
    NonceReplay,

    #[msg("Expiry timestamp is in the past")]
    ExpiryInPast,

    #[msg("Expiry timestamp too far in the future")]
    ExpiryTooFar,

    // ── CPI / Firewall errors ───────────────────────────────────
    #[msg("CPI target program is not an allowed program")]
    DisallowedCpiTarget,

    #[msg("Drift CPI unavailable on this cluster")]
    DriftCpiUnavailable,

    #[msg("Drift instruction discriminator not in allowlist")]
    DisallowedInstruction,

    #[msg("Order params violate policy bounds")]
    OrderParamsViolation,

    // ── Payload / predicate errors ──────────────────────────────
    #[msg("Market index not in policy allowlist")]
    MarketNotAllowed,

    #[msg("Base amount exceeds policy max")]
    BaseAmountExceeded,

    #[msg("Policy requires reduce_only but payload is not")]
    ReduceOnlyViolation,

    #[msg("Payload deadline has passed")]
    DeadlineExpired,

    #[msg("Trigger predicate not satisfied")]
    PredicateNotMet,

    #[msg("Oracle price is stale")]
    OracleStale,

    #[msg("Invalid oracle account")]
    InvalidOracleAccount,

    #[msg("Rate limit exceeded for this policy window")]
    RateLimitExceeded,

    // ── Access control ──────────────────────────────────────────
    #[msg("Unauthorized: signer is not the authority")]
    Unauthorized,

    #[msg("Unauthorized: signer is not the ticket owner")]
    NotTicketOwner,

    // ── Serialization ───────────────────────────────────────────
    #[msg("Failed to deserialize revealed data")]
    InvalidRevealData,

    #[msg("Arithmetic overflow")]
    MathOverflow,
}
