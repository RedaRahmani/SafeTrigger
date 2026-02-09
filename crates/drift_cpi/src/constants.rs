//! Hardcoded constants for Drift Protocol CPI.
//!
//! These MUST NOT be configurable at runtime.

use anchor_lang::prelude::*;

/// Drift Protocol v2 program ID — same on mainnet-beta and devnet.
/// Invariant P4a: this is a compile-time constant, never user-supplied.
pub const DRIFT_PROGRAM_ID: Pubkey =
    anchor_lang::solana_program::pubkey!("dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH");

/// Maximum allowed instructions in a single Drift CPI call.
/// We only support a strict subset: place_perp_order, cancel_order.
pub const ALLOWED_DRIFT_INSTRUCTIONS: &[&str] = &["place_perp_order", "cancel_order"];

/// Seeds for Drift PDA derivations
pub const DRIFT_USER_SEED: &[u8] = b"user";
pub const DRIFT_USER_STATS_SEED: &[u8] = b"user_stats";
pub const DRIFT_STATE_SEED: &[u8] = b"drift_state";
