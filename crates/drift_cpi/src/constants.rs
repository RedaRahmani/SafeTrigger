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
pub const DRIFT_PERP_MARKET_SEED: &[u8] = b"perp_market";
pub const DRIFT_SPOT_MARKET_SEED: &[u8] = b"spot_market";

/// Drift quote spot market index (USDC) in protocol-v2.
pub const QUOTE_SPOT_MARKET_INDEX: u16 = 0;

/// Drift State PDA: `find_program_address([b"drift_state"], DRIFT_PROGRAM_ID)`.
pub fn derive_drift_state_pda() -> (Pubkey, u8) {
    Pubkey::find_program_address(&[DRIFT_STATE_SEED], &DRIFT_PROGRAM_ID)
}

/// Drift User PDA: `find_program_address([b"user", authority, sub_account_id_le], DRIFT_PROGRAM_ID)`.
pub fn derive_drift_user_pda(authority: &Pubkey, sub_account_id: u16) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            DRIFT_USER_SEED,
            authority.as_ref(),
            &sub_account_id.to_le_bytes(),
        ],
        &DRIFT_PROGRAM_ID,
    )
}

/// Drift UserStats PDA: `find_program_address([b"user_stats", authority], DRIFT_PROGRAM_ID)`.
pub fn derive_drift_user_stats_pda(authority: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[DRIFT_USER_STATS_SEED, authority.as_ref()],
        &DRIFT_PROGRAM_ID,
    )
}

/// Drift PerpMarket PDA: `find_program_address([b"perp_market", market_index_le], DRIFT_PROGRAM_ID)`.
pub fn derive_drift_perp_market_pda(market_index: u16) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[DRIFT_PERP_MARKET_SEED, &market_index.to_le_bytes()],
        &DRIFT_PROGRAM_ID,
    )
}

/// Drift SpotMarket PDA: `find_program_address([b"spot_market", market_index_le], DRIFT_PROGRAM_ID)`.
pub fn derive_drift_spot_market_pda(market_index: u16) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[DRIFT_SPOT_MARKET_SEED, &market_index.to_le_bytes()],
        &DRIFT_PROGRAM_ID,
    )
}
