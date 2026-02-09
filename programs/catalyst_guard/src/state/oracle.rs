//! Oracle account adapters for CatalystGuard.
//!
//! MVP uses a minimal `PriceFeed` layout for localnet/integration tests.

use anchor_lang::prelude::*;

/// Minimal oracle price feed format (Anchor account).
///
/// This intentionally matches the `test_oracle::PriceFeed` account so that
/// CatalystGuard can deserialize it in integration tests.
#[account]
#[derive(Debug)]
pub struct PriceFeed {
    pub authority: Pubkey,
    /// Price in PRICE_PRECISION (1e6) units.
    pub price: u64,
    /// Slot of last update.
    pub last_updated_slot: u64,
}
