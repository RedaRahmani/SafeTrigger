//! Policy account – governs what a delegated sub-account PDA may do.

use anchor_lang::prelude::*;

/// Maximum number of allowed market indices per policy.
pub const MAX_ALLOWED_MARKETS: usize = 32;

/// Seed prefix for Policy PDA derivation.
pub const POLICY_SEED: &[u8] = b"policy";

/// A policy defines boundaries for conditional execution on a specific
/// Drift sub-account. The authority creates/updates policies, and they
/// are referenced when tickets are created/executed to enforce bounds.
#[account]
#[derive(Debug)]
pub struct Policy {
    /// The authority that can create/update/pause this policy.
    pub authority: Pubkey,

    /// The Drift sub-account this policy governs.
    pub drift_sub_account: Pubkey,

    /// Bump seed for PDA derivation.
    pub bump: u8,

    /// Whether this policy is active.
    pub paused: bool,

    /// Allowed perp market indices (max 32).
    pub allowed_markets: Vec<u16>,

    /// Maximum base asset amount per order (in base lots).
    pub max_base_amount: u64,

    /// Maximum oracle deviation in basis points (e.g., 100 = 1%).
    pub oracle_deviation_bps: u16,

    /// Minimum time window for triggers (seconds).
    pub min_time_window: i64,

    /// Maximum time window for triggers (seconds).
    pub max_time_window: i64,

    /// Max ticket executions allowed per time window.
    pub rate_limit_per_window: u16,

    /// Whether orders must be reduce-only.
    pub reduce_only: bool,

    /// Number of tickets created under this policy.
    pub ticket_count: u64,

    /// Number of tickets executed under this policy.
    pub executed_count: u64,

    /// Timestamp of policy creation.
    pub created_at: i64,

    /// Timestamp of last update.
    pub updated_at: i64,
}

impl Policy {
    /// Calculates the space needed for the account including discriminator.
    /// 8 (discriminator) + fields
    pub const fn space(num_markets: usize) -> usize {
        8   // discriminator
        + 32  // authority
        + 32  // drift_sub_account
        + 1   // bump
        + 1   // paused
        + 4 + (num_markets * 2)  // Vec<u16> (4-byte len prefix + data)
        + 8   // max_base_amount
        + 2   // oracle_deviation_bps
        + 8   // min_time_window
        + 8   // max_time_window
        + 2   // rate_limit_per_window
        + 1   // reduce_only
        + 8   // ticket_count
        + 8   // executed_count
        + 8   // created_at
        + 8 // updated_at
    }

    /// Fixed space: always allocates for MAX_ALLOWED_MARKETS so that
    /// update_policy can grow allowed_markets without realloc.
    pub const FIXED_SPACE: usize = Self::space(MAX_ALLOWED_MARKETS);

    /// Is the given market index allowed by this policy?
    pub fn is_market_allowed(&self, market_index: u16) -> bool {
        self.allowed_markets.contains(&market_index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_space_calculation() {
        // Minimum space with 0 markets
        let space_0 = Policy::space(0);
        assert!(space_0 > 8); // at least discriminator

        // Space with max markets
        let space_max = Policy::space(MAX_ALLOWED_MARKETS);
        assert!(space_max > space_0);
        assert_eq!(space_max - space_0, MAX_ALLOWED_MARKETS * 2);
    }

    #[test]
    fn test_fixed_space_equals_max() {
        assert_eq!(Policy::FIXED_SPACE, Policy::space(MAX_ALLOWED_MARKETS));
    }

    #[test]
    fn test_is_market_allowed() {
        let policy = Policy {
            authority: Pubkey::default(),
            drift_sub_account: Pubkey::default(),
            bump: 0,
            paused: false,
            allowed_markets: vec![0, 1, 5, 10],
            max_base_amount: 1_000_000,
            oracle_deviation_bps: 100,
            min_time_window: 60,
            max_time_window: 3600,
            rate_limit_per_window: 10,
            reduce_only: false,
            ticket_count: 0,
            executed_count: 0,
            created_at: 0,
            updated_at: 0,
        };
        assert!(policy.is_market_allowed(0));
        assert!(policy.is_market_allowed(5));
        assert!(!policy.is_market_allowed(2));
        assert!(!policy.is_market_allowed(99));
    }
}
