//! HedgePayloadV1 — the revealed-data schema for M1.
//!
//! This struct is what gets Borsh-serialized into the opaque `revealed_data`
//! bytes of a ticket's commitment preimage.  On execution, `execute_ticket`
//! deserializes these bytes back into `HedgePayloadV1` and validates them
//! against the associated Policy account.

use anchor_lang::prelude::*;
use drift_cpi::instructions::{OrderType, PositionDirection};

/// Direction the trigger condition must move to become actionable.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum TriggerDirection {
    /// Trigger fires when oracle price >= trigger_price.
    Above,
    /// Trigger fires when oracle price <= trigger_price.
    Below,
}

/// Version-1 payload schema for sealed hedge intents.
///
/// Borsh-serialized into the `revealed_data` field of a ticket's commitment.
/// Every field is validated against the linked Policy account at execution time.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct HedgePayloadV1 {
    /// Drift perp market index (e.g. 0 = SOL-PERP).
    pub market_index: u16,

    /// Direction that must be satisfied for the trigger to fire.
    pub trigger_direction: TriggerDirection,

    /// Oracle price threshold in PRICE_PRECISION (1e6).
    /// Compared against the oracle price via `trigger_direction`.
    pub trigger_price: u64,

    /// Trade side (Long / Short).
    pub side: PositionDirection,

    /// Base asset amount in BASE_PRECISION (1e9).
    /// Must be ≤ `policy.max_base_amount`.
    pub base_amount: u64,

    /// If true, this order can only reduce an existing position.
    /// Must be true when `policy.reduce_only` is true.
    pub reduce_only: bool,

    /// Order type (Market / Limit).
    pub order_type: OrderType,

    /// Limit price in PRICE_PRECISION (1e6). Required for Limit orders, ignored for Market.
    pub limit_price: Option<u64>,

    /// Maximum slippage tolerance in basis points (e.g. 50 = 0.5%).
    /// Enforced by the keeper; on-chain we just store it for validation.
    pub max_slippage_bps: u16,

    /// Unix timestamp deadline — ticket must execute before this.
    /// Provides a secondary time-bound independent of ticket expiry.
    pub deadline_ts: i64,

    /// Oracle program ID that owns the oracle price feed account.
    /// This is commitment-bound so an executor cannot swap oracle programs.
    pub oracle_program: Pubkey,

    /// Oracle price feed account pubkey.
    /// This is commitment-bound so an executor cannot swap oracle accounts.
    pub oracle: Pubkey,
}

impl HedgePayloadV1 {
    /// Validate that payload respects policy constraints.
    ///
    /// Returns `Ok(())` if all checks pass, custom error otherwise.
    pub fn validate_against_policy(
        &self,
        allowed_markets: &[u16],
        max_base_amount: u64,
        reduce_only_required: bool,
        now: i64,
    ) -> Result<()> {
        // 1. Market must be in policy allowlist
        require!(
            allowed_markets.contains(&self.market_index),
            crate::error::CatalystError::MarketNotAllowed
        );

        // 2. Base amount must not exceed policy cap
        require!(
            self.base_amount <= max_base_amount,
            crate::error::CatalystError::BaseAmountExceeded
        );

        // 3. If policy says reduce-only, payload must comply
        if reduce_only_required {
            require!(
                self.reduce_only,
                crate::error::CatalystError::ReduceOnlyViolation
            );
        }

        // 4. Deadline must be in the future
        require!(
            self.deadline_ts > now,
            crate::error::CatalystError::DeadlineExpired
        );

        // 5. Limit price must be set for Limit orders
        if self.order_type == OrderType::Limit {
            require!(
                self.limit_price.is_some(),
                crate::error::CatalystError::InvalidRevealData
            );
        }

        Ok(())
    }

    /// Evaluate the trigger predicate against a given oracle price.
    ///
    /// Returns `true` if the trigger condition is satisfied.
    pub fn is_trigger_met(&self, oracle_price: u64) -> bool {
        match self.trigger_direction {
            TriggerDirection::Above => oracle_price >= self.trigger_price,
            TriggerDirection::Below => oracle_price <= self.trigger_price,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_payload() -> HedgePayloadV1 {
        HedgePayloadV1 {
            market_index: 0,
            trigger_direction: TriggerDirection::Above,
            trigger_price: 150_000_000, // $150 in 1e6
            side: PositionDirection::Long,
            base_amount: 1_000_000_000, // 1 SOL in 1e9
            reduce_only: false,
            order_type: OrderType::Market,
            limit_price: None,
            max_slippage_bps: 50,
            deadline_ts: 2_000_000_000,
            oracle_program: Pubkey::default(),
            oracle: Pubkey::default(),
        }
    }

    #[test]
    fn test_trigger_above() {
        let p = sample_payload();
        assert!(!p.is_trigger_met(149_999_999));
        assert!(p.is_trigger_met(150_000_000));
        assert!(p.is_trigger_met(200_000_000));
    }

    #[test]
    fn test_trigger_below() {
        let mut p = sample_payload();
        p.trigger_direction = TriggerDirection::Below;
        p.trigger_price = 100_000_000;
        assert!(p.is_trigger_met(99_000_000));
        assert!(p.is_trigger_met(100_000_000));
        assert!(!p.is_trigger_met(100_000_001));
    }

    #[test]
    fn test_validate_happy_path() {
        let p = sample_payload();
        assert!(p
            .validate_against_policy(&[0, 1, 2], 10_000_000_000, false, 1_000_000_000)
            .is_ok());
    }

    #[test]
    fn test_validate_market_not_allowed() {
        let mut p = sample_payload();
        p.market_index = 99;
        assert!(p
            .validate_against_policy(&[0, 1, 2], 10_000_000_000, false, 1_000_000_000)
            .is_err());
    }

    #[test]
    fn test_validate_base_amount_exceeded() {
        let mut p = sample_payload();
        p.base_amount = 100_000_000_000;
        assert!(p
            .validate_against_policy(&[0], 10_000_000_000, false, 1_000_000_000)
            .is_err());
    }

    #[test]
    fn test_validate_reduce_only_violation() {
        let p = sample_payload(); // reduce_only = false
        assert!(p
            .validate_against_policy(&[0], 10_000_000_000, true, 1_000_000_000)
            .is_err());
    }

    #[test]
    fn test_validate_deadline_expired() {
        let p = sample_payload(); // deadline_ts = 2_000_000_000
        assert!(p
            .validate_against_policy(&[0], 10_000_000_000, false, 3_000_000_000)
            .is_err());
    }

    #[test]
    fn test_validate_limit_price_required() {
        let mut p = sample_payload();
        p.order_type = OrderType::Limit;
        p.limit_price = None;
        assert!(p
            .validate_against_policy(&[0], 10_000_000_000, false, 1_000_000_000)
            .is_err());

        p.limit_price = Some(155_000_000);
        assert!(p
            .validate_against_policy(&[0], 10_000_000_000, false, 1_000_000_000)
            .is_ok());
    }

    #[test]
    fn test_borsh_roundtrip() {
        let p = sample_payload();
        let bytes = borsh::to_vec(&p).unwrap();
        let p2 = HedgePayloadV1::try_from_slice(&bytes).unwrap();
        assert_eq!(p.market_index, p2.market_index);
        assert_eq!(p.trigger_price, p2.trigger_price);
        assert_eq!(p.base_amount, p2.base_amount);
        assert_eq!(p.reduce_only, p2.reduce_only);
    }
}
