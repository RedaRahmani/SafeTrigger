//! Drift CPI instruction builders.
//!
//! Milestone 2 will implement actual CPI calls. This module provides
//! the pinned interface stubs.

use anchor_lang::prelude::*;

/// Direction for a perp order.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum PositionDirection {
    Long,
    Short,
}

/// Order type subset that CatalystGuard may place.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrderType {
    Market,
    Limit,
}

/// Bounded order parameters that CatalystGuard constructs.
/// All values are validated against the Policy account before CPI.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct BoundedOrderParams {
    pub market_index: u16,
    pub direction: PositionDirection,
    pub order_type: OrderType,
    /// Base asset amount in Drift BASE_PRECISION (1e9)
    pub base_asset_amount: u64,
    /// Price in Drift PRICE_PRECISION (1e6), 0 for market orders
    pub price: u64,
    /// Whether this order can only reduce an existing position
    pub reduce_only: bool,
}

impl BoundedOrderParams {
    /// Validate that the order params respect the policy bounds.
    /// Returns Ok(()) if valid, Err with a descriptive message otherwise.
    pub fn validate_against_policy(
        &self,
        allowed_markets: &[u16],
        max_base_amount: u64,
        reduce_only_required: bool,
    ) -> Result<()> {
        require!(
            allowed_markets.contains(&self.market_index),
            ErrorCode::ConstraintRaw
        );
        require!(
            self.base_asset_amount <= max_base_amount,
            ErrorCode::ConstraintRaw
        );
        if reduce_only_required {
            require!(self.reduce_only, ErrorCode::ConstraintRaw);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bounded_order_params_valid() {
        let params = BoundedOrderParams {
            market_index: 0,
            direction: PositionDirection::Long,
            order_type: OrderType::Market,
            base_asset_amount: 1_000_000_000, // 1 SOL
            price: 0,
            reduce_only: false,
        };
        assert!(params
            .validate_against_policy(&[0, 1, 2], 10_000_000_000, false)
            .is_ok());
    }

    #[test]
    fn test_bounded_order_params_market_not_allowed() {
        let params = BoundedOrderParams {
            market_index: 99,
            direction: PositionDirection::Short,
            order_type: OrderType::Limit,
            base_asset_amount: 1_000_000_000,
            price: 150_000_000,
            reduce_only: false,
        };
        assert!(params
            .validate_against_policy(&[0, 1, 2], 10_000_000_000, false)
            .is_err());
    }

    #[test]
    fn test_bounded_order_params_exceeds_max() {
        let params = BoundedOrderParams {
            market_index: 0,
            direction: PositionDirection::Long,
            order_type: OrderType::Market,
            base_asset_amount: 100_000_000_000, // 100 SOL
            price: 0,
            reduce_only: false,
        };
        assert!(params
            .validate_against_policy(&[0, 1, 2], 10_000_000_000, false)
            .is_err());
    }

    #[test]
    fn test_bounded_order_params_reduce_only_required() {
        let params = BoundedOrderParams {
            market_index: 0,
            direction: PositionDirection::Short,
            order_type: OrderType::Market,
            base_asset_amount: 1_000_000_000,
            price: 0,
            reduce_only: false, // not reduce-only but required
        };
        assert!(params
            .validate_against_policy(&[0], 10_000_000_000, true)
            .is_err());

        let params_ok = BoundedOrderParams {
            market_index: 0,
            direction: PositionDirection::Short,
            order_type: OrderType::Market,
            base_asset_amount: 1_000_000_000,
            price: 0,
            reduce_only: true,
        };
        assert!(params_ok
            .validate_against_policy(&[0], 10_000_000_000, true)
            .is_ok());
    }
}
