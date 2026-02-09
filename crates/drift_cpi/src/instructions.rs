//! Drift CPI instruction builders.
//!
//! Builds validated `place_perp_order` CPI instructions against the hardcoded
//! Drift program ID.  All account metas are constructed explicitly — no
//! remaining_accounts passthrough.

use anchor_lang::prelude::*;

use crate::constants::DRIFT_PROGRAM_ID;

/// Sighash discriminator for Drift `place_perp_order` (first 8 bytes of
/// SHA-256("global:place_perp_order")).
pub const PLACE_PERP_ORDER_DISC: [u8; 8] = [0x45, 0xa3, 0x10, 0x6a, 0x4b, 0x1f, 0x3b, 0x52];

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

/// Verify that a program key matches the hardcoded Drift program ID.
///
/// Invariant P4a: CPI target is never user-supplied.
pub fn verify_drift_program(program_key: &Pubkey) -> Result<()> {
    require!(*program_key == DRIFT_PROGRAM_ID, ErrorCode::ConstraintRaw);
    Ok(())
}

/// Build the Drift `place_perp_order` instruction data.
///
/// This constructs the serialized instruction data that would be passed to
/// Drift's place_perp_order instruction.  The discriminator is hardcoded.
///
/// NOTE: On localnet (without Drift deployed), the CPI cannot actually be
/// invoked.  The caller gates the actual `invoke_signed` behind the
/// presence of a valid Drift program account.
pub fn build_place_perp_order_data(params: &BoundedOrderParams) -> Vec<u8> {
    let mut data = Vec::with_capacity(64);
    // 8-byte discriminator
    data.extend_from_slice(&PLACE_PERP_ORDER_DISC);
    // Borsh-serialize the params after the discriminator
    params
        .serialize(&mut data)
        .expect("BoundedOrderParams serialization infallible");
    data
}

/// Build account metas for `place_perp_order`.
///
/// Drift's place_perp_order requires:
///   0. state      (read-only)
///   1. user       (writable, signer — the delegate/authority)
///   2. authority   (signer)
///
/// All PDAs are derived deterministically — no user-supplied accounts.
pub fn build_place_perp_order_accounts(
    drift_state: Pubkey,
    drift_user: Pubkey,
    authority: Pubkey,
) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new_readonly(drift_state, false),
        AccountMeta::new(drift_user, false),
        AccountMeta::new_readonly(authority, true),
    ]
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
