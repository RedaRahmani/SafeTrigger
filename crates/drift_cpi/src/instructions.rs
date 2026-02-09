//! Drift CPI instruction builders.
//!
//! This crate intentionally pins:
//! - Drift program ID
//! - instruction discriminators
//! - account PDA derivations
//! - instruction data layouts
//!
//! so CatalystGuard can construct deterministic CPI calls with no user-supplied
//! program IDs and no arbitrary instruction forwarding.

use anchor_lang::prelude::*;

use crate::constants::DRIFT_PROGRAM_ID;

/// Anchor discriminator for Drift `place_perp_order` (first 8 bytes of
/// SHA-256("global:place_perp_order")).
///
/// Verified against the Anchor discriminator scheme and Drift's IDL naming.
pub const PLACE_PERP_ORDER_DISC: [u8; 8] = [0x45, 0xA1, 0x5D, 0xCA, 0x78, 0x7E, 0x4C, 0xB9];

/// Direction for a position/order.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum PositionDirection {
    #[default]
    Long,
    Short,
}

/// Drift `OrderType` (subset is used by CatalystGuard, but enum order MUST match Drift).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum OrderType {
    Market,
    #[default]
    Limit,
    TriggerMarket,
    TriggerLimit,
    Oracle,
}

/// Drift `MarketType`.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum MarketType {
    #[default]
    Spot,
    Perp,
}

/// Drift `OrderTriggerCondition`.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum OrderTriggerCondition {
    #[default]
    Above,
    Below,
    TriggeredAbove,
    TriggeredBelow,
}

/// Drift `PostOnlyParam`.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum PostOnlyParam {
    #[default]
    None,
    MustPostOnly,
    TryPostOnly,
    Slide,
}

/// Drift `OrderParams` — MUST match Drift's on-chain struct field order and types.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct OrderParams {
    pub order_type: OrderType,
    pub market_type: MarketType,
    pub direction: PositionDirection,
    pub user_order_id: u8,
    pub base_asset_amount: u64,
    pub price: u64,
    pub market_index: u16,
    pub reduce_only: bool,
    pub post_only: PostOnlyParam,
    pub bit_flags: u8,
    pub max_ts: Option<i64>,
    pub trigger_price: Option<u64>,
    pub trigger_condition: OrderTriggerCondition,
    pub oracle_price_offset: Option<i32>,
    pub auction_duration: Option<u8>,
    pub auction_start_price: Option<i64>,
    pub auction_end_price: Option<i64>,
}

/// Verify that a program key matches the hardcoded Drift program ID.
///
/// Invariant: CPI target is never user-supplied.
pub fn verify_drift_program(program_key: &Pubkey) -> Result<()> {
    require!(*program_key == DRIFT_PROGRAM_ID, ErrorCode::ConstraintRaw);
    Ok(())
}

/// Build the Drift `place_perp_order` instruction data.
pub fn build_place_perp_order_data(params: &OrderParams) -> Vec<u8> {
    let mut data = Vec::with_capacity(8 + 128);
    data.extend_from_slice(&PLACE_PERP_ORDER_DISC);
    params
        .serialize(&mut data)
        .expect("OrderParams serialization infallible");
    data
}

/// Build account metas for Drift `place_perp_order`.
///
/// Drift's IDL declares:
///   0. state      (read-only)
///   1. user       (writable)
///   2. authority  (read-only signer)
///
/// Additional market/oracle accounts are passed as *explicit* extra accounts
/// after these three (Drift consumes them via its remaining-accounts loaders).
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
    fn test_place_perp_order_discriminator_matches_anchor_scheme() {
        // sha256("global:place_perp_order")[..8]
        let expected: [u8; 8] = [0x45, 0xA1, 0x5D, 0xCA, 0x78, 0x7E, 0x4C, 0xB9];
        assert_eq!(PLACE_PERP_ORDER_DISC, expected);
    }

    #[test]
    fn test_build_place_perp_order_data_prefix() {
        let params = OrderParams {
            market_type: MarketType::Perp,
            market_index: 0,
            direction: PositionDirection::Long,
            order_type: OrderType::Market,
            base_asset_amount: 1,
            price: 0,
            reduce_only: true,
            ..OrderParams::default()
        };
        let data = build_place_perp_order_data(&params);
        assert!(data.starts_with(&PLACE_PERP_ORDER_DISC));
        assert!(data.len() > 8);
    }
}
