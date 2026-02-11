//! Oracle account adapters for CatalystGuard.
//!
//! Supports two oracle formats:
//! 1. **TestOracle PriceFeed** — for localnet / integration tests
//! 2. **PythLazerOracle** — Drift's on-chain oracle format (devnet + mainnet)

use anchor_lang::prelude::*;

// ── PRICE_PRECISION ─────────────────────────────────────────────
/// All CatalystGuard prices are normalised to 1 e 6 (micro-USD).
pub const PRICE_PRECISION: u64 = 1_000_000;

// ── TestOracle PriceFeed ────────────────────────────────────────

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

// ── PythLazerOracle ─────────────────────────────────────────────

/// Discriminator: `sha256("account:PythLazerOracle")[0..8]`.
/// Verified against the live Drift devnet SOL-PERP oracle.
const PYTH_LAZER_DISC: [u8; 8] = [0x9f, 0x07, 0xa1, 0xf9, 0x22, 0x51, 0x79, 0x85];

/// Total on-chain account size (8 disc + 40 data).
const PYTH_LAZER_ACCOUNT_LEN: usize = 48;

/// PythLazerOracle data layout (zero_copy, C-repr, owned by Drift program):
///
/// | offset | size | field         |
/// |--------|------|---------------|
/// |  0     |  8   | discriminator |
/// |  8     |  8   | price  (i64)  |
/// | 16     |  8   | publish_time  |
/// | 24     |  8   | posted_slot   |
/// | 32     |  4   | exponent (i32)|
/// | 36     |  4   | _padding      |
/// | 40     |  8   | conf   (u64)  |

// ── Unified reader ──────────────────────────────────────────────

/// Read an oracle price from raw account data.
///
/// Returns `(price_in_1e6, slot)` or `CatalystError::InvalidOracleAccount`.
/// Auto-detects format by discriminator match.
pub fn read_oracle_price(data: &[u8]) -> Result<(u64, u64)> {
    if data.len() < 8 {
        return Err(error!(crate::error::CatalystError::InvalidOracleAccount));
    }

    // Fast path: PythLazerOracle (48 bytes, discriminator match).
    if data.len() >= PYTH_LAZER_ACCOUNT_LEN && data[0..8] == PYTH_LAZER_DISC {
        return parse_pyth_lazer(&data[8..]);
    }

    // Fallback: TestOracle PriceFeed (Anchor-deserialized).
    let mut cursor: &[u8] = data;
    let feed = PriceFeed::try_deserialize(&mut cursor)
        .map_err(|_| error!(crate::error::CatalystError::InvalidOracleAccount))?;
    Ok((feed.price, feed.last_updated_slot))
}

/// Parse the 40 data-bytes of a PythLazerOracle.
///
/// Normalises the raw `price × 10^exponent` representation to
/// `PRICE_PRECISION` (1 e 6).
fn parse_pyth_lazer(data: &[u8]) -> Result<(u64, u64)> {
    if data.len() < 40 {
        return Err(error!(crate::error::CatalystError::InvalidOracleAccount));
    }

    let raw_price = i64::from_le_bytes(data[0..8].try_into().unwrap());
    let posted_slot = u64::from_le_bytes(data[16..24].try_into().unwrap());
    let exponent = i32::from_le_bytes(data[24..28].try_into().unwrap());

    // Price must be positive (negative / zero is non-sensical for assets).
    require!(raw_price > 0, crate::error::CatalystError::InvalidOracleAccount);
    let price_abs = raw_price as u64;

    // Normalise to 1e6:  price_1e6 = price_abs × 10^(6 + exponent)
    //   exponent = -8 ⇒ scale = -2 ⇒ divide by 100
    //   exponent = -6 ⇒ scale =  0 ⇒ identity
    let scale = 6i32.checked_add(exponent)
        .ok_or(error!(crate::error::CatalystError::MathOverflow))?;

    let price_1e6 = if scale >= 0 {
        let mult = 10u64.checked_pow(scale as u32)
            .ok_or(error!(crate::error::CatalystError::MathOverflow))?;
        price_abs.checked_mul(mult)
            .ok_or(error!(crate::error::CatalystError::MathOverflow))?
    } else {
        let div = 10u64.checked_pow((-scale) as u32)
            .ok_or(error!(crate::error::CatalystError::MathOverflow))?;
        price_abs / div
    };

    Ok((price_1e6, posted_slot))
}

// ── Unit tests ──────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal PythLazerOracle byte buffer for testing.
    fn make_pyth_lazer(price: i64, posted_slot: u64, exponent: i32, conf: u64) -> Vec<u8> {
        let mut buf = Vec::with_capacity(48);
        buf.extend_from_slice(&PYTH_LAZER_DISC);
        buf.extend_from_slice(&price.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes()); // publish_time
        buf.extend_from_slice(&posted_slot.to_le_bytes());
        buf.extend_from_slice(&exponent.to_le_bytes());
        buf.extend_from_slice(&[0u8; 4]); // padding
        buf.extend_from_slice(&conf.to_le_bytes());
        buf
    }

    #[test]
    fn pyth_lazer_sol_exponent_neg8() {
        // SOL ≈ $83.56 at exponent=-8 ⇒ raw_price = 8_355_749_610
        let data = make_pyth_lazer(8_355_749_610, 1000, -8, 0);
        let (price, slot) = read_oracle_price(&data).unwrap();
        assert_eq!(price, 83_557_496); // $83.557496 in 1e6
        assert_eq!(slot, 1000);
    }

    #[test]
    fn pyth_lazer_sol_exponent_neg6() {
        let data = make_pyth_lazer(170_000_000, 5000, -6, 0);
        let (price, slot) = read_oracle_price(&data).unwrap();
        assert_eq!(price, 170_000_000); // identity
        assert_eq!(slot, 5000);
    }

    #[test]
    fn pyth_lazer_negative_price_rejected() {
        let data = make_pyth_lazer(-100, 1000, -8, 0);
        assert!(read_oracle_price(&data).is_err());
    }

    #[test]
    fn short_data_rejected() {
        assert!(read_oracle_price(&[0u8; 4]).is_err());
    }

    #[test]
    fn unknown_discriminator_fallback_fails() {
        // 48 bytes but wrong disc → fallback to PriceFeed deserialize → fails
        let mut data = vec![0u8; 48];
        data[0..8].copy_from_slice(&[0xAA; 8]);
        assert!(read_oracle_price(&data).is_err());
    }
}
