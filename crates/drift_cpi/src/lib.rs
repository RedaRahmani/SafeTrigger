//! # drift_cpi
//!
//! Pinned Drift Protocol CPI constants, account structures, and instruction
//! builders for CatalystGuard. All targets are hardcoded — no user-supplied
//! program IDs or arbitrary instruction forwarding.

pub mod constants;
pub mod instructions;

pub use constants::*;
