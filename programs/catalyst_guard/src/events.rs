//! Anchor events emitted by CatalystGuard for off-chain indexing.
//!
//! These events are consumed by the keeper service and any future
//! analytics/UI layer.

use anchor_lang::prelude::*;

/// Emitted when a new ticket is created.
#[event]
pub struct TicketCreated {
    /// Policy this ticket is bound to.
    pub policy: Pubkey,
    /// Ticket PDA address.
    pub ticket: Pubkey,
    /// Owner who created the ticket.
    pub owner: Pubkey,
    /// Ticket ID (32-byte public identifier).
    pub ticket_id: [u8; 32],
    /// Unix timestamp of ticket expiry.
    pub expiry: i64,
    /// Slot at creation.
    pub slot: u64,
}

/// Emitted when a ticket is executed (commitment verified + payload validated).
#[event]
pub struct TicketExecuted {
    /// Policy this ticket was bound to.
    pub policy: Pubkey,
    /// Ticket PDA address.
    pub ticket: Pubkey,
    /// Keeper who executed the ticket.
    pub keeper: Pubkey,
    /// SHA-256 hash of the revealed payload bytes (Borsh serialized).
    pub payload_hash: [u8; 32],
    /// Market index from the revealed payload.
    pub market_index: u16,
    /// Base asset amount from the revealed payload.
    pub base_amount: u64,
    /// Price used in the order (slippage-adjusted for Market, limit_price for Limit).
    pub order_price: u64,
    /// Slot at execution.
    pub slot: u64,
    /// Unix timestamp at execution.
    pub timestamp: i64,
}

/// Emitted when a ticket is cancelled by the owner.
#[event]
pub struct TicketCancelled {
    /// Ticket PDA address.
    pub ticket: Pubkey,
    /// Owner who cancelled.
    pub owner: Pubkey,
    /// Slot at cancellation.
    pub slot: u64,
}

/// Emitted when a ticket is expired.
#[event]
pub struct TicketExpired {
    /// Ticket PDA address.
    pub ticket: Pubkey,
    /// Cranker who triggered the expiry.
    pub cranker: Pubkey,
    /// Slot at expiry.
    pub slot: u64,
}
