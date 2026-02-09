//! Ticket account – a sealed conditional intent commitment.

use anchor_lang::prelude::*;

/// Seed prefix for Ticket PDA derivation.
pub const TICKET_SEED: &[u8] = b"ticket";

/// Ticket status enum.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum TicketStatus {
    /// Ticket is open and can be executed.
    Open,
    /// Ticket has been successfully executed.
    Executed,
    /// Ticket was cancelled by the owner.
    Cancelled,
    /// Ticket expired without execution.
    Expired,
}

/// A ticket holds a SHA-256 commitment hash (no plaintext trigger params)
/// and tracks its lifecycle: Open → Executed / Cancelled / Expired.
///
/// **Invariant P1**: `commitment` is a SHA-256 hash of the trigger + order
/// params concatenated with a random nonce. The plaintext is never stored.
///
/// **Invariant P3**: Once `status != Open`, the ticket cannot be re-executed.
/// The `nonce` provides additional replay protection across tickets.
#[account]
#[derive(Debug)]
pub struct Ticket {
    /// Owner who created this ticket.
    pub owner: Pubkey,

    /// The policy this ticket is bound to.
    pub policy: Pubkey,

    /// SHA-256 commitment hash = H(trigger_params || order_params || nonce).
    pub commitment: [u8; 32],

    /// Random nonce used in the commitment (stored for efficient indexing).
    /// The full preimage is only known off-chain until reveal.
    pub nonce: [u8; 32],

    /// Bump for PDA derivation.
    pub bump: u8,

    /// Current status of the ticket.
    pub status: TicketStatus,

    /// Unix timestamp after which the ticket can no longer be executed.
    pub expiry: i64,

    /// Slot at which the ticket was created (for ordering/forensics).
    pub created_slot: u64,

    /// Timestamp of creation.
    pub created_at: i64,

    /// Timestamp of last status change.
    pub updated_at: i64,

    /// Slot at which the ticket was executed (0 if not executed).
    pub executed_slot: u64,
}

impl Ticket {
    /// Space needed for a Ticket account including discriminator.
    pub const SPACE: usize = 8  // discriminator
        + 32  // owner
        + 32  // policy
        + 32  // commitment
        + 32  // nonce
        + 1   // bump
        + 1   // status (enum, 1 byte via Borsh)
        + 8   // expiry
        + 8   // created_slot
        + 8   // created_at
        + 8   // updated_at
        + 8; // executed_slot

    /// Returns true if the ticket is still open for execution.
    pub fn is_open(&self) -> bool {
        self.status == TicketStatus::Open
    }

    /// Returns true if the ticket has expired based on current clock.
    pub fn is_expired(&self, now: i64) -> bool {
        now >= self.expiry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ticket_status_lifecycle() {
        let ticket = Ticket {
            owner: Pubkey::default(),
            policy: Pubkey::default(),
            commitment: [0u8; 32],
            nonce: [0u8; 32],
            bump: 255,
            status: TicketStatus::Open,
            expiry: 1_000_000,
            created_slot: 100,
            created_at: 999_000,
            updated_at: 999_000,
            executed_slot: 0,
        };

        assert!(ticket.is_open());
        assert!(!ticket.is_expired(999_999));
        assert!(ticket.is_expired(1_000_000));
        assert!(ticket.is_expired(1_000_001));
    }

    #[test]
    fn test_space_constant() {
        // Ensure space is reasonable
        assert_eq!(
            Ticket::SPACE,
            8 + 32 + 32 + 32 + 32 + 1 + 1 + 8 + 8 + 8 + 8 + 8
        );
    }
}
