/**
 * CatalystGuard TypeScript SDK
 *
 * Provides helpers for:
 * - Creating commitment hashes (SHA-256, domain-separated)
 * - Building ticket creation transactions
 * - Reading policy and ticket accounts
 *
 * Stub for Milestone 0 – full implementation in Milestone 2.
 */

import { sha256 } from "js-sha256";
import { PublicKey } from "@solana/web3.js";

// ── Constants ───────────────────────────────────────────────────

export const CATALYST_GUARD_PROGRAM_ID = new PublicKey(
  "2oUmUDgTvVFBDqNC2TpVLhtvaenKgiNnuvsPMUYT4yJq"
);

export const POLICY_SEED = Buffer.from("policy");
export const TICKET_SEED = Buffer.from("ticket");

/** Domain separator for commitment preimage (must match on-chain constant). */
export const COMMITMENT_DOMAIN = Buffer.from("CSv0.2");

// ── Commitment helpers ──────────────────────────────────────────

/**
 * Generate a random 32-byte ticket ID (public identifier for PDA seeds).
 */
export function generateTicketId(): Uint8Array {
  const id = new Uint8Array(32);
  crypto.getRandomValues(id);
  return id;
}

/**
 * Generate a random 32-byte secret salt (kept off-chain until execute).
 */
export function generateSecretSalt(): Uint8Array {
  const salt = new Uint8Array(32);
  crypto.getRandomValues(salt);
  return salt;
}

/**
 * Create a domain-separated SHA-256 commitment hash.
 *
 * commitment = SHA-256(b"CSv0.2" || owner || policy || ticketId || secretSalt || revealData)
 *
 * This matches the on-chain verification logic in execute_ticket.
 */
export function createCommitment(
  owner: PublicKey,
  policy: PublicKey,
  ticketId: Uint8Array,
  secretSalt: Uint8Array,
  revealData: Uint8Array
): Uint8Array {
  const hasher = sha256.create();
  hasher.update(COMMITMENT_DOMAIN);
  hasher.update(owner.toBytes());
  hasher.update(policy.toBytes());
  hasher.update(ticketId);
  hasher.update(secretSalt);
  hasher.update(revealData);
  return new Uint8Array(hasher.arrayBuffer());
}

// ── PDA derivation ──────────────────────────────────────────────

/**
 * Derive the Policy PDA address.
 */
export function findPolicyAddress(
  authority: PublicKey,
  driftSubAccount: PublicKey
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [POLICY_SEED, authority.toBuffer(), driftSubAccount.toBuffer()],
    CATALYST_GUARD_PROGRAM_ID
  );
}

/**
 * Derive the Ticket PDA address.
 */
export function findTicketAddress(
  policy: PublicKey,
  ticketId: Uint8Array
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [TICKET_SEED, policy.toBuffer(), Buffer.from(ticketId)],
    CATALYST_GUARD_PROGRAM_ID
  );
}
