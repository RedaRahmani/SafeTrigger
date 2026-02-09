/**
 * CatalystGuard TypeScript SDK
 *
 * Provides helpers for:
 * - Creating commitment hashes (SHA-256)
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

// ── Commitment helpers ──────────────────────────────────────────

/**
 * Generate a random 32-byte nonce.
 */
export function generateNonce(): Uint8Array {
  const nonce = new Uint8Array(32);
  crypto.getRandomValues(nonce);
  return nonce;
}

/**
 * Create a SHA-256 commitment hash from trigger params + order params + nonce.
 *
 * The commitment = SHA-256(revealData || nonce)
 *
 * This matches the on-chain verification logic.
 */
export function createCommitment(
  revealData: Uint8Array,
  nonce: Uint8Array
): Uint8Array {
  const combined = new Uint8Array(revealData.length + nonce.length);
  combined.set(revealData, 0);
  combined.set(nonce, revealData.length);
  const hash = sha256.arrayBuffer(combined);
  return new Uint8Array(hash);
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
  nonce: Uint8Array
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [TICKET_SEED, policy.toBuffer(), Buffer.from(nonce)],
    CATALYST_GUARD_PROGRAM_ID
  );
}
