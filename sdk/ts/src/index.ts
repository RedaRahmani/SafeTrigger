/**
 * CatalystGuard TypeScript SDK
 *
 * Provides helpers for:
 * - Creating commitment hashes (SHA-256, domain-separated)
 * - Building and serializing HedgePayloadV1 for sealed intents
 * - PDA derivation for policy and ticket accounts
 *
 * Milestone 1 – v0.3 MVP
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

// ── Enums (must match Borsh order in Rust) ──────────────────────

/** Trigger direction – matches on-chain TriggerDirection enum. */
export enum TriggerDirection {
  Above = 0,
  Below = 1,
}

/** Position direction – matches drift_cpi::PositionDirection enum. */
export enum PositionDirection {
  Long = 0,
  Short = 1,
}

/** Order type – matches drift_cpi::OrderType enum. */
export enum OrderType {
  Market = 0,
  Limit = 1,
}

// ── HedgePayloadV1 ─────────────────────────────────────────────

export interface HedgePayloadV1 {
  marketIndex: number; // u16
  triggerDirection: TriggerDirection;
  triggerPrice: bigint; // u64
  side: PositionDirection;
  baseAmount: bigint; // u64
  reduceOnly: boolean;
  orderType: OrderType;
  limitPrice: bigint | null; // Option<u64>
  maxSlippageBps: number; // u16
  deadlineTs: bigint; // i64
  oracleProgram: PublicKey; // Pubkey
  oracle: PublicKey; // Pubkey
}

/**
 * Borsh-serialize a HedgePayloadV1 to bytes.
 * Layout must exactly match the Rust struct field order and Borsh encoding:
 *   u16 + enum(u8) + u64 + enum(u8) + u64 + bool(u8) + enum(u8) + Option<u64> + u16 + i64 + Pubkey + Pubkey
 */
export function serializeHedgePayload(p: HedgePayloadV1): Buffer {
  // Calculate size: 2 + 1 + 8 + 1 + 8 + 1 + 1 + (1 + optional 8) + 2 + 8 + 32 + 32
  const hasLimit = p.limitPrice !== null && p.limitPrice !== undefined;
  const size =
    2 + 1 + 8 + 1 + 8 + 1 + 1 + 1 + (hasLimit ? 8 : 0) + 2 + 8 + 32 + 32;
  const buf = Buffer.alloc(size);
  let offset = 0;

  // market_index: u16 LE
  buf.writeUInt16LE(p.marketIndex, offset);
  offset += 2;

  // trigger_direction: enum as u8
  buf.writeUInt8(p.triggerDirection, offset);
  offset += 1;

  // trigger_price: u64 LE
  buf.writeBigUInt64LE(BigInt(p.triggerPrice), offset);
  offset += 8;

  // side: enum as u8
  buf.writeUInt8(p.side, offset);
  offset += 1;

  // base_amount: u64 LE
  buf.writeBigUInt64LE(BigInt(p.baseAmount), offset);
  offset += 8;

  // reduce_only: bool as u8
  buf.writeUInt8(p.reduceOnly ? 1 : 0, offset);
  offset += 1;

  // order_type: enum as u8
  buf.writeUInt8(p.orderType, offset);
  offset += 1;

  // limit_price: Option<u64> — 0x00 for None, 0x01 + u64 LE for Some
  if (hasLimit) {
    buf.writeUInt8(1, offset);
    offset += 1;
    buf.writeBigUInt64LE(BigInt(p.limitPrice!), offset);
    offset += 8;
  } else {
    buf.writeUInt8(0, offset);
    offset += 1;
  }

  // max_slippage_bps: u16 LE
  buf.writeUInt16LE(p.maxSlippageBps, offset);
  offset += 2;

  // deadline_ts: i64 LE
  buf.writeBigInt64LE(BigInt(p.deadlineTs), offset);
  offset += 8;

  // oracle_program: Pubkey (32 bytes)
  buf.set(p.oracleProgram.toBytes(), offset);
  offset += 32;

  // oracle: Pubkey (32 bytes)
  buf.set(p.oracle.toBytes(), offset);
  offset += 32;

  return buf;
}

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
