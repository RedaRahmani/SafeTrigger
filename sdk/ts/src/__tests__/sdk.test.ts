/**
 * CatalystGuard SDK – Unit Tests (Known Answer Tests)
 *
 * Validates:
 * 1. serializeHedgePayload: deterministic Borsh encoding
 * 2. createCommitment: domain-separated SHA-256 hash
 * 3. findPolicyAddress / findTicketAddress: PDA derivation
 * 4. Edge cases: Option encoding, direction enums
 */

import { PublicKey } from "@solana/web3.js";
import { sha256 } from "js-sha256";
import {
  CATALYST_GUARD_PROGRAM_ID,
  COMMITMENT_DOMAIN,
  POLICY_SEED,
  TICKET_SEED,
  TriggerDirection,
  PositionDirection,
  OrderType,
  serializeHedgePayload,
  createCommitment,
  findPolicyAddress,
  findTicketAddress,
  generateTicketId,
  generateSecretSalt,
  HedgePayloadV1,
} from "../index";

// ── Helper to create a default payload for tests ─────────────────

function defaultPayload(overrides: Partial<HedgePayloadV1> = {}): HedgePayloadV1 {
  return {
    marketIndex: 0,
    triggerDirection: TriggerDirection.Above,
    triggerPrice: BigInt(150_000_000),
    side: PositionDirection.Long,
    baseAmount: BigInt(1_000_000_000),
    reduceOnly: false,
    orderType: OrderType.Market,
    limitPrice: null,
    maxSlippageBps: 50,
    deadlineTs: BigInt(2_000_000_000),
    oracleProgram: PublicKey.default,
    oracle: PublicKey.default,
    ...overrides,
  };
}

// ── serializeHedgePayload ────────────────────────────────────────

describe("serializeHedgePayload", () => {
  it("produces correct length for Market order (no limit_price)", () => {
    const buf = serializeHedgePayload(defaultPayload());
    // 2 + 1 + 8 + 1 + 8 + 1 + 1 + 1(None) + 2 + 8 + 32 + 32 = 97
    expect(buf.length).toBe(97);
  });

  it("produces correct length for Limit order (with limit_price)", () => {
    const buf = serializeHedgePayload(
      defaultPayload({
        orderType: OrderType.Limit,
        limitPrice: BigInt(155_000_000),
      })
    );
    // 97 + 8 (Some value) = 105
    expect(buf.length).toBe(105);
  });

  it("KAT: deterministic encoding for a known payload", () => {
    const payload = defaultPayload();
    const buf1 = serializeHedgePayload(payload);
    const buf2 = serializeHedgePayload(payload);
    expect(buf1.equals(buf2)).toBe(true);
  });

  it("encodes market_index as u16 LE at offset 0", () => {
    const buf = serializeHedgePayload(defaultPayload({ marketIndex: 5 }));
    expect(buf.readUInt16LE(0)).toBe(5);
  });

  it("encodes trigger_direction as u8 at offset 2", () => {
    const above = serializeHedgePayload(
      defaultPayload({ triggerDirection: TriggerDirection.Above })
    );
    expect(above[2]).toBe(0);

    const below = serializeHedgePayload(
      defaultPayload({ triggerDirection: TriggerDirection.Below })
    );
    expect(below[2]).toBe(1);
  });

  it("encodes trigger_price as u64 LE at offset 3", () => {
    const buf = serializeHedgePayload(
      defaultPayload({ triggerPrice: BigInt(160_000_000) })
    );
    expect(buf.readBigUInt64LE(3)).toBe(BigInt(160_000_000));
  });

  it("encodes side (Long=0, Short=1) at offset 11", () => {
    const long = serializeHedgePayload(
      defaultPayload({ side: PositionDirection.Long })
    );
    expect(long[11]).toBe(0);

    const short = serializeHedgePayload(
      defaultPayload({ side: PositionDirection.Short })
    );
    expect(short[11]).toBe(1);
  });

  it("encodes base_amount as u64 LE at offset 12", () => {
    const buf = serializeHedgePayload(
      defaultPayload({ baseAmount: BigInt(2_000_000_000) })
    );
    expect(buf.readBigUInt64LE(12)).toBe(BigInt(2_000_000_000));
  });

  it("encodes reduce_only bool at offset 20", () => {
    const notRO = serializeHedgePayload(defaultPayload({ reduceOnly: false }));
    expect(notRO[20]).toBe(0);

    const isRO = serializeHedgePayload(defaultPayload({ reduceOnly: true }));
    expect(isRO[20]).toBe(1);
  });

  it("encodes Option<u64> None as 0x00 for limit_price", () => {
    const buf = serializeHedgePayload(defaultPayload({ limitPrice: null }));
    // order_type at 21, limit_price option tag at 22
    expect(buf[22]).toBe(0);
  });

  it("encodes Option<u64> Some as 0x01 + u64 LE for limit_price", () => {
    const buf = serializeHedgePayload(
      defaultPayload({
        orderType: OrderType.Limit,
        limitPrice: BigInt(155_000_000),
      })
    );
    expect(buf[22]).toBe(1);
    expect(buf.readBigUInt64LE(23)).toBe(BigInt(155_000_000));
  });

  it("encodes oracle pubkeys at the tail", () => {
    const oracleProg = PublicKey.default;
    const oracle = PublicKey.default;
    const buf = serializeHedgePayload(
      defaultPayload({ oracleProgram: oracleProg, oracle })
    );
    // For None limit_price: offset = 2+1+8+1+8+1+1+1+2+8 = 33
    const oracleProgBytes = buf.subarray(33, 65);
    expect(Buffer.from(oracleProgBytes).equals(oracleProg.toBuffer())).toBe(true);
    const oracleBytes = buf.subarray(65, 97);
    expect(Buffer.from(oracleBytes).equals(oracle.toBuffer())).toBe(true);
  });
});

// ── createCommitment ─────────────────────────────────────────────

describe("createCommitment", () => {
  const owner = PublicKey.default;
  const policy = PublicKey.default;
  const ticketId = new Uint8Array(32).fill(1);
  const secretSalt = new Uint8Array(32).fill(2);
  const revealData = serializeHedgePayload(defaultPayload());

  it("produces 32 bytes", () => {
    const c = createCommitment(owner, policy, ticketId, secretSalt, revealData);
    expect(c.length).toBe(32);
  });

  it("is deterministic", () => {
    const c1 = createCommitment(owner, policy, ticketId, secretSalt, revealData);
    const c2 = createCommitment(owner, policy, ticketId, secretSalt, revealData);
    expect(Buffer.from(c1).equals(Buffer.from(c2))).toBe(true);
  });

  it("differs with different secret_salt", () => {
    const altSalt = new Uint8Array(32).fill(99);
    const c1 = createCommitment(owner, policy, ticketId, secretSalt, revealData);
    const c2 = createCommitment(owner, policy, ticketId, altSalt, revealData);
    expect(Buffer.from(c1).equals(Buffer.from(c2))).toBe(false);
  });

  it("differs with different reveal_data", () => {
    const altPayload = serializeHedgePayload(
      defaultPayload({ marketIndex: 5 })
    );
    const c1 = createCommitment(owner, policy, ticketId, secretSalt, revealData);
    const c2 = createCommitment(
      owner, policy, ticketId, secretSalt, altPayload
    );
    expect(Buffer.from(c1).equals(Buffer.from(c2))).toBe(false);
  });

  it("differs with different owner", () => {
    const altOwner = new PublicKey(new Uint8Array(32).fill(0xAA));
    const c1 = createCommitment(owner, policy, ticketId, secretSalt, revealData);
    const c2 = createCommitment(
      altOwner, policy, ticketId, secretSalt, revealData
    );
    expect(Buffer.from(c1).equals(Buffer.from(c2))).toBe(false);
  });

  it("matches manual SHA-256 computation", () => {
    const hasher = sha256.create();
    hasher.update(COMMITMENT_DOMAIN);
    hasher.update(owner.toBytes());
    hasher.update(policy.toBytes());
    hasher.update(ticketId);
    hasher.update(secretSalt);
    hasher.update(revealData);
    const expected = new Uint8Array(hasher.arrayBuffer());

    const actual = createCommitment(
      owner, policy, ticketId, secretSalt, revealData
    );
    expect(Buffer.from(actual).equals(Buffer.from(expected))).toBe(true);
  });
});

// ── PDA derivation ───────────────────────────────────────────────

describe("findPolicyAddress", () => {
  it("returns a valid public key and bump", () => {
    const authority = PublicKey.default;
    const drift = PublicKey.default;
    const [addr, bump] = findPolicyAddress(authority, drift);
    expect(addr).toBeInstanceOf(PublicKey);
    expect(typeof bump).toBe("number");
    expect(bump).toBeGreaterThanOrEqual(0);
    expect(bump).toBeLessThanOrEqual(255);
  });

  it("is deterministic", () => {
    const authority = PublicKey.default;
    const drift = PublicKey.default;
    const [a1] = findPolicyAddress(authority, drift);
    const [a2] = findPolicyAddress(authority, drift);
    expect(a1.equals(a2)).toBe(true);
  });

  it("differs for different authorities", () => {
    const auth1 = PublicKey.default;
    const auth2 = new PublicKey(new Uint8Array(32).fill(0xBB));
    const drift = PublicKey.default;
    const [a1] = findPolicyAddress(auth1, drift);
    const [a2] = findPolicyAddress(auth2, drift);
    expect(a1.equals(a2)).toBe(false);
  });

  it("verifies against on-chain PDA derivation", () => {
    const authority = PublicKey.default;
    const drift = PublicKey.default;
    const [addr] = findPolicyAddress(authority, drift);
    // Cross-check with raw findProgramAddressSync
    const [expected] = PublicKey.findProgramAddressSync(
      [POLICY_SEED, authority.toBuffer(), drift.toBuffer()],
      CATALYST_GUARD_PROGRAM_ID
    );
    expect(addr.equals(expected)).toBe(true);
  });
});

describe("findTicketAddress", () => {
  it("returns a valid public key and bump", () => {
    const policy = PublicKey.default;
    const ticketId = new Uint8Array(32).fill(0xCC);
    const [addr, bump] = findTicketAddress(policy, ticketId);
    expect(addr).toBeInstanceOf(PublicKey);
    expect(typeof bump).toBe("number");
  });

  it("is deterministic", () => {
    const policy = PublicKey.default;
    const ticketId = new Uint8Array(32).fill(0xDD);
    const [a1] = findTicketAddress(policy, ticketId);
    const [a2] = findTicketAddress(policy, ticketId);
    expect(a1.equals(a2)).toBe(true);
  });

  it("differs for different ticket IDs", () => {
    const policy = PublicKey.default;
    const id1 = new Uint8Array(32).fill(1);
    const id2 = new Uint8Array(32).fill(2);
    const [a1] = findTicketAddress(policy, id1);
    const [a2] = findTicketAddress(policy, id2);
    expect(a1.equals(a2)).toBe(false);
  });

  it("verifies against on-chain PDA derivation", () => {
    const policy = PublicKey.default;
    const ticketId = new Uint8Array(32).fill(0xEE);
    const [addr] = findTicketAddress(policy, ticketId);
    const [expected] = PublicKey.findProgramAddressSync(
      [TICKET_SEED, policy.toBuffer(), Buffer.from(ticketId)],
      CATALYST_GUARD_PROGRAM_ID
    );
    expect(addr.equals(expected)).toBe(true);
  });
});

// ── Random generators ────────────────────────────────────────────

describe("generateTicketId", () => {
  it("returns 32 bytes", () => {
    const id = generateTicketId();
    expect(id.length).toBe(32);
  });

  it("produces unique values", () => {
    const a = generateTicketId();
    const b = generateTicketId();
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });
});

describe("generateSecretSalt", () => {
  it("returns 32 bytes", () => {
    const salt = generateSecretSalt();
    expect(salt.length).toBe(32);
  });

  it("produces unique values", () => {
    const a = generateSecretSalt();
    const b = generateSecretSalt();
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });
});

// ── Constants ────────────────────────────────────────────────────

describe("constants", () => {
  it("COMMITMENT_DOMAIN matches on-chain b\"CSv0.2\"", () => {
    expect(COMMITMENT_DOMAIN.toString()).toBe("CSv0.2");
  });

  it("POLICY_SEED is b\"policy\"", () => {
    expect(POLICY_SEED.toString()).toBe("policy");
  });

  it("TICKET_SEED is b\"ticket\"", () => {
    expect(TICKET_SEED.toString()).toBe("ticket");
  });

  it("CATALYST_GUARD_PROGRAM_ID is correct", () => {
    expect(CATALYST_GUARD_PROGRAM_ID.toBase58()).toBe(
      "2oUmUDgTvVFBDqNC2TpVLhtvaenKgiNnuvsPMUYT4yJq"
    );
  });
});
