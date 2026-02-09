import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { CatalystGuard } from "../target/types/catalyst_guard";
import { TestOracle } from "../target/types/test_oracle";
import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import { createHash, randomBytes } from "crypto";
import { expect } from "chai";

// ── Constants ───────────────────────────────────────────────────

const POLICY_SEED = Buffer.from("policy");
const TICKET_SEED = Buffer.from("ticket");
const COMMITMENT_DOMAIN = Buffer.from("CSv0.2");

// ── Enums as plain constants (TS enums not supported in strip-only mode) ──

const TriggerDirection = { Above: 0, Below: 1 } as const;
type TriggerDirection = (typeof TriggerDirection)[keyof typeof TriggerDirection];

const PositionDirection = { Long: 0, Short: 1 } as const;
type PositionDirection =
  (typeof PositionDirection)[keyof typeof PositionDirection];

const OrderType = { Market: 0, Limit: 1 } as const;
type OrderType = (typeof OrderType)[keyof typeof OrderType];

// Set during oracle initialization test; used by defaultPayload().
let oracleProgramId: PublicKey;
let oracleFeedPubkey: PublicKey;

// ── HedgePayloadV1 helpers ──────────────────────────────────────

interface HedgePayloadV1 {
  marketIndex: number;
  triggerDirection: TriggerDirection;
  triggerPrice: bigint;
  side: PositionDirection;
  baseAmount: bigint;
  reduceOnly: boolean;
  orderType: OrderType;
  limitPrice: bigint | null;
  maxSlippageBps: number;
  deadlineTs: bigint;
  oracleProgram: PublicKey;
  oracle: PublicKey;
}

/**
 * Borsh-serialize HedgePayloadV1 — must match Rust struct field order.
 */
function serializePayload(p: HedgePayloadV1): Buffer {
  const hasLimit = p.limitPrice !== null && p.limitPrice !== undefined;
  const size =
    2 +
    1 +
    8 +
    1 +
    8 +
    1 +
    1 +
    1 +
    (hasLimit ? 8 : 0) +
    2 +
    8 +
    32 +
    32;
  const buf = Buffer.alloc(size);
  let offset = 0;

  buf.writeUInt16LE(p.marketIndex, offset); offset += 2;
  buf.writeUInt8(p.triggerDirection, offset); offset += 1;
  buf.writeBigUInt64LE(BigInt(p.triggerPrice), offset); offset += 8;
  buf.writeUInt8(p.side, offset); offset += 1;
  buf.writeBigUInt64LE(BigInt(p.baseAmount), offset); offset += 8;
  buf.writeUInt8(p.reduceOnly ? 1 : 0, offset); offset += 1;
  buf.writeUInt8(p.orderType, offset); offset += 1;
  if (hasLimit) {
    buf.writeUInt8(1, offset); offset += 1;
    buf.writeBigUInt64LE(BigInt(p.limitPrice!), offset); offset += 8;
  } else {
    buf.writeUInt8(0, offset); offset += 1;
  }
  buf.writeUInt16LE(p.maxSlippageBps, offset); offset += 2;
  buf.writeBigInt64LE(BigInt(p.deadlineTs), offset); offset += 8;
  buf.set(p.oracleProgram.toBuffer(), offset); offset += 32;
  buf.set(p.oracle.toBuffer(), offset); offset += 32;

  return buf;
}

/** Build a valid default payload for tests. Policy must allow these values. */
function defaultPayload(): HedgePayloadV1 {
  const now = Math.floor(Date.now() / 1000);
  if (!oracleProgramId || !oracleFeedPubkey) {
    throw new Error("oracle not initialized");
  }
  return {
    marketIndex: 0,
    triggerDirection: TriggerDirection.Above,
    triggerPrice: BigInt(150_000_000),
    side: PositionDirection.Long,
    baseAmount: BigInt(1_000_000_000),
    reduceOnly: true,
    orderType: OrderType.Market,
    limitPrice: null,
    maxSlippageBps: 50,
    deadlineTs: BigInt(now + 7200),
    oracleProgram: oracleProgramId,
    oracle: oracleFeedPubkey,
  };
}

// ── PDA derivation ──────────────────────────────────────────────

function findPolicyPDA(
  programId: PublicKey,
  authority: PublicKey,
  driftSubAccount: PublicKey
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [POLICY_SEED, authority.toBuffer(), driftSubAccount.toBuffer()],
    programId
  );
}

function findTicketPDA(
  programId: PublicKey,
  policy: PublicKey,
  ticketId: Buffer
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [TICKET_SEED, policy.toBuffer(), ticketId],
    programId
  );
}

// ── Commitment ──────────────────────────────────────────────────

function createCommitment(
  owner: PublicKey,
  policy: PublicKey,
  ticketId: Buffer,
  secretSalt: Buffer,
  revealData: Buffer
): Buffer {
  const hasher = createHash("sha256");
  hasher.update(COMMITMENT_DOMAIN);
  hasher.update(owner.toBuffer());
  hasher.update(policy.toBuffer());
  hasher.update(ticketId);
  hasher.update(secretSalt);
  hasher.update(revealData);
  return hasher.digest();
}

// ── Tests ───────────────────────────────────────────────────────

describe("catalyst_guard", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.catalystGuard as Program<CatalystGuard>;
  const oracleProgram = anchor.workspace.testOracle as Program<TestOracle>;
  const authority = provider.wallet;
  const driftSubAccount = Keypair.generate();

  let oracleFeed: Keypair;

  let policyPDA: PublicKey;
  let policyBump: number;

  // ── Policy Tests ────────────────────────────────────────────

  describe("Policy Management", () => {
    it("initializes test oracle feed", async () => {
      oracleProgramId = oracleProgram.programId;
      oracleFeed = Keypair.generate();
      oracleFeedPubkey = oracleFeed.publicKey;

      const slot = await provider.connection.getSlot();

      const tx = await oracleProgram.methods
        .initFeed(new anchor.BN(160_000_000), new anchor.BN(slot))
        .accounts({
          feed: oracleFeed.publicKey,
          authority: authority.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([oracleFeed])
        .rpc();

      console.log("  initFeed tx:", tx);
    });

    it("initializes a policy", async () => {
      const allowedMarkets = [0, 1, 5];
      const maxBaseAmount = new anchor.BN(1_000_000_000);
      const oracleDeviationBps = 100;
      const minTimeWindow = new anchor.BN(10); // also used as max oracle staleness (slots)
      const maxTimeWindow = new anchor.BN(3600);
      const rateLimitPerWindow = 0; // disabled for general tests; tested separately
      const reduceOnly = false;

      [policyPDA, policyBump] = findPolicyPDA(
        program.programId,
        authority.publicKey,
        driftSubAccount.publicKey
      );

      const tx = await program.methods
        .initPolicy(
          allowedMarkets,
          maxBaseAmount,
          oracleDeviationBps,
          minTimeWindow,
          maxTimeWindow,
          rateLimitPerWindow,
          reduceOnly
        )
        .accounts({
          policy: policyPDA,
          authority: authority.publicKey,
          driftSubAccount: driftSubAccount.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      console.log("  initPolicy tx:", tx);

      const policyAccount = await program.account.policy.fetch(policyPDA);
      expect(policyAccount.authority.toBase58()).to.equal(
        authority.publicKey.toBase58()
      );
      expect(policyAccount.paused).to.be.false;
      expect(policyAccount.allowedMarkets).to.deep.equal(allowedMarkets);
      expect(policyAccount.maxBaseAmount.toNumber()).to.equal(1_000_000_000);
      expect(policyAccount.oracleDeviationBps).to.equal(100);
      expect(policyAccount.reduceOnly).to.be.false;
    });

    it("updates a policy", async () => {
      const tx = await program.methods
        .updatePolicy(null, new anchor.BN(2_000_000_000), null, true)
        .accounts({
          policy: policyPDA,
          authority: authority.publicKey,
        })
        .rpc();

      console.log("  updatePolicy tx:", tx);

      const policyAccount = await program.account.policy.fetch(policyPDA);
      expect(policyAccount.maxBaseAmount.toNumber()).to.equal(2_000_000_000);
      expect(policyAccount.reduceOnly).to.be.true;
    });

    it("pauses and unpauses a policy", async () => {
      await program.methods
        .pausePolicy(true)
        .accounts({
          policy: policyPDA,
          authority: authority.publicKey,
        })
        .rpc();

      let policyAccount = await program.account.policy.fetch(policyPDA);
      expect(policyAccount.paused).to.be.true;

      await program.methods
        .pausePolicy(false)
        .accounts({
          policy: policyPDA,
          authority: authority.publicKey,
        })
        .rpc();

      policyAccount = await program.account.policy.fetch(policyPDA);
      expect(policyAccount.paused).to.be.false;
    });

    it("rejects policy update from non-authority", async () => {
      const impostor = Keypair.generate();

      try {
        await program.methods
          .updatePolicy(null, null, null, null)
          .accounts({
            policy: policyPDA,
            authority: impostor.publicKey,
          })
          .signers([impostor])
          .rpc();
        expect.fail("Should have thrown");
      } catch (err: any) {
        expect(err).to.exist;
      }
    });

    it("rejects update_policy with more than 32 markets (TooManyMarkets)", async () => {
      const tooManyMarkets = Array.from({ length: 33 }, (_, i) => i);

      try {
        await program.methods
          .updatePolicy(tooManyMarkets, null, null, null)
          .accounts({
            policy: policyPDA,
            authority: authority.publicKey,
          })
          .rpc();
        expect.fail("Should have thrown – too many markets");
      } catch (err: any) {
        expect(err.toString()).to.contain("TooManyMarkets");
      }
    });
  });

  // ── Ticket Lifecycle Tests ──────────────────────────────────
  // After policy updates: allowed_markets=[0,1,5], max_base=2B, reduce_only=true

  describe("Ticket Lifecycle", () => {
    let revealData: Buffer;
    const ticketId = randomBytes(32);
    const secretSalt = randomBytes(32);
    let commitment: Buffer;
    let ticketPDA: PublicKey;

    before(() => {
      revealData = serializePayload(defaultPayload());
    });

    it("rejects create_ticket from non-authority under someone else's policy (owner==policy.authority)", async () => {
      const impostor = Keypair.generate();
      const airdropSig = await provider.connection.requestAirdrop(
        impostor.publicKey,
        2_000_000_000
      );
      await provider.connection.confirmTransaction(airdropSig);

      const ticketIdX = randomBytes(32);
      const secretSaltX = randomBytes(32);
      const revealDataX = serializePayload(defaultPayload());
      const commitmentX = createCommitment(
        impostor.publicKey,
        policyPDA,
        ticketIdX,
        secretSaltX,
        revealDataX
      );
      const now = Math.floor(Date.now() / 1000);
      const [ticketPDAX] = findTicketPDA(program.programId, policyPDA, ticketIdX);

      try {
        await program.methods
          .createTicket(
            Array.from(commitmentX) as any,
            Array.from(ticketIdX) as any,
            new anchor.BN(now + 3600)
          )
          .accounts({
            ticket: ticketPDAX,
            policy: policyPDA,
            owner: impostor.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .signers([impostor])
          .rpc();
        expect.fail("Should have thrown – unauthorized ticket owner");
      } catch (err: any) {
        expect(err.toString()).to.contain("Unauthorized");
      }
    });

    it("creates a ticket with commitment hash", async () => {
      commitment = createCommitment(
        authority.publicKey,
        policyPDA,
        ticketId,
        secretSalt,
        revealData
      );

      const now = Math.floor(Date.now() / 1000);
      const expiry = new anchor.BN(now + 3600);

      [ticketPDA] = findTicketPDA(program.programId, policyPDA, ticketId);

      const tx = await program.methods
        .createTicket(
          Array.from(commitment) as any,
          Array.from(ticketId) as any,
          expiry
        )
        .accounts({
          ticket: ticketPDA,
          policy: policyPDA,
          owner: authority.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      console.log("  createTicket tx:", tx);

      const ticketAccount = await program.account.ticket.fetch(ticketPDA);
      expect(ticketAccount.owner.toBase58()).to.equal(
        authority.publicKey.toBase58()
      );
      expect(Buffer.from(ticketAccount.commitment)).to.deep.equal(commitment);
      expect(Buffer.from(ticketAccount.ticketId)).to.deep.equal(ticketId);
      expect(ticketAccount.status).to.deep.equal({ open: {} });
    });

    it("P1: commitment is opaque (no plaintext params stored)", async () => {
      const ticketAccount = await program.account.ticket.fetch(ticketPDA);

      expect(Buffer.from(ticketAccount.commitment)).to.not.deep.equal(
        revealData
      );
      expect(ticketAccount).to.not.have.property("triggerPrice");
      expect(ticketAccount).to.not.have.property("triggerAboveThreshold");
      expect(ticketAccount).to.not.have.property("direction");
    });

    it("atomicity: valid reveal does not consume ticket when Drift CPI is unavailable", async () => {
      const slot = await provider.connection.getSlot();
      await oracleProgram.methods
        .setFeed(new anchor.BN(160_000_000), new anchor.BN(slot))
        .accounts({
          feed: oracleFeed.publicKey,
          authority: authority.publicKey,
        })
        .rpc();

      try {
        await program.methods
          .executeTicket(Array.from(secretSalt) as any, revealData)
          .accounts({
            ticket: ticketPDA,
            policy: policyPDA,
            keeper: authority.publicKey,
            oracle: oracleFeed.publicKey,
          })
          .rpc();
        expect.fail("Should have thrown – Drift CPI unavailable");
      } catch (err: any) {
        expect(err.toString()).to.contain("DriftCpiUnavailable");
      }

      const ticketAccount = await program.account.ticket.fetch(ticketPDA);
      expect(ticketAccount.status).to.deep.equal({ open: {} });
      expect(ticketAccount.executedSlot.toNumber()).to.equal(0);

      const policyAccount = await program.account.policy.fetch(policyPDA);
      expect(policyAccount.executedCount.toNumber()).to.equal(0);
    });

    it("atomicity: repeated execute attempts still fail and ticket remains Open", async () => {
      const slot = await provider.connection.getSlot();
      await oracleProgram.methods
        .setFeed(new anchor.BN(160_000_000), new anchor.BN(slot))
        .accounts({
          feed: oracleFeed.publicKey,
          authority: authority.publicKey,
        })
        .rpc();

      try {
        await program.methods
          .executeTicket(Array.from(secretSalt) as any, revealData)
          .accounts({
            ticket: ticketPDA,
            policy: policyPDA,
            keeper: authority.publicKey,
            oracle: oracleFeed.publicKey,
          })
          .rpc();
        expect.fail("Should have thrown – Drift CPI unavailable");
      } catch (err: any) {
        expect(err.toString()).to.contain("DriftCpiUnavailable");
      }

      const ticketAccount = await program.account.ticket.fetch(ticketPDA);
      expect(ticketAccount.status).to.deep.equal({ open: {} });
      expect(ticketAccount.executedSlot.toNumber()).to.equal(0);
    });

    it("rejects execution with wrong reveal data (P2)", async () => {
      const ticketId2 = randomBytes(32);
      const secretSalt2 = randomBytes(32);
      const commitment2 = createCommitment(
        authority.publicKey,
        policyPDA,
        ticketId2,
        secretSalt2,
        revealData
      );
      const now = Math.floor(Date.now() / 1000);

      const [ticketPDA2] = findTicketPDA(
        program.programId,
        policyPDA,
        ticketId2
      );

      await program.methods
        .createTicket(
          Array.from(commitment2) as any,
          Array.from(ticketId2) as any,
          new anchor.BN(now + 3600)
        )
        .accounts({
          ticket: ticketPDA2,
          policy: policyPDA,
          owner: authority.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      // Wrong reveal data → commitment mismatch (checked before deserialization)
      const wrongReveal = Buffer.from("WRONG DATA");
      try {
        await program.methods
          .executeTicket(Array.from(secretSalt2) as any, wrongReveal)
          .accounts({
            ticket: ticketPDA2,
            policy: policyPDA,
            keeper: authority.publicKey,
            oracle: oracleFeed.publicKey,
          })
          .rpc();
        expect.fail("Should have thrown – commitment mismatch");
      } catch (err: any) {
        expect(err.toString()).to.contain("CommitmentMismatch");
      }
    });
  });

  // ── Cancel / Expire Tests ─────────────────────────────────

  describe("Cancel and Expire", () => {
    it("owner can cancel an open ticket", async () => {
      const revealData3 = serializePayload(defaultPayload());
      const ticketId3 = randomBytes(32);
      const secretSalt3 = randomBytes(32);
      const commitment3 = createCommitment(
        authority.publicKey,
        policyPDA,
        ticketId3,
        secretSalt3,
        revealData3
      );
      const now = Math.floor(Date.now() / 1000);

      const [ticketPDA3] = findTicketPDA(
        program.programId,
        policyPDA,
        ticketId3
      );

      await program.methods
        .createTicket(
          Array.from(commitment3) as any,
          Array.from(ticketId3) as any,
          new anchor.BN(now + 3600)
        )
        .accounts({
          ticket: ticketPDA3,
          policy: policyPDA,
          owner: authority.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      await program.methods
        .cancelTicket()
        .accounts({
          ticket: ticketPDA3,
          owner: authority.publicKey,
        })
        .rpc();

      const ticketAccount = await program.account.ticket.fetch(ticketPDA3);
      expect(ticketAccount.status).to.deep.equal({ cancelled: {} });
    });

    it("rejects ticket creation with past expiry", async () => {
      const revealData4 = serializePayload(defaultPayload());
      const ticketId4 = randomBytes(32);
      const secretSalt4 = randomBytes(32);
      const commitment4 = createCommitment(
        authority.publicKey,
        policyPDA,
        ticketId4,
        secretSalt4,
        revealData4
      );

      const [ticketPDA4] = findTicketPDA(
        program.programId,
        policyPDA,
        ticketId4
      );

      try {
        await program.methods
          .createTicket(
            Array.from(commitment4) as any,
            Array.from(ticketId4) as any,
            new anchor.BN(1000)
          )
          .accounts({
            ticket: ticketPDA4,
            policy: policyPDA,
            owner: authority.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .rpc();
        expect.fail("Should have thrown – expiry in past");
      } catch (err: any) {
        expect(err.toString()).to.contain("ExpiryInPast");
      }
    });
  });

  // ── Policy-binding bypass test ──────────────────────────────

  describe("Policy-binding enforcement", () => {
    it("rejects execute_ticket with a different policy than ticket.policy", async () => {
      const driftSubAccountB = Keypair.generate();
      const [policyBPDA] = findPolicyPDA(
        program.programId,
        authority.publicKey,
        driftSubAccountB.publicKey
      );

      await program.methods
        .initPolicy(
          [0, 1],
          new anchor.BN(1_000_000_000),
          100,
          new anchor.BN(60),
          new anchor.BN(3600),
          10,
          false
        )
        .accounts({
          policy: policyBPDA,
          authority: authority.publicKey,
          driftSubAccount: driftSubAccountB.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      const revealDataBypass = serializePayload(defaultPayload());
      const ticketIdBypass = randomBytes(32);
      const secretSaltBypass = randomBytes(32);
      const commitmentBypass = createCommitment(
        authority.publicKey,
        policyPDA,
        ticketIdBypass,
        secretSaltBypass,
        revealDataBypass
      );
      const now = Math.floor(Date.now() / 1000);

      const [ticketBypassPDA] = findTicketPDA(
        program.programId,
        policyPDA,
        ticketIdBypass
      );

      await program.methods
        .createTicket(
          Array.from(commitmentBypass) as any,
          Array.from(ticketIdBypass) as any,
          new anchor.BN(now + 3600)
        )
        .accounts({
          ticket: ticketBypassPDA,
          policy: policyPDA,
          owner: authority.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      // Pause policy A
      await program.methods
        .pausePolicy(true)
        .accounts({
          policy: policyPDA,
          authority: authority.publicKey,
        })
        .rpc();

      // Attempt execute with wrong policy → must fail
      try {
        await program.methods
          .executeTicket(
            Array.from(secretSaltBypass) as any,
            revealDataBypass
          )
          .accounts({
            ticket: ticketBypassPDA,
            policy: policyBPDA,
            keeper: authority.publicKey,
            oracle: oracleFeed.publicKey,
          })
          .rpc();
        expect.fail("Should have thrown – policy mismatch");
      } catch (err: any) {
        expect(err).to.exist;
        const errStr = err.toString();
        expect(
          errStr.includes("PolicyMismatch") ||
            errStr.includes("ConstraintHasOne") ||
            errStr.includes("ConstraintSeeds") ||
            errStr.includes("A seeds constraint was violated")
        ).to.be.true;
      }

      // Cleanup: unpause policy A
      await program.methods
        .pausePolicy(false)
        .accounts({
          policy: policyPDA,
          authority: authority.publicKey,
        })
        .rpc();
    });
  });

  // ── Commitment binding tests ────────────────────────────────

  describe("Commitment binding (domain-separated)", () => {
    let commitTicketId: Buffer;
    let commitSecretSalt: Buffer;
    let commitRevealData: Buffer;
    let commitTicketPDA: PublicKey;

    before(async () => {
      commitTicketId = randomBytes(32);
      commitSecretSalt = randomBytes(32);
      commitRevealData = serializePayload(defaultPayload());

      const commitment = createCommitment(
        authority.publicKey,
        policyPDA,
        commitTicketId,
        commitSecretSalt,
        commitRevealData
      );
      const now = Math.floor(Date.now() / 1000);

      [commitTicketPDA] = findTicketPDA(
        program.programId,
        policyPDA,
        commitTicketId
      );

      await program.methods
        .createTicket(
          Array.from(commitment) as any,
          Array.from(commitTicketId) as any,
          new anchor.BN(now + 3600)
        )
        .accounts({
          ticket: commitTicketPDA,
          policy: policyPDA,
          owner: authority.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
    });

    it("rejects execution with wrong secret salt", async () => {
      const wrongSalt = randomBytes(32);
      try {
        await program.methods
          .executeTicket(Array.from(wrongSalt) as any, commitRevealData)
          .accounts({
            ticket: commitTicketPDA,
            policy: policyPDA,
            keeper: authority.publicKey,
            oracle: oracleFeed.publicKey,
          })
          .rpc();
        expect.fail("Should have thrown – wrong salt");
      } catch (err: any) {
        expect(err.toString()).to.contain("CommitmentMismatch");
      }
    });

    it("atomicity: correct salt + reveal validates but still fails without Drift CPI", async () => {
      const slot = await provider.connection.getSlot();
      await oracleProgram.methods
        .setFeed(new anchor.BN(160_000_000), new anchor.BN(slot))
        .accounts({
          feed: oracleFeed.publicKey,
          authority: authority.publicKey,
        })
        .rpc();

      try {
        await program.methods
          .executeTicket(
            Array.from(commitSecretSalt) as any,
            commitRevealData
          )
          .accounts({
            ticket: commitTicketPDA,
            policy: policyPDA,
            keeper: authority.publicKey,
            oracle: oracleFeed.publicKey,
          })
          .rpc();
        expect.fail("Should have thrown – Drift CPI unavailable");
      } catch (err: any) {
        expect(err.toString()).to.contain("DriftCpiUnavailable");
      }

      const ticketAccount = await program.account.ticket.fetch(commitTicketPDA);
      expect(ticketAccount.status).to.deep.equal({ open: {} });
    });
  });

  // ── M1 Adversarial: Payload validation tests ─────────────────

  describe("Payload validation (M1)", () => {
    /** Helper to create+execute a ticket with a specific payload. */
    async function createAndExecute(payload: HedgePayloadV1) {
      const revealData = serializePayload(payload);
      const ticketId = randomBytes(32);
      const secretSalt = randomBytes(32);
      const commitment = createCommitment(
        authority.publicKey,
        policyPDA,
        ticketId,
        secretSalt,
        revealData
      );
      const now = Math.floor(Date.now() / 1000);

      const [ticketPDA] = findTicketPDA(
        program.programId,
        policyPDA,
        ticketId
      );

      await program.methods
        .createTicket(
          Array.from(commitment) as any,
          Array.from(ticketId) as any,
          new anchor.BN(now + 3600)
        )
        .accounts({
          ticket: ticketPDA,
          policy: policyPDA,
          owner: authority.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      // Ensure oracle is fresh and predicate is satisfied for validation tests.
      const slot = await provider.connection.getSlot();
      await oracleProgram.methods
        .setFeed(new anchor.BN(160_000_000), new anchor.BN(slot))
        .accounts({
          feed: oracleFeed.publicKey,
          authority: authority.publicKey,
        })
        .rpc();

      return program.methods
        .executeTicket(Array.from(secretSalt) as any, revealData)
        .accounts({
          ticket: ticketPDA,
          policy: policyPDA,
          keeper: authority.publicKey,
          oracle: oracleFeed.publicKey,
        })
        .rpc();
    }

    it("rejects execute_ticket when predicate not met (PredicateNotMet)", async () => {
      const payload = defaultPayload();
      payload.triggerPrice = BigInt(200_000_000); // oracle will be 160_000_000

      const revealData = serializePayload(payload);
      const ticketId = randomBytes(32);
      const secretSalt = randomBytes(32);
      const commitment = createCommitment(
        authority.publicKey,
        policyPDA,
        ticketId,
        secretSalt,
        revealData
      );
      const now = Math.floor(Date.now() / 1000);
      const [ticketPDA] = findTicketPDA(program.programId, policyPDA, ticketId);

      await program.methods
        .createTicket(
          Array.from(commitment) as any,
          Array.from(ticketId) as any,
          new anchor.BN(now + 3600)
        )
        .accounts({
          ticket: ticketPDA,
          policy: policyPDA,
          owner: authority.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      const slot = await provider.connection.getSlot();
      await oracleProgram.methods
        .setFeed(new anchor.BN(160_000_000), new anchor.BN(slot))
        .accounts({
          feed: oracleFeed.publicKey,
          authority: authority.publicKey,
        })
        .rpc();

      try {
        await program.methods
          .executeTicket(Array.from(secretSalt) as any, revealData)
          .accounts({
            ticket: ticketPDA,
            policy: policyPDA,
            keeper: authority.publicKey,
            oracle: oracleFeed.publicKey,
          })
          .rpc();
        expect.fail("Should have thrown – predicate not met");
      } catch (err: any) {
        expect(err.toString()).to.contain("PredicateNotMet");
      }
    });

    it("rejects execute_ticket when oracle is stale (OracleStale)", async () => {
      const payload = defaultPayload();
      const revealData = serializePayload(payload);
      const ticketId = randomBytes(32);
      const secretSalt = randomBytes(32);
      const commitment = createCommitment(
        authority.publicKey,
        policyPDA,
        ticketId,
        secretSalt,
        revealData
      );
      const now = Math.floor(Date.now() / 1000);
      const [ticketPDA] = findTicketPDA(program.programId, policyPDA, ticketId);

      await program.methods
        .createTicket(
          Array.from(commitment) as any,
          Array.from(ticketId) as any,
          new anchor.BN(now + 3600)
        )
        .accounts({
          ticket: ticketPDA,
          policy: policyPDA,
          owner: authority.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      const currentSlot = await provider.connection.getSlot();
      const staleSlot = Math.max(0, currentSlot - 11); // policy.min_time_window = 10
      await oracleProgram.methods
        .setFeed(new anchor.BN(160_000_000), new anchor.BN(staleSlot))
        .accounts({
          feed: oracleFeed.publicKey,
          authority: authority.publicKey,
        })
        .rpc();

      try {
        await program.methods
          .executeTicket(Array.from(secretSalt) as any, revealData)
          .accounts({
            ticket: ticketPDA,
            policy: policyPDA,
            keeper: authority.publicKey,
            oracle: oracleFeed.publicKey,
          })
          .rpc();
        expect.fail("Should have thrown – oracle stale");
      } catch (err: any) {
        expect(err.toString()).to.contain("OracleStale");
      }
    });

    it("rejects market_index not in policy allowlist", async () => {
      const payload = defaultPayload();
      payload.marketIndex = 99; // not in [0, 1, 5]

      try {
        await createAndExecute(payload);
        expect.fail("Should have thrown");
      } catch (err: any) {
        expect(err.toString()).to.contain("MarketNotAllowed");
      }
    });

    it("rejects base_amount exceeding policy max", async () => {
      const payload = defaultPayload();
      payload.baseAmount = BigInt(3_000_000_000); // exceeds 2B cap

      try {
        await createAndExecute(payload);
        expect.fail("Should have thrown");
      } catch (err: any) {
        expect(err.toString()).to.contain("BaseAmountExceeded");
      }
    });

    it("rejects reduce_only=false when policy requires reduce_only", async () => {
      const payload = defaultPayload();
      payload.reduceOnly = false; // policy has reduce_only=true

      try {
        await createAndExecute(payload);
        expect.fail("Should have thrown");
      } catch (err: any) {
        expect(err.toString()).to.contain("ReduceOnlyViolation");
      }
    });

    it("rejects payload with expired deadline", async () => {
      const payload = defaultPayload();
      payload.deadlineTs = BigInt(1000); // way in the past

      try {
        await createAndExecute(payload);
        expect.fail("Should have thrown");
      } catch (err: any) {
        expect(err.toString()).to.contain("DeadlineExpired");
      }
    });

    it("rejects Limit order without limit_price", async () => {
      const payload = defaultPayload();
      payload.orderType = OrderType.Limit;
      payload.limitPrice = null;

      try {
        await createAndExecute(payload);
        expect.fail("Should have thrown");
      } catch (err: any) {
        expect(err.toString()).to.contain("InvalidRevealData");
      }
    });

    it("accepts valid Limit order with limit_price", async () => {
      const payload = defaultPayload();
      payload.orderType = OrderType.Limit;
      payload.limitPrice = BigInt(155_000_000);

      try {
        await createAndExecute(payload);
        expect.fail("Should have thrown – Drift CPI unavailable");
      } catch (err: any) {
        expect(err.toString()).to.contain("DriftCpiUnavailable");
      }
    });

    it("accepts payload on allowed market index 5", async () => {
      const payload = defaultPayload();
      payload.marketIndex = 5;

      try {
        await createAndExecute(payload);
        expect.fail("Should have thrown – Drift CPI unavailable");
      } catch (err: any) {
        expect(err.toString()).to.contain("DriftCpiUnavailable");
      }
    });

    it("rejects invalid Borsh (truncated payload)", async () => {
      const truncatedData = Buffer.from([0, 0, 1]); // too short for HedgePayloadV1
      const ticketId = randomBytes(32);
      const secretSalt = randomBytes(32);
      const commitment = createCommitment(
        authority.publicKey,
        policyPDA,
        ticketId,
        secretSalt,
        truncatedData
      );
      const now = Math.floor(Date.now() / 1000);

      const [ticketPDA] = findTicketPDA(
        program.programId,
        policyPDA,
        ticketId
      );

      await program.methods
        .createTicket(
          Array.from(commitment) as any,
          Array.from(ticketId) as any,
          new anchor.BN(now + 3600)
        )
        .accounts({
          ticket: ticketPDA,
          policy: policyPDA,
          owner: authority.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      try {
        await program.methods
          .executeTicket(Array.from(secretSalt) as any, truncatedData)
          .accounts({
            ticket: ticketPDA,
            policy: policyPDA,
            keeper: authority.publicKey,
            oracle: oracleFeed.publicKey,
          })
          .rpc();
        expect.fail("Should have thrown – invalid Borsh");
      } catch (err: any) {
        expect(err.toString()).to.contain("InvalidRevealData");
      }
    });

    it("rejects execute on paused policy", async () => {
      // Pause policy A
      await program.methods
        .pausePolicy(true)
        .accounts({
          policy: policyPDA,
          authority: authority.publicKey,
        })
        .rpc();

      const payload = defaultPayload();
      const revealData = serializePayload(payload);
      const ticketId = randomBytes(32);
      const secretSalt = randomBytes(32);
      const commitment = createCommitment(
        authority.publicKey,
        policyPDA,
        ticketId,
        secretSalt,
        revealData
      );
      const now = Math.floor(Date.now() / 1000);

      const [ticketPDA] = findTicketPDA(
        program.programId,
        policyPDA,
        ticketId
      );

      // Create ticket should also fail since policy is paused
      try {
        await program.methods
          .createTicket(
            Array.from(commitment) as any,
            Array.from(ticketId) as any,
            new anchor.BN(now + 3600)
          )
          .accounts({
            ticket: ticketPDA,
            policy: policyPDA,
            owner: authority.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .rpc();
        expect.fail("Should have thrown – policy paused");
      } catch (err: any) {
        expect(err.toString()).to.contain("PolicyPaused");
      }

      // Unpause for subsequent tests
      await program.methods
        .pausePolicy(false)
        .accounts({
          policy: policyPDA,
          authority: authority.publicKey,
        })
        .rpc();
    });

    it("rejects cancel from non-owner (NotTicketOwner)", async () => {
      const payload = defaultPayload();
      const revealData = serializePayload(payload);
      const ticketId = randomBytes(32);
      const secretSalt = randomBytes(32);
      const commitment = createCommitment(
        authority.publicKey,
        policyPDA,
        ticketId,
        secretSalt,
        revealData
      );
      const now = Math.floor(Date.now() / 1000);

      const [ticketPDA] = findTicketPDA(
        program.programId,
        policyPDA,
        ticketId
      );

      await program.methods
        .createTicket(
          Array.from(commitment) as any,
          Array.from(ticketId) as any,
          new anchor.BN(now + 3600)
        )
        .accounts({
          ticket: ticketPDA,
          policy: policyPDA,
          owner: authority.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      const impostor = Keypair.generate();
      try {
        await program.methods
          .cancelTicket()
          .accounts({
            ticket: ticketPDA,
            owner: impostor.publicKey,
          })
          .signers([impostor])
          .rpc();
        expect.fail("Should have thrown – not owner");
      } catch (err: any) {
        expect(err.toString()).to.contain("NotTicketOwner");
      }
    });

    it("rejects expire on non-expired ticket (TicketNotExpired)", async () => {
      const payload = defaultPayload();
      const revealData = serializePayload(payload);
      const ticketId = randomBytes(32);
      const secretSalt = randomBytes(32);
      const commitment = createCommitment(
        authority.publicKey,
        policyPDA,
        ticketId,
        secretSalt,
        revealData
      );
      const now = Math.floor(Date.now() / 1000);

      const [ticketPDA] = findTicketPDA(
        program.programId,
        policyPDA,
        ticketId
      );

      await program.methods
        .createTicket(
          Array.from(commitment) as any,
          Array.from(ticketId) as any,
          new anchor.BN(now + 3600) // expires in 1 hour
        )
        .accounts({
          ticket: ticketPDA,
          policy: policyPDA,
          owner: authority.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      try {
        await program.methods
          .expireTicket()
          .accounts({
            ticket: ticketPDA,
            cranker: authority.publicKey,
          })
          .rpc();
        expect.fail("Should have thrown – ticket not yet expired");
      } catch (err: any) {
        expect(err.toString()).to.contain("TicketNotExpired");
      }
    });

    it("rejects ticket creation with expiry too far in future (>7d)", async () => {
      const payload = defaultPayload();
      const revealData = serializePayload(payload);
      const ticketId = randomBytes(32);
      const secretSalt = randomBytes(32);
      const commitment = createCommitment(
        authority.publicKey,
        policyPDA,
        ticketId,
        secretSalt,
        revealData
      );

      const [ticketPDA] = findTicketPDA(
        program.programId,
        policyPDA,
        ticketId
      );

      const eightDays = Math.floor(Date.now() / 1000) + 8 * 24 * 60 * 60;
      try {
        await program.methods
          .createTicket(
            Array.from(commitment) as any,
            Array.from(ticketId) as any,
            new anchor.BN(eightDays)
          )
          .accounts({
            ticket: ticketPDA,
            policy: policyPDA,
            owner: authority.publicKey,
            systemProgram: SystemProgram.programId,
          })
          .rpc();
        expect.fail("Should have thrown – expiry too far");
      } catch (err: any) {
        expect(err.toString()).to.contain("ExpiryTooFar");
      }
    });

    it("rejects double-cancel (TicketAlreadyConsumed)", async () => {
      const payload = defaultPayload();
      const revealData = serializePayload(payload);
      const ticketId = randomBytes(32);
      const secretSalt = randomBytes(32);
      const commitment = createCommitment(
        authority.publicKey,
        policyPDA,
        ticketId,
        secretSalt,
        revealData
      );
      const now = Math.floor(Date.now() / 1000);

      const [ticketPDA] = findTicketPDA(
        program.programId,
        policyPDA,
        ticketId
      );

      await program.methods
        .createTicket(
          Array.from(commitment) as any,
          Array.from(ticketId) as any,
          new anchor.BN(now + 3600)
        )
        .accounts({
          ticket: ticketPDA,
          policy: policyPDA,
          owner: authority.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      // First cancel succeeds
      await program.methods
        .cancelTicket()
        .accounts({
          ticket: ticketPDA,
          owner: authority.publicKey,
        })
        .rpc();

      // Second cancel must fail
      try {
        await program.methods
          .cancelTicket()
          .accounts({
            ticket: ticketPDA,
            owner: authority.publicKey,
          })
          .rpc();
        expect.fail("Should have thrown – already cancelled");
      } catch (err: any) {
        expect(err.toString()).to.contain("TicketAlreadyConsumed");
      }
    });

    it("verifies ticket_count increments on create", async () => {
      const policyBefore = await program.account.policy.fetch(policyPDA);
      const countBefore = policyBefore.ticketCount.toNumber();

      const payload = defaultPayload();
      const revealData = serializePayload(payload);
      const ticketId = randomBytes(32);
      const secretSalt = randomBytes(32);
      const commitment = createCommitment(
        authority.publicKey,
        policyPDA,
        ticketId,
        secretSalt,
        revealData
      );
      const now = Math.floor(Date.now() / 1000);

      const [ticketPDA] = findTicketPDA(
        program.programId,
        policyPDA,
        ticketId
      );

      await program.methods
        .createTicket(
          Array.from(commitment) as any,
          Array.from(ticketId) as any,
          new anchor.BN(now + 3600)
        )
        .accounts({
          ticket: ticketPDA,
          policy: policyPDA,
          owner: authority.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      const policyAfter = await program.account.policy.fetch(policyPDA);
      expect(policyAfter.ticketCount.toNumber()).to.equal(countBefore + 1);
    });
  });
});
