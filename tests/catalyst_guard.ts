import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { CatalystGuard } from "../target/types/catalyst_guard";
import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import { createHash, randomBytes } from "crypto";
import { expect } from "chai";

// ── Helpers ─────────────────────────────────────────────────────

const POLICY_SEED = Buffer.from("policy");
const TICKET_SEED = Buffer.from("ticket");
const COMMITMENT_DOMAIN = Buffer.from("CSv0.2");

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

/**
 * Domain-separated commitment:
 * SHA-256(b"CSv0.2" || owner || policy || ticketId || secretSalt || revealData)
 */
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
  const authority = provider.wallet;
  const driftSubAccount = Keypair.generate();

  let policyPDA: PublicKey;
  let policyBump: number;

  // ── Policy Tests ────────────────────────────────────────────

  describe("Policy Management", () => {
    it("initializes a policy", async () => {
      const allowedMarkets = [0, 1, 5];
      const maxBaseAmount = new anchor.BN(1_000_000_000);
      const oracleDeviationBps = 100;
      const minTimeWindow = new anchor.BN(60);
      const maxTimeWindow = new anchor.BN(3600);
      const rateLimitPerWindow = 10;
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
      // Pause
      await program.methods
        .pausePolicy(true)
        .accounts({
          policy: policyPDA,
          authority: authority.publicKey,
        })
        .rpc();

      let policyAccount = await program.account.policy.fetch(policyPDA);
      expect(policyAccount.paused).to.be.true;

      // Unpause
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
        // Expected: Unauthorized or constraint violation
        expect(err).to.exist;
      }
    });

    it("rejects update_policy with more than 32 markets (TooManyMarkets)", async () => {
      // Create an array of 33 market indices
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

  // ── Ticket Tests ────────────────────────────────────────────

  describe("Ticket Lifecycle", () => {
    const revealData = Buffer.from("trigger:SOL-PERP,price>150,amount=1000");
    const ticketId = randomBytes(32);
    const secretSalt = randomBytes(32);
    let commitment: Buffer;
    let ticketPDA: PublicKey;

    it("creates a ticket with commitment hash", async () => {
      commitment = createCommitment(
        authority.publicKey,
        policyPDA,
        ticketId,
        secretSalt,
        revealData
      );

      // Expiry = now + 1 hour
      const now = Math.floor(Date.now() / 1000);
      const expiry = new anchor.BN(now + 3600);

      [ticketPDA] = findTicketPDA(
        program.programId,
        policyPDA,
        ticketId
      );

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

      // The commitment should NOT equal the plaintext reveal data
      expect(Buffer.from(ticketAccount.commitment)).to.not.deep.equal(
        revealData
      );

      // The account should not contain any plaintext trigger data
      // (we verify structurally: Ticket has no trigger/price/direction fields)
      expect(ticketAccount).to.not.have.property("triggerPrice");
      expect(ticketAccount).to.not.have.property("triggerAboveThreshold");
      expect(ticketAccount).to.not.have.property("direction");
    });

    it("executes a ticket with valid reveal (P2 + P3)", async () => {
      const tx = await program.methods
        .executeTicket(Array.from(secretSalt) as any, revealData)
        .accounts({
          ticket: ticketPDA,
          policy: policyPDA,
          keeper: authority.publicKey,
        })
        .rpc();

      console.log("  executeTicket tx:", tx);

      const ticketAccount = await program.account.ticket.fetch(ticketPDA);
      expect(ticketAccount.status).to.deep.equal({ executed: {} });
      expect(ticketAccount.executedSlot.toNumber()).to.be.greaterThan(0);
    });

    it("P3: replay protection – cannot execute consumed ticket", async () => {
      try {
        await program.methods
          .executeTicket(Array.from(secretSalt) as any, revealData)
          .accounts({
            ticket: ticketPDA,
            policy: policyPDA,
            keeper: authority.publicKey,
          })
          .rpc();
        expect.fail("Should have thrown – ticket already consumed");
      } catch (err: any) {
        expect(err.toString()).to.contain("TicketAlreadyConsumed");
      }
    });

    it("rejects execution with wrong reveal data (P2)", async () => {
      // Create a new ticket to test bad reveal
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

      // Try to execute with WRONG reveal data
      const wrongReveal = Buffer.from("WRONG DATA");
      try {
        await program.methods
          .executeTicket(Array.from(secretSalt2) as any, wrongReveal)
          .accounts({
            ticket: ticketPDA2,
            policy: policyPDA,
            keeper: authority.publicKey,
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
      const ticketId3 = randomBytes(32);
      const secretSalt3 = randomBytes(32);
      const revealData3 = Buffer.from("cancel-test");
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
      const ticketId4 = randomBytes(32);
      const secretSalt4 = randomBytes(32);
      const commitment4 = createCommitment(
        authority.publicKey,
        policyPDA,
        ticketId4,
        secretSalt4,
        Buffer.from("past")
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
            new anchor.BN(1000) // way in the past
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
      // 1. Create a second policy (policy B) with a different drift sub-account
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

      // 2. Create a ticket under policy A
      const ticketIdBypass = randomBytes(32);
      const secretSaltBypass = randomBytes(32);
      const revealDataBypass = Buffer.from("bypass-test");
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
        policyPDA,  // ticket is under policy A
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
          policy: policyPDA,  // policy A
          owner: authority.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      // 3. Pause policy A
      await program.methods
        .pausePolicy(true)
        .accounts({
          policy: policyPDA,
          authority: authority.publicKey,
        })
        .rpc();

      // 4. Attempt to execute the ticket with policy B (unpaused) – must FAIL
      try {
        await program.methods
          .executeTicket(Array.from(secretSaltBypass) as any, revealDataBypass)
          .accounts({
            ticket: ticketBypassPDA,
            policy: policyBPDA,  // wrong policy!
            keeper: authority.publicKey,
          })
          .rpc();
        expect.fail("Should have thrown – policy mismatch");
      } catch (err: any) {
        // The error should indicate policy mismatch or a seeds constraint failure
        expect(err).to.exist;
        const errStr = err.toString();
        expect(
          errStr.includes("PolicyMismatch") ||
          errStr.includes("ConstraintHasOne") ||
          errStr.includes("ConstraintSeeds") ||
          errStr.includes("A seeds constraint was violated")
        ).to.be.true;
      }

      // 5. Cleanup: unpause policy A for subsequent tests
      await program.methods
        .pausePolicy(false)
        .accounts({
          policy: policyPDA,
          authority: authority.publicKey,
        })
        .rpc();
    });
  });

  // ── Commitment binding negative tests ───────────────────────

  describe("Commitment binding (domain-separated)", () => {
    let commitTicketId: Buffer;
    let commitSecretSalt: Buffer;
    let commitRevealData: Buffer;
    let commitTicketPDA: PublicKey;

    before(async () => {
      commitTicketId = randomBytes(32);
      commitSecretSalt = randomBytes(32);
      commitRevealData = Buffer.from("commitment-binding-test");

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
          })
          .rpc();
        expect.fail("Should have thrown – wrong salt");
      } catch (err: any) {
        expect(err.toString()).to.contain("CommitmentMismatch");
      }
    });

    it("succeeds with correct salt and reveal data", async () => {
      const tx = await program.methods
        .executeTicket(Array.from(commitSecretSalt) as any, commitRevealData)
        .accounts({
          ticket: commitTicketPDA,
          policy: policyPDA,
          keeper: authority.publicKey,
        })
        .rpc();

      const ticketAccount = await program.account.ticket.fetch(commitTicketPDA);
      expect(ticketAccount.status).to.deep.equal({ executed: {} });
    });
  });
});
