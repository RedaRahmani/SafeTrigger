import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { CatalystGuard } from "../target/types/catalyst_guard";
import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import { createHash, randomBytes } from "crypto";
import { expect } from "chai";

// ── Helpers ─────────────────────────────────────────────────────

const POLICY_SEED = Buffer.from("policy");
const TICKET_SEED = Buffer.from("ticket");

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
  nonce: Buffer
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [TICKET_SEED, policy.toBuffer(), nonce],
    programId
  );
}

function createCommitment(revealData: Buffer, nonce: Buffer): Buffer {
  const hasher = createHash("sha256");
  hasher.update(revealData);
  hasher.update(nonce);
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
  });

  // ── Ticket Tests ────────────────────────────────────────────

  describe("Ticket Lifecycle", () => {
    const revealData = Buffer.from("trigger:SOL-PERP,price>150,amount=1000");
    const nonce = randomBytes(32);
    const commitment = createCommitment(revealData, nonce);
    let ticketPDA: PublicKey;

    it("creates a ticket with commitment hash", async () => {
      // Expiry = now + 1 hour
      const now = Math.floor(Date.now() / 1000);
      const expiry = new anchor.BN(now + 3600);

      [ticketPDA] = findTicketPDA(
        program.programId,
        policyPDA,
        nonce
      );

      const tx = await program.methods
        .createTicket(
          Array.from(commitment) as any,
          Array.from(nonce) as any,
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
      expect(Buffer.from(ticketAccount.nonce)).to.deep.equal(nonce);
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
        .executeTicket(revealData)
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
          .executeTicket(revealData)
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
      const nonce2 = randomBytes(32);
      const commitment2 = createCommitment(revealData, nonce2);
      const now = Math.floor(Date.now() / 1000);

      const [ticketPDA2] = findTicketPDA(
        program.programId,
        policyPDA,
        nonce2
      );

      await program.methods
        .createTicket(
          Array.from(commitment2) as any,
          Array.from(nonce2) as any,
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
          .executeTicket(wrongReveal)
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
      const nonce3 = randomBytes(32);
      const revealData3 = Buffer.from("cancel-test");
      const commitment3 = createCommitment(revealData3, nonce3);
      const now = Math.floor(Date.now() / 1000);

      const [ticketPDA3] = findTicketPDA(
        program.programId,
        policyPDA,
        nonce3
      );

      await program.methods
        .createTicket(
          Array.from(commitment3) as any,
          Array.from(nonce3) as any,
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
      const nonce4 = randomBytes(32);
      const commitment4 = createCommitment(Buffer.from("past"), nonce4);

      const [ticketPDA4] = findTicketPDA(
        program.programId,
        policyPDA,
        nonce4
      );

      try {
        await program.methods
          .createTicket(
            Array.from(commitment4) as any,
            Array.from(nonce4) as any,
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
      const nonceBypass = randomBytes(32);
      const revealDataBypass = Buffer.from("bypass-test");
      const commitmentBypass = createCommitment(revealDataBypass, nonceBypass);
      const now = Math.floor(Date.now() / 1000);

      const [ticketBypassPDA] = findTicketPDA(
        program.programId,
        policyPDA,  // ticket is under policy A
        nonceBypass
      );

      await program.methods
        .createTicket(
          Array.from(commitmentBypass) as any,
          Array.from(nonceBypass) as any,
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
          .executeTicket(revealDataBypass)
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
});
