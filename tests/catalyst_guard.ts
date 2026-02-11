import anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import { createHash, randomBytes } from "crypto";
import { expect } from "chai";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import path from "path";
import {
  POLICY_SEED,
  TICKET_SEED,
  serializeHedgePayload,
  createCommitment as sdkCreateCommitment,
  TriggerDirection,
  PositionDirection,
  OrderType,
} from "../sdk/ts/src/index.ts";
import type { HedgePayloadV1 } from "../sdk/ts/src/index.ts";

// ── Constants ───────────────────────────────────────────────────

// Drift (pinned program id + PDA seeds)
const DRIFT_PROGRAM_ID = new PublicKey(
  "dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH"
);
const DRIFT_STATE_SEED = Buffer.from("drift_state");
const DRIFT_USER_SEED = Buffer.from("user");
const DRIFT_USER_STATS_SEED = Buffer.from("user_stats");
const DRIFT_SPOT_MARKET_SEED = Buffer.from("spot_market");
const DRIFT_PERP_MARKET_SEED = Buffer.from("perp_market");
const DRIFT_SUB_ACCOUNT_ID = 0; // MVP: only sub-account 0
const ZERO_PUBKEY = new PublicKey(new Uint8Array(32));

function u16LE(n: number): Buffer {
  const b = Buffer.alloc(2);
  b.writeUInt16LE(n, 0);
  return b;
}

function loadIdl(name: string): any {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  const idlPath = path.join(__dirname, "..", "target", "idl", `${name}.json`);
  return JSON.parse(readFileSync(idlPath, "utf8"));
}

function findDriftStatePDA(): [PublicKey, number] {
  return PublicKey.findProgramAddressSync([DRIFT_STATE_SEED], DRIFT_PROGRAM_ID);
}

function findDriftUserPDA(authority: PublicKey, subAccountId: number): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [DRIFT_USER_SEED, authority.toBuffer(), u16LE(subAccountId)],
    DRIFT_PROGRAM_ID
  );
}

function findDriftUserStatsPDA(authority: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [DRIFT_USER_STATS_SEED, authority.toBuffer()],
    DRIFT_PROGRAM_ID
  );
}

function findDriftSpotMarketPDA(marketIndex: number): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [DRIFT_SPOT_MARKET_SEED, u16LE(marketIndex)],
    DRIFT_PROGRAM_ID
  );
}

function findDriftPerpMarketPDA(marketIndex: number): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [DRIFT_PERP_MARKET_SEED, u16LE(marketIndex)],
    DRIFT_PROGRAM_ID
  );
}

// Set during oracle initialization test; used by defaultPayload().
let oracleProgramId: PublicKey;
let oracleFeedPubkey: PublicKey;

// ── HedgePayloadV1 helpers ──────────────────────────────────────

/** Canonical serializer: SDK implementation (single source of truth). */
function serializePayload(p: HedgePayloadV1): Buffer {
  return serializeHedgePayload(p);
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
  return Buffer.from(
    sdkCreateCommitment(owner, policy, ticketId, secretSalt, revealData)
  );
}

// ── Tests ───────────────────────────────────────────────────────

describe("catalyst_guard", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.catalystGuard as Program;
  const oracleProgram = anchor.workspace.testOracle as Program;
  const authority = provider.wallet;

  let oracleFeed: Keypair;

  let policyPDA: PublicKey;
  let policyBump: number;

  // Drift stub program + PDAs (loaded at DRIFT_PROGRAM_ID via genesis)
  let driftStub: Program;
  let driftStatePDA: PublicKey;
  let driftUserPDA: PublicKey;
  let driftUserStatsPDA: PublicKey;
  let driftSpotMarketPDA: PublicKey;
  let driftPerpMarket0PDA: PublicKey;
  let driftPerpMarket5PDA: PublicKey;

  // ── Policy Tests ────────────────────────────────────────────

  describe("Policy Management", () => {
    it("initializes test oracle feed", async () => {
      oracleProgramId = oracleProgram.programId;
      // Deterministic so known-answer vectors can bind to a stable oracle pubkey.
      oracleFeed = Keypair.fromSeed(
        Uint8Array.from(Array.from({ length: 32 }, (_, i) => i + 100))
      );
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

    it("initializes drift stub accounts (state/user/markets)", async () => {
      // Load the local IDL so we can call the stub program that is loaded at genesis.
      const driftIdl = loadIdl("drift_stub");
      // Anchor v0.31 Program derives the program id from `idl.address`.
      // Our drift stub is loaded at the pinned Drift program id via validator genesis,
      // so overwrite the IDL address before constructing the client.
      driftIdl.address = DRIFT_PROGRAM_ID.toBase58();
      driftStub = new Program(driftIdl, provider);

      [driftStatePDA] = findDriftStatePDA();
      [driftUserPDA] = findDriftUserPDA(authority.publicKey, DRIFT_SUB_ACCOUNT_ID);
      [driftUserStatsPDA] = findDriftUserStatsPDA(authority.publicKey);
      [driftSpotMarketPDA] = findDriftSpotMarketPDA(0);
      [driftPerpMarket0PDA] = findDriftPerpMarketPDA(0);
      [driftPerpMarket5PDA] = findDriftPerpMarketPDA(5);

      const tx1 = await driftStub.methods
        .initState()
        .accounts({
          state: driftStatePDA,
          admin: authority.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      console.log("  initDriftState tx:", tx1);

      const tx2 = await driftStub.methods
        .initUser(DRIFT_SUB_ACCOUNT_ID)
        .accounts({
          user: driftUserPDA,
          authority: authority.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      console.log("  initDriftUser tx:", tx2);

      const tx3 = await driftStub.methods
        .initUserStats()
        .accounts({
          userStats: driftUserStatsPDA,
          authority: authority.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      console.log("  initDriftUserStats tx:", tx3);

      const tx4 = await driftStub.methods
        .initSpotMarket(0, ZERO_PUBKEY)
        .accounts({
          spotMarket: driftSpotMarketPDA,
          admin: authority.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      console.log("  initDriftSpotMarket0 tx:", tx4);

      // Initialize perp markets used by tests. Both point at the same oracle feed for simplicity.
      const tx5 = await driftStub.methods
        .initPerpMarket(0, oracleFeedPubkey)
        .accounts({
          perpMarket: driftPerpMarket0PDA,
          admin: authority.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      console.log("  initDriftPerpMarket0 tx:", tx5);

      const tx6 = await driftStub.methods
        .initPerpMarket(5, oracleFeedPubkey)
        .accounts({
          perpMarket: driftPerpMarket5PDA,
          admin: authority.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      console.log("  initDriftPerpMarket5 tx:", tx6);
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
        driftUserPDA
      );

      const tx = await program.methods
        .initPolicy(
          allowedMarkets,
          maxBaseAmount,
          oracleDeviationBps,
          minTimeWindow,
          maxTimeWindow,
          rateLimitPerWindow,
          reduceOnly,
          new anchor.BN(100)
        )
        .accounts({
          policy: policyPDA,
          authority: authority.publicKey,
          driftSubAccount: driftUserPDA,
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

      // Configure Drift user delegate = Policy PDA so CatalystGuard can sign CPIs.
      const txDel = await driftStub.methods
        .updateUserDelegate(policyPDA)
        .accounts({
          user: driftUserPDA,
          authority: authority.publicKey,
        })
        .rpc();
      console.log("  updateDriftUserDelegate tx:", txDel);
    });

    it("updates a policy", async () => {
      const tx = await program.methods
        .updatePolicy(null, new anchor.BN(2_000_000_000), null, true, null)
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
          .updatePolicy(null, null, null, null, null)
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
          .updatePolicy(tooManyMarkets, null, null, null, null)
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

  // ── Known-answer vectors (KAT) ───────────────────────────────

  describe("Known-answer vectors (KAT)", () => {
    // Deterministic keypairs so the derived PDAs and expected commitment are stable.
    const katAuthority = Keypair.fromSeed(
      Uint8Array.from(Array.from({ length: 32 }, (_, i) => i))
    );

    const katTicketId = Buffer.from(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      "hex"
    );
    const katSecretSalt = Buffer.from(
      "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
      "hex"
    );

    // Computed offline from the fixed vector:
    // sha256("CSv0.2" || owner || policy || ticket_id || secret_salt || revealed_payload)
    const expectedCommitmentHex =
      "71b6d2505ca5649a2e3f7faea7cec06c04f86822102983c8d342ff51558fb9a8";

    let katPolicyPDA: PublicKey;
    let katDriftUserPDA: PublicKey;
    let katDriftUserStatsPDA: PublicKey;
    let katTicketPDA: PublicKey;

    before(async () => {
      const airdropSig = await provider.connection.requestAirdrop(
        katAuthority.publicKey,
        5_000_000_000
      );
      await provider.connection.confirmTransaction(airdropSig);

      [katDriftUserPDA] = findDriftUserPDA(
        katAuthority.publicKey,
        DRIFT_SUB_ACCOUNT_ID
      );
      [katDriftUserStatsPDA] = findDriftUserStatsPDA(katAuthority.publicKey);

      await driftStub.methods
        .initUser(DRIFT_SUB_ACCOUNT_ID)
        .accounts({
          user: katDriftUserPDA,
          authority: katAuthority.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([katAuthority])
        .rpc();

      await driftStub.methods
        .initUserStats()
        .accounts({
          userStats: katDriftUserStatsPDA,
          authority: katAuthority.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([katAuthority])
        .rpc();

      [katPolicyPDA] = findPolicyPDA(
        program.programId,
        katAuthority.publicKey,
        katDriftUserPDA
      );

      await program.methods
        .initPolicy(
          [0],
          new anchor.BN(1_000_000_000),
          100,
          new anchor.BN(10),
          new anchor.BN(60),
          0,
          true,
          new anchor.BN(100)
        )
        .accounts({
          policy: katPolicyPDA,
          authority: katAuthority.publicKey,
          driftSubAccount: katDriftUserPDA,
          systemProgram: SystemProgram.programId,
        })
        .signers([katAuthority])
        .rpc();

      await driftStub.methods
        .updateUserDelegate(katPolicyPDA)
        .accounts({
          user: katDriftUserPDA,
          authority: katAuthority.publicKey,
        })
        .signers([katAuthority])
        .rpc();

      [katTicketPDA] = findTicketPDA(program.programId, katPolicyPDA, katTicketId);
    });

    it("KAT: commitment matches expected bytes and verifies on-chain in execute_ticket", async () => {
      const payload: HedgePayloadV1 = {
        marketIndex: 0,
        triggerDirection: TriggerDirection.Above,
        triggerPrice: BigInt(150_000_000),
        side: PositionDirection.Long,
        baseAmount: BigInt(1_000_000_000),
        reduceOnly: true,
        orderType: OrderType.Market,
        limitPrice: null,
        maxSlippageBps: 50,
        // Far future so test won't break due to wall-clock time.
        deadlineTs: BigInt(4_102_444_800),
        oracleProgram: oracleProgram.programId,
        oracle: oracleFeed.publicKey,
      };

      const revealData = serializePayload(payload);
      const commitment = createCommitment(
        katAuthority.publicKey,
        katPolicyPDA,
        katTicketId,
        katSecretSalt,
        revealData
      );
      expect(commitment.toString("hex")).to.equal(expectedCommitmentHex);

      const now = Math.floor(Date.now() / 1000);
      await program.methods
        .createTicket(
          Array.from(commitment) as any,
          Array.from(katTicketId) as any,
          new anchor.BN(now + 3600)
        )
        .accounts({
          ticket: katTicketPDA,
          policy: katPolicyPDA,
          owner: katAuthority.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([katAuthority])
        .rpc();

      // Fresh oracle + predicate satisfied.
      const slot = await provider.connection.getSlot();
      await oracleProgram.methods
        .setFeed(new anchor.BN(160_000_000), new anchor.BN(slot))
        .accounts({
          feed: oracleFeed.publicKey,
          authority: authority.publicKey,
        })
        .rpc();

      const tx = await program.methods
        .executeTicket(Array.from(katSecretSalt) as any, revealData)
        .accounts({
          ticket: katTicketPDA,
          policy: katPolicyPDA,
          keeper: katAuthority.publicKey,
          oracle: oracleFeed.publicKey,
          driftProgram: DRIFT_PROGRAM_ID,
          driftState: driftStatePDA,
          driftUser: katDriftUserPDA,
          driftUserStats: katDriftUserStatsPDA,
          driftSpotMarket: driftSpotMarketPDA,
          driftPerpMarket: driftPerpMarket0PDA,
        })
        .signers([katAuthority])
        .rpc();
      expect(tx).to.exist;

      const ticketAccount = await program.account.ticket.fetch(katTicketPDA);
      expect(ticketAccount.status).to.deep.equal({ executed: {} });
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

    it("executes a ticket end-to-end (commitment + predicate + Drift CPI) and consumes it", async () => {
      const slot = await provider.connection.getSlot();
      await oracleProgram.methods
        .setFeed(new anchor.BN(160_000_000), new anchor.BN(slot))
        .accounts({
          feed: oracleFeed.publicKey,
          authority: authority.publicKey,
        })
        .rpc();

      // Receipt: payload_hash must match client-side sha256(revealed_payload_bytes).
      // Use simulate() to avoid requiring RPC transaction history on local validator.
      const expectedPayloadHash = createHash("sha256").update(revealData).digest();
      const sim = await program.methods
        .executeTicket(Array.from(secretSalt) as any, revealData)
        .accounts({
          ticket: ticketPDA,
          policy: policyPDA,
          keeper: authority.publicKey,
          oracle: oracleFeed.publicKey,
          driftProgram: DRIFT_PROGRAM_ID,
          driftState: driftStatePDA,
          driftUser: driftUserPDA,
          driftUserStats: driftUserStatsPDA,
          driftSpotMarket: driftSpotMarketPDA,
          driftPerpMarket: driftPerpMarket0PDA,
        })
        .simulate();
      // Anchor JS camelCases event names (TicketExecuted -> ticketExecuted).
      const executedSim = sim.events?.find((e: any) => e.name === "ticketExecuted");
      expect(executedSim).to.exist;
      expect(Buffer.from(executedSim.data.payloadHash)).to.deep.equal(expectedPayloadHash);

      const tx = await program.methods
        .executeTicket(Array.from(secretSalt) as any, revealData)
        .accounts({
          ticket: ticketPDA,
          policy: policyPDA,
          keeper: authority.publicKey,
          oracle: oracleFeed.publicKey,
          driftProgram: DRIFT_PROGRAM_ID,
          driftState: driftStatePDA,
          driftUser: driftUserPDA,
          driftUserStats: driftUserStatsPDA,
          driftSpotMarket: driftSpotMarketPDA,
          driftPerpMarket: driftPerpMarket0PDA,
        })
        .rpc();
      expect(tx).to.exist;

      const ticketAccount = await program.account.ticket.fetch(ticketPDA);
      expect(ticketAccount.status).to.deep.equal({ executed: {} });
      expect(ticketAccount.executedSlot.toNumber()).to.be.greaterThan(0);

      const policyAccount = await program.account.policy.fetch(policyPDA);
      expect(policyAccount.executedCount.toNumber()).to.equal(1);
    });

    it("replay: repeated execute attempts fail and ticket remains Executed", async () => {
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
            driftProgram: DRIFT_PROGRAM_ID,
            driftState: driftStatePDA,
            driftUser: driftUserPDA,
            driftUserStats: driftUserStatsPDA,
            driftSpotMarket: driftSpotMarketPDA,
            driftPerpMarket: driftPerpMarket0PDA,
          })
          .rpc();
        expect.fail("Should have thrown – ticket already consumed");
      } catch (err: any) {
        expect(err.toString()).to.contain("TicketAlreadyConsumed");
      }

      const ticketAccount = await program.account.ticket.fetch(ticketPDA);
      expect(ticketAccount.status).to.deep.equal({ executed: {} });
      expect(ticketAccount.executedSlot.toNumber()).to.be.greaterThan(0);
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
            driftProgram: DRIFT_PROGRAM_ID,
            driftState: driftStatePDA,
            driftUser: driftUserPDA,
            driftUserStats: driftUserStatsPDA,
            driftSpotMarket: driftSpotMarketPDA,
            driftPerpMarket: driftPerpMarket0PDA,
          })
          .rpc();
        expect.fail("Should have thrown – commitment mismatch");
      } catch (err: any) {
        expect(err.toString()).to.contain("CommitmentMismatch");
      }
    });
  });

  // ── Drift CPI Firewall: boundary validations (MVP) ────────────

  describe("Drift CPI firewall (MVP)", () => {
    async function createExecutableTicket(payload: HedgePayloadV1) {
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

      // Make oracle fresh and predicate satisfied.
      const slot = await provider.connection.getSlot();
      await oracleProgram.methods
        .setFeed(new anchor.BN(160_000_000), new anchor.BN(slot))
        .accounts({
          feed: oracleFeed.publicKey,
          authority: authority.publicKey,
        })
        .rpc();

      return { ticketPDA, secretSalt, revealData };
    }

    it("rejects wrong Drift program id before CPI (InvalidDriftProgram)", async () => {
      const payload = defaultPayload();
      const { ticketPDA, secretSalt, revealData } = await createExecutableTicket(payload);

      try {
        await program.methods
          .executeTicket(Array.from(secretSalt) as any, revealData)
          .accounts({
            ticket: ticketPDA,
            policy: policyPDA,
            keeper: authority.publicKey,
            oracle: oracleFeed.publicKey,
            driftProgram: SystemProgram.programId, // wrong
            driftState: driftStatePDA,
            driftUser: driftUserPDA,
            driftUserStats: driftUserStatsPDA,
            driftSpotMarket: driftSpotMarketPDA,
            driftPerpMarket: driftPerpMarket0PDA,
          })
          .rpc();
        expect.fail("Should have thrown – invalid drift program");
      } catch (err: any) {
        expect(err.toString()).to.contain("InvalidDriftProgram");
      }

      const ticketAccount = await program.account.ticket.fetch(ticketPDA);
      expect(ticketAccount.status).to.deep.equal({ open: {} });
    });

    it("rejects wrong Drift user PDA before CPI (InvalidDriftUser)", async () => {
      const payload = defaultPayload();
      const { ticketPDA, secretSalt, revealData } = await createExecutableTicket(payload);

      const [wrongDriftUser] = findDriftUserPDA(authority.publicKey, 1);

      try {
        await program.methods
          .executeTicket(Array.from(secretSalt) as any, revealData)
          .accounts({
            ticket: ticketPDA,
            policy: policyPDA,
            keeper: authority.publicKey,
            oracle: oracleFeed.publicKey,
            driftProgram: DRIFT_PROGRAM_ID,
            driftState: driftStatePDA,
            driftUser: wrongDriftUser, // wrong
            driftUserStats: driftUserStatsPDA,
            driftSpotMarket: driftSpotMarketPDA,
            driftPerpMarket: driftPerpMarket0PDA,
          })
          .rpc();
        expect.fail("Should have thrown – invalid drift user");
      } catch (err: any) {
        expect(err.toString()).to.contain("InvalidDriftUser");
      }

      const ticketAccount = await program.account.ticket.fetch(ticketPDA);
      expect(ticketAccount.status).to.deep.equal({ open: {} });
    });

    it("rejects wrong perp market account before CPI (InvalidDriftPerpMarket)", async () => {
      const payload = defaultPayload(); // marketIndex=0
      const { ticketPDA, secretSalt, revealData } = await createExecutableTicket(payload);

      try {
        await program.methods
          .executeTicket(Array.from(secretSalt) as any, revealData)
          .accounts({
            ticket: ticketPDA,
            policy: policyPDA,
            keeper: authority.publicKey,
            oracle: oracleFeed.publicKey,
            driftProgram: DRIFT_PROGRAM_ID,
            driftState: driftStatePDA,
            driftUser: driftUserPDA,
            driftUserStats: driftUserStatsPDA,
            driftSpotMarket: driftSpotMarketPDA,
            driftPerpMarket: driftPerpMarket5PDA, // wrong market
          })
          .rpc();
        expect.fail("Should have thrown – invalid perp market");
      } catch (err: any) {
        expect(err.toString()).to.contain("InvalidDriftPerpMarket");
      }

      const ticketAccount = await program.account.ticket.fetch(ticketPDA);
      expect(ticketAccount.status).to.deep.equal({ open: {} });
    });

    it("rejects oracle mismatch vs perp market before CPI (InvalidOracleAccount)", async () => {
      // Create a second oracle feed and bind the payload to it, but keep the perp market bound to the original feed.
      const oracleFeedB = Keypair.generate();
      const slot = await provider.connection.getSlot();
      await oracleProgram.methods
        .initFeed(new anchor.BN(160_000_000), new anchor.BN(slot))
        .accounts({
          feed: oracleFeedB.publicKey,
          authority: authority.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([oracleFeedB])
        .rpc();

      const payload = defaultPayload();
      payload.oracle = oracleFeedB.publicKey;
      payload.oracleProgram = oracleProgram.programId;

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

      // Update feed B so predicate is satisfied.
      const slot2 = await provider.connection.getSlot();
      await oracleProgram.methods
        .setFeed(new anchor.BN(160_000_000), new anchor.BN(slot2))
        .accounts({
          feed: oracleFeedB.publicKey,
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
            oracle: oracleFeedB.publicKey, // matches payload
            driftProgram: DRIFT_PROGRAM_ID,
            driftState: driftStatePDA,
            driftUser: driftUserPDA,
            driftUserStats: driftUserStatsPDA,
            driftSpotMarket: driftSpotMarketPDA,
            driftPerpMarket: driftPerpMarket0PDA, // market oracle is still feed A
          })
          .rpc();
        expect.fail("Should have thrown – oracle mismatch");
      } catch (err: any) {
        expect(err.toString()).to.contain("InvalidOracleAccount");
      }

      const ticketAccount = await program.account.ticket.fetch(ticketPDA);
      expect(ticketAccount.status).to.deep.equal({ open: {} });
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

      // Account is closed (rent reclaimed) — verify it no longer exists
      const ticketInfo = await provider.connection.getAccountInfo(ticketPDA3);
      expect(ticketInfo).to.be.null;
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
      // Create a second policy under a different authority (policy B),
      // then attempt to execute a ticket from policy A under policy B.
      const impostor = Keypair.generate();
      const airdropSig = await provider.connection.requestAirdrop(
        impostor.publicKey,
        2_000_000_000
      );
      await provider.connection.confirmTransaction(airdropSig);

      const [driftUserB] = findDriftUserPDA(impostor.publicKey, DRIFT_SUB_ACCOUNT_ID);
      const [driftUserStatsB] = findDriftUserStatsPDA(impostor.publicKey);
      const [policyBPDA] = findPolicyPDA(
        program.programId,
        impostor.publicKey,
        driftUserB
      );

      // Initialize required Drift stub accounts for the impostor authority.
      await driftStub.methods
        .initUser(DRIFT_SUB_ACCOUNT_ID)
        .accounts({
          user: driftUserB,
          authority: impostor.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([impostor])
        .rpc();

      await driftStub.methods
        .initUserStats()
        .accounts({
          userStats: driftUserStatsB,
          authority: impostor.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([impostor])
        .rpc();

      await program.methods
        .initPolicy(
          [0, 1],
          new anchor.BN(1_000_000_000),
          100,
          new anchor.BN(60),
          new anchor.BN(3600),
          10,
          false,
          new anchor.BN(100)
        )
        .accounts({
          policy: policyBPDA,
          authority: impostor.publicKey,
          driftSubAccount: driftUserB,
          systemProgram: SystemProgram.programId,
        })
        .signers([impostor])
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
            driftProgram: DRIFT_PROGRAM_ID,
            driftState: driftStatePDA,
            driftUser: driftUserPDA,
            driftUserStats: driftUserStatsPDA,
            driftSpotMarket: driftSpotMarketPDA,
            driftPerpMarket: driftPerpMarket0PDA,
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
            driftProgram: DRIFT_PROGRAM_ID,
            driftState: driftStatePDA,
            driftUser: driftUserPDA,
            driftUserStats: driftUserStatsPDA,
            driftSpotMarket: driftSpotMarketPDA,
            driftPerpMarket: driftPerpMarket0PDA,
          })
          .rpc();
        expect.fail("Should have thrown – wrong salt");
      } catch (err: any) {
        expect(err.toString()).to.contain("CommitmentMismatch");
      }
    });

    it("atomicity: CPI failure does not consume the ticket", async () => {
      const slot = await provider.connection.getSlot();
      await oracleProgram.methods
        .setFeed(new anchor.BN(160_000_000), new anchor.BN(slot))
        .accounts({
          feed: oracleFeed.publicKey,
          authority: authority.publicKey,
        })
        .rpc();

      // Break delegate configuration so the Drift CPI fails inside the stub.
      await driftStub.methods
        .updateUserDelegate(ZERO_PUBKEY)
        .accounts({
          user: driftUserPDA,
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
            driftProgram: DRIFT_PROGRAM_ID,
            driftState: driftStatePDA,
            driftUser: driftUserPDA,
            driftUserStats: driftUserStatsPDA,
            driftSpotMarket: driftSpotMarketPDA,
            driftPerpMarket: driftPerpMarket0PDA,
          })
          .rpc();
        expect.fail("Should have thrown – Drift CPI unauthorized");
      } catch (err: any) {
        expect(err.toString()).to.contain("Unauthorized");
      }

      const ticketAccount = await program.account.ticket.fetch(commitTicketPDA);
      expect(ticketAccount.status).to.deep.equal({ open: {} });

      // Restore correct delegate so later tests can execute successfully.
      await driftStub.methods
        .updateUserDelegate(policyPDA)
        .accounts({
          user: driftUserPDA,
          authority: authority.publicKey,
        })
        .rpc();
    });
  });

  // ── Rate limit tests ─────────────────────────────────────────

  describe("Rate limiting (M1)", () => {
    const rlAuthority = Keypair.generate();

    let rlPolicyPDA: PublicKey;
    let rlDriftUserPDA: PublicKey;
    let rlDriftUserStatsPDA: PublicKey;

    before(async () => {
      const airdropSig = await provider.connection.requestAirdrop(
        rlAuthority.publicKey,
        5_000_000_000
      );
      await provider.connection.confirmTransaction(airdropSig);

      [rlDriftUserPDA] = findDriftUserPDA(rlAuthority.publicKey, DRIFT_SUB_ACCOUNT_ID);
      [rlDriftUserStatsPDA] = findDriftUserStatsPDA(rlAuthority.publicKey);

      await driftStub.methods
        .initUser(DRIFT_SUB_ACCOUNT_ID)
        .accounts({
          user: rlDriftUserPDA,
          authority: rlAuthority.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([rlAuthority])
        .rpc();

      await driftStub.methods
        .initUserStats()
        .accounts({
          userStats: rlDriftUserStatsPDA,
          authority: rlAuthority.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([rlAuthority])
        .rpc();

      [rlPolicyPDA] = findPolicyPDA(
        program.programId,
        rlAuthority.publicKey,
        rlDriftUserPDA
      );

      await program.methods
        .initPolicy(
          [0],
          new anchor.BN(1_000_000_000),
          100,
          new anchor.BN(10),
          new anchor.BN(60),
          1,
          false,
          new anchor.BN(100)
        )
        .accounts({
          policy: rlPolicyPDA,
          authority: rlAuthority.publicKey,
          driftSubAccount: rlDriftUserPDA,
          systemProgram: SystemProgram.programId,
        })
        .signers([rlAuthority])
        .rpc();

      // Configure Drift user delegate = Policy PDA so CatalystGuard can sign CPIs.
      await driftStub.methods
        .updateUserDelegate(rlPolicyPDA)
        .accounts({
          user: rlDriftUserPDA,
          authority: rlAuthority.publicKey,
        })
        .signers([rlAuthority])
        .rpc();
    });

    it("rejects execute_ticket when rate limit interval not elapsed (RateLimitExceeded)", async () => {
      // Ensure oracle is fresh and predicate is satisfied.
      const slot = await provider.connection.getSlot();
      await oracleProgram.methods
        .setFeed(new anchor.BN(160_000_000), new anchor.BN(slot))
        .accounts({
          feed: oracleFeed.publicKey,
          authority: authority.publicKey,
        })
        .rpc();

      const payload = defaultPayload();
      const revealData = serializePayload(payload);

      // Ticket 1: execute successfully.
      const ticketId1 = randomBytes(32);
      const salt1 = randomBytes(32);
      const commitment1 = createCommitment(
        rlAuthority.publicKey,
        rlPolicyPDA,
        ticketId1,
        salt1,
        revealData
      );
      const now = Math.floor(Date.now() / 1000);
      const [ticketPDA1] = findTicketPDA(program.programId, rlPolicyPDA, ticketId1);

      await program.methods
        .createTicket(
          Array.from(commitment1) as any,
          Array.from(ticketId1) as any,
          new anchor.BN(now + 3600)
        )
        .accounts({
          ticket: ticketPDA1,
          policy: rlPolicyPDA,
          owner: rlAuthority.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([rlAuthority])
        .rpc();

      await program.methods
        .executeTicket(Array.from(salt1) as any, revealData)
        .accounts({
          ticket: ticketPDA1,
          policy: rlPolicyPDA,
          keeper: rlAuthority.publicKey,
          oracle: oracleFeed.publicKey,
          driftProgram: DRIFT_PROGRAM_ID,
          driftState: driftStatePDA,
          driftUser: rlDriftUserPDA,
          driftUserStats: rlDriftUserStatsPDA,
          driftSpotMarket: driftSpotMarketPDA,
          driftPerpMarket: driftPerpMarket0PDA,
        })
        .signers([rlAuthority])
        .rpc();

      // Ticket 2: immediate execution should be rate-limited.
      const ticketId2 = randomBytes(32);
      const salt2 = randomBytes(32);
      const commitment2 = createCommitment(
        rlAuthority.publicKey,
        rlPolicyPDA,
        ticketId2,
        salt2,
        revealData
      );
      const [ticketPDA2] = findTicketPDA(program.programId, rlPolicyPDA, ticketId2);

      await program.methods
        .createTicket(
          Array.from(commitment2) as any,
          Array.from(ticketId2) as any,
          new anchor.BN(now + 3600)
        )
        .accounts({
          ticket: ticketPDA2,
          policy: rlPolicyPDA,
          owner: rlAuthority.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .signers([rlAuthority])
        .rpc();

      try {
        await program.methods
          .executeTicket(Array.from(salt2) as any, revealData)
          .accounts({
            ticket: ticketPDA2,
            policy: rlPolicyPDA,
            keeper: rlAuthority.publicKey,
            oracle: oracleFeed.publicKey,
            driftProgram: DRIFT_PROGRAM_ID,
            driftState: driftStatePDA,
            driftUser: rlDriftUserPDA,
            driftUserStats: rlDriftUserStatsPDA,
            driftSpotMarket: driftSpotMarketPDA,
            driftPerpMarket: driftPerpMarket0PDA,
          })
          .signers([rlAuthority])
          .rpc();
        expect.fail("Should have thrown – rate limited");
      } catch (err: any) {
        expect(err.toString()).to.contain("RateLimitExceeded");
      }

      const ticket2 = await program.account.ticket.fetch(ticketPDA2);
      expect(ticket2.status).to.deep.equal({ open: {} });
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

      const [driftPerpMarket] = findDriftPerpMarketPDA(payload.marketIndex);

      const tx = await program.methods
        .executeTicket(Array.from(secretSalt) as any, revealData)
        .accounts({
          ticket: ticketPDA,
          policy: policyPDA,
          keeper: authority.publicKey,
          oracle: oracleFeed.publicKey,
          driftProgram: DRIFT_PROGRAM_ID,
          driftState: driftStatePDA,
          driftUser: driftUserPDA,
          driftUserStats: driftUserStatsPDA,
          driftSpotMarket: driftSpotMarketPDA,
          driftPerpMarket,
        })
        .rpc();

      return { ticketPDA, tx };
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
            driftProgram: DRIFT_PROGRAM_ID,
            driftState: driftStatePDA,
            driftUser: driftUserPDA,
            driftUserStats: driftUserStatsPDA,
            driftSpotMarket: driftSpotMarketPDA,
            driftPerpMarket: driftPerpMarket0PDA,
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

      // Temporarily lower max_oracle_staleness_slots so the test works on a
      // fresh local validator where currentSlot is small (often < 100).
      await program.methods
        .updatePolicy(null, null, null, null, new anchor.BN(10))
        .accounts({ policy: policyPDA, authority: authority.publicKey })
        .rpc();

      const staleSlot = Math.max(0, currentSlot - 11); // policy.max_oracle_staleness_slots = 10

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
            driftProgram: DRIFT_PROGRAM_ID,
            driftState: driftStatePDA,
            driftUser: driftUserPDA,
            driftUserStats: driftUserStatsPDA,
            driftSpotMarket: driftSpotMarketPDA,
            driftPerpMarket: driftPerpMarket0PDA,
          })
          .rpc();
        expect.fail("Should have thrown – oracle stale");
      } catch (err: any) {
        expect(err.toString()).to.contain("OracleStale");
      }

      // Restore original staleness setting
      await program.methods
        .updatePolicy(null, null, null, null, new anchor.BN(100))
        .accounts({ policy: policyPDA, authority: authority.publicKey })
        .rpc();
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

    it("rejects Limit order with limit_price = 0 (InvalidRevealData)", async () => {
      const payload = defaultPayload();
      payload.orderType = OrderType.Limit;
      payload.limitPrice = BigInt(0);

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

      const { ticketPDA } = await createAndExecute(payload);
      const ticketAccount = await program.account.ticket.fetch(ticketPDA);
      expect(ticketAccount.status).to.deep.equal({ executed: {} });
    });

    it("accepts payload on allowed market index 5", async () => {
      const payload = defaultPayload();
      payload.marketIndex = 5;

      const { ticketPDA } = await createAndExecute(payload);
      const ticketAccount = await program.account.ticket.fetch(ticketPDA);
      expect(ticketAccount.status).to.deep.equal({ executed: {} });
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
            driftProgram: DRIFT_PROGRAM_ID,
            driftState: driftStatePDA,
            driftUser: driftUserPDA,
            driftUserStats: driftUserStatsPDA,
            driftSpotMarket: driftSpotMarketPDA,
            driftPerpMarket: driftPerpMarket0PDA,
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
        // Account is closed on first cancel, so second cancel fails with
        // an Anchor account deserialization/not-found error
        const errStr = err.toString();
        expect(
          errStr.includes("AccountNotInitialized") ||
          errStr.includes("Account does not exist") ||
          errStr.includes("TicketAlreadyConsumed") ||
          errStr.includes("3012") ||
          errStr.includes("Error processing Instruction")
        ).to.be.true;
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
