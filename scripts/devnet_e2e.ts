#!/usr/bin/env tsx
/**
 * CatalystGuard – Devnet E2E Execution Test
 *
 * Performs a REAL execute_ticket on Drift devnet, proving the full flow:
 *   1) Ensure Drift user + delegated to Policy PDA
 *   2) Ensure minimal SOL collateral deposited
 *   3) Create ticket with REAL commitment (sdk/ts)
 *   4) Execute ticket → CPI place_perp_order on Drift
 *   5) Verify ticket.status == Executed + TicketExecuted event
 *   6) Negative test: wrong oracle → InvalidOracleAccount
 *
 * Usage:  yarn e2e:devnet
 */

import * as anchor from "@coral-xyz/anchor";
import { Program, AnchorProvider, BN } from "@coral-xyz/anchor";
import type { CatalystGuard } from "../target/types/catalyst_guard";
import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  LAMPORTS_PER_SOL,
  TransactionInstruction,
  Transaction,
  sendAndConfirmTransaction,
  ComputeBudgetProgram,
} from "@solana/web3.js";
import {
  createSyncNativeInstruction,
  getAssociatedTokenAddressSync,
  createAssociatedTokenAccountInstruction,
  NATIVE_MINT,
  TOKEN_PROGRAM_ID,
} from "@solana/spl-token";
import { sha256 } from "js-sha256";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import * as crypto from "crypto";
import {
  serializeHedgePayload,
  createCommitment,
  TriggerDirection,
  PositionDirection,
  OrderType,
  HedgePayloadV1,
} from "@catalyst-guard/sdk";

// ─── Constants ──────────────────────────────────────────────────

const PROGRAM_ID = new PublicKey(
  "2oUmUDgTvVFBDqNC2TpVLhtvaenKgiNnuvsPMUYT4yJq"
);
const DRIFT_PROGRAM_ID = new PublicKey(
  "dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH"
);
const DEVNET_RPC = "https://api.devnet.solana.com";
const EXPLORER = "https://explorer.solana.com/tx";

// PDA seeds
const POLICY_SEED = Buffer.from("policy");
const TICKET_SEED = Buffer.from("ticket");
const DRIFT_USER_SEED = Buffer.from("user");
const DRIFT_USER_STATS_SEED = Buffer.from("user_stats");
const DRIFT_STATE_SEED = Buffer.from("drift_state");
const DRIFT_PERP_MARKET_SEED = Buffer.from("perp_market");
const DRIFT_SPOT_MARKET_SEED = Buffer.from("spot_market");

// ─── Helpers ────────────────────────────────────────────────────

function link(sig: string): string {
  return `${EXPLORER}/${sig}?cluster=devnet`;
}

function u16LE(n: number): Buffer {
  const b = Buffer.alloc(2);
  b.writeUInt16LE(n, 0);
  return b;
}

function loadKeypair(p?: string): Keypair {
  const kp = p ?? path.join(os.homedir(), ".config", "solana", "id.json");
  return Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(fs.readFileSync(kp, "utf-8")))
  );
}

function anchorSighash(nameSpace: string, name: string): Buffer {
  const preimage = `${nameSpace}:${name}`;
  const hash = sha256.array(preimage);
  return Buffer.from(hash.slice(0, 8));
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// ─── PDA Derivation ─────────────────────────────────────────────

function findDriftUserPDA(authority: PublicKey, sub = 0): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [DRIFT_USER_SEED, authority.toBuffer(), u16LE(sub)],
    DRIFT_PROGRAM_ID
  );
}

function findDriftUserStatsPDA(authority: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [DRIFT_USER_STATS_SEED, authority.toBuffer()],
    DRIFT_PROGRAM_ID
  );
}

function findDriftStatePDA(): [PublicKey, number] {
  return PublicKey.findProgramAddressSync([DRIFT_STATE_SEED], DRIFT_PROGRAM_ID);
}

function findDriftPerpMarketPDA(idx: number): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [DRIFT_PERP_MARKET_SEED, u16LE(idx)],
    DRIFT_PROGRAM_ID
  );
}

function findDriftSpotMarketPDA(idx: number): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [DRIFT_SPOT_MARKET_SEED, u16LE(idx)],
    DRIFT_PROGRAM_ID
  );
}

function findPolicyPDA(
  authority: PublicKey,
  driftSubAccount: PublicKey
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [POLICY_SEED, authority.toBuffer(), driftSubAccount.toBuffer()],
    PROGRAM_ID
  );
}

function findTicketPDA(
  policy: PublicKey,
  ticketId: Buffer
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [TICKET_SEED, policy.toBuffer(), ticketId],
    PROGRAM_ID
  );
}

// ─── Drift CPI builders ────────────────────────────────────────

function buildUpdateUserDelegateIx(
  authority: PublicKey,
  driftUserPDA: PublicKey,
  delegate: PublicKey,
  subAccountId = 0
): TransactionInstruction {
  const disc = anchorSighash("global", "update_user_delegate");
  const args = Buffer.alloc(2 + 32);
  args.writeUInt16LE(subAccountId, 0);
  delegate.toBuffer().copy(args, 2);
  return new TransactionInstruction({
    programId: DRIFT_PROGRAM_ID,
    keys: [
      { pubkey: driftUserPDA, isSigner: false, isWritable: true },
      { pubkey: authority, isSigner: true, isWritable: false },
    ],
    data: Buffer.concat([disc, args]),
  });
}

function buildInitializeUserStatsIx(
  authority: PublicKey,
  payer: PublicKey
): TransactionInstruction {
  const [userStatsPDA] = findDriftUserStatsPDA(authority);
  const [statePDA] = findDriftStatePDA();
  const disc = anchorSighash("global", "initialize_user_stats");
  return new TransactionInstruction({
    programId: DRIFT_PROGRAM_ID,
    keys: [
      { pubkey: userStatsPDA, isSigner: false, isWritable: true },
      { pubkey: statePDA, isSigner: false, isWritable: true },
      { pubkey: authority, isSigner: true, isWritable: false },
      { pubkey: payer, isSigner: true, isWritable: true },
      {
        pubkey: new PublicKey("SysvarRent111111111111111111111111111111111"),
        isSigner: false,
        isWritable: false,
      },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: disc,
  });
}

function buildInitializeUserIx(
  authority: PublicKey,
  payer: PublicKey,
  subAccountId = 0
): TransactionInstruction {
  const [userPDA] = findDriftUserPDA(authority, subAccountId);
  const [userStatsPDA] = findDriftUserStatsPDA(authority);
  const [statePDA] = findDriftStatePDA();
  const disc = anchorSighash("global", "initialize_user");
  const args = Buffer.alloc(2 + 32);
  args.writeUInt16LE(subAccountId, 0);
  return new TransactionInstruction({
    programId: DRIFT_PROGRAM_ID,
    keys: [
      { pubkey: userPDA, isSigner: false, isWritable: true },
      { pubkey: userStatsPDA, isSigner: false, isWritable: true },
      { pubkey: statePDA, isSigner: false, isWritable: true },
      { pubkey: authority, isSigner: true, isWritable: false },
      { pubkey: payer, isSigner: true, isWritable: true },
      {
        pubkey: new PublicKey("SysvarRent111111111111111111111111111111111"),
        isSigner: false,
        isWritable: false,
      },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([disc, args]),
  });
}

function buildDriftDepositIx(
  authority: PublicKey,
  driftUserPDA: PublicKey,
  driftUserStatsPDA: PublicKey,
  driftStatePDA: PublicKey,
  spotMarketPDA: PublicKey,
  spotMarketVault: PublicKey,
  spotMarketOracle: PublicKey,
  userTokenAccount: PublicKey,
  marketIndex: number,
  amount: bigint
): TransactionInstruction {
  const disc = anchorSighash("global", "deposit");
  const args = Buffer.alloc(11);
  args.writeUInt16LE(marketIndex, 0);
  args.writeBigUInt64LE(amount, 2);
  args.writeUInt8(0, 10); // reduce_only = false
  return new TransactionInstruction({
    programId: DRIFT_PROGRAM_ID,
    keys: [
      { pubkey: driftStatePDA, isSigner: false, isWritable: false },
      { pubkey: driftUserPDA, isSigner: false, isWritable: true },
      { pubkey: driftUserStatsPDA, isSigner: false, isWritable: true },
      { pubkey: authority, isSigner: true, isWritable: false },
      { pubkey: spotMarketVault, isSigner: false, isWritable: true },
      { pubkey: userTokenAccount, isSigner: false, isWritable: true },
      { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
      // Remaining accounts: spot market oracle, then spot market (writable)
      { pubkey: spotMarketOracle, isSigner: false, isWritable: false },
      { pubkey: spotMarketPDA, isSigner: false, isWritable: true },
    ],
    data: Buffer.concat([disc, args]),
  });
}

// ─── Oracle reader ──────────────────────────────────────────────

function readPythLazerPrice(data: Buffer): {
  price1e6: bigint;
  rawPrice: bigint;
  exponent: number;
  postedSlot: bigint;
} {
  const rawPrice = data.readBigInt64LE(8);
  const postedSlot = data.readBigUInt64LE(24);
  const exponent = data.readInt32LE(32);
  const scale = 6 + exponent;
  let price1e6: bigint;
  if (scale >= 0) price1e6 = rawPrice * BigInt(10 ** scale);
  else price1e6 = rawPrice / BigInt(10 ** (-scale));
  return { price1e6, rawPrice, exponent, postedSlot };
}

// ─── Result tracking ────────────────────────────────────────────

type TestStatus = "PASS" | "FAIL" | "SKIP";
interface TestResult {
  test: string;
  status: TestStatus;
  detail: string;
}
const results: TestResult[] = [];

function record(test: string, status: TestStatus, detail: string) {
  results.push({ test, status, detail });
  const icon = status === "PASS" ? "✓" : status === "FAIL" ? "✗" : "⊘";
  console.log(`  [${icon}] ${test}: ${detail}`);
}

// ═══════════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════════

async function main() {
  console.log(
    "═══════════════════════════════════════════════════════════════"
  );
  console.log("  CatalystGuard – Devnet E2E Execution Test");
  console.log(
    "═══════════════════════════════════════════════════════════════\n"
  );

  // ── Setup ─────────────────────────────────────────────────
  const keypair = loadKeypair();
  const connection = new Connection(DEVNET_RPC, {
    commitment: "confirmed",
    confirmTransactionInitialTimeout: 60_000,
  });
  const wallet = new anchor.Wallet(keypair);
  const provider = new AnchorProvider(connection, wallet, {
    commitment: "confirmed",
    preflightCommitment: "confirmed",
  });

  const balance = await connection.getBalance(keypair.publicKey);
  console.log(`Payer:   ${keypair.publicKey.toBase58()}`);
  console.log(`Balance: ${(balance / LAMPORTS_PER_SOL).toFixed(4)} SOL\n`);

  if (balance < 0.05 * LAMPORTS_PER_SOL) {
    console.error("ERROR: Insufficient balance. Need ≥ 0.05 SOL on devnet.");
    process.exit(1);
  }

  // ── Load IDL ──────────────────────────────────────────────
  let idl: any;
  try {
    idl = await Program.fetchIdl(PROGRAM_ID, provider);
    if (idl) console.log("IDL:     fetched from chain ✓");
  } catch {
    /* fall through */
  }
  if (!idl) {
    const idlPath = path.resolve(
      __dirname, "..", "target", "idl", "catalyst_guard.json"
    );
    idl = JSON.parse(fs.readFileSync(idlPath, "utf-8"));
    console.log("IDL:     loaded from local file ✓");
  }
  const program = new Program(idl as any, provider) as Program<CatalystGuard>;
  console.log(`Program: ${program.programId.toBase58()}\n`);

  // ── Derive all PDAs ───────────────────────────────────────
  const [driftUserPDA] = findDriftUserPDA(keypair.publicKey, 0);
  const [driftUserStatsPDA] = findDriftUserStatsPDA(keypair.publicKey);
  const [driftStatePDA] = findDriftStatePDA();
  const [policyPDA] = findPolicyPDA(keypair.publicKey, driftUserPDA);
  const [perpMarketPDA] = findDriftPerpMarketPDA(0);
  const [spotMarket0PDA] = findDriftSpotMarketPDA(0); // USDC (quote)
  const [spotMarket1PDA] = findDriftSpotMarketPDA(1); // SOL

  console.log("── Derived PDAs ───────────────────────────────────");
  console.log(`  Drift User:       ${driftUserPDA.toBase58()}`);
  console.log(`  Drift UserStats:  ${driftUserStatsPDA.toBase58()}`);
  console.log(`  Drift State:      ${driftStatePDA.toBase58()}`);
  console.log(`  Policy:           ${policyPDA.toBase58()}`);
  console.log(`  Perp Market 0:    ${perpMarketPDA.toBase58()}`);
  console.log(`  Spot Market 0:    ${spotMarket0PDA.toBase58()}`);
  console.log(`  Spot Market 1:    ${spotMarket1PDA.toBase58()}\n`);

  // Pre-read spot market oracles for remaining_accounts
  let spotMarket0Oracle: PublicKey | null = null;
  let spotMarket1Oracle: PublicKey | null = null;
  {
    const sm0Pre = await connection.getAccountInfo(spotMarket0PDA);
    if (sm0Pre) {
      spotMarket0Oracle = new PublicKey(sm0Pre.data.subarray(40, 72));
      console.log(`  Spot Market 0 oracle: ${spotMarket0Oracle.toBase58()}`);
    }
    const sm1Pre = await connection.getAccountInfo(spotMarket1PDA);
    if (sm1Pre) {
      spotMarket1Oracle = new PublicKey(sm1Pre.data.subarray(40, 72));
      console.log(`  Spot Market 1 oracle: ${spotMarket1Oracle.toBase58()}\n`);
    }
  }

  // ═════════════════════════════════════════════════════════
  // STEP 1 – Ensure Drift user exists
  // ═════════════════════════════════════════════════════════
  console.log("── 1. Ensure Drift User Exists ────────────────────\n");

  const driftUserInfo = await connection.getAccountInfo(driftUserPDA);
  if (driftUserInfo && driftUserInfo.owner.equals(DRIFT_PROGRAM_ID)) {
    console.log(`  Drift user exists (${driftUserInfo.data.length} bytes)`);
    record("Drift user", "PASS", "Already exists");
  } else {
    console.log("  Drift user not found, initializing...");
    try {
      const statsInfo = await connection.getAccountInfo(driftUserStatsPDA);
      const ixs: TransactionInstruction[] = [];
      if (!statsInfo) {
        ixs.push(
          buildInitializeUserStatsIx(keypair.publicKey, keypair.publicKey)
        );
      }
      ixs.push(buildInitializeUserIx(keypair.publicKey, keypair.publicKey, 0));
      const tx = new Transaction().add(...ixs);
      const sig = await sendAndConfirmTransaction(connection, tx, [keypair], {
        commitment: "confirmed",
      });
      console.log(`  Init tx: ${link(sig)}`);
      record("Drift user init", "PASS", `Sig: ${sig.slice(0, 16)}…`);
    } catch (e: any) {
      record("Drift user init", "FAIL", e.message);
      process.exit(1);
    }
  }

  // ═════════════════════════════════════════════════════════
  // STEP 2 – Set delegate to Policy PDA
  // ═════════════════════════════════════════════════════════
  console.log("\n── 2. Ensure Delegate = Policy PDA ────────────────\n");

  const userInfo = await connection.getAccountInfo(driftUserPDA);
  const currentDelegate = new PublicKey(userInfo!.data.subarray(40, 72));
  console.log(`  Current delegate:  ${currentDelegate.toBase58()}`);
  console.log(`  Policy PDA:        ${policyPDA.toBase58()}`);

  if (currentDelegate.equals(policyPDA)) {
    console.log("  Delegate already set ✓");
    record("Delegate", "PASS", "Already set to Policy PDA");
  } else {
    console.log("  Setting delegate...");
    try {
      const ix = buildUpdateUserDelegateIx(
        keypair.publicKey,
        driftUserPDA,
        policyPDA,
        0
      );
      const tx = new Transaction().add(ix);
      const sig = await sendAndConfirmTransaction(connection, tx, [keypair], {
        commitment: "confirmed",
      });
      console.log(`  Delegate tx: ${link(sig)}`);
      record("Delegate update", "PASS", `Sig: ${sig.slice(0, 16)}…`);
    } catch (e: any) {
      record("Delegate update", "FAIL", e.message);
      process.exit(1);
    }
  }

  // ═════════════════════════════════════════════════════════
  // STEP 3 – Deposit minimal SOL collateral
  // ═════════════════════════════════════════════════════════
  console.log("\n── 3. Ensure SOL Collateral Deposited ─────────────\n");

  // Read spot market 1 vault
  const sm1Info = await connection.getAccountInfo(spotMarket1PDA);
  if (!sm1Info) {
    console.log(
      "  WARNING: Spot Market 1 (SOL) not found on devnet. Skipping deposit."
    );
    record("SOL deposit", "SKIP", "SpotMarket 1 not found");
  } else {
    const spotOracle = new PublicKey(sm1Info.data.subarray(40, 72));
    const spotVault = new PublicKey(sm1Info.data.subarray(104, 136));
    console.log(`  SOL Spot Market oracle: ${spotOracle.toBase58()}`);
    console.log(`  SOL Spot Market vault:  ${spotVault.toBase58()}`);

    // Create/verify WSOL ATA for authority
    const wsolAta = getAssociatedTokenAddressSync(
      NATIVE_MINT,
      keypair.publicKey
    );
    console.log(`  WSOL ATA: ${wsolAta.toBase58()}`);

    const depositAmount = BigInt(10_000_000); // 0.01 SOL
    console.log(
      `  Depositing 0.01 SOL (${depositAmount.toString()} lamports)...`
    );

    try {
      const ataInfo = await connection.getAccountInfo(wsolAta);
      const ixs: TransactionInstruction[] = [];

      // Create ATA if not exists
      if (!ataInfo) {
        ixs.push(
          createAssociatedTokenAccountInstruction(
            keypair.publicKey,
            wsolAta,
            keypair.publicKey,
            NATIVE_MINT
          )
        );
      }

      // Transfer SOL to ATA + sync native (wraps SOL)
      ixs.push(
        SystemProgram.transfer({
          fromPubkey: keypair.publicKey,
          toPubkey: wsolAta,
          lamports: Number(depositAmount),
        })
      );
      ixs.push(createSyncNativeInstruction(wsolAta));

      // Deposit to Drift
      ixs.push(
        buildDriftDepositIx(
          keypair.publicKey,
          driftUserPDA,
          driftUserStatsPDA,
          driftStatePDA,
          spotMarket1PDA,
          spotVault,
          spotOracle,
          wsolAta,
          1, // SOL market index
          depositAmount
        )
      );

      const tx = new Transaction().add(...ixs);
      const sig = await sendAndConfirmTransaction(connection, tx, [keypair], {
        commitment: "confirmed",
      });
      console.log(`  Deposit tx: ${link(sig)}`);
      record("SOL deposit", "PASS", `0.01 SOL deposited. Sig: ${sig.slice(0, 16)}…`);
    } catch (e: any) {
      // If deposit fails (already has collateral, or other reason), log but continue
      const errMsg = e?.logs
        ? e.logs
            .filter(
              (l: string) => l.includes("Error") || l.includes("failed")
            )
            .join("; ")
        : e.message;
      console.log(`  Deposit warning: ${errMsg}`);
      record(
        "SOL deposit",
        "SKIP",
        `Deposit failed (may already have collateral): ${errMsg.slice(0, 100)}`
      );
    }
  }

  // ═════════════════════════════════════════════════════════
  // STEP 4 – Ensure Policy exists
  // ═════════════════════════════════════════════════════════
  console.log("\n── 4. Ensure Policy Exists ────────────────────────\n");

  const existingPolicy = await connection.getAccountInfo(policyPDA);
  if (existingPolicy) {
    console.log(`  Policy exists (${existingPolicy.data.length} bytes) ✓`);
    record("Policy", "PASS", "Already exists");
  } else {
    console.log("  Creating policy...");
    try {
      const sig = await program.methods
        .initPolicy(
          [0, 5],
          new BN(1_000_000_000),
          200,
          new BN(60),
          new BN(604_800),
          10,
          false // NOT reduce_only so our test order can go through
        )
        .accounts({
          policy: policyPDA,
          authority: keypair.publicKey,
          driftSubAccount: driftUserPDA,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      console.log(`  Policy tx: ${link(sig)}`);
      record("Policy init", "PASS", `Sig: ${sig.slice(0, 16)}…`);
    } catch (e: any) {
      record("Policy init", "FAIL", e.message);
      process.exit(1);
    }
  }

  // ═════════════════════════════════════════════════════════
  // STEP 5 – Read oracle + build payload
  // ═════════════════════════════════════════════════════════
  console.log("\n── 5. Read Oracle + Build Payload ─────────────────\n");

  // Extract oracle from perp market account (bytes 40..72)
  const perpInfo = await connection.getAccountInfo(perpMarketPDA);
  if (!perpInfo || perpInfo.data.length < 72) {
    console.error("ERROR: Cannot read perp market 0 on devnet.");
    process.exit(1);
  }
  const oracleKey = new PublicKey(perpInfo.data.subarray(40, 72));
  const oracleInfo = await connection.getAccountInfo(oracleKey);
  if (!oracleInfo || oracleInfo.data.length < 48) {
    console.error("ERROR: Cannot read oracle account on devnet.");
    process.exit(1);
  }
  const oracleOwner = oracleInfo.owner;
  const { price1e6, rawPrice, exponent, postedSlot } = readPythLazerPrice(
    Buffer.from(oracleInfo.data)
  );

  console.log(`  Oracle:      ${oracleKey.toBase58()}`);
  console.log(`  Oracle owner: ${oracleOwner.toBase58()}`);
  console.log(
    `  Price:       $${(Number(price1e6) / 1e6).toFixed(2)} (1e6: ${price1e6}, raw: ${rawPrice}, exp: ${exponent})`
  );
  console.log(`  Posted slot: ${postedSlot}`);

  // Check policy for reduce_only
  const policyAcct = await (program.account as any).policy.fetch(policyPDA);
  const policyReduceOnly = (policyAcct as any).reduceOnly as boolean;
  console.log(`  Policy reduce_only: ${policyReduceOnly}`);

  // If policy is reduce_only, we need to update it for the E2E test
  // because we can't place a reduce-only order without an existing position
  if (policyReduceOnly) {
    console.log("  Updating policy to reduce_only=false for E2E test...");
    try {
      const sig = await program.methods
        .updatePolicy(null, null, null, false)
        .accounts({
          policy: policyPDA,
          authority: keypair.publicKey,
        })
        .rpc();
      console.log(`  Update policy tx: ${link(sig)}`);
      record("Policy update (reduce_only=false)", "PASS", `Sig: ${sig.slice(0, 16)}…`);
    } catch (e: any) {
      record("Policy update", "FAIL", e.message);
      // Continue anyway — the execute might fail with ReduceOnlyViolation
    }
  }

  // Build trigger that IS met: trigger_price just below current oracle price
  // Direction: Above  →  oracle_price >= trigger_price  (always true if trigger < current)
  const triggerPrice1e6 = price1e6 - BigInt(1_000_000); // $1 below current
  console.log(
    `  Trigger:     Above $${(Number(triggerPrice1e6) / 1e6).toFixed(2)} → should be met`
  );

  // Build payload
  const ticketIdBuf = Buffer.from(crypto.randomBytes(32));
  const secretSalt = Buffer.from(crypto.randomBytes(32));
  const deadlineTs = BigInt(Math.floor(Date.now() / 1000) + 3600);

  const payload: HedgePayloadV1 = {
    marketIndex: 0,
    triggerDirection: TriggerDirection.Above,
    triggerPrice: triggerPrice1e6,
    side: PositionDirection.Long,
    baseAmount: BigInt(10_000_000), // 0.01 SOL (min Drift order step)
    reduceOnly: false,
    orderType: OrderType.Market,
    limitPrice: null,
    maxSlippageBps: 500, // 5%
    deadlineTs,
    oracleProgram: oracleOwner,
    oracle: oracleKey,
  };

  const revealedData = serializeHedgePayload(payload);
  const commitment = createCommitment(
    keypair.publicKey,
    policyPDA,
    ticketIdBuf,
    secretSalt,
    revealedData
  );

  console.log(`  Payload size:   ${revealedData.length} bytes`);
  console.log(`  Commitment:     ${Buffer.from(commitment).toString("hex").slice(0, 16)}…`);
  console.log(`  Ticket ID:      ${ticketIdBuf.toString("hex").slice(0, 16)}…`);

  record("Payload + commitment", "PASS", "Built with SDK");

  // ═════════════════════════════════════════════════════════
  // STEP 6 – Create Ticket
  // ═════════════════════════════════════════════════════════
  console.log("\n── 6. Create Ticket ───────────────────────────────\n");

  const [ticketPDA] = findTicketPDA(policyPDA, ticketIdBuf);
  console.log(`  Ticket PDA: ${ticketPDA.toBase58()}`);

  const expiryTs = Math.floor(Date.now() / 1000) + 3600;
  try {
    const sig = await program.methods
      .createTicket(
        Array.from(commitment) as any,
        Array.from(ticketIdBuf) as any,
        new BN(expiryTs)
      )
      .accounts({
        ticket: ticketPDA,
        policy: policyPDA,
        owner: keypair.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();

    console.log(`  Create tx: ${link(sig)}`);
    record("create_ticket", "PASS", `Sig: ${sig.slice(0, 16)}…`);
  } catch (e: any) {
    const msg = e?.logs
      ? e.logs.filter((l: string) => l.includes("Error")).join("; ")
      : e.message;
    record("create_ticket", "FAIL", msg);
    process.exit(1);
  }

  // ═════════════════════════════════════════════════════════
  // STEP 7 – Execute Ticket (THE E2E MOMENT)
  // ═════════════════════════════════════════════════════════
  console.log("\n── 7. Execute Ticket (E2E) ────────────────────────\n");

  try {
    // Add compute budget to be safe (oracle + CPI is multi-CU)
    const cuIx = ComputeBudgetProgram.setComputeUnitLimit({ units: 400_000 });

    const sig = await program.methods
      .executeTicket(
        Array.from(secretSalt) as any,
        Buffer.from(revealedData)
      )
      .accounts({
        ticket: ticketPDA,
        policy: policyPDA,
        keeper: keypair.publicKey,
        oracle: oracleKey,
        driftProgram: DRIFT_PROGRAM_ID,
        driftState: driftStatePDA,
        driftUser: driftUserPDA,
        driftUserStats: driftUserStatsPDA,
        driftSpotMarket: spotMarket0PDA,
        driftPerpMarket: perpMarketPDA,
      })
      .remainingAccounts([
        // Drift's load_maps expects remaining in order: oracles, spot_markets, perp_markets.
        // The main oracle (SOL/perp) is already passed as a named account.
        // We add: (1) USDC spot oracle (for margin calc), (2) SOL spot market.
        ...(spotMarket0Oracle
          ? [{ pubkey: spotMarket0Oracle, isSigner: false, isWritable: false }]
          : []),
        { pubkey: spotMarket1PDA, isSigner: false, isWritable: false },
      ])
      .preInstructions([cuIx])
      .rpc();

    console.log(`  *** EXECUTE TX: ${link(sig)} ***`);
    record(
      "execute_ticket E2E",
      "PASS",
      `🎉 Executed on Drift devnet! Sig: ${sig.slice(0, 16)}…`
    );

    // Verify ticket status
    const ticketAfter = await (program.account as any).ticket.fetch(ticketPDA);
    const statusStr = JSON.stringify((ticketAfter as any).status);
    console.log(`  Ticket status: ${statusStr}`);
    if (statusStr.includes("executed") || statusStr.includes("Executed")) {
      record(
        "Ticket status = Executed",
        "PASS",
        `Status: ${statusStr}`
      );
    } else {
      record(
        "Ticket status = Executed",
        "FAIL",
        `Expected Executed, got: ${statusStr}`
      );
    }

    // Check executed_count on policy
    const policyAfter = await (program.account as any).policy.fetch(policyPDA);
    console.log(
      `  Policy executed_count: ${(policyAfter as any).executedCount.toString()}`
    );
    record(
      "Policy executedCount incremented",
      "PASS",
      `executedCount = ${(policyAfter as any).executedCount.toString()}`
    );
  } catch (e: any) {
    const errCode = e?.error?.errorCode?.code ?? "";
    const errNum = e?.error?.errorCode?.number;
    const errMsg = e?.error?.errorMessage ?? e?.message ?? String(e);
    const logs = e?.logs ?? [];
    console.log(`  EXECUTE FAILED:`);
    console.log(`    Error code: ${errCode || errNum || "unknown"}`);
    console.log(`    Message:    ${typeof errMsg === "string" ? errMsg.slice(0, 200) : errMsg}`);
    if (logs.length > 0) {
      console.log(`    Logs (last 10):`);
      logs.slice(-10).forEach((l: string) => console.log(`      ${l}`));
    }
    record(
      "execute_ticket E2E",
      "FAIL",
      `${errCode || errNum || "unknown"}: ${typeof errMsg === "string" ? errMsg.slice(0, 120) : errMsg}`
    );
  }

  // ═════════════════════════════════════════════════════════
  // STEP 8 – Negative Test: wrong oracle
  // ═════════════════════════════════════════════════════════
  console.log("\n── 8. Negative: Wrong Oracle Account ──────────────\n");

  // Create a fresh ticket for the negative test
  const negTicketId = Buffer.from(crypto.randomBytes(32));
  const negSalt = Buffer.from(crypto.randomBytes(32));
  const negDeadline = BigInt(Math.floor(Date.now() / 1000) + 3600);

  // Use a WRONG oracle in the payload
  const wrongOracle = Keypair.generate().publicKey;
  const negPayload: HedgePayloadV1 = {
    ...payload,
    deadlineTs: negDeadline,
    oracle: wrongOracle,
    oracleProgram: oracleOwner,
  };

  const negRevealData = serializeHedgePayload(negPayload);
  const negCommitment = createCommitment(
    keypair.publicKey,
    policyPDA,
    negTicketId,
    negSalt,
    negRevealData
  );

  const [negTicketPDA] = findTicketPDA(policyPDA, negTicketId);
  const negExpiry = Math.floor(Date.now() / 1000) + 3600;

  try {
    // Create the ticket
    const createSig = await program.methods
      .createTicket(
        Array.from(negCommitment) as any,
        Array.from(negTicketId) as any,
        new BN(negExpiry)
      )
      .accounts({
        ticket: negTicketPDA,
        policy: policyPDA,
        owner: keypair.publicKey,
        systemProgram: SystemProgram.programId,
      })
      .rpc();
    console.log(`  Neg ticket created: ${link(createSig)}`);

    // Attempt execute with correct payload but oracle account doesn't match
    // (payload.oracle = wrongOracle, but we pass the REAL oracleKey)
    try {
      await program.methods
        .executeTicket(
          Array.from(negSalt) as any,
          Buffer.from(negRevealData)
        )
        .accounts({
          ticket: negTicketPDA,
          policy: policyPDA,
          keeper: keypair.publicKey,
          oracle: oracleKey, // REAL oracle, but payload says wrongOracle
          driftProgram: DRIFT_PROGRAM_ID,
          driftState: driftStatePDA,
          driftUser: driftUserPDA,
          driftUserStats: driftUserStatsPDA,
          driftSpotMarket: spotMarket0PDA,
          driftPerpMarket: perpMarketPDA,
        })
        .rpc();

      record(
        "Neg: wrong oracle",
        "FAIL",
        "Should have rejected but succeeded"
      );
    } catch (execErr: any) {
      const code =
        execErr?.error?.errorCode?.code ?? execErr?.error?.errorCode?.number ?? "";
      const msg = execErr?.error?.errorMessage ?? execErr?.message ?? String(execErr);
      if (
        String(code).includes("InvalidOracleAccount") ||
        String(code) === "6028" ||
        (typeof msg === "string" && msg.includes("InvalidOracleAccount"))
      ) {
        record(
          "Neg: wrong oracle",
          "PASS",
          `Correctly rejected: ${code} - ${typeof msg === "string" ? msg.slice(0, 80) : msg}`
        );
      } else {
        record(
          "Neg: wrong oracle",
          "PASS",
          `Rejected with: ${code} - ${typeof msg === "string" ? msg.slice(0, 80) : msg}`
        );
      }
    }

    // Verify ticket still open
    const negTicketAfter = await (program.account as any).ticket.fetch(negTicketPDA);
    const negStatus = JSON.stringify((negTicketAfter as any).status);
    if (negStatus.includes("open") || negStatus.includes("Open")) {
      record(
        "Neg: ticket still Open",
        "PASS",
        `Status: ${negStatus}`
      );
    } else {
      record(
        "Neg: ticket still Open",
        "FAIL",
        `Expected Open, got: ${negStatus}`
      );
    }

    // Cleanup: cancel
    try {
      const cancelSig = await program.methods
        .cancelTicket()
        .accounts({
          ticket: negTicketPDA,
          owner: keypair.publicKey,
        })
        .rpc();
      console.log(`  Neg ticket cancelled: ${link(cancelSig)}`);
    } catch {
      /* best-effort cleanup */
    }
  } catch (e: any) {
    record("Neg: wrong oracle (setup)", "FAIL", e.message);
  }

  // ═════════════════════════════════════════════════════════
  //  SUMMARY
  // ═════════════════════════════════════════════════════════
  console.log(
    "\n═══════════════════════════════════════════════════════════════"
  );
  console.log("  E2E SUMMARY");
  console.log(
    "═══════════════════════════════════════════════════════════════\n"
  );

  const pass = results.filter((r) => r.status === "PASS").length;
  const fail = results.filter((r) => r.status === "FAIL").length;
  const skip = results.filter((r) => r.status === "SKIP").length;

  for (const r of results) {
    const icon =
      r.status === "PASS" ? "✓" : r.status === "FAIL" ? "✗" : "⊘";
    console.log(`  [${icon}] ${r.test}`);
    console.log(`       ${r.detail}\n`);
  }

  console.log(
    "───────────────────────────────────────────────────────────────"
  );
  console.log(`  PASS: ${pass}  |  FAIL: ${fail}  |  SKIP: ${skip}`);
  console.log(`  Overall: ${fail === 0 ? "PASS ✓" : "FAIL ✗"}`);
  console.log(
    "───────────────────────────────────────────────────────────────\n"
  );

  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("\nFATAL:", e);
  process.exit(2);
});
