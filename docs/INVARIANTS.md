# On-Chain Invariants – Catalyst Shield v0.2

> These invariants MUST be enforced in the Anchor program and verified by tests.

## P1: No Plaintext Triggers On-Chain

**Statement:** Ticket accounts store NO plaintext trigger/order fields. They store only:
- `commitment` (32 bytes) — SHA-256 hash of `(trigger_params || nonce || owner)`
- `nonce` (32 bytes) — random nonce used in commitment
- `expiry` (i64) — unix timestamp after which ticket is invalid
- `policy` (Pubkey) — pointer to a Policy account
- `owner` (Pubkey) — the authority who created the ticket
- `consumed` (bool) — whether the ticket has been executed
- `created_at` (i64) — creation timestamp
- `bump` (u8) — PDA bump

**Rationale:** Before execution, no on-chain account reveals what price triggers the order, what direction, what size, or what market. Keepers and MEV searchers cannot extract actionable trading signals from ticket accounts alone.

**Test requirements:**
- Unit test: verify ticket account contains only above fields
- Negative test: attempt to deserialize trigger params from a ticket → must fail
- Fuzz: random commitment values produce valid tickets

---

## P2: Atomic Reveal + Execute

**Statement:** Reveal occurs ONLY inside `execute_ticket` and is coupled to CPI execution. There is no standalone "reveal" instruction.

**Mechanism:**
1. Executor calls `execute_ticket` with revealed params + commitment proof
2. Program verifies `SHA-256(trigger_params || nonce || owner) == ticket.commitment`
3. Program evaluates predicate (oracle price cross)  
4. If predicate passes, program executes CPI to Drift
5. Ticket is marked `consumed = true`

**Rationale:** Separating reveal from execution would allow MEV searchers to observe revealed params and front-run the actual execution. By coupling them atomically, the reveal and execution happen in the same transaction.

**Test requirements:**
- Unit test: execute_ticket verifies commitment, evaluates predicate, marks consumed
- Negative test: no instruction exists to reveal without executing
- Negative test: revealed params that don't match commitment → reject

---

## P3: Replay Protection

**Statement:** Replay is impossible via nonce + consumed state machine. Repeats are rejected.

**Mechanism:**
- Each ticket has a unique PDA derived from `[b"ticket", owner, nonce]`
- The `consumed` flag transitions: `false → true` (one-way, irreversible)
- Attempting to call `execute_ticket` on a consumed ticket → error
- PDA derivation ensures uniqueness (same owner + nonce = same address = already consumed)

**State machine:**
```
  Created (consumed=false)
      │
      ├──→ Executed (consumed=true)     [execute_ticket]
      │
      ├──→ Cancelled (account closed)   [cancel_ticket, owner-only]
      │
      └──→ Expired (account closed)     [expire_ticket, permissionless after expiry]
```

**Test requirements:**
- Unit test: execute → consumed=true
- Negative test: execute consumed ticket → error
- Negative test: execute with same nonce → PDA collision (already exists or consumed)
- Unit test: cancel only by owner
- Unit test: expire only after expiry timestamp

---

## P4: CPI Safety / Allowlist

**Statement:** CPI targets are hard-allowlisted. No user-supplied `program_id` for CPI. No arbitrary instruction forwarding. Strict account validation.

**Enforced rules:**

### 4a. Fixed Program ID
```rust
pub const DRIFT_PROGRAM_ID: Pubkey = pubkey!("dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH");
```
The Drift program ID is a compile-time constant. CPI invocations MUST target this exact address. No instruction accepts a program ID as an argument.

### 4b. Fixed Instruction Set
Only the following Drift CPI paths are allowed in MVP:
- `place_perp_order` — place a single perp order
- `cancel_order` — cancel a specific order
- No `withdraw`, `borrow`, `transfer_deposit`, `delete_user`, `update_user_delegate`

### 4c. Strict Account Constraints
Every CPI account is validated via Anchor's account constraints:
- `state` must be the Drift State PDA
- `user` must be derived from the expected authority + sub_account_id
- `user_stats` must be derived from the expected authority
- Oracle accounts must match the market's registered oracle
- No `remaining_accounts` passthrough to CPI

### 4d. No Arbitrary Remaining Accounts Abuse
The program does NOT pass user-supplied remaining accounts to CPI calls. All CPI account metas are constructed explicitly in the program.

### 4e. No Instruction Sysvar Introspection
MVP does NOT use the instruction sysvar (`Sysvar<Instructions>`) to inspect surrounding instructions. This avoids the footgun of trusting instruction ordering.

**Test requirements:**
- Negative test: CPI with wrong program ID → rejected
- Negative test: attempt to call a disallowed Drift instruction → no path exists
- Negative test: pass extra remaining accounts → ignored/rejected
- Unit test: verify all CPI account metas are deterministic (not user-supplied)

---

## CPI Privilege Escalation Threat Model

### Attack: User supplies a fake Drift program
**Mitigation:** Drift program ID is a `const`. No instruction accepts it as input.

### Attack: Executor injects extra accounts to redirect CPI
**Mitigation:** CPI account lists are constructed in the program. `remaining_accounts` are not forwarded.

### Attack: Executor replays an old ticket
**Mitigation:** `consumed` flag + PDA uniqueness.

### Attack: Executor reveals params but doesn't execute (to leak signal)
**Mitigation:** Reveal is coupled to execution. No standalone reveal instruction exists.

### Attack: Instruction sysvar introspection bypass
**Mitigation:** We don't use instruction sysvar introspection in MVP. No dependency to exploit.

### Attack: Ticket owner changes between create and execute
**Mitigation:** `owner` is part of the commitment hash. Changing owner invalidates the commitment.
