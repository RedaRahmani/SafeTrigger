# On-Chain Invariants – Catalyst Shield v0.2

> These invariants MUST be enforced in the Anchor program and verified by tests.
> Last updated: 2026-02-09 (post-audit hardening M0.1).

## P1: No Plaintext Triggers On-Chain

**Statement:** Ticket accounts store NO plaintext trigger/order fields. They store only:
- `commitment` (32 bytes) — domain-separated SHA-256 hash (see P2 for preimage)
- `ticket_id` (32 bytes) — public identifier used for PDA derivation (NOT a secret)
- `expiry` (i64) — unix timestamp after which ticket is invalid
- `policy` (Pubkey) — pointer to a Policy account
- `owner` (Pubkey) — the authority who created the ticket
- `status` (enum) — `Open | Executed | Cancelled | Expired`
- `bump` (u8) — PDA bump
- `created_slot` (u64) — slot at creation
- `created_at` (i64) — creation timestamp
- `updated_at` (i64) — last status change timestamp
- `executed_slot` (u64) — slot at execution (0 if not executed)

**Rationale:** Before execution, no on-chain account reveals what price triggers the order, what direction, what size, or what market. Keepers and MEV searchers cannot extract actionable trading signals from ticket accounts alone.

**Important:** The secret salt is NEVER stored on-chain. It is provided only at `execute_ticket` time.

**Test requirements:**
- Unit test: verify ticket account contains only above fields
- Negative test: attempt to deserialize trigger params from a ticket → must fail

---

## P2: Atomic Reveal + Execute (with Domain-Separated Commitment)

**Statement:** Reveal occurs ONLY inside `execute_ticket` and is coupled to CPI execution. There is no standalone "reveal" instruction.

**Commitment preimage (v0.2):**
```
commitment = SHA-256(b"CSv0.2" || owner || policy || ticket_id || secret_salt || revealed_payload)
```

Where:
- `b"CSv0.2"` — domain separator (prevents cross-protocol hash collisions)
- `owner` (32 bytes) — ticket owner pubkey (binds commitment to owner)
- `policy` (32 bytes) — policy pubkey (binds commitment to policy)
- `ticket_id` (32 bytes) — public ticket identifier (binds to specific ticket PDA)
- `secret_salt` (32 bytes) — kept off-chain, provided at execute time (prevents brute-force)
- `revealed_payload` (variable) — opaque bytes (trigger/order params), treated as raw bytes in M0

**Mechanism:**
1. Executor calls `execute_ticket(secret_salt, revealed_data)` providing the secret salt and payload
2. Program computes `SHA-256(b"CSv0.2" || ticket.owner || ticket.policy || ticket.ticket_id || secret_salt || revealed_data)`
3. Program verifies computed hash == `ticket.commitment`
4. Program validates `ticket.policy == policy.key()` (has_one constraint)
5. Program validates policy is not paused
6. In M1: program evaluates predicate + CPI to Drift
7. Ticket status is set to `Executed`

**Rationale:** Domain separation prevents hash collisions across protocols. Owner and policy binding prevent commitment replay across different owners or policies. Secret salt prevents brute-forcing low-entropy revealed data.

**Test requirements:**
- Positive: correct salt + reveal data → commitment matches, ticket executed
- Negative: wrong salt → CommitmentMismatch
- Negative: wrong reveal data → CommitmentMismatch
- Negative: no standalone reveal instruction exists

---

## P3: Replay Protection

**Statement:** Replay is impossible via ticket_id PDA uniqueness + status state machine.

**Mechanism:**
- Each ticket has a unique PDA derived from `[b"ticket", policy_pubkey, ticket_id]`
- The `status` transitions: `Open → Executed | Cancelled | Expired` (one-way, irreversible)
- Attempting to call `execute_ticket` on a non-Open ticket → `TicketAlreadyConsumed`
- PDA derivation ensures uniqueness (same policy + ticket_id = same address)
- ExecuteTicket re-validates PDA seeds (defense-in-depth via `seeds` constraint)

**State machine:**
```
  Created (status=Open)
      │
      ├──→ Executed (status=Executed)    [execute_ticket, permissionless]
      │
      ├──→ Cancelled (status=Cancelled)  [cancel_ticket, owner-only]
      │
      └──→ Expired (status=Expired)      [expire_ticket, permissionless after expiry]
```

**Note (M0):** Cancelled and Expired tickets keep accounts alive with status set. Accounts are NOT closed in M0. This may change in M1 with `close = owner` for cancelled tickets.

**PDA seeds:**
- Policy: `[b"policy", authority_pubkey, drift_sub_account_pubkey]`
- Ticket: `[b"ticket", policy_pubkey, ticket_id]`

**Test requirements:**
- Unit test: execute → status=Executed
- Negative test: execute consumed ticket → TicketAlreadyConsumed
- Negative test: same ticket_id → PDA collision (init fails)
- Unit test: cancel only by owner
- Unit test: expire only after expiry timestamp

---

## P4: CPI Safety / Allowlist

**Statement:** CPI targets are hard-allowlisted. No user-supplied `program_id` for CPI. No arbitrary instruction forwarding. Strict account validation.

> **Note:** CPI to Drift is stubbed in M0 (no actual CPI calls). The infrastructure (constants, allowlists) is in place for M1.

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

---

## P5: Policy-Ticket Binding

**Statement:** A ticket's execution is bound to its recorded policy. The `execute_ticket` instruction enforces:
1. `has_one = policy` — ticket.policy must match the provided policy account
2. PDA seeds re-derivation — ticket PDA seeds `[b"ticket", ticket.policy, ticket.ticket_id]` are re-verified
3. Policy PDA seeds are verified via `seeds` constraint

**Rationale:** Without this binding, an attacker could create a ticket under policy A (which has strict bounds), pause policy A, then execute the ticket by passing policy B (unpaused, permissive). The `has_one` + PDA seeds constraints prevent this attack.

**Test requirements:**
- Negative test: create ticket under policy A, attempt execute with policy B → PolicyMismatch / ConstraintSeeds

---

## CPI Privilege Escalation Threat Model

### Attack: User supplies a fake Drift program
**Mitigation:** Drift program ID is a `const`. No instruction accepts it as input.

### Attack: Executor injects extra accounts to redirect CPI
**Mitigation:** CPI account lists are constructed in the program. `remaining_accounts` are not forwarded.

### Attack: Executor replays an old ticket
**Mitigation:** Status state machine + PDA uniqueness.

### Attack: Executor reveals params but doesn't execute (to leak signal)
**Mitigation:** Reveal is coupled to execution. No standalone reveal instruction exists.

### Attack: Instruction sysvar introspection bypass
**Mitigation:** We don't use instruction sysvar introspection in MVP. No dependency to exploit.

### Attack: Ticket owner changes between create and execute
**Mitigation:** `owner` is part of the commitment hash. Changing owner invalidates the commitment.

### Attack: Execute ticket with wrong policy to bypass pause
**Mitigation:** `has_one = policy` constraint + PDA seeds re-derivation in ExecuteTicket.

### Attack: Brute-force low-entropy revealed data
**Mitigation:** 32-byte secret salt is included in the commitment preimage and never stored on-chain.
