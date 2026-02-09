# On-Chain Invariants – Catalyst Shield v0.3

> These invariants MUST be enforced in the Anchor program and verified by tests.
> Last updated: 2026-02-10 (M1 MVP v0.3).

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
6. Program deserializes `HedgePayloadV1` from revealed data (Borsh)
7. Program validates payload against policy bounds (market allowlist, max size, reduce-only, deadline)
8. Program checks rate limiting (min interval between executions)
9. Program constructs `BoundedOrderParams` and CPI data for Drift `place_perp_order`
10. Ticket status is set to `Executed`; policy counters updated

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

**Note (M0):** Cancelled and Expired tickets keep accounts alive with status set. Accounts are NOT closed in M0. This may change with `close = owner` for cancelled tickets.

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

> **Note:** CPI to Drift constructs validated instruction data but actual `invoke` is gated on Drift deployment. On localnet (no Drift), all validation occurs but invoke is skipped.

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

---

## P6: Payload Validation (M1)

**Statement:** The revealed payload (`HedgePayloadV1`) is validated against policy bounds before any CPI data is constructed.

**HedgePayloadV1 fields** (Borsh-serialized):
| Field | Type | Description |
|-------|------|-------------|
| `market_index` | u16 | Drift perp market index |
| `trigger_direction` | enum(u8) | `Above=0, Below=1` |
| `trigger_price` | u64 | PRICE_PRECISION (1e6) |
| `side` | enum(u8) | `Long=0, Short=1` |
| `base_amount` | u64 | BASE_PRECISION (1e9) |
| `reduce_only` | bool(u8) | Whether order is reduce-only |
| `order_type` | enum(u8) | `Market=0, Limit=1` |
| `limit_price` | Option\<u64\> | Required for Limit orders |
| `max_slippage_bps` | u16 | Max slippage basis points |
| `deadline_ts` | i64 | Unix timestamp deadline |

**Validation rules:**
1. `market_index` must be in `policy.allowed_markets` → `MarketNotAllowed`
2. `base_amount` must be ≤ `policy.max_base_amount` → `BaseAmountExceeded`
3. If `policy.reduce_only == true`, payload must have `reduce_only == true` → `ReduceOnlyViolation`
4. `deadline_ts` must be > current clock timestamp → `DeadlineExpired`
5. Limit orders must include a non-zero `limit_price` → `InvalidRevealData`
6. Invalid Borsh serialization → `InvalidRevealData`

**Test requirements:**
- Negative: market not in allowlist → MarketNotAllowed
- Negative: base amount exceeds max → BaseAmountExceeded
- Negative: reduce_only violation → ReduceOnlyViolation
- Negative: expired deadline → DeadlineExpired
- Negative: limit order without price → InvalidRevealData
- Negative: truncated Borsh → InvalidRevealData
- Positive: valid limit order, valid market 5

---

## P7: Rate Limiting (M1)

**Statement:** Policy-level rate limiting prevents execution spam.

**Mechanism:**
- `policy.rate_limit_per_window` and `policy.max_time_window` define the rate limit
- Minimum interval = `ceil(max_time_window / rate_limit_per_window)` (implemented as `(max_time_window + rate_limit_per_window - 1) / rate_limit_per_window`)
- If `rate_limit_per_window > 0` and `last_executed_at > 0`, elapsed time must be ≥ min interval
- Setting `rate_limit_per_window = 0` disables rate limiting

**Policy counters updated on execution:**
- `executed_count` incremented by 1
- `last_executed_at` set to current unix timestamp
- `ticket_count` incremented on ticket creation

---

## P8: Events / Receipts (M1)

**Statement:** All ticket lifecycle transitions emit Anchor events for off-chain indexing.

**Events:**
| Event | Trigger | Fields |
|-------|---------|--------|
| `TicketCreated` | `create_ticket` | policy, ticket, owner, ticket_id, expiry, slot |
| `TicketExecuted` | `execute_ticket` | policy, ticket, keeper, payload_hash, market_index, base_amount, slot, timestamp |
| `TicketCancelled` | `cancel_ticket` | ticket, owner, slot |
| `TicketExpired` | `expire_ticket` | ticket, cranker, slot |

---

## Test Coverage Summary (v0.3)

| Category | Tests | Status |
|----------|-------|--------|
| Policy Management | 5 | ✅ |
| Ticket Lifecycle | 5 | ✅ |
| Cancel and Expire | 2 | ✅ |
| Policy-binding | 1 | ✅ |
| Commitment binding | 2 | ✅ |
| Payload validation | 14 | ✅ |
| **Total integration** | **29** | ✅ |
| Rust unit tests | 24 | ✅ |
