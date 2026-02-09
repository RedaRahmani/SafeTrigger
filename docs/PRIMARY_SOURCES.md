# Primary Sources – Catalyst Shield v0.2

> Last updated: 2026-02-08

## 1. Drift Protocol v2 – Delegated Accounts

**Source:** https://drift-labs.github.io/v2-teacher/ (API docs)  
**Source:** https://github.com/drift-labs/protocol-v2 (program source)  
**Program ID (mainnet & devnet):** `dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH`

### Delegate Capabilities & Restrictions

A delegate is a secondary signer assigned to a Drift sub-account via `updateUserDelegate()`. The delegate address is stored in `User.delegate` on-chain.

**What a delegate CAN do (confirmed from protocol source + SDK docs):**
- `deposit` – deposit collateral into the sub-account
- `placePerpOrder` / `placeSpotOrder` / `placeOrders` – place orders on any market
- `cancelOrder` / `cancelOrders` – cancel orders
- `modifyOrder` – modify existing orders
- Swap via Jupiter integration
- Execute Place-and-Take atomic orders

**What a delegate CANNOT do (enforced in the program):**
- `withdraw` – withdraw collateral from the sub-account
- `borrow` – create borrow positions
- `deleteUser` – close/delete the sub-account
- `updateUserDelegate` – change or remove the delegate assignment
- Transfer deposits between sub-accounts (requires authority signer)

**CatalystGuard implication:** Our PDA acts as a delegate on a user's Drift sub-account. This means the PDA can place/cancel orders but CANNOT withdraw funds. This is a critical security property — even if the PDA is compromised, user funds remain safe.

---

## 2. Drift Keeper / Open-Order Visibility Model

**Source:** https://drift-labs.github.io/v2-teacher/#orderbook-blockchain  
**Source:** https://github.com/drift-labs/keeper-bots-v2

### How Orders Become Visible

- Drift does NOT have a single on-chain order book. The "DLOB" (Decentralized Limit Order Book) is reconstructed off-chain by indexing all `User` accounts that have open orders.
- `UserMap` or `OrderSubscriber` track all user accounts / orders via websocket or polling.
- Orders are stored directly in the `User.orders[32]` array as `Order` structs containing: `order_type`, `market_index`, `direction`, `base_asset_amount`, `price`, `trigger_price`, `trigger_condition`, etc.
- **All order fields are plaintext on-chain.** Any keeper, MEV searcher, or indexer can read trigger prices, sizes, directions from any user account.
- Keepers (fillers) compete to fill triggerable orders (TriggerMarket / TriggerLimit) by calling `trigger_order` then `fill_order`.

**CatalystGuard implication:** This plaintext visibility is the core "intent leak" problem we solve. By replacing on-chain trigger orders with off-chain commitment hashes (tickets), we prevent frontrunning of trigger prices while maintaining the same execution path via delegated order placement.

---

## 3. Jupiter Perpetuals – PositionRequest / TP-SL Intent Leak

**Source:** https://dev.jup.ag/docs/perps/position-request-account  
**Source:** https://dev.jup.ag/docs/perps/position-account

### PositionRequest On-Chain Storage

The Jupiter Perpetuals program stores TP/SL requests as `PositionRequest` accounts with the following fields stored **in plaintext on-chain**:

| Field | Type | Description |
|-------|------|-------------|
| `triggerPrice` | `u64` | The USD price at which the TP/SL fires |
| `triggerAboveThreshold` | `bool` | true = fires above price; false = fires below |
| `sizeUsdDelta` | `u64` | Size of the close |
| `entirePosition` | `bool` | Whether to close the entire position |
| `requestType` | `RequestType` | `Trigger` for TP/SL |
| `side` | `Side` | Long or Short |
| `executed` | `bool` | Whether already executed |

**The problem:** These `PositionRequest` accounts persist on-chain until triggered. Any MEV searcher can:
1. Read all pending TP/SL requests
2. Know exact trigger prices, sides, and sizes
3. Front-run or manipulate oracle prices toward trigger thresholds

**CatalystGuard implication:** This is direct evidence of the "intent leak" pattern we address. Our commitment-hash approach stores ZERO plaintext trigger parameters on-chain.

---

## 4. DFlow Proof (KYC) – Requirements & Timeline

**Source:** https://pond.dflow.net/build/proof/introduction  
**Source:** https://pond.dflow.net/build/proof/partner-integration  
**Source:** https://dflow.net/blog/proof (announced Feb 6, 2026)

### What is Proof?

Proof is DFlow's identity verification service that links KYC'd real-world identities to Solana wallets. It enables apps to query `GET https://proof.dflow.net/verify/{address}` → `{ "verified": true/false }`.

### Integration Timeline (Prediction Markets)

| Date | Requirement |
|------|-------------|
| Feb 13, 2026 | Confirm development work has begun |
| **Feb 20, 2026 17:00 UTC** | All prediction market **buying** requires Proof. Unverified wallets can only sell. |

**Failure to integrate = loss of Prediction Markets API access.**

### Integration Pattern

1. Deep-link user to `https://dflow.net/proof?wallet={addr}&signature={sig}&timestamp={ts}&redirect_uri={uri}`
2. User completes KYC (document + biometric verification)
3. On return, query `GET https://proof.dflow.net/verify/{address}`
4. Gate features based on `verified` boolean

### Geo-Blocking Obligations

DFlow prediction markets (via Kalshi) are US-regulated. Partners must:
- Implement geo-blocking at UI level (prevent access from restricted jurisdictions)
- Implement server-side geo verification  
- NOT provide VPN circumvention advice or tools
- Proof verification alone is not sufficient; jurisdiction checks are separate

**CatalystGuard implication:** Our compliance service must stub Proof verification + geo-blocking interfaces from day 1, even if prediction market features are metadata-only in MVP.

---

## 5. Jito Bundles – Private Transaction Execution

**Source:** https://docs.jito.wtf/lowlatencytxnsend/

### What Jito Provides

- **Bundles:** Groups of up to 5 transactions executed sequentially and atomically (all-or-nothing)
- **sendTransaction:** Single tx submission with MEV protection via Jito block engine
- **Sandwich Mitigation:** Include `jitodontfront` account to prevent sandwich attacks

### Bundle API

```
POST https://mainnet.block-engine.jito.wtf/api/v1/bundles
method: "sendBundle"
params: [["<base64_tx_1>", "<base64_tx_2>", ...], { "encoding": "base64" }]
```

- Minimum tip: 1000 lamports
- Parallel auctions run at 50ms ticks
- Tips go to Jito validators and stakers
- `getBundleStatuses` to check landing
- `getTipAccounts` for 8 tip accounts (pick randomly to reduce contention)

### For CatalystGuard

Jito bundles are an "execution quality" optimization, not a security guarantee:
- Keepers can optionally submit `execute_ticket` transactions via Jito `sendTransaction` for MEV protection
- Bundle submission behind a feature flag
- NOT relied upon for privacy (our commitment-hash scheme provides that)
- Uncled blocks can still leak transactions; always include state assertions

---

## 6. Drift Program ID (Pinned)

For CPI allowlisting, we hardcode:

```
dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH
```

This is the same on **mainnet-beta** and **devnet**.
