# CatalystGuard Keeper (v0.3 MVP)

Off-chain service that:

- Scans on-chain `Ticket` accounts in `Open` status via Solana JSON-RPC `getProgramAccounts`.
- Looks up the corresponding off-chain secrets (`secret_salt`, `HedgePayloadV1` bytes) from a local `secrets.json`.
- Evaluates the trigger predicate against an oracle (localnet `test_oracle`) or configured mock prices.
- Submits an `execute_ticket` transaction via JSON-RPC `sendTransaction` (with retries + backoff).

## Config

The keeper loads its config from a JSON file pointed to by `KEEPER_CONFIG`.
If unset or unreadable, it uses defaults (see `services/keeper/src/main.rs`).

Example `keeper.config.json`:

```json
{
  "rpc_url": "http://localhost:8899",
  "poll_interval_secs": 5,
  "keypair_path": "~/.config/solana/id.json",
  "secrets_path": "secrets.json",
  "dry_run": false,
  "max_execute_retries": 3,
  "retry_backoff_ms": 500,
  "mock_oracle_prices": [
    { "market_index": 0, "price": 160000000 }
  ]
}
```

Run:

```bash
KEEPER_CONFIG=keeper.config.json RUST_LOG=info cargo run -p keeper --release
```

## Secrets File

`secrets.json` schema:

```json
{
  "TicketPubkeyBase58": {
    "secret_salt_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "payload_b64": "AAABAAAB..."
  }
}
```

Notes:

- `secret_salt_b64` must decode to exactly 32 bytes.
- `payload_b64` must decode to the Borsh-serialized `HedgePayloadV1` bytes that were committed to at `create_ticket`.
- The keeper verifies the on-chain `commitment` before attempting execution.

## Oracle Support

- If the ticket payload specifies `oracle_program == programs/test_oracle` (used in the Anchor tests),
  the keeper will parse the oracle feed account data to pre-filter tickets and enforce staleness checks.
- Otherwise, the keeper falls back to `mock_oracle_prices` from config (best-effort only).

The on-chain program is the source of truth; keeper-side checks are prefilters and do not weaken
on-chain enforcement.

