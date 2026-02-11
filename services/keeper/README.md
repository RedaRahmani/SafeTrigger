# CatalystGuard Keeper (v0.4 Production)

Off-chain service that:

- Scans on-chain `Ticket` accounts in `Open` status via Solana JSON-RPC `getProgramAccounts`.
- Looks up the corresponding off-chain secrets (`secret_salt`, `HedgePayloadV1` bytes) from a local `secrets.json`.
- Evaluates the trigger predicate against an oracle (localnet `test_oracle`, devnet/mainnet `PythLazerOracle`) or configured mock prices.
- Submits an `execute_ticket` transaction via JSON-RPC `sendTransaction` (with retries + backoff).
- Exposes `/healthz` and `/metrics` (Prometheus format) HTTP endpoints.
- Handles graceful shutdown via SIGINT/SIGTERM.
- Deduplicates recent execution attempts to avoid double-submits.

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
  "http_port": 9090,
  "mock_oracle_prices": [
    { "market_index": 0, "price": 160000000 }
  ]
}
```

Run:

```bash
KEEPER_CONFIG=keeper.config.json RUST_LOG=info cargo run -p keeper --release
```

## HTTP Endpoints

| Endpoint   | Description                             |
|------------|-----------------------------------------|
| `/healthz` | Returns `200 ok` or `503 unhealthy`     |
| `/metrics` | Prometheus-format counters and gauges   |

Default port: `9090` (configurable via `http_port`).

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

- **PythLazerOracle** (devnet/mainnet): Auto-detected by discriminator (`9f07a1f922517985`). Parses `price`, `posted_slot`, `exponent` and normalizes to 1e6 precision.
- **TestOracle** (localnet): Raw byte parsing for the `test_oracle` program's `PriceFeed` account.
- **Mock prices**: Fallback from `mock_oracle_prices` in config.

The on-chain program is the source of truth; keeper-side checks are prefilters and do not weaken
on-chain enforcement.

