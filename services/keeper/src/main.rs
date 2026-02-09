//! CatalystGuard Keeper Service – v0.3 MVP
//!
//! Monitors open tickets via Solana JSON-RPC, evaluates trigger predicates
//! against mock oracle prices, and logs which tickets are ready to execute.
//!
//! # Architecture
//!
//! 1. Poll open Ticket accounts via `getProgramAccounts` (JSON-RPC + memcmp)
//! 2. Deserialize HedgePayloadV1 from off-chain database (when available)
//! 3. Evaluate trigger conditions against oracle prices
//! 4. Submit `execute_ticket` via JSON-RPC `sendTransaction`
//!
//! # Running
//!
//! ```bash
//! # Start localnet first: solana-test-validator
//! # Then:
//! RUST_LOG=info cargo run -p keeper
//! ```

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use borsh::BorshDeserialize;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tracing::{error, info, warn};

// ── Constants ───────────────────────────────────────────────────

/// Domain separator for commitment preimage (must match on-chain).
const COMMITMENT_DOMAIN: &[u8] = b"CSv0.2";

/// CatalystGuard program ID.
const PROGRAM_ID: &str = "2oUmUDgTvVFBDqNC2TpVLhtvaenKgiNnuvsPMUYT4yJq";

/// Ticket::SPACE — expected account data length for filtering.
const TICKET_DATA_LEN: u64 = 178;

/// Offset of the `status` byte in a Ticket account.
/// 8 (discriminator) + 32 (owner) + 32 (policy) + 32 (commitment) + 32 (ticket_id) + 1 (bump) = 137
const STATUS_OFFSET: usize = 137;

// ── Configuration ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeeperConfig {
    pub rpc_url: String,
    pub poll_interval_secs: u64,
    pub mock_oracle_prices: Vec<MockOraclePrice>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockOraclePrice {
    pub market_index: u16,
    /// Price in PRICE_PRECISION (1e6).
    pub price: u64,
}

impl Default for KeeperConfig {
    fn default() -> Self {
        Self {
            rpc_url: "http://localhost:8899".to_string(),
            poll_interval_secs: 5,
            mock_oracle_prices: vec![
                MockOraclePrice {
                    market_index: 0,
                    price: 160_000_000,
                },
                MockOraclePrice {
                    market_index: 1,
                    price: 3_500_000_000,
                },
                MockOraclePrice {
                    market_index: 5,
                    price: 95_000_000_000,
                },
            ],
        }
    }
}

// ── HedgePayloadV1 ─────────────────────────────────────────────

#[derive(BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TriggerDirection {
    Above = 0,
    Below = 1,
}

#[derive(BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PositionDirection {
    Long = 0,
    Short = 1,
}

#[derive(BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OrderType {
    Market = 0,
    Limit = 1,
}

#[derive(BorshDeserialize, Debug, Clone, PartialEq)]
pub struct HedgePayloadV1 {
    pub market_index: u16,
    pub trigger_direction: TriggerDirection,
    pub trigger_price: u64,
    pub side: PositionDirection,
    pub base_amount: u64,
    pub reduce_only: bool,
    pub order_type: OrderType,
    pub limit_price: Option<u64>,
    pub max_slippage_bps: u16,
    pub deadline_ts: i64,
    pub oracle_program: [u8; 32],
    pub oracle: [u8; 32],
}

impl HedgePayloadV1 {
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        Self::try_from_slice(data).map_err(|_| "invalid borsh".to_string())
    }

    pub fn is_trigger_met(&self, oracle_price: u64) -> bool {
        match self.trigger_direction {
            TriggerDirection::Above => oracle_price >= self.trigger_price,
            TriggerDirection::Below => oracle_price <= self.trigger_price,
        }
    }
}

// ── Commitment ──────────────────────────────────────────────────

pub fn compute_commitment(
    owner: &[u8; 32],
    policy: &[u8; 32],
    ticket_id: &[u8; 32],
    secret_salt: &[u8; 32],
    revealed_data: &[u8],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(COMMITMENT_DOMAIN);
    h.update(owner);
    h.update(policy);
    h.update(ticket_id);
    h.update(secret_salt);
    h.update(revealed_data);
    h.finalize().into()
}

// ── Ticket account parsing ──────────────────────────────────────

#[derive(Debug)]
pub struct ParsedTicket {
    pub owner: [u8; 32],
    pub policy: [u8; 32],
    pub commitment: [u8; 32],
    pub ticket_id: [u8; 32],
    pub bump: u8,
    pub status: u8,
    pub expiry: i64,
}

impl ParsedTicket {
    pub fn from_account_data(data: &[u8]) -> Result<Self, String> {
        if data.len() < TICKET_DATA_LEN as usize {
            return Err(format!(
                "account data too short: {} < {}",
                data.len(),
                TICKET_DATA_LEN
            ));
        }
        let mut o = 8; // skip discriminator
        let read32 = |d: &[u8], off: &mut usize| -> [u8; 32] {
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&d[*off..*off + 32]);
            *off += 32;
            buf
        };
        let owner = read32(data, &mut o);
        let policy = read32(data, &mut o);
        let commitment = read32(data, &mut o);
        let ticket_id = read32(data, &mut o);
        let bump = data[o];
        o += 1;
        let status = data[o];
        o += 1;
        let expiry = i64::from_le_bytes(data[o..o + 8].try_into().unwrap());

        Ok(Self {
            owner,
            policy,
            commitment,
            ticket_id,
            bump,
            status,
            expiry,
        })
    }
}

// ── JSON-RPC helpers ────────────────────────────────────────────

#[derive(Serialize)]
struct RpcRequest {
    jsonrpc: &'static str,
    id: u64,
    method: &'static str,
    params: serde_json::Value,
}

#[derive(Deserialize)]
struct RpcResponse {
    result: Option<serde_json::Value>,
    error: Option<serde_json::Value>,
}

async fn get_program_accounts(
    client: &reqwest::Client,
    rpc_url: &str,
) -> Result<Vec<(String, Vec<u8>)>, Box<dyn std::error::Error>> {
    let request = RpcRequest {
        jsonrpc: "2.0",
        id: 1,
        method: "getProgramAccounts",
        params: serde_json::json!([
            PROGRAM_ID,
            {
                "encoding": "base64",
                "filters": [
                    { "dataSize": TICKET_DATA_LEN },
                    { "memcmp": { "offset": STATUS_OFFSET, "bytes": BASE64.encode([0x00]) } }
                ]
            }
        ]),
    };

    let resp: RpcResponse = client
        .post(rpc_url)
        .json(&request)
        .send()
        .await?
        .json()
        .await?;

    if let Some(err) = resp.error {
        return Err(format!("RPC error: {}", err).into());
    }

    let accounts = resp.result.unwrap_or(serde_json::Value::Array(vec![]));
    let arr = accounts.as_array().ok_or("expected array")?;

    let mut results = Vec::new();
    for item in arr {
        let pubkey = item["pubkey"].as_str().unwrap_or("").to_string();
        let data_arr = item["account"]["data"].as_array();
        if let Some(data_parts) = data_arr {
            if let Some(b64_data) = data_parts.first().and_then(|v| v.as_str()) {
                if let Ok(decoded) = BASE64.decode(b64_data) {
                    results.push((pubkey, decoded));
                }
            }
        }
    }

    Ok(results)
}

// ── Main ────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".parse().unwrap()),
        )
        .init();

    info!("CatalystGuard Keeper v0.3 MVP starting...");

    let config = load_config();
    info!(
        "RPC={}, poll={}s, oracles={}",
        config.rpc_url,
        config.poll_interval_secs,
        config.mock_oracle_prices.len()
    );

    let client = reqwest::Client::new();

    // Verify RPC connectivity
    match check_rpc(&client, &config.rpc_url).await {
        Ok(version) => info!("Connected to Solana: {}", version),
        Err(e) => {
            error!("RPC connection failed: {}", e);
            std::process::exit(1);
        }
    }

    info!("Monitoring program: {}", PROGRAM_ID);

    let poll_interval = Duration::from_secs(config.poll_interval_secs);
    let mut iteration = 0u64;

    loop {
        iteration += 1;
        info!("── Poll #{} ──", iteration);

        match get_program_accounts(&client, &config.rpc_url).await {
            Ok(tickets) => {
                info!("Found {} open ticket(s)", tickets.len());
                for (pubkey, data) in &tickets {
                    match ParsedTicket::from_account_data(data) {
                        Ok(ticket) => {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_secs() as i64;
                            let expired = now >= ticket.expiry;
                            info!(
                                "  Ticket {} | status={} | expiry={} | expired={}",
                                &pubkey[..8],
                                ticket.status,
                                ticket.expiry,
                                expired
                            );
                            // In production: look up secret from off-chain DB,
                            // deserialize payload, check oracle, submit tx.
                        }
                        Err(e) => warn!("  Failed to parse ticket {}: {}", &pubkey[..8], e),
                    }
                }
            }
            Err(e) => warn!("Poll failed: {}", e),
        }

        tokio::time::sleep(poll_interval).await;
    }
}

fn load_config() -> KeeperConfig {
    let path = std::env::var("KEEPER_CONFIG").unwrap_or_default();
    if !path.is_empty() {
        if let Ok(contents) = std::fs::read_to_string(&path) {
            if let Ok(config) = serde_json::from_str::<KeeperConfig>(&contents) {
                return config;
            }
        }
        warn!("Failed to load config from {}, using defaults", path);
    }
    KeeperConfig::default()
}

async fn check_rpc(
    client: &reqwest::Client,
    url: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let req = RpcRequest {
        jsonrpc: "2.0",
        id: 1,
        method: "getVersion",
        params: serde_json::json!([]),
    };
    let resp: RpcResponse = client.post(url).json(&req).send().await?.json().await?;
    let version = resp.result.unwrap_or_default();
    Ok(version["solana-core"]
        .as_str()
        .unwrap_or("unknown")
        .to_string())
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_roundtrip() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.push(0); // Above
        buf.extend_from_slice(&150_000_000u64.to_le_bytes());
        buf.push(0); // Long
        buf.extend_from_slice(&1_000_000_000u64.to_le_bytes());
        buf.push(0); // reduce_only=false
        buf.push(0); // Market
        buf.push(0); // None
        buf.extend_from_slice(&50u16.to_le_bytes());
        buf.extend_from_slice(&2_000_000_000i64.to_le_bytes());
        buf.extend_from_slice(&[0u8; 32]); // oracle_program
        buf.extend_from_slice(&[0u8; 32]); // oracle

        let p = HedgePayloadV1::from_bytes(&buf).unwrap();
        assert_eq!(p.market_index, 0);
        assert_eq!(p.trigger_direction, TriggerDirection::Above);
        assert_eq!(p.trigger_price, 150_000_000);
        assert_eq!(p.base_amount, 1_000_000_000);
        assert!(!p.reduce_only);
        assert!(p.limit_price.is_none());
    }

    #[test]
    fn test_trigger_evaluation() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.push(0);
        buf.extend_from_slice(&150_000_000u64.to_le_bytes());
        buf.push(0);
        buf.extend_from_slice(&1_000_000_000u64.to_le_bytes());
        buf.push(0);
        buf.push(0);
        buf.push(0);
        buf.extend_from_slice(&50u16.to_le_bytes());
        buf.extend_from_slice(&2_000_000_000i64.to_le_bytes());
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(&[0u8; 32]);

        let p = HedgePayloadV1::from_bytes(&buf).unwrap();
        assert!(!p.is_trigger_met(149_999_999));
        assert!(p.is_trigger_met(150_000_000));
        assert!(p.is_trigger_met(200_000_000));
    }

    #[test]
    fn test_commitment_computation() {
        let owner = [1u8; 32];
        let policy = [2u8; 32];
        let ticket_id = [3u8; 32];
        let salt = [4u8; 32];
        let data = b"test";

        let c1 = compute_commitment(&owner, &policy, &ticket_id, &salt, data);
        let c2 = compute_commitment(&owner, &policy, &ticket_id, &salt, data);
        assert_eq!(c1, c2);

        let salt2 = [5u8; 32];
        let c3 = compute_commitment(&owner, &policy, &ticket_id, &salt2, data);
        assert_ne!(c1, c3);
    }

    #[test]
    fn test_parse_ticket() {
        let mut data = vec![0u8; 178];
        // Set status = 0 (Open) at offset 137
        data[STATUS_OFFSET] = 0;
        let ticket = ParsedTicket::from_account_data(&data).unwrap();
        assert_eq!(ticket.status, 0);
    }

    #[test]
    fn test_default_config() {
        let c = KeeperConfig::default();
        assert_eq!(c.rpc_url, "http://localhost:8899");
        assert!(!c.mock_oracle_prices.is_empty());
    }
}
