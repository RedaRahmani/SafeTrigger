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
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_sdk::{
    hash::Hash,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{read_keypair_file, Keypair, Signature, Signer},
    transaction::Transaction,
};
use std::{collections::HashMap, path::PathBuf, str::FromStr, time::Duration};
use tracing::{error, info, warn};

// ── Constants ───────────────────────────────────────────────────

/// Domain separator for commitment preimage (must match on-chain).
const COMMITMENT_DOMAIN: &[u8] = b"CSv0.2";

/// CatalystGuard program ID.
const PROGRAM_ID: &str = "2oUmUDgTvVFBDqNC2TpVLhtvaenKgiNnuvsPMUYT4yJq";

/// Test oracle program ID used in localnet integration tests.
/// The keeper can parse this oracle's account layout to pre-filter executions.
const TEST_ORACLE_PROGRAM_ID: &str = "2ys3Ma4PQeQTXPp7wDzhUw6dbgFLmdDWuAWXBmeourqn";

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
    /// Path to the keeper signer keypair (Solana JSON keypair file).
    pub keypair_path: String,
    /// Path to secrets mapping: { ticket_pubkey: { secret_salt_b64, payload_b64 } }.
    pub secrets_path: String,
    /// If true, evaluates and logs but does not submit transactions.
    pub dry_run: bool,
    /// Max retries per ticket execution attempt.
    pub max_execute_retries: u32,
    /// Base backoff (ms) between retries.
    pub retry_backoff_ms: u64,
    pub mock_oracle_prices: Vec<MockOraclePrice>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockOraclePrice {
    pub market_index: u16,
    /// Price in PRICE_PRECISION (1e6).
    pub price: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketSecret {
    pub secret_salt_b64: String,
    pub payload_b64: String,
}

type SecretsMap = HashMap<String, TicketSecret>;

impl Default for KeeperConfig {
    fn default() -> Self {
        Self {
            rpc_url: "http://localhost:8899".to_string(),
            poll_interval_secs: 5,
            keypair_path: "~/.config/solana/id.json".to_string(),
            secrets_path: "secrets.json".to_string(),
            dry_run: false,
            max_execute_retries: 3,
            retry_backoff_ms: 500,
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

fn anchor_discriminator(ix_name: &str) -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(b"global:");
    h.update(ix_name.as_bytes());
    let out = h.finalize();
    out[..8].try_into().expect("slice length is 8")
}

#[derive(BorshSerialize)]
struct ExecuteTicketArgs {
    pub secret_salt: [u8; 32],
    pub revealed_data: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
struct ExecuteTicketAccountKeys {
    ticket: Pubkey,
    policy: Pubkey,
    keeper: Pubkey,
    oracle: Pubkey,
    drift_state: Pubkey,
    drift_user: Pubkey,
    drift_user_stats: Pubkey,
    drift_spot_market: Pubkey,
    drift_perp_market: Pubkey,
}

fn build_execute_ticket_ix(
    program_id: Pubkey,
    keys: ExecuteTicketAccountKeys,
    args: ExecuteTicketArgs,
) -> Result<Instruction, String> {
    let mut data = Vec::with_capacity(8 + 32 + 4 + args.revealed_data.len());
    data.extend_from_slice(&anchor_discriminator("execute_ticket"));
    data.extend_from_slice(
        &args
            .try_to_vec()
            .map_err(|_| "borsh serialize execute_ticket args".to_string())?,
    );

    Ok(Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(keys.ticket, false),
            AccountMeta::new(keys.policy, false),
            AccountMeta::new_readonly(keys.keeper, true),
            AccountMeta::new_readonly(keys.oracle, false),
            AccountMeta::new_readonly(drift_cpi::DRIFT_PROGRAM_ID, false),
            AccountMeta::new_readonly(keys.drift_state, false),
            AccountMeta::new(keys.drift_user, false),
            AccountMeta::new_readonly(keys.drift_user_stats, false),
            AccountMeta::new_readonly(keys.drift_spot_market, false),
            AccountMeta::new_readonly(keys.drift_perp_market, false),
        ],
        data,
    })
}

fn parse_test_oracle_feed(data: &[u8]) -> Result<(u64, u64), String> {
    // PriceFeed layout:
    // 8 discriminator + 32 authority + 8 price + 8 last_updated_slot
    const MIN_LEN: usize = 8 + 32 + 8 + 8;
    if data.len() < MIN_LEN {
        return Err(format!(
            "oracle data too short: {} < {}",
            data.len(),
            MIN_LEN
        ));
    }
    let price = u64::from_le_bytes(data[40..48].try_into().unwrap());
    let last_updated_slot = u64::from_le_bytes(data[48..56].try_into().unwrap());
    Ok((price, last_updated_slot))
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

// ── Policy account parsing ──────────────────────────────────────

/// Minimal off-chain decoder for the on-chain `Policy` account (Anchor/Borsh).
#[derive(BorshDeserialize, Debug)]
pub struct PolicyAccount {
    pub authority: [u8; 32],
    pub drift_sub_account: [u8; 32],
    pub bump: u8,
    pub paused: bool,
    pub allowed_markets: Vec<u16>,
    pub max_base_amount: u64,
    pub oracle_deviation_bps: u16,
    pub min_time_window: i64,
    pub max_time_window: i64,
    pub rate_limit_per_window: u16,
    pub reduce_only: bool,
    pub ticket_count: u64,
    pub executed_count: u64,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_executed_at: i64,
}

impl PolicyAccount {
    pub fn from_account_data(data: &[u8]) -> Result<Self, String> {
        if data.len() < 8 {
            return Err("policy account too short".to_string());
        }
        Self::try_from_slice(&data[8..]).map_err(|_| "invalid policy borsh".to_string())
    }

    pub fn authority_pubkey(&self) -> Pubkey {
        Pubkey::new_from_array(self.authority)
    }

    pub fn drift_sub_account_pubkey(&self) -> Pubkey {
        Pubkey::new_from_array(self.drift_sub_account)
    }
}

// ── JSON-RPC helpers ────────────────────────────────────────────

struct Rpc<'a> {
    client: &'a reqwest::Client,
    rpc_url: &'a str,
}

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
                    { "memcmp": { "offset": STATUS_OFFSET, "bytes": "1" } }
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

async fn get_account_data(
    client: &reqwest::Client,
    rpc_url: &str,
    pubkey: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let request = RpcRequest {
        jsonrpc: "2.0",
        id: 1,
        method: "getAccountInfo",
        params: serde_json::json!([pubkey, { "encoding": "base64" }]),
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

    let result = resp.result.unwrap_or_default();
    let value = &result["value"];
    if value.is_null() {
        return Err("account not found".into());
    }

    let data_arr = value["data"]
        .as_array()
        .ok_or("expected value.data array")?;
    let b64_data = data_arr
        .first()
        .and_then(|v| v.as_str())
        .ok_or("expected base64 data")?;

    Ok(BASE64.decode(b64_data)?)
}

async fn get_slot(
    client: &reqwest::Client,
    rpc_url: &str,
) -> Result<u64, Box<dyn std::error::Error>> {
    let request = RpcRequest {
        jsonrpc: "2.0",
        id: 1,
        method: "getSlot",
        params: serde_json::json!([{ "commitment": "confirmed" }]),
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
    Ok(resp
        .result
        .unwrap_or_default()
        .as_u64()
        .ok_or("expected slot u64")?)
}

async fn get_latest_blockhash(
    client: &reqwest::Client,
    rpc_url: &str,
) -> Result<Hash, Box<dyn std::error::Error>> {
    let request = RpcRequest {
        jsonrpc: "2.0",
        id: 1,
        method: "getLatestBlockhash",
        params: serde_json::json!([{ "commitment": "confirmed" }]),
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
    let result = resp.result.unwrap_or_default();
    let bh = result["value"]["blockhash"]
        .as_str()
        .ok_or("missing blockhash")?;
    Ok(Hash::from_str(bh)?)
}

async fn send_transaction(
    client: &reqwest::Client,
    rpc_url: &str,
    tx: &Transaction,
) -> Result<Signature, Box<dyn std::error::Error>> {
    let tx_bytes = bincode::serialize(tx)?;
    let tx_b64 = BASE64.encode(tx_bytes);

    let request = RpcRequest {
        jsonrpc: "2.0",
        id: 1,
        method: "sendTransaction",
        params: serde_json::json!([tx_b64, { "encoding": "base64", "skipPreflight": false, "preflightCommitment": "confirmed" }]),
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

    let result = resp.result.unwrap_or_default();
    let sig_str = result.as_str().ok_or("expected signature string")?;
    Ok(Signature::from_str(sig_str)?)
}

async fn wait_for_signature_confirmation(
    client: &reqwest::Client,
    rpc_url: &str,
    sig: &Signature,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let start = std::time::Instant::now();
    loop {
        let request = RpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method: "getSignatureStatuses",
            params: serde_json::json!([[sig.to_string()], { "searchTransactionHistory": true }]),
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

        let result = resp.result.unwrap_or_default();
        let value0 = &result["value"][0];
        if !value0.is_null() {
            if !value0["err"].is_null() {
                return Err(format!("transaction failed: {}", value0["err"]).into());
            }
            if let Some(status) = value0["confirmationStatus"].as_str() {
                if status == "confirmed" || status == "finalized" {
                    return Ok(());
                }
            }
        }

        if start.elapsed() > timeout {
            return Err("timeout waiting for confirmation".into());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn execute_ticket_with_retries(
    rpc: &Rpc<'_>,
    cfg: &KeeperConfig,
    keeper: &Keypair,
    ix: Instruction,
) -> Result<Signature, String> {
    let keeper_pk = keeper.pubkey();

    for attempt in 0..cfg.max_execute_retries.max(1) {
        let bh = get_latest_blockhash(rpc.client, rpc.rpc_url)
            .await
            .map_err(|e| e.to_string())?;

        let signers: [&dyn Signer; 1] = [keeper];
        let tx = Transaction::new_signed_with_payer(
            std::slice::from_ref(&ix),
            Some(&keeper_pk),
            &signers,
            bh,
        );

        let sig = match send_transaction(rpc.client, rpc.rpc_url, &tx).await {
            Ok(s) => s,
            Err(e) => {
                warn!("sendTransaction failed (attempt {}): {}", attempt + 1, e);
                if attempt + 1 >= cfg.max_execute_retries.max(1) {
                    return Err(format!("sendTransaction failed: {e}"));
                }
                let shift = attempt.min(16);
                let factor = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
                let backoff = cfg.retry_backoff_ms.saturating_mul(factor);
                tokio::time::sleep(Duration::from_millis(backoff)).await;
                continue;
            }
        };

        match wait_for_signature_confirmation(
            rpc.client,
            rpc.rpc_url,
            &sig,
            Duration::from_secs(30),
        )
        .await
        {
            Ok(()) => return Ok(sig),
            Err(e) => {
                warn!("tx not confirmed / failed (attempt {}): {}", attempt + 1, e);
                if attempt + 1 >= cfg.max_execute_retries.max(1) {
                    return Err(format!("transaction failed: {e}"));
                }
                let shift = attempt.min(16);
                let factor = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
                let backoff = cfg.retry_backoff_ms.saturating_mul(factor);
                tokio::time::sleep(Duration::from_millis(backoff)).await;
            }
        }
    }

    Err("exhausted retries".to_string())
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
    let rpc = Rpc {
        client: &client,
        rpc_url: &config.rpc_url,
    };

    // Verify RPC connectivity
    match check_rpc(rpc.client, rpc.rpc_url).await {
        Ok(version) => info!("Connected to Solana: {}", version),
        Err(e) => {
            error!("RPC connection failed: {}", e);
            std::process::exit(1);
        }
    }

    info!("Monitoring program: {}", PROGRAM_ID);

    let poll_interval = Duration::from_secs(config.poll_interval_secs);
    let mut iteration = 0u64;

    let keeper = match load_keypair(&config.keypair_path) {
        Ok(k) => k,
        Err(e) => {
            error!("Failed to load keeper keypair: {}", e);
            std::process::exit(1);
        }
    };
    let keeper_pubkey = keeper.pubkey();
    info!("Keeper signer: {}", keeper_pubkey);
    info!("Secrets: {}", expand_tilde(&config.secrets_path).display());
    info!("Dry run: {}", config.dry_run);

    let program_id = Pubkey::from_str(PROGRAM_ID).expect("PROGRAM_ID is valid");
    let test_oracle_program_id =
        Pubkey::from_str(TEST_ORACLE_PROGRAM_ID).expect("TEST_ORACLE_PROGRAM_ID is valid");

    loop {
        iteration += 1;
        info!("── Poll #{} ──", iteration);

        let secrets = load_secrets(&config.secrets_path);
        let current_slot = match get_slot(&client, &config.rpc_url).await {
            Ok(s) => s,
            Err(e) => {
                warn!("getSlot failed: {}", e);
                0
            }
        };

        match get_program_accounts(&client, &config.rpc_url).await {
            Ok(tickets) => {
                info!("Found {} open ticket(s)", tickets.len());
                for (pubkey, data) in &tickets {
                    let short = pubkey.get(0..8).unwrap_or(pubkey);
                    let ticket_pubkey = match Pubkey::from_str(pubkey) {
                        Ok(pk) => pk,
                        Err(e) => {
                            warn!("  Ticket {} invalid pubkey: {}", short, e);
                            continue;
                        }
                    };

                    let ticket = match ParsedTicket::from_account_data(data) {
                        Ok(t) => t,
                        Err(e) => {
                            warn!("  Failed to parse ticket {}: {}", short, e);
                            continue;
                        }
                    };

                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64;
                    if now >= ticket.expiry {
                        info!("  Ticket {} expired (skipping)", short);
                        continue;
                    }

                    let secret = match secrets.get(pubkey) {
                        Some(s) => s,
                        None => {
                            info!("  Ticket {} missing secret (skipping)", short);
                            continue;
                        }
                    };

                    let salt_vec = match BASE64.decode(&secret.secret_salt_b64) {
                        Ok(v) => v,
                        Err(e) => {
                            warn!("  Ticket {} bad secret_salt_b64: {}", short, e);
                            continue;
                        }
                    };
                    let secret_salt: [u8; 32] = match salt_vec.as_slice().try_into() {
                        Ok(a) => a,
                        Err(_) => {
                            warn!(
                                "  Ticket {} secret_salt wrong length: {}",
                                short,
                                salt_vec.len()
                            );
                            continue;
                        }
                    };

                    let revealed_data = match BASE64.decode(&secret.payload_b64) {
                        Ok(v) => v,
                        Err(e) => {
                            warn!("  Ticket {} bad payload_b64: {}", short, e);
                            continue;
                        }
                    };

                    let computed = compute_commitment(
                        &ticket.owner,
                        &ticket.policy,
                        &ticket.ticket_id,
                        &secret_salt,
                        &revealed_data,
                    );
                    if computed != ticket.commitment {
                        warn!("  Ticket {} commitment mismatch (skipping)", short);
                        continue;
                    }

                    let payload = match HedgePayloadV1::from_bytes(&revealed_data) {
                        Ok(p) => p,
                        Err(e) => {
                            warn!("  Ticket {} invalid payload borsh: {}", short, e);
                            continue;
                        }
                    };

                    let policy_pubkey = Pubkey::new_from_array(ticket.policy);
                    let policy_data = match get_account_data(
                        &client,
                        &config.rpc_url,
                        &policy_pubkey.to_string(),
                    )
                    .await
                    {
                        Ok(d) => d,
                        Err(e) => {
                            warn!("  Ticket {} failed to fetch policy: {}", short, e);
                            continue;
                        }
                    };
                    let policy = match PolicyAccount::from_account_data(&policy_data) {
                        Ok(p) => p,
                        Err(e) => {
                            warn!("  Ticket {} failed to parse policy: {}", short, e);
                            continue;
                        }
                    };
                    if policy.paused {
                        info!("  Ticket {} policy paused (skipping)", short);
                        continue;
                    }

                    // Optional off-chain precheck for allowlist to avoid wasting tx fees.
                    if !policy.allowed_markets.contains(&payload.market_index) {
                        info!(
                            "  Ticket {} market {} not allowed (skipping)",
                            short, payload.market_index
                        );
                        continue;
                    }

                    let policy_authority = policy.authority_pubkey();
                    let drift_user = policy.drift_sub_account_pubkey();
                    let (expected_user, _) = drift_cpi::derive_drift_user_pda(&policy_authority, 0);
                    if drift_user != expected_user {
                        warn!("  Ticket {} policy drift_user mismatch (skipping)", short);
                        continue;
                    }

                    let (drift_state, _) = drift_cpi::derive_drift_state_pda();
                    let (drift_user_stats, _) =
                        drift_cpi::derive_drift_user_stats_pda(&policy_authority);
                    let (drift_spot_market, _) =
                        drift_cpi::derive_drift_spot_market_pda(drift_cpi::QUOTE_SPOT_MARKET_INDEX);
                    let (drift_perp_market, _) =
                        drift_cpi::derive_drift_perp_market_pda(payload.market_index);

                    let oracle_program = Pubkey::new_from_array(payload.oracle_program);
                    let oracle_pubkey = Pubkey::new_from_array(payload.oracle);

                    // Off-chain predicate precheck.
                    let oracle_price = if oracle_program == test_oracle_program_id {
                        match get_account_data(&client, &config.rpc_url, &oracle_pubkey.to_string())
                            .await
                        {
                            Ok(oracle_data) => match parse_test_oracle_feed(&oracle_data) {
                                Ok((price, last_slot)) => {
                                    if current_slot > 0 && policy.min_time_window > 0 {
                                        let age = current_slot.saturating_sub(last_slot);
                                        let max_age = policy.min_time_window as u64;
                                        if age > max_age {
                                            info!("  Ticket {} oracle stale (skipping)", short);
                                            continue;
                                        }
                                    }
                                    price
                                }
                                Err(e) => {
                                    warn!("  Ticket {} oracle parse failed: {}", short, e);
                                    continue;
                                }
                            },
                            Err(e) => {
                                warn!("  Ticket {} oracle fetch failed: {}", short, e);
                                continue;
                            }
                        }
                    } else if let Some(m) = config
                        .mock_oracle_prices
                        .iter()
                        .find(|m| m.market_index == payload.market_index)
                    {
                        m.price
                    } else {
                        info!("  Ticket {} no oracle adapter (skipping)", short);
                        continue;
                    };

                    if !payload.is_trigger_met(oracle_price) {
                        continue;
                    }

                    if config.dry_run {
                        info!("  Ticket {} predicate met; dry_run=true", short);
                        continue;
                    }

                    let keys = ExecuteTicketAccountKeys {
                        ticket: ticket_pubkey,
                        policy: policy_pubkey,
                        keeper: keeper_pubkey,
                        oracle: oracle_pubkey,
                        drift_state,
                        drift_user,
                        drift_user_stats,
                        drift_spot_market,
                        drift_perp_market,
                    };
                    let args = ExecuteTicketArgs {
                        secret_salt,
                        revealed_data,
                    };
                    let ix = match build_execute_ticket_ix(program_id, keys, args) {
                        Ok(ix) => ix,
                        Err(e) => {
                            warn!("  Ticket {} ix build failed: {}", short, e);
                            continue;
                        }
                    };

                    match execute_ticket_with_retries(&rpc, &config, &keeper, ix).await {
                        Ok(sig) => info!("  Ticket {} executed: {}", short, sig),
                        Err(e) => warn!("  Ticket {} execute failed: {}", short, e),
                    }
                }
            }
            Err(e) => warn!("Poll failed: {}", e),
        }

        tokio::time::sleep(poll_interval).await;
    }
}

fn expand_tilde(path: &str) -> PathBuf {
    if path == "~" || path.starts_with("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            let mut p = PathBuf::from(home);
            if path.len() > 2 {
                p.push(&path[2..]);
            }
            return p;
        }
    }
    PathBuf::from(path)
}

fn load_keypair(path: &str) -> Result<Keypair, String> {
    let expanded = expand_tilde(path);
    read_keypair_file(expanded).map_err(|e| format!("read keypair: {e}"))
}

fn load_secrets(path: &str) -> SecretsMap {
    let expanded = expand_tilde(path);
    let contents = match std::fs::read_to_string(&expanded) {
        Ok(c) => c,
        Err(e) => {
            warn!(
                "Secrets file not found/readable ({}): {}",
                expanded.display(),
                e
            );
            return HashMap::new();
        }
    };

    match serde_json::from_str::<SecretsMap>(&contents) {
        Ok(m) => m,
        Err(e) => {
            warn!(
                "Failed to parse secrets JSON ({}): {}",
                expanded.display(),
                e
            );
            HashMap::new()
        }
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
