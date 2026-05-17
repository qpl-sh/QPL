// SPDX-License-Identifier: MIT OR Apache-2.0

//! QPL operator server — JSON-RPC over TCP.
//!
//! Exposes all QPL services via a newline-delimited JSON protocol over TCP.
//! This is the MVP transport layer; gRPC (via tonic + protoc) will be
//! layered on top once protoc is available in the build environment.
//!
//! Protocol: client sends `{"method":"...", "params":{...}}\n`
//! Server responds with `{"result":{...}}\n` or `{"error":"..."}\n`

use crate::handlers;
use crate::state::NodeState;
use serde::{Deserialize, Serialize};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

// ─── Request / Response Types ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub operator_id: String,
    pub node_name: String,
    pub requests_total: u64,
    pub uptime_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeEstimateRequest {
    pub service_type: String,
    pub urgency: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeEstimateResponse {
    pub fee_micro_usd: u64,
    pub quote_id: String,
    pub breakdown_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    pub message: Vec<u8>,
    pub threshold: u32,
    pub total: u32,
    pub fee_proof_tx: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResponse {
    pub signature: Vec<u8>,
    pub request_id: String,
    pub participants: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProveRequest {
    pub transactions: Vec<u8>,
    pub security_bits: u32,
    pub fee_proof_tx: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProveResponse {
    pub proof: Vec<u8>,
    pub public_inputs: Vec<u8>,
    pub request_id: String,
}

// ─── Server State ──────────────────────────────────────────────────────────

#[derive(Clone)]
struct ServerState {
    node: NodeState,
    start_time: std::time::Instant,
}

// ─── Server Entry Point ────────────────────────────────────────────────────

/// Start the QPL operator server.
pub async fn run(state: NodeState) -> Result<(), Box<dyn std::error::Error>> {
    let addr = state.config.listen_addr.clone();
    let server_state = Arc::new(ServerState {
        node: state,
        start_time: std::time::Instant::now(),
    });

    let listener = TcpListener::bind(&addr).await?;
    tracing::info!(%addr, "QPL node listening (JSON-RPC over TCP)");

    loop {
        let (stream, peer) = listener.accept().await?;
        let state = server_state.clone();

        tokio::spawn(async move {
            tracing::debug!(%peer, "Client connected");
            if let Err(e) = handle_connection(state, stream).await {
                tracing::debug!(%peer, error = %e, "Connection ended");
            }
        });
    }
}

async fn handle_connection(
    state: Arc<ServerState>,
    stream: tokio::net::TcpStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let response = handle_request(&state, &line).await;
        writer.write_all(response.as_bytes()).await?;
        writer.write_all(b"\n").await?;
    }

    Ok(())
}

// ─── Request Router ────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RpcRequest {
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

async fn handle_request(state: &ServerState, data: &str) -> String {
    let request: RpcRequest = match serde_json::from_str(data) {
        Ok(r) => r,
        Err(e) => return format_error(&format!("invalid request: {}", e)),
    };

    let result = match request.method.as_str() {
        "health" => handle_health(state),
        "estimate_fee" => handle_estimate_fee(state, request.params).await,
        "sign" => handle_sign(state, request.params).await,
        "prove" => handle_prove(state, request.params).await,
        _ => return format_error(&format!("unknown method: {}", request.method)),
    };

    match result {
        Ok(value) => serde_json::json!({ "result": value }).to_string(),
        Err(e) => format_error(&e),
    }
}

fn handle_health(state: &ServerState) -> Result<serde_json::Value, String> {
    let resp = HealthResponse {
        status: "healthy".to_string(),
        operator_id: state.node.identity.operator_id(),
        node_name: state.node.config.name.clone(),
        requests_total: state.node.metrics.requests_total.load(Ordering::Relaxed),
        uptime_seconds: state.start_time.elapsed().as_secs(),
    };
    Ok(serde_json::to_value(resp).unwrap())
}

async fn handle_estimate_fee(
    state: &ServerState,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let req: FeeEstimateRequest =
        serde_json::from_value(params).map_err(|e| e.to_string())?;
    let resp = handlers::estimate_fee(&state.node, &req.service_type, &req.urgency)
        .await
        .map_err(|e| e.to_string())?;
    Ok(serde_json::to_value(resp).unwrap())
}

async fn handle_sign(
    state: &ServerState,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    state.node.metrics.record_request();
    let req: SignRequest = serde_json::from_value(params).map_err(|e| e.to_string())?;
    match handlers::handle_sign(&state.node, req).await {
        Ok(resp) => {
            state.node.metrics.record_success();
            Ok(serde_json::to_value(resp).unwrap())
        }
        Err(e) => {
            state.node.metrics.record_failure();
            Err(e.to_string())
        }
    }
}

async fn handle_prove(
    state: &ServerState,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    state.node.metrics.record_request();
    let req: ProveRequest = serde_json::from_value(params).map_err(|e| e.to_string())?;
    match handlers::handle_prove(&state.node, req).await {
        Ok(resp) => {
            state.node.metrics.record_success();
            Ok(serde_json::to_value(resp).unwrap())
        }
        Err(e) => {
            state.node.metrics.record_failure();
            Err(e.to_string())
        }
    }
}

fn format_error(msg: &str) -> String {
    serde_json::json!({ "error": msg }).to_string()
}
