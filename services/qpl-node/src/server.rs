// SPDX-License-Identifier: MIT OR Apache-2.0

//! QPL operator server — JSON-RPC over TLS (D-1 / D-2 / D-3 / D-6).
//!
//! Wire layout:
//!
//! 1. Accept TCP connection.
//! 2. If `tls.enabled` (default), perform a rustls handshake; otherwise
//!    a prominent WARN was already emitted at startup. After this the
//!    underlying byte stream is protected (and, with `client_ca_path`
//!    set, mutually authenticated).
//! 3. Read newline-delimited JSON requests. Each line is expected to be
//!    an [`crate::auth::AuthEnvelope`] except for the unauthenticated
//!    `health` liveness probe, which may also arrive as a bare
//!    `{"method":"health"}` JSON object.
//! 4. Verify auth (operator allow-listed, timestamp within ±skew window,
//!    ML-DSA-65 signature OK). Failures → sanitized
//!    [`crate::errors::ErrorCode::AuthenticationFailed`] (-32001).
//! 5. Apply per-operator token-bucket rate limit. Failures → sanitized
//!    [`crate::errors::ErrorCode::RateLimitExceeded`] (-32002).
//! 6. Dispatch to handler. Any handler error is logged in detail
//!    server-side and returned as a sanitized public error.
//!
//! Health requests are exempt from BOTH auth and rate limiting.

use crate::auth::{self, AuthEnvelope};
use crate::errors::{sanitized_error_response, ErrorCode};
use crate::handlers;
use crate::state::NodeState;
use crate::tls;
use serde::{Deserialize, Serialize};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

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
    let tls_enabled = state.config.tls.enabled;

    // Build the rustls acceptor up-front (fail-fast at startup if certs are bad).
    let acceptor: Option<TlsAcceptor> = if tls_enabled {
        let cfg = tls::build_server_config(&state.config.tls)
            .map_err(|e| -> Box<dyn std::error::Error> { Box::new(e) })?;
        Some(TlsAcceptor::from(cfg))
    } else {
        tracing::warn!(
            "⚠ TLS DISABLED — qpl-node is accepting plaintext JSON-RPC. \
             This mode is for LOCAL DEVELOPMENT ONLY. Never run with \
             tls.enabled=false in production."
        );
        None
    };

    let server_state = Arc::new(ServerState {
        node: state,
        start_time: std::time::Instant::now(),
    });

    let listener = TcpListener::bind(&addr).await?;
    tracing::info!(
        %addr,
        tls = tls_enabled,
        "QPL node listening (JSON-RPC over {})",
        if tls_enabled { "TLS" } else { "TCP" }
    );

    loop {
        let (stream, peer) = listener.accept().await?;
        let state = server_state.clone();
        let acceptor = acceptor.clone();

        tokio::spawn(async move {
            tracing::debug!(%peer, "client connected");
            let result = match acceptor {
                Some(a) => match a.accept(stream).await {
                    Ok(tls_stream) => handle_connection(state, tls_stream).await,
                    Err(e) => {
                        // Handshake failed — log internally, drop client.
                        tracing::error!(%peer, error = ?e, "TLS handshake failed");
                        return;
                    }
                },
                None => handle_connection(state, stream).await,
            };
            if let Err(e) = result {
                tracing::debug!(%peer, error = %e, "connection ended");
            }
        });
    }
}

async fn handle_connection<S>(
    state: Arc<ServerState>,
    stream: S,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let response = handle_line(&state, &line).await;
        writer.write_all(response.as_bytes()).await?;
        writer.write_all(b"\n").await?;
    }

    Ok(())
}

// ─── Request Router ────────────────────────────────────────────────────────

/// Inner JSON-RPC body.
#[derive(Deserialize)]
struct RpcRequest {
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

async fn handle_line(state: &ServerState, data: &str) -> String {
    // Try the authenticated envelope first.
    match serde_json::from_str::<AuthEnvelope>(data) {
        Ok(env) => handle_authenticated(state, env).await,
        Err(_) => handle_unauthenticated_or_reject(state, data).await,
    }
}

/// Path A: a parseable [`AuthEnvelope`] arrived. Verify auth, rate
/// limit, dispatch.
async fn handle_authenticated(state: &ServerState, env: AuthEnvelope) -> String {
    // Parse the inner request first so the auth pre-image is well-defined.
    let inner: RpcRequest = match serde_json::from_value(env.request.clone()) {
        Ok(r) => r,
        Err(e) => return sanitized_error_response(ErrorCode::InvalidRequest, e),
    };

    // Health is exempt from auth & rate limit even when it arrives in
    // an envelope (operators MAY still wrap it for uniformity).
    if inner.method == "health" {
        return dispatch(state, &inner).await;
    }

    // Verify the auth header.
    let operator_id = match auth::verify_auth(&state.node.auth, &env.auth, &inner.method, &inner.params) {
        Ok(id) => id,
        Err(failure) => {
            state.node.metrics.record_auth_failure();
            return sanitized_error_response(auth::failure_to_code(&failure), failure);
        }
    };

    // Rate-limit AFTER auth (so unauthenticated traffic can't fill a bucket).
    if !state.node.rate_limiter.check(&operator_id) {
        state.node.metrics.record_rate_limited();
        return sanitized_error_response(
            ErrorCode::RateLimitExceeded,
            format_args!("operator={} method={}", operator_id, inner.method),
        );
    }

    dispatch(state, &inner).await
}

/// Path B: not an envelope. Allow only `{"method":"health"}` here so
/// liveness probes from k8s / load balancers keep working without
/// needing to sign requests. Anything else is rejected.
async fn handle_unauthenticated_or_reject(state: &ServerState, data: &str) -> String {
    match serde_json::from_str::<RpcRequest>(data) {
        Ok(req) if req.method == "health" => dispatch(state, &req).await,
        Ok(_) => sanitized_error_response(
            ErrorCode::AuthenticationFailed,
            "missing auth envelope on non-health method",
        ),
        Err(e) => sanitized_error_response(ErrorCode::InvalidRequest, e),
    }
}

async fn dispatch(state: &ServerState, request: &RpcRequest) -> String {
    let result = match request.method.as_str() {
        "health" => handle_health(state),
        "estimate_fee" => handle_estimate_fee(state, request.params.clone()).await,
        "sign" => handle_sign(state, request.params.clone()).await,
        "prove" => handle_prove(state, request.params.clone()).await,
        unknown => {
            return sanitized_error_response(
                ErrorCode::MethodNotFound,
                format_args!("method={}", unknown),
            )
        }
    };

    match result {
        Ok(value) => serde_json::json!({ "result": value }).to_string(),
        Err((code, detail)) => sanitized_error_response(code, detail),
    }
}

type DispatchResult = Result<serde_json::Value, (ErrorCode, String)>;

fn handle_health(state: &ServerState) -> DispatchResult {
    let resp = HealthResponse {
        status: "healthy".to_string(),
        operator_id: state.node.identity.operator_id(),
        node_name: state.node.config.name.clone(),
        requests_total: state.node.metrics.requests_total.load(Ordering::Relaxed),
        uptime_seconds: state.start_time.elapsed().as_secs(),
    };
    serde_json::to_value(resp).map_err(|e| (ErrorCode::InternalError, e.to_string()))
}

async fn handle_estimate_fee(state: &ServerState, params: serde_json::Value) -> DispatchResult {
    let req: FeeEstimateRequest = serde_json::from_value(params)
        .map_err(|e| (ErrorCode::InvalidParams, e.to_string()))?;
    let resp = handlers::estimate_fee(&state.node, &req.service_type, &req.urgency)
        .await
        .map_err(|e| (ErrorCode::InternalError, e.to_string()))?;
    serde_json::to_value(resp).map_err(|e| (ErrorCode::InternalError, e.to_string()))
}

async fn handle_sign(state: &ServerState, params: serde_json::Value) -> DispatchResult {
    state.node.metrics.record_request();
    let req: SignRequest = serde_json::from_value(params)
        .map_err(|e| (ErrorCode::InvalidParams, e.to_string()))?;
    match handlers::handle_sign(&state.node, req).await {
        Ok(resp) => {
            state.node.metrics.record_success();
            serde_json::to_value(resp).map_err(|e| (ErrorCode::InternalError, e.to_string()))
        }
        Err(e) => {
            state.node.metrics.record_failure();
            Err((ErrorCode::InternalError, e.to_string()))
        }
    }
}

async fn handle_prove(state: &ServerState, params: serde_json::Value) -> DispatchResult {
    state.node.metrics.record_request();
    let req: ProveRequest = serde_json::from_value(params)
        .map_err(|e| (ErrorCode::InvalidParams, e.to_string()))?;
    match handlers::handle_prove(&state.node, req).await {
        Ok(resp) => {
            state.node.metrics.record_success();
            serde_json::to_value(resp).map_err(|e| (ErrorCode::InternalError, e.to_string()))
        }
        Err(e) => {
            state.node.metrics.record_failure();
            Err((ErrorCode::InternalError, e.to_string()))
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{canonical_preimage, dev_signature};
    use crate::config::NodeConfig;
    use crate::identity::OperatorIdentity;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now_ns() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }

    fn make_state(authorized: Vec<(String, Vec<u8>)>, burst: u32, refill: u32) -> ServerState {
        let mut cfg = NodeConfig::default();
        cfg.tls.enabled = false;
        cfg.rate_limit.refill_per_sec = refill;
        cfg.rate_limit.burst_capacity = burst;
        for (id, pk) in authorized {
            cfg.authorized_operators.insert(id, hex::encode(pk));
        }
        let identity = OperatorIdentity::generate().unwrap();
        let node = NodeState::new(identity, cfg);
        ServerState {
            node,
            start_time: std::time::Instant::now(),
        }
    }

    fn build_envelope_line(operator_id: &str, pubkey: &[u8], method: &str, params: serde_json::Value) -> String {
        let ts = now_ns();
        let preimage = canonical_preimage(method, &params, ts).unwrap();
        let sig = dev_signature(pubkey, &preimage);
        let env = serde_json::json!({
            "auth": {
                "operator_id": operator_id,
                "timestamp_nanos": ts,
                "signature": hex::encode(sig),
            },
            "request": {
                "method": method,
                "params": params,
            }
        });
        env.to_string()
    }

    #[tokio::test]
    async fn unauthenticated_health_works() {
        let state = make_state(vec![], 100, 100);
        let line = r#"{"method":"health"}"#;
        let resp = handle_line(&state, line).await;
        assert!(resp.contains("\"result\""));
        assert!(resp.contains("healthy"));
    }

    #[tokio::test]
    async fn unauthenticated_sign_rejected() {
        let state = make_state(vec![], 100, 100);
        let line = r#"{"method":"sign","params":{}}"#;
        let resp = handle_line(&state, line).await;
        assert!(resp.contains("-32001"));
        assert!(resp.contains("authentication failed"));
    }

    #[tokio::test]
    async fn auth_rejects_bad_signature() {
        let pk = vec![0x11u8; 32];
        let op = "55".repeat(32);
        let state = make_state(vec![(op.clone(), pk.clone())], 100, 100);

        let ts = now_ns();
        let env = serde_json::json!({
            "auth": {
                "operator_id": op,
                "timestamp_nanos": ts,
                "signature": hex::encode([0u8; 32]),
            },
            "request": { "method": "estimate_fee", "params": {"service_type":"sign","urgency":"standard"} }
        }).to_string();
        let resp = handle_line(&state, &env).await;
        assert!(resp.contains("-32001"));
    }

    #[tokio::test]
    async fn auth_rejects_stale_timestamp() {
        let pk = vec![0x22u8; 32];
        let op = "66".repeat(32);
        let state = make_state(vec![(op.clone(), pk.clone())], 100, 100);

        let stale = now_ns().saturating_sub(60 * 1_000_000_000);
        let params = serde_json::json!({"service_type":"sign","urgency":"standard"});
        let preimage = canonical_preimage("estimate_fee", &params, stale).unwrap();
        let sig = dev_signature(&pk, &preimage);
        let env = serde_json::json!({
            "auth": {
                "operator_id": op,
                "timestamp_nanos": stale,
                "signature": hex::encode(sig),
            },
            "request": { "method": "estimate_fee", "params": params }
        }).to_string();
        let resp = handle_line(&state, &env).await;
        assert!(resp.contains("-32001"));
    }

    #[tokio::test]
    async fn rate_limiter_rejects_after_burst() {
        let pk = vec![0x33u8; 32];
        let op = "77".repeat(32);
        // Burst of 2, refill 0/s → 3rd request must hit -32002.
        let state = make_state(vec![(op.clone(), pk.clone())], 2, 0);

        for _ in 0..2 {
            let line = build_envelope_line(&op, &pk, "estimate_fee",
                serde_json::json!({"service_type":"sign","urgency":"standard"}));
            let resp = handle_line(&state, &line).await;
            assert!(resp.contains("\"result\""), "unexpected: {}", resp);
        }
        let line = build_envelope_line(&op, &pk, "estimate_fee",
            serde_json::json!({"service_type":"sign","urgency":"standard"}));
        let resp = handle_line(&state, &line).await;
        assert!(resp.contains("-32002"), "expected rate-limit, got: {}", resp);
        assert_eq!(
            state.node.metrics.rate_limited_total.load(Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn unknown_method_returns_minus_32601() {
        let pk = vec![0x44u8; 32];
        let op = "88".repeat(32);
        let state = make_state(vec![(op.clone(), pk.clone())], 100, 100);
        let line = build_envelope_line(&op, &pk, "wormhole", serde_json::json!({}));
        let resp = handle_line(&state, &line).await;
        assert!(resp.contains("-32601"));
        assert!(resp.contains("method not found"));
    }
}
