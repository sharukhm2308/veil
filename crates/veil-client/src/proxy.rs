//! HTTP proxy that encrypts OpenAI-compatible requests.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

use veil_core::{ClientSession, VeilEnvelope};

use crate::config::ClientConfig;

/// Shared state for the proxy.
struct ProxyState {
    config: ClientConfig,
    http_client: reqwest::Client,
}

/// Start the Veil client proxy server.
pub async fn run_proxy(config: ClientConfig) -> Result<()> {
    let addr: SocketAddr = config
        .listen_addr
        .parse()
        .context("Invalid listen address")?;

    // Warn if public key pinning is not configured
    if config.expected_server_public_key.is_none() {
        warn!(
            "No expected_server_public_key configured. \
             Public key pinning is disabled — server key will not be verified."
        );
    } else {
        info!("Public key pinning is enabled");
    }

    let state = Arc::new(ProxyState {
        config,
        http_client: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(300))
            .build()?,
    });

    let listener = TcpListener::bind(addr)
        .await
        .context("Failed to bind listener")?;

    info!(listen_addr = %addr, "Veil client proxy listening");

    loop {
        let (stream, peer) = listener.accept().await?;
        let state = Arc::clone(&state);
        debug!("Connection from {}", peer);

        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req| {
                let state = Arc::clone(&state);
                async move { handle_request(req, state).await }
            });

            if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                error!("Connection error: {}", e);
            }
        });
    }
}

/// Handle an incoming request: encrypt and forward.
async fn handle_request(
    req: Request<Incoming>,
    state: Arc<ProxyState>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let result = process_request(req, &state).await;

    match result {
        Ok(response) => Ok(response),
        Err(e) => {
            error!("Request processing error: {}", e);
            let body = serde_json::json!({
                "error": {
                    "message": format!("Veil proxy error: {}", e),
                    "type": "veil_proxy_error"
                }
            });
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(body.to_string())))
                .unwrap())
        }
    }
}

async fn process_request(
    req: Request<Incoming>,
    state: &ProxyState,
) -> Result<Response<Full<Bytes>>> {
    // Verify public key pinning if configured
    if let Some(ref expected_key) = state.config.expected_server_public_key {
        if state.config.server_public_key != *expected_key {
            anyhow::bail!(
                "Server public key mismatch! Expected pinned key does not match configured key. \
                 Possible MITM attack or misconfiguration."
            );
        }
    }

    // Read the full request body
    let body_bytes = req
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read request body: {}", e))?
        .to_bytes();

    // Parse to extract model name for metadata
    let body_json: serde_json::Value =
        serde_json::from_slice(&body_bytes).context("Request body is not valid JSON")?;

    let model = body_json
        .get("model")
        .and_then(|v| v.as_str())
        .or(state.config.default_model.as_deref())
        .unwrap_or("unknown")
        .to_string();

    // Estimate token count from body size (rough: ~4 chars per token)
    let token_estimate = (body_bytes.len() / 4) as u32;

    // Create a new session (ephemeral key per request = forward secrecy)
    let mut session =
        ClientSession::new(&state.config.server_public_key, &state.config.server_key_id)
            .context("Failed to create Veil session")?;

    // Encrypt the request
    let (envelope, metadata) = session
        .encrypt_request(&body_bytes, &model, Some(token_estimate))
        .context("Failed to encrypt request")?;

    // Serialize envelope to JSON for transport
    let envelope_json = envelope.to_json().context("Failed to serialize envelope")?;

    // Build upstream request with Veil headers
    let mut upstream_req = state
        .http_client
        .post(format!("{}/v1/veil/inference", state.config.upstream_url))
        .header("Content-Type", "application/octet-stream");

    for (key, value) in metadata.to_headers() {
        upstream_req = upstream_req.header(&key, &value);
    }

    // Send encrypted request upstream
    let upstream_resp = upstream_req
        .body(envelope_json)
        .send()
        .await
        .context("Failed to send request to upstream")?;

    let status = upstream_resp.status();
    let resp_bytes = upstream_resp
        .bytes()
        .await
        .context("Failed to read upstream response")?;

    if !status.is_success() {
        return Ok(Response::builder()
            .status(StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY))
            .header("content-type", "application/json")
            .body(Full::new(resp_bytes))
            .unwrap());
    }

    // Decrypt the response envelope
    let resp_envelope =
        VeilEnvelope::from_json(std::str::from_utf8(&resp_bytes).context("Response is not UTF-8")?)
            .context("Failed to parse response envelope")?;

    let plaintext = session
        .decrypt_response(&resp_envelope)
        .context("Failed to decrypt response")?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(plaintext)))
        .unwrap())
}
