//! Axum server setup and routing.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    routing::{get, post},
    Router,
};
use tower_http::{cors::CorsLayer, limit::RequestBodyLimitLayer, trace::TraceLayer};
use tracing::info;

use crate::config::ServerConfig;
use crate::handler::{self, AppState, PreKeyPool};

/// Build and start the Veil server.
pub async fn run(config: ServerConfig) -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "veil_server=info,tower_http=info".into()),
        )
        .json()
        .init();

    // Load all key pairs (primary + additional)
    let all_keypairs = config
        .load_all_keypairs()
        .context("Failed to load server key pairs")?;

    let mut keypairs = HashMap::new();
    for (kid, kp) in all_keypairs {
        info!(
            key_id = %kid,
            public_key = %kp.public_base64(),
            "Loaded key pair"
        );
        keypairs.insert(kid, kp);
    }

    info!(
        active_key_id = %config.key_id,
        total_keys = keypairs.len(),
        "Key pairs loaded"
    );

    // Build HTTP client for backend
    let http_client = reqwest::Client::builder()
        .timeout(config.request_timeout())
        .pool_max_idle_per_host(32)
        .build()
        .context("Failed to build HTTP client")?;

    let state = Arc::new(AppState {
        keypairs,
        active_key_id: config.key_id.clone(),
        backend_url: config.backend_url.clone(),
        http_client,
        max_request_age: config.max_request_age(),
        replay_cache: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        prekey_pool: Arc::new(std::sync::Mutex::new(PreKeyPool::new(50))),
    });

    // Build router
    // TODO: Add rate limiting on /v1/veil/public-key (e.g., tower_governor or custom middleware)
    let app = Router::new()
        // Veil protocol endpoints
        .route("/v1/veil/inference", post(handler::inference))
        .route("/v1/veil/public-key", get(handler::public_key))
        .route("/v1/veil/prekeys", get(handler::prekeys))
        // Operational endpoints
        .route("/health", get(handler::health))
        .route("/metrics", get(handler::metrics_handler))
        // Middleware
        .layer(RequestBodyLimitLayer::new(config.max_body_size()))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = config
        .listen_addr
        .parse::<std::net::SocketAddr>()
        .context("Invalid listen address")?;

    info!(listen_addr = %addr, "Veil server listening");
    info!(backend = %config.backend_url, "Backend URL");
    info!(active_key = %config.key_id, "Active Key ID");
    info!(
        max_age = config.max_request_age().as_secs(),
        "Max request age (seconds)"
    );

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .context("Failed to bind listener")?;

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("Server error")?;

    info!("Server shut down gracefully");
    Ok(())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C handler");
    info!("Shutdown signal received");
}
