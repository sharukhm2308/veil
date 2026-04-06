//! Server configuration.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use veil_core::keys::StaticKeyPair;

/// Configuration for an additional server key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyConfig {
    /// Base64-encoded secret key.
    pub secret_key: String,
    /// Key identifier.
    pub key_id: String,
}

/// Server configuration loaded from TOML file or environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Address to listen on.
    pub listen_addr: String,

    /// URL of the actual LLM inference backend.
    pub backend_url: String,

    /// Server's static secret key (base64).
    /// In production, load from a secure secret store.
    pub server_secret_key: String,

    /// Key ID advertised to clients.
    pub key_id: String,

    /// Maximum request body size in bytes (default: 10MB).
    pub max_body_size: Option<usize>,

    /// Request timeout in seconds (default: 300).
    pub request_timeout_secs: Option<u64>,

    /// Enable Prometheus metrics endpoint.
    pub metrics_enabled: Option<bool>,

    /// Maximum age of a request in seconds for replay protection (default: 300).
    pub max_request_age_secs: Option<u64>,

    /// Additional key pairs for key rotation support.
    pub additional_keys: Option<Vec<KeyConfig>>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8481".to_string(),
            backend_url: "http://127.0.0.1:8000".to_string(),
            server_secret_key: String::new(),
            key_id: "default".to_string(),
            max_body_size: Some(10 * 1024 * 1024),
            request_timeout_secs: Some(300),
            metrics_enabled: Some(true),
            max_request_age_secs: Some(300),
            additional_keys: None,
        }
    }
}

impl ServerConfig {
    /// Load configuration from a TOML file.
    pub fn from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path))?;
        toml::from_str(&content).with_context(|| format!("Failed to parse config file: {}", path))
    }

    /// Resolve the server secret key, checking `VEIL_SERVER_SECRET_KEY`
    /// environment variable first, falling back to config file value.
    pub fn resolve_secret_key(&self) -> String {
        std::env::var("VEIL_SERVER_SECRET_KEY").unwrap_or_else(|_| self.server_secret_key.clone())
    }

    /// Load the primary server key pair from the resolved secret key.
    pub fn load_keypair(&self) -> Result<StaticKeyPair> {
        let secret = self.resolve_secret_key();
        StaticKeyPair::from_secret_base64(&secret)
            .map_err(|e| anyhow::anyhow!("Failed to load server key pair: {}", e))
    }

    /// Load all configured key pairs (primary + additional).
    pub fn load_all_keypairs(&self) -> Result<Vec<(String, StaticKeyPair)>> {
        let mut pairs = Vec::new();

        // Primary key
        let primary = self.load_keypair()?;
        pairs.push((self.key_id.clone(), primary));

        // Additional keys for rotation
        if let Some(ref additional) = self.additional_keys {
            for kc in additional {
                let kp = StaticKeyPair::from_secret_base64(&kc.secret_key)
                    .map_err(|e| anyhow::anyhow!("Failed to load key '{}': {}", kc.key_id, e))?;
                pairs.push((kc.key_id.clone(), kp));
            }
        }

        Ok(pairs)
    }

    /// Get the max body size with default.
    pub fn max_body_size(&self) -> usize {
        self.max_body_size.unwrap_or(10 * 1024 * 1024)
    }

    /// Get the request timeout.
    pub fn request_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.request_timeout_secs.unwrap_or(300))
    }

    /// Get the maximum request age for replay protection.
    pub fn max_request_age(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.max_request_age_secs.unwrap_or(300))
    }
}
