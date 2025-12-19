//! RPC endpoint configuration

use serde::{Deserialize, Serialize};

/// Configuration for a single RPC endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointConfig {
    /// RPC URL
    pub url: String,
    /// Maximum block range for getLogs
    #[serde(default = "default_max_block_range")]
    pub max_block_range: u64,
    /// Maximum number of logs in response
    #[serde(default = "default_max_logs")]
    pub max_logs: usize,
    /// Priority (higher = preferred)
    #[serde(default = "default_priority")]
    pub priority: u8,
    /// Optional note about the endpoint
    #[serde(default)]
    pub note: Option<String>,
    /// Optional endpoint-specific proxy
    #[serde(default)]
    pub proxy: Option<String>,
    /// Whether this endpoint is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_max_block_range() -> u64 {
    10_000
}

fn default_max_logs() -> usize {
    10_000
}

fn default_priority() -> u8 {
    5
}

fn default_enabled() -> bool {
    true
}

impl EndpointConfig {
    /// Create a new endpoint config with defaults
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            max_block_range: default_max_block_range(),
            max_logs: default_max_logs(),
            priority: default_priority(),
            note: None,
            proxy: None,
            enabled: true,
        }
    }

    /// Builder-style setter for max_block_range
    pub fn with_max_block_range(mut self, range: u64) -> Self {
        self.max_block_range = range;
        self
    }

    /// Builder-style setter for max_logs
    pub fn with_max_logs(mut self, max: usize) -> Self {
        self.max_logs = max;
        self
    }

    /// Builder-style setter for priority
    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    /// Builder-style setter for note
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    /// Builder-style setter for proxy
    pub fn with_proxy(mut self, proxy: impl Into<String>) -> Self {
        self.proxy = Some(proxy.into());
        self
    }

    /// Check if endpoint is suitable for a given block range
    pub fn can_handle_range(&self, range: u64) -> bool {
        self.max_block_range == 0 || range <= self.max_block_range
    }

    /// Check if endpoint is suitable for a given log count
    pub fn can_handle_logs(&self, count: usize) -> bool {
        self.max_logs == 0 || count <= self.max_logs
    }
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self::new("http://localhost:8545")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_config() {
        let config = EndpointConfig::new("https://example.com/rpc")
            .with_max_block_range(1_000_000)
            .with_max_logs(50_000)
            .with_priority(10);

        assert_eq!(config.url, "https://example.com/rpc");
        assert_eq!(config.max_block_range, 1_000_000);
        assert_eq!(config.max_logs, 50_000);
        assert_eq!(config.priority, 10);
        assert!(config.enabled);
    }

    #[test]
    fn test_can_handle_range() {
        let config = EndpointConfig::new("test").with_max_block_range(10_000);

        assert!(config.can_handle_range(5_000));
        assert!(config.can_handle_range(10_000));
        assert!(!config.can_handle_range(15_000));

        // Unlimited
        let unlimited = EndpointConfig::new("test").with_max_block_range(0);
        assert!(unlimited.can_handle_range(1_000_000_000));
    }
}
