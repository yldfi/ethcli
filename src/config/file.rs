//! Configuration file handling

use super::{EndpointConfig, ProxyConfig};
use crate::error::{ConfigError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Configuration file structure
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConfigFile {
    /// Global settings
    #[serde(default)]
    pub settings: Settings,

    /// Custom endpoints
    #[serde(default)]
    pub endpoints: Vec<EndpointConfig>,

    /// Disabled endpoints
    #[serde(default)]
    pub disabled_endpoints: DisabledEndpoints,

    /// Proxy configuration
    #[serde(default)]
    pub proxy: Option<ProxyFileConfig>,

    /// Etherscan API key
    #[serde(default)]
    pub etherscan_api_key: Option<String>,
}

/// Global settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    /// Default concurrency
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,

    /// Request timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,

    /// Max retry attempts
    #[serde(default = "default_retries")]
    pub retry_attempts: u32,

    /// Checkpoint save interval (blocks)
    #[serde(default = "default_checkpoint_interval")]
    pub checkpoint_interval: u64,
}

fn default_concurrency() -> usize {
    5
}

fn default_timeout() -> u64 {
    30
}

fn default_retries() -> u32 {
    3
}

fn default_checkpoint_interval() -> u64 {
    1000
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            concurrency: default_concurrency(),
            timeout_seconds: default_timeout(),
            retry_attempts: default_retries(),
            checkpoint_interval: default_checkpoint_interval(),
        }
    }
}

/// Disabled endpoints configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DisabledEndpoints {
    /// List of URLs to disable
    #[serde(default)]
    pub urls: Vec<String>,
}

/// Proxy configuration from file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyFileConfig {
    /// Default proxy URL
    #[serde(default)]
    pub default: Option<String>,

    /// Rotate between proxies
    #[serde(default)]
    pub rotate: bool,

    /// File containing proxy URLs
    #[serde(default)]
    pub file: Option<PathBuf>,
}

impl ConfigFile {
    /// Get the default config file path
    pub fn default_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("eth-log-fetcher")
            .join("config.toml")
    }

    /// Load from default path
    pub fn load_default() -> Result<Option<Self>> {
        let path = Self::default_path();
        if path.exists() {
            Ok(Some(Self::load(&path)?))
        } else {
            Ok(None)
        }
    }

    /// Load from a specific path
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::InvalidFile(format!("{}: {}", path.display(), e)))?;

        let config: Self = toml::from_str(&content).map_err(ConfigError::from)?;
        Ok(config)
    }

    /// Save to a specific path
    pub fn save(&self, path: &Path) -> Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                ConfigError::InvalidFile(format!("Failed to create directory: {}", e))
            })?;
        }

        let content = toml::to_string_pretty(self)
            .map_err(|e| ConfigError::InvalidFile(format!("Failed to serialize config: {}", e)))?;

        std::fs::write(path, content)
            .map_err(|e| ConfigError::InvalidFile(format!("Failed to write config: {}", e)))?;

        Ok(())
    }

    /// Save to default path
    pub fn save_default(&self) -> Result<()> {
        self.save(&Self::default_path())
    }

    /// Check if an endpoint URL is disabled
    pub fn is_endpoint_disabled(&self, url: &str) -> bool {
        self.disabled_endpoints.urls.iter().any(|u| u == url)
    }

    /// Convert proxy config to runtime ProxyConfig
    pub fn proxy_config(&self) -> Option<ProxyConfig> {
        self.proxy.as_ref().map(|p| ProxyConfig {
            url: p.default.clone(),
            file: p.file.clone(),
            rotate_per_request: p.rotate,
        })
    }

    /// Set the Etherscan API key and save
    pub fn set_etherscan_key(&mut self, key: String) -> Result<()> {
        self.etherscan_api_key = Some(key);
        self.save_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config() {
        let toml = r#"
etherscan_api_key = "test_key"

[settings]
concurrency = 10
timeout_seconds = 60

[[endpoints]]
url = "https://example.com/rpc"
max_block_range = 1000000
priority = 10

[disabled_endpoints]
urls = ["https://disabled.com/rpc"]
"#;

        let config: ConfigFile = toml::from_str(toml).unwrap();
        assert_eq!(config.settings.concurrency, 10);
        assert_eq!(config.endpoints.len(), 1);
        assert_eq!(config.endpoints[0].url, "https://example.com/rpc");
        assert!(config.is_endpoint_disabled("https://disabled.com/rpc"));
        assert_eq!(config.etherscan_api_key, Some("test_key".to_string()));
    }

    #[test]
    fn test_default_path() {
        let path = ConfigFile::default_path();
        assert!(path.to_string_lossy().contains("eth-log-fetcher"));
    }
}
