//! Etherscan ABI fetcher using API v2
//!
//! Uses the unified Etherscan API v2 endpoint which works for all supported chains.

use crate::config::Chain;
use crate::error::{AbiError, Result};
use alloy::json_abi::JsonAbi;
use serde::Deserialize;
use std::path::Path;
use std::time::Duration;

/// Etherscan API response
#[derive(Debug, Deserialize)]
struct EtherscanResponse {
    status: String,
    message: String,
    result: serde_json::Value,
}

/// ABI fetcher from Etherscan and local files
pub struct AbiFetcher {
    /// HTTP client
    client: reqwest::Client,
    /// Etherscan API key (optional)
    api_key: Option<String>,
}

impl AbiFetcher {
    /// Create a new ABI fetcher
    pub fn new(api_key: Option<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to build HTTP client");

        Self { client, api_key }
    }

    /// Fetch ABI from Etherscan API v2
    ///
    /// Works without an API key (rate limited to ~5 calls/sec)
    /// With API key: ~100 calls/sec
    pub async fn fetch_from_etherscan(&self, chain: Chain, address: &str) -> Result<JsonAbi> {
        let chain_id = chain.chain_id();

        // Build URL with API v2
        let mut url = format!(
            "https://api.etherscan.io/v2/api?chainid={}&module=contract&action=getabi&address={}",
            chain_id, address
        );

        // Add API key if available
        if let Some(key) = &self.api_key {
            url.push_str(&format!("&apikey={}", key));
        }

        tracing::debug!("Fetching ABI from Etherscan for {} on chain {}", address, chain_id);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| AbiError::EtherscanFetch(format!("Request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(AbiError::EtherscanFetch(format!(
                "HTTP error: {}",
                response.status()
            ))
            .into());
        }

        let etherscan_response: EtherscanResponse = response
            .json()
            .await
            .map_err(|e| AbiError::EtherscanFetch(format!("Failed to parse response: {}", e)))?;

        // Check for errors
        if etherscan_response.status != "1" {
            let message = etherscan_response.message;
            let result = etherscan_response.result.as_str().unwrap_or("Unknown error");

            if result.contains("not verified") || message.contains("not verified") {
                return Err(AbiError::ContractNotVerified(address.to_string()).into());
            }

            return Err(AbiError::EtherscanFetch(format!("{}: {}", message, result)).into());
        }

        // Parse ABI from result
        let abi_str = etherscan_response
            .result
            .as_str()
            .ok_or_else(|| AbiError::ParseError("ABI result is not a string".to_string()))?;

        let abi: JsonAbi = serde_json::from_str(abi_str)
            .map_err(|e| AbiError::ParseError(format!("Failed to parse ABI JSON: {}", e)))?;

        Ok(abi)
    }

    /// Load ABI from a local file
    pub fn load_from_file(&self, path: &Path) -> Result<JsonAbi> {
        if !path.exists() {
            return Err(AbiError::FileNotFound(path.display().to_string()).into());
        }

        let content = std::fs::read_to_string(path)
            .map_err(|e| AbiError::FileNotFound(format!("{}: {}", path.display(), e)))?;

        // Try to parse as JSON ABI
        let abi: JsonAbi = serde_json::from_str(&content)
            .map_err(|e| AbiError::ParseError(format!("Invalid ABI JSON: {}", e)))?;

        Ok(abi)
    }

    /// Get events from an ABI
    pub fn get_events(abi: &JsonAbi) -> Vec<&alloy::json_abi::Event> {
        abi.events().collect()
    }

    /// Find an event by name in an ABI
    pub fn find_event<'a>(abi: &'a JsonAbi, name: &str) -> Option<&'a alloy::json_abi::Event> {
        abi.events().find(|e| e.name == name)
    }

    /// Get the event selector (topic0) for an event
    pub fn event_selector(event: &alloy::json_abi::Event) -> alloy::primitives::B256 {
        event.selector()
    }
}

impl Default for AbiFetcher {
    fn default() -> Self {
        Self::new(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fetcher_creation() {
        let fetcher = AbiFetcher::new(Some("test_key".to_string()));
        assert!(fetcher.api_key.is_some());

        let fetcher = AbiFetcher::default();
        assert!(fetcher.api_key.is_none());
    }

    // Integration test (requires network)
    #[tokio::test]
    #[ignore]
    async fn test_fetch_usdc_abi() {
        let fetcher = AbiFetcher::default();
        let result = fetcher
            .fetch_from_etherscan(
                Chain::Ethereum,
                "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            )
            .await;

        assert!(result.is_ok());
        let abi = result.unwrap();
        let events: Vec<_> = AbiFetcher::get_events(&abi);
        assert!(!events.is_empty());

        // Should have Transfer event
        let transfer = AbiFetcher::find_event(&abi, "Transfer");
        assert!(transfer.is_some());
    }
}
