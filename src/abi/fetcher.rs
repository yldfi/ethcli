//! Etherscan ABI fetcher using API v2
//!
//! Uses the unified Etherscan API v2 endpoint which works for all supported chains.

use crate::config::Chain;
use crate::error::{AbiError, Result};
use alloy::json_abi::JsonAbi;
use serde::Deserialize;
use std::borrow::Cow;
use std::path::Path;
use std::time::Duration;

/// URL-encode a string for safe use in query parameters
/// Only encodes characters that are unsafe in URLs
fn urlencoding_encode(input: &str) -> Cow<'_, str> {
    let needs_encoding = input
        .bytes()
        .any(|b| !matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~'));

    if !needs_encoding {
        return Cow::Borrowed(input);
    }

    let mut encoded = String::with_capacity(input.len() * 3);
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    Cow::Owned(encoded)
}

/// Etherscan API response
#[derive(Debug, Deserialize)]
struct EtherscanResponse {
    status: String,
    message: String,
    result: serde_json::Value,
}

/// Contract creation info from Etherscan
#[derive(Debug, Clone)]
pub struct ContractCreation {
    /// Block number where contract was created
    pub block_number: u64,
    /// Transaction hash of contract creation
    pub tx_hash: String,
    /// Contract creator address
    pub creator: String,
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
    ///
    /// Returns an error if the HTTP client cannot be initialized (rare, usually
    /// indicates TLS backend issues).
    pub fn new(api_key: Option<String>) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| AbiError::HttpClientInit(e.to_string()))?;

        Ok(Self { client, api_key })
    }

    /// Fetch ABI from Etherscan API v2
    ///
    /// Works without an API key (rate limited to ~5 calls/sec)
    /// With API key: ~100 calls/sec
    pub async fn fetch_from_etherscan(&self, chain: Chain, address: &str) -> Result<JsonAbi> {
        let chain_id = chain.chain_id();

        // URL-encode the address to prevent parameter injection
        let encoded_address: Cow<str> = urlencoding_encode(address);

        // Build URL with API v2 using proper URL encoding to prevent parameter injection
        let base_url = format!(
            "https://api.etherscan.io/v2/api?chainid={}&module=contract&action=getabi&address={}",
            chain_id, encoded_address
        );

        let url = if let Some(key) = &self.api_key {
            // URL-encode the API key to prevent injection attacks
            let encoded_key: Cow<str> = urlencoding_encode(key);
            format!("{}&apikey={}", base_url, encoded_key)
        } else {
            base_url
        };

        tracing::debug!(
            "Fetching ABI from Etherscan for {} on chain {}",
            address,
            chain_id
        );

        let response = self.client.get(&url).send().await.map_err(|e| {
            AbiError::EtherscanFetch(format!(
                "Request failed: {}",
                crate::error::sanitize_error_message(&e.to_string())
            ))
        })?;

        if !response.status().is_success() {
            return Err(
                AbiError::EtherscanFetch(format!("HTTP error: {}", response.status())).into(),
            );
        }

        let etherscan_response: EtherscanResponse = response.json().await.map_err(|e| {
            AbiError::EtherscanFetch(format!(
                "Failed to parse response: {}",
                crate::error::sanitize_error_message(&e.to_string())
            ))
        })?;

        // Check for errors
        if etherscan_response.status != "1" {
            let message = etherscan_response.message;
            let result = etherscan_response
                .result
                .as_str()
                .unwrap_or("Unknown error");

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

    /// Get the full event signature string from an ABI event
    /// e.g., "Transfer(address,address,uint256)"
    pub fn event_signature_string(event: &alloy::json_abi::Event) -> String {
        let param_types: Vec<String> = event.inputs.iter().map(|p| p.ty.to_string()).collect();
        format!("{}({})", event.name, param_types.join(","))
    }

    /// Resolve an event name to its full signature using the contract ABI
    /// Returns the full signature string like "TokenExchange(address,uint256,uint256,uint256,uint256)"
    pub async fn resolve_event_name(
        &self,
        chain: Chain,
        contract: &str,
        event_name: &str,
    ) -> Result<String> {
        let abi = self.fetch_from_etherscan(chain, contract).await?;

        let event = Self::find_event(&abi, event_name).ok_or_else(|| {
            crate::error::AbiError::EventNotFound(format!(
                "Event '{}' not found in contract ABI",
                event_name
            ))
        })?;

        Ok(Self::event_signature_string(event))
    }

    /// Get contract creation info from Etherscan API v2
    pub async fn get_contract_creation(
        &self,
        chain: Chain,
        contract: &str,
    ) -> Result<ContractCreation> {
        let chain_id = chain.chain_id();
        let encoded_address: Cow<str> = urlencoding_encode(contract);

        let base_url = format!(
            "https://api.etherscan.io/v2/api?chainid={}&module=contract&action=getcontractcreation&contractaddresses={}",
            chain_id, encoded_address
        );

        let url = if let Some(key) = &self.api_key {
            let encoded_key: Cow<str> = urlencoding_encode(key);
            format!("{}&apikey={}", base_url, encoded_key)
        } else {
            base_url
        };

        tracing::debug!(
            "Fetching contract creation for {} on chain {}",
            contract,
            chain_id
        );

        let response = self.client.get(&url).send().await.map_err(|e| {
            AbiError::EtherscanFetch(format!(
                "Request failed: {}",
                crate::error::sanitize_error_message(&e.to_string())
            ))
        })?;

        if !response.status().is_success() {
            return Err(
                AbiError::EtherscanFetch(format!("HTTP error: {}", response.status())).into(),
            );
        }

        let etherscan_response: EtherscanResponse = response.json().await.map_err(|e| {
            AbiError::EtherscanFetch(format!(
                "Failed to parse response: {}",
                crate::error::sanitize_error_message(&e.to_string())
            ))
        })?;

        if etherscan_response.status != "1" {
            return Err(AbiError::EtherscanFetch(format!(
                "Failed to get contract creation: {}",
                etherscan_response.message
            ))
            .into());
        }

        // Parse the result array
        let results = etherscan_response
            .result
            .as_array()
            .ok_or_else(|| AbiError::ParseError("Expected array result".to_string()))?;

        let first = results
            .first()
            .ok_or_else(|| AbiError::ParseError("Empty result array".to_string()))?;

        // Extract fields - txHash contains the creation tx
        let tx_hash = first["txHash"]
            .as_str()
            .ok_or_else(|| AbiError::ParseError("Missing txHash".to_string()))?
            .to_string();

        let creator = first["contractCreator"]
            .as_str()
            .ok_or_else(|| AbiError::ParseError("Missing contractCreator".to_string()))?
            .to_string();

        // We need to fetch the transaction to get the block number
        // Use eth_getTransactionByHash via a simple RPC call
        let block_number = self.get_tx_block_number(chain, &tx_hash).await.unwrap_or(0);

        Ok(ContractCreation {
            block_number,
            tx_hash,
            creator,
        })
    }

    /// Get transaction block number from Etherscan
    async fn get_tx_block_number(&self, chain: Chain, tx_hash: &str) -> Result<u64> {
        let chain_id = chain.chain_id();
        let encoded_hash: Cow<str> = urlencoding_encode(tx_hash);

        let base_url = format!(
            "https://api.etherscan.io/v2/api?chainid={}&module=proxy&action=eth_getTransactionByHash&txhash={}",
            chain_id, encoded_hash
        );

        let url = if let Some(key) = &self.api_key {
            let encoded_key: Cow<str> = urlencoding_encode(key);
            format!("{}&apikey={}", base_url, encoded_key)
        } else {
            base_url
        };

        let response = self.client.get(&url).send().await.map_err(|e| {
            AbiError::EtherscanFetch(format!(
                "Request failed: {}",
                crate::error::sanitize_error_message(&e.to_string())
            ))
        })?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AbiError::EtherscanFetch(format!("Failed to parse response: {}", e)))?;

        // Extract block number from result.blockNumber (hex string)
        let block_hex = json["result"]["blockNumber"]
            .as_str()
            .ok_or_else(|| AbiError::ParseError("Missing blockNumber".to_string()))?;

        // Parse hex block number (0x...)
        let block_number = u64::from_str_radix(block_hex.trim_start_matches("0x"), 16)
            .map_err(|_| AbiError::ParseError(format!("Invalid block number: {}", block_hex)))?;

        Ok(block_number)
    }
}

impl AbiFetcher {
    /// Create a new ABI fetcher with default settings (no API key)
    ///
    /// # Panics
    /// Panics if the HTTP client cannot be initialized (extremely rare).
    pub fn new_default() -> Self {
        Self::new(None).expect("Failed to initialize HTTP client")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fetcher_creation() {
        let fetcher = AbiFetcher::new(Some("test_key".to_string())).unwrap();
        assert!(fetcher.api_key.is_some());

        let fetcher = AbiFetcher::new_default();
        assert!(fetcher.api_key.is_none());
    }

    // Integration test (requires network)
    #[tokio::test]
    #[ignore]
    async fn test_fetch_usdc_abi() {
        let fetcher = AbiFetcher::new_default();
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
