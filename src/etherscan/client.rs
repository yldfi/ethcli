//! Extended Etherscan client
//!
//! Wraps `foundry-block-explorers::Client` with additional functionality:
//! - Signature cache for function/event lookups
//! - 4byte.directory integration
//! - Token metadata via eth_call proxy

use crate::config::Chain;
use crate::error::{AbiError, Result};
use crate::etherscan::SignatureCache;
use alloy_chains::Chain as AlloyChain;
use foundry_block_explorers::Client as EtherscanClient;
use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

/// Token metadata (ERC20/ERC721/ERC1155)
#[derive(Debug, Clone)]
pub struct TokenMetadata {
    /// Token name
    pub name: Option<String>,
    /// Token symbol
    pub symbol: Option<String>,
    /// Token decimals (for ERC20)
    pub decimals: Option<u8>,
}

/// Extended Etherscan client with signature caching and 4byte lookups
pub struct Client {
    /// Inner foundry-block-explorers client
    inner: EtherscanClient,
    /// HTTP client for 4byte.directory and eth_call
    http: reqwest::Client,
    /// Signature cache
    cache: Arc<SignatureCache>,
    /// Chain
    chain: Chain,
    /// API key (if any)
    api_key: Option<String>,
}

impl Client {
    /// Create a new client for the given chain
    pub fn new(chain: Chain, api_key: Option<String>) -> Result<Self> {
        // Convert our Chain enum to alloy_chains::Chain for foundry-block-explorers
        let alloy_chain = AlloyChain::from_id(chain.chain_id());

        let inner = EtherscanClient::builder()
            .chain(alloy_chain)
            .map_err(|e| AbiError::EtherscanFetch(format!("Unsupported chain: {}", e)))?
            .with_api_key(api_key.as_deref().unwrap_or_default())
            .build()
            .map_err(|e| AbiError::EtherscanFetch(format!("Failed to build client: {}", e)))?;

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| AbiError::HttpClientInit(e.to_string()))?;

        Ok(Self {
            inner,
            http,
            cache: Arc::new(SignatureCache::new()),
            chain,
            api_key,
        })
    }

    /// Create a new client with a shared cache
    pub fn with_cache(
        chain: Chain,
        api_key: Option<String>,
        cache: Arc<SignatureCache>,
    ) -> Result<Self> {
        let mut client = Self::new(chain, api_key)?;
        client.cache = cache;
        Ok(client)
    }

    /// Get the inner foundry-block-explorers client
    pub fn inner(&self) -> &EtherscanClient {
        &self.inner
    }

    /// Get the chain
    pub fn chain(&self) -> Chain {
        self.chain
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> crate::etherscan::CacheStats {
        self.cache.stats()
    }

    /// Get the signature cache
    pub fn cache(&self) -> &SignatureCache {
        &self.cache
    }

    // ========================================================================
    // Signature lookups (our unique value-add)
    // ========================================================================

    /// Lookup function signature by 4-byte selector
    ///
    /// Checks cache first, then queries 4byte.directory.
    /// Returns the first (most popular) result.
    pub async fn lookup_selector(&self, selector: &str) -> Option<String> {
        self.lookup_selector_all(selector)
            .await
            .and_then(|v| v.into_iter().next())
    }

    /// Lookup all function signatures by 4-byte selector
    ///
    /// Returns all matching signatures from 4byte.directory, sorted by popularity.
    /// The first result is typically the most common/correct one.
    /// Note: This always queries 4byte.directory to ensure all collisions are returned.
    pub async fn lookup_selector_all(&self, selector: &str) -> Option<Vec<String>> {
        let normalized = format!(
            "0x{}",
            selector
                .strip_prefix("0x")
                .unwrap_or(selector)
                .to_lowercase()
        );

        // Always fetch from 4byte.directory to get all collisions
        // (cache only stores first result, so we skip it here)
        let url = format!(
            "https://www.4byte.directory/api/v1/signatures/?hex_signature={}",
            normalized
        );

        let response = self.http.get(&url).send().await.ok()?;
        let json: serde_json::Value = response.json().await.ok()?;

        // Get all results
        let results: Vec<String> = json["results"]
            .as_array()?
            .iter()
            .filter_map(|r| r.get("text_signature")?.as_str().map(String::from))
            .collect();

        if results.is_empty() {
            return None;
        }

        // Cache the first (most popular) result for future single lookups
        self.cache.set_function(&normalized, &results[0]);
        tracing::debug!("Cached selector {} -> {}", normalized, results[0]);

        Some(results)
    }

    /// Lookup event signature by topic0 hash
    ///
    /// Checks cache first, then queries 4byte.directory.
    /// Returns the first (most popular) result.
    pub async fn lookup_event(&self, topic0: &str) -> Option<String> {
        self.lookup_event_all(topic0)
            .await
            .and_then(|v| v.into_iter().next())
    }

    /// Lookup all event signatures by topic0 hash
    ///
    /// Returns all matching signatures from 4byte.directory, sorted by popularity.
    /// Note: This always queries 4byte.directory to ensure all collisions are returned.
    pub async fn lookup_event_all(&self, topic0: &str) -> Option<Vec<String>> {
        let normalized = format!(
            "0x{}",
            topic0.strip_prefix("0x").unwrap_or(topic0).to_lowercase()
        );

        // Always fetch from 4byte.directory to get all collisions
        // (cache only stores first result, so we skip it here)
        let url = format!(
            "https://www.4byte.directory/api/v1/event-signatures/?hex_signature={}",
            normalized
        );

        let response = self.http.get(&url).send().await.ok()?;
        let json: serde_json::Value = response.json().await.ok()?;

        // Get all results
        let results: Vec<String> = json["results"]
            .as_array()?
            .iter()
            .filter_map(|r| r.get("text_signature")?.as_str().map(String::from))
            .collect();

        if results.is_empty() {
            return None;
        }

        // Cache the first result for future single lookups
        self.cache.set_event(&normalized, &results[0]);
        tracing::debug!("Cached event {} -> {}", normalized, results[0]);

        Some(results)
    }

    // ========================================================================
    // Token metadata via eth_call (our unique value-add)
    // ========================================================================

    /// Get token metadata via RPC calls (ERC20 standard methods)
    ///
    /// Uses Etherscan's eth_call proxy to fetch name(), symbol(), decimals()
    pub async fn get_token_metadata(&self, address: &str) -> Result<TokenMetadata> {
        let chain_id = self.chain.chain_id();

        // name() = 0x06fdde03
        // symbol() = 0x95d89b41
        // decimals() = 0x313ce567

        let name = self
            .eth_call(chain_id, address, "0x06fdde03")
            .await
            .ok()
            .and_then(|data| decode_string_from_hex(&data));

        let symbol = self
            .eth_call(chain_id, address, "0x95d89b41")
            .await
            .ok()
            .and_then(|data| decode_string_from_hex(&data));

        let decimals = self
            .eth_call(chain_id, address, "0x313ce567")
            .await
            .ok()
            .and_then(|data| decode_uint8_from_hex(&data));

        Ok(TokenMetadata {
            name,
            symbol,
            decimals,
        })
    }

    /// Make an eth_call via Etherscan proxy
    async fn eth_call(&self, chain_id: u64, to: &str, data: &str) -> Result<String> {
        let encoded_to: Cow<str> = urlencoding_encode(to);
        let encoded_data: Cow<str> = urlencoding_encode(data);

        let base_url = format!(
            "https://api.etherscan.io/v2/api?chainid={}&module=proxy&action=eth_call&to={}&data={}&tag=latest",
            chain_id, encoded_to, encoded_data
        );

        let url = if let Some(key) = &self.api_key {
            let encoded_key: Cow<str> = urlencoding_encode(key);
            format!("{}&apikey={}", base_url, encoded_key)
        } else {
            base_url
        };

        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| AbiError::EtherscanFetch(format!("eth_call failed: {}", e)))?;

        let json: serde_json::Value = response.json().await.map_err(|e| {
            AbiError::EtherscanFetch(format!("Failed to parse eth_call response: {}", e))
        })?;

        // Result should be a hex string
        let result = json["result"]
            .as_str()
            .ok_or_else(|| AbiError::ParseError("Missing result in eth_call".to_string()))?;

        // Check for error
        if result == "0x" || result.len() < 3 {
            return Err(AbiError::ParseError("Empty eth_call result".to_string()).into());
        }

        Ok(result.to_string())
    }
}

// Allow accessing inner client methods directly
impl std::ops::Deref for Client {
    type Target = EtherscanClient;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// URL-encode a string for safe use in query parameters
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

/// Decode a string from ABI-encoded hex data
fn decode_string_from_hex(hex: &str) -> Option<String> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.len() < 128 {
        return decode_bytes32_string(hex);
    }

    let bytes = hex::decode(hex).ok()?;
    if bytes.len() < 64 {
        return None;
    }

    let length = u64::from_be_bytes(bytes[56..64].try_into().ok()?) as usize;
    let end = 64usize.checked_add(length)?;
    if bytes.len() < end {
        return None;
    }

    let string_bytes = &bytes[64..end];
    String::from_utf8(string_bytes.to_vec())
        .ok()
        .map(|s| s.trim_end_matches('\0').to_string())
        .filter(|s| !s.is_empty())
}

/// Decode a bytes32 as a string
fn decode_bytes32_string(hex: &str) -> Option<String> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.len() != 64 {
        return None;
    }

    let bytes = hex::decode(hex).ok()?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(32);
    String::from_utf8(bytes[..end].to_vec())
        .ok()
        .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_graphic() || c == ' '))
}

/// Decode a uint8 from hex data
fn decode_uint8_from_hex(hex: &str) -> Option<u8> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.is_empty() {
        return None;
    }

    let trimmed = hex.trim_start_matches('0');
    if trimmed.is_empty() {
        return Some(0);
    }

    let value = u64::from_str_radix(trimmed, 16).ok()?;
    if value > 255 {
        return None;
    }
    Some(value as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_string() {
        // "USDC" encoded as ABI string
        let hex = "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000455534443000000000000000000000000000000000000000000000000000000";
        let result = decode_string_from_hex(hex);
        assert_eq!(result, Some("USDC".to_string()));
    }

    #[test]
    fn test_decode_uint8() {
        assert_eq!(decode_uint8_from_hex("0x06"), Some(6));
        assert_eq!(decode_uint8_from_hex("0x12"), Some(18));
        assert_eq!(decode_uint8_from_hex("0x00"), Some(0));
    }
}
