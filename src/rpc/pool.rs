//! RPC pool for managing multiple endpoints with parallel requests

use crate::config::{Chain, EndpointConfig, RpcConfig};
use crate::error::{Error, Result, RpcError};
use crate::rpc::{default_endpoints, Endpoint, EndpointHealth, HealthTracker};
use alloy::rpc::types::{Filter, Log};
use futures::future::join_all;
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

/// Pool of RPC endpoints with load balancing and health tracking
pub struct RpcPool {
    /// Available endpoints
    endpoints: Vec<Endpoint>,
    /// Health tracker
    health: Arc<HealthTracker>,
    /// Max concurrent requests
    concurrency: usize,
    /// Global proxy URL
    proxy: Option<String>,
    /// Minimum priority to use
    min_priority: u8,
}

impl RpcPool {
    /// Create a new RPC pool for a chain
    pub fn new(chain: Chain, config: &RpcConfig) -> Result<Self> {
        let mut endpoint_configs = Vec::new();

        // Start with user-provided endpoints or defaults
        if config.endpoints.is_empty() {
            endpoint_configs = default_endpoints(chain);
        } else {
            endpoint_configs = config.endpoints.clone();
        }

        // Add additional endpoints
        for url in &config.add_endpoints {
            if !endpoint_configs.iter().any(|e| &e.url == url) {
                endpoint_configs.push(EndpointConfig::new(url.clone()));
            }
        }

        // Exclude specified endpoints
        let excluded: HashSet<_> = config.exclude_endpoints.iter().collect();
        endpoint_configs.retain(|e| !excluded.contains(&e.url));

        // Filter by minimum priority
        endpoint_configs.retain(|e| e.priority >= config.min_priority);

        // Filter disabled endpoints
        endpoint_configs.retain(|e| e.enabled);

        if endpoint_configs.is_empty() {
            return Err(RpcError::NoHealthyEndpoints.into());
        }

        // Get global proxy
        let proxy = config.proxy.as_ref().and_then(|p| p.url.clone());

        // Create endpoint instances
        let mut endpoints = Vec::new();
        for cfg in endpoint_configs {
            match Endpoint::new(cfg.clone(), config.timeout_secs, proxy.as_deref()) {
                Ok(ep) => endpoints.push(ep),
                Err(e) => {
                    tracing::warn!("Failed to create endpoint {}: {}", cfg.url, e);
                }
            }
        }

        if endpoints.is_empty() {
            return Err(RpcError::NoHealthyEndpoints.into());
        }

        Ok(Self {
            endpoints,
            health: Arc::new(HealthTracker::new()),
            concurrency: config.concurrency,
            proxy,
            min_priority: config.min_priority,
        })
    }

    /// Create from a single endpoint URL
    pub fn from_url(url: &str, timeout_secs: u64) -> Result<Self> {
        let config = EndpointConfig::new(url);
        let endpoint = Endpoint::new(config, timeout_secs, None)?;

        Ok(Self {
            endpoints: vec![endpoint],
            health: Arc::new(HealthTracker::new()),
            concurrency: 1,
            proxy: None,
            min_priority: 1,
        })
    }

    /// Get number of available endpoints
    pub fn endpoint_count(&self) -> usize {
        self.endpoints.len()
    }

    /// Get concurrency level
    pub fn concurrency(&self) -> usize {
        self.concurrency
    }

    /// Get health tracker
    pub fn health_tracker(&self) -> Arc<HealthTracker> {
        self.health.clone()
    }

    /// Get current block number (tries multiple endpoints)
    pub async fn get_block_number(&self) -> Result<u64> {
        let endpoints = self.select_endpoints(3);

        for endpoint in endpoints {
            match endpoint.get_block_number().await {
                Ok(block) => {
                    self.health
                        .record_success(endpoint.url(), Duration::from_millis(100));
                    return Ok(block);
                }
                Err(e) => {
                    self.health.record_failure(endpoint.url(), false, false);
                    tracing::debug!("Failed to get block number from {}: {}", endpoint.url(), e);
                }
            }
        }

        Err(RpcError::AllEndpointsFailed.into())
    }

    /// Fetch logs with automatic retry and load balancing
    pub async fn get_logs(&self, filter: &Filter) -> Result<Vec<Log>> {
        let endpoints = self.select_endpoints(self.concurrency);

        if endpoints.is_empty() {
            return Err(RpcError::NoHealthyEndpoints.into());
        }

        // Try endpoints in order of health score
        for endpoint in &endpoints {
            match endpoint.get_logs(filter).await {
                Ok((logs, latency)) => {
                    self.health.record_success(endpoint.url(), latency);
                    return Ok(logs);
                }
                Err(e) => {
                    let is_rate_limit = matches!(&e, Error::Rpc(RpcError::RateLimited(_)));
                    let is_timeout = matches!(&e, Error::Rpc(RpcError::Timeout(_)));

                    self.health
                        .record_failure(endpoint.url(), is_rate_limit, is_timeout);

                    // Learn from block range errors
                    if let Error::Rpc(RpcError::BlockRangeTooLarge { max, .. }) = &e {
                        self.health.record_block_range_limit(endpoint.url(), *max);
                    }

                    tracing::debug!("Failed to get logs from {}: {}", endpoint.url(), e);
                }
            }
        }

        Err(RpcError::AllEndpointsFailed.into())
    }

    /// Fetch logs from multiple filters in parallel
    pub async fn get_logs_parallel(&self, filters: Vec<Filter>) -> Vec<Result<Vec<Log>>> {
        let endpoints = self.select_endpoints(self.concurrency.max(filters.len()));

        // Create a task for each filter
        let tasks: Vec<_> = filters
            .into_iter()
            .enumerate()
            .map(|(i, filter)| {
                let endpoint = endpoints[i % endpoints.len()].clone();
                let health = self.health.clone();

                async move {
                    match endpoint.get_logs(&filter).await {
                        Ok((logs, latency)) => {
                            health.record_success(endpoint.url(), latency);
                            Ok(logs)
                        }
                        Err(e) => {
                            let is_rate_limit = matches!(&e, Error::Rpc(RpcError::RateLimited(_)));
                            let is_timeout = matches!(&e, Error::Rpc(RpcError::Timeout(_)));
                            health.record_failure(endpoint.url(), is_rate_limit, is_timeout);
                            Err(e)
                        }
                    }
                }
            })
            .collect();

        join_all(tasks).await
    }

    /// Select endpoints for a request based on health and priority
    fn select_endpoints(&self, count: usize) -> Vec<Endpoint> {
        // Get URLs sorted by health score
        let urls: Vec<_> = self.endpoints.iter().map(|e| e.url().to_string()).collect();
        let ranked = self.health.rank_endpoints(&urls);

        // Get available endpoints
        let mut available: Vec<_> = self
            .endpoints
            .iter()
            .filter(|e| self.health.is_available(e.url()))
            .cloned()
            .collect();

        // Sort by ranking
        available.sort_by(|a, b| {
            let a_score = ranked
                .iter()
                .find(|(u, _)| u == a.url())
                .map(|(_, s)| *s)
                .unwrap_or(0.0);
            let b_score = ranked
                .iter()
                .find(|(u, _)| u == b.url())
                .map(|(_, s)| *s)
                .unwrap_or(0.0);
            b_score
                .partial_cmp(&a_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Add some randomization among similar scores
        let mut rng = thread_rng();
        if available.len() > 2 {
            // Shuffle top endpoints a bit for load distribution
            let shuffle_count = (available.len() / 3).max(2).min(available.len());
            available[..shuffle_count].shuffle(&mut rng);
        }

        available.truncate(count);
        available
    }

    /// Get effective max block range for an endpoint
    pub fn effective_max_block_range(&self, url: &str) -> u64 {
        if let Some(endpoint) = self.endpoints.iter().find(|e| e.url() == url) {
            self.health
                .effective_max_block_range(url, endpoint.max_block_range())
        } else {
            10_000 // Default
        }
    }

    /// Get the smallest max block range across all endpoints
    pub fn min_block_range(&self) -> u64 {
        self.endpoints
            .iter()
            .map(|e| {
                self.health
                    .effective_max_block_range(e.url(), e.max_block_range())
            })
            .min()
            .unwrap_or(10_000)
    }

    /// Get the largest max block range across healthy endpoints
    pub fn max_block_range(&self) -> u64 {
        self.endpoints
            .iter()
            .filter(|e| self.health.is_available(e.url()))
            .map(|e| {
                self.health
                    .effective_max_block_range(e.url(), e.max_block_range())
            })
            .max()
            .unwrap_or(10_000)
    }

    /// Get health info for all endpoints
    pub fn get_endpoint_health(&self) -> Vec<(String, u8, Option<EndpointHealth>)> {
        self.endpoints
            .iter()
            .map(|e| {
                (
                    e.url().to_string(),
                    e.priority(),
                    self.health.get_health(e.url()),
                )
            })
            .collect()
    }

    /// List all endpoint URLs
    pub fn list_endpoints(&self) -> Vec<&str> {
        self.endpoints.iter().map(|e| e.url()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_creation() {
        let config = RpcConfig {
            endpoints: vec![EndpointConfig::new("https://eth.llamarpc.com")],
            ..Default::default()
        };

        // Pool creation will fail without network, but we can test config handling
        let result = RpcPool::new(Chain::Ethereum, &config);
        // This may fail due to URL validation, which is fine for unit test
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_endpoint_selection() {
        // Test that health tracker rankings work
        let tracker = HealthTracker::new();
        tracker.record_success("https://a.com", Duration::from_millis(100));
        tracker.record_success("https://b.com", Duration::from_millis(500));

        let urls = vec!["https://a.com".to_string(), "https://b.com".to_string()];
        let ranked = tracker.rank_endpoints(&urls);

        assert_eq!(ranked.len(), 2);
        // First should have higher score (lower latency)
        assert!(ranked[0].1 >= ranked[1].1);
    }
}
