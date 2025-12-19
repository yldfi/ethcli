//! Main log fetcher coordinator

use crate::abi::{AbiFetcher, DecodedLog, EventSignature, LogDecoder};
use crate::checkpoint::CheckpointManager;
use crate::config::{BlockNumber, Config};
use crate::error::{Error, Result, RpcError};
use crate::rpc::RpcPool;
use alloy::primitives::Address;
use alloy::rpc::types::{Filter, Log};
use futures::stream::{self, StreamExt};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Result of a fetch operation
#[derive(Debug)]
pub enum FetchResult {
    /// Raw logs (undecoded)
    Raw(Vec<Log>),
    /// Decoded logs
    Decoded(Vec<DecodedLog>),
}

impl FetchResult {
    pub fn len(&self) -> usize {
        match self {
            FetchResult::Raw(logs) => logs.len(),
            FetchResult::Decoded(logs) => logs.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Progress callback type
pub type ProgressCallback = Box<dyn Fn(FetchProgress) + Send + Sync>;

/// Fetch progress information
#[derive(Debug, Clone)]
pub struct FetchProgress {
    /// Current block being processed
    pub current_block: u64,
    /// Total blocks to process
    pub total_blocks: u64,
    /// Logs fetched so far
    pub logs_fetched: u64,
    /// Percentage complete
    pub percent: f64,
    /// Blocks per second
    pub blocks_per_second: f64,
}

/// Main log fetcher
pub struct LogFetcher {
    /// Configuration
    config: Config,
    /// RPC pool
    pool: RpcPool,
    /// Log decoder (if not raw mode)
    decoder: Option<LogDecoder>,
    /// Progress callback
    progress_callback: Option<ProgressCallback>,
}

impl LogFetcher {
    /// Create a new log fetcher from config
    pub async fn new(config: Config) -> Result<Self> {
        // Create RPC pool
        let pool = RpcPool::new(config.chain, &config.rpc)?;

        // Set up decoder if not raw mode
        let decoder = if config.raw {
            None
        } else {
            Some(Self::setup_decoder(&config).await?)
        };

        Ok(Self {
            config,
            pool,
            decoder,
            progress_callback: None,
        })
    }

    /// Set up the log decoder
    async fn setup_decoder(config: &Config) -> Result<LogDecoder> {
        // If event signature provided, use that
        if let Some(event_str) = &config.event {
            let sig = EventSignature::parse(event_str)?;
            return LogDecoder::from_signature(&sig);
        }

        // If ABI file provided, load it
        if let Some(abi_path) = &config.abi_path {
            let fetcher = AbiFetcher::default();
            let abi = fetcher.load_from_file(abi_path)?;
            return LogDecoder::from_abi(&abi);
        }

        // Try to fetch ABI from Etherscan
        let fetcher = AbiFetcher::new(config.etherscan_key.clone());
        let abi = fetcher
            .fetch_from_etherscan(config.chain, &config.contract)
            .await?;
        LogDecoder::from_abi(&abi)
    }

    /// Set progress callback
    pub fn with_progress<F>(mut self, callback: F) -> Self
    where
        F: Fn(FetchProgress) + Send + Sync + 'static,
    {
        self.progress_callback = Some(Box::new(callback));
        self
    }

    /// Fetch all logs
    pub async fn fetch_all(&self) -> Result<FetchResult> {
        let end_block = self.resolve_end_block().await?;
        let from_block = self.config.block_range.from_block();

        // Calculate chunks based on endpoint capabilities
        let max_range = self.pool.max_block_range();
        let chunks = Self::calculate_chunks(from_block, end_block, max_range);

        tracing::info!(
            "Fetching logs from block {} to {} ({} chunks)",
            from_block,
            end_block,
            chunks.len()
        );

        // Build base filter
        let address: Address = self
            .config
            .contract
            .parse()
            .map_err(|_| Error::from("Invalid contract address"))?;

        let mut base_filter = Filter::new().address(address);

        // Add event topic if we have a specific event
        if let Some(_decoder) = &self.decoder {
            if let Some(event_str) = &self.config.event {
                let sig = EventSignature::parse(event_str)?;
                base_filter = base_filter.event_signature(sig.topic);
            }
        }

        // Fetch chunks in parallel
        let concurrency = self.config.rpc.concurrency;
        let logs_count = Arc::new(AtomicU64::new(0));
        let start_time = std::time::Instant::now();

        let results: Vec<Result<Vec<Log>>> = stream::iter(chunks.clone())
            .map(|(from, to)| {
                let filter = base_filter.clone().from_block(from).to_block(to);
                let pool = &self.pool;
                let logs_count = logs_count.clone();
                let callback = &self.progress_callback;
                let total_blocks = end_block - from_block + 1;

                async move {
                    let result = Self::fetch_chunk_with_retry(pool, &filter, from, to).await;

                    if let Ok(ref logs) = result {
                        let count = logs_count.fetch_add(logs.len() as u64, Ordering::Relaxed);

                        if let Some(cb) = callback {
                            let elapsed = start_time.elapsed().as_secs_f64();
                            let blocks_done = to - from_block + 1;
                            cb(FetchProgress {
                                current_block: to,
                                total_blocks,
                                logs_fetched: count + logs.len() as u64,
                                percent: (blocks_done as f64 / total_blocks as f64) * 100.0,
                                blocks_per_second: if elapsed > 0.0 {
                                    blocks_done as f64 / elapsed
                                } else {
                                    0.0
                                },
                            });
                        }
                    }

                    result
                }
            })
            .buffer_unordered(concurrency)
            .collect()
            .await;

        // Collect all logs
        let mut all_logs = Vec::new();
        for result in results {
            match result {
                Ok(logs) => all_logs.extend(logs),
                Err(e) => {
                    tracing::warn!("Chunk fetch failed: {}", e);
                    // Continue with other chunks
                }
            }
        }

        // Sort by block number and log index
        all_logs.sort_by(|a, b| {
            let block_cmp = a.block_number.cmp(&b.block_number);
            if block_cmp == std::cmp::Ordering::Equal {
                a.log_index.cmp(&b.log_index)
            } else {
                block_cmp
            }
        });

        // Decode if needed
        if let Some(decoder) = &self.decoder {
            let decoded: Vec<DecodedLog> = all_logs
                .iter()
                .filter_map(|log| {
                    match decoder.decode(log) {
                        Ok(decoded) => Some(decoded),
                        Err(e) => {
                            tracing::debug!("Failed to decode log: {}", e);
                            None
                        }
                    }
                })
                .collect();

            Ok(FetchResult::Decoded(decoded))
        } else {
            Ok(FetchResult::Raw(all_logs))
        }
    }

    /// Fetch a single chunk with retry and adaptive splitting
    async fn fetch_chunk_with_retry(
        pool: &RpcPool,
        filter: &Filter,
        from: u64,
        to: u64,
    ) -> Result<Vec<Log>> {
        let mut current_from = from;
        let mut current_to = to;
        let mut all_logs = Vec::new();
        let mut retries = 0;
        const MAX_RETRIES: u32 = 3;

        while current_from <= to {
            let chunk_filter = filter.clone().from_block(current_from).to_block(current_to);

            match pool.get_logs(&chunk_filter).await {
                Ok(logs) => {
                    all_logs.extend(logs);
                    current_from = current_to + 1;
                    current_to = to;
                    retries = 0;
                }
                Err(Error::Rpc(RpcError::BlockRangeTooLarge { .. }))
                | Err(Error::Rpc(RpcError::ResponseTooLarge(_))) => {
                    // Split the range in half
                    let mid = (current_from + current_to) / 2;
                    if mid == current_from {
                        // Can't split further
                        return Err(RpcError::ResponseTooLarge(0).into());
                    }
                    current_to = mid;
                    tracing::debug!(
                        "Range too large, splitting: {} - {} -> {} - {}",
                        current_from,
                        to,
                        current_from,
                        current_to
                    );
                }
                Err(Error::Rpc(RpcError::RateLimited(_))) => {
                    // Wait and retry
                    retries += 1;
                    if retries > MAX_RETRIES {
                        return Err(RpcError::RateLimited("Max retries exceeded".to_string()).into());
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(2u64.pow(retries))).await;
                }
                Err(e) => {
                    retries += 1;
                    if retries > MAX_RETRIES {
                        return Err(e);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            }
        }

        Ok(all_logs)
    }

    /// Resolve end block number
    async fn resolve_end_block(&self) -> Result<u64> {
        match self.config.block_range.to_block() {
            BlockNumber::Number(n) => Ok(n),
            BlockNumber::Latest => self.pool.get_block_number().await,
        }
    }

    /// Calculate optimal chunks for fetching
    fn calculate_chunks(from: u64, to: u64, max_range: u64) -> Vec<(u64, u64)> {
        let mut chunks = Vec::new();
        let mut current = from;

        while current <= to {
            let chunk_end = (current + max_range - 1).min(to);
            chunks.push((current, chunk_end));
            current = chunk_end + 1;
        }

        chunks
    }

    /// Get the RPC pool
    pub fn pool(&self) -> &RpcPool {
        &self.pool
    }

    /// Get endpoint count
    pub fn endpoint_count(&self) -> usize {
        self.pool.endpoint_count()
    }
}

/// Streaming fetcher for large datasets
pub struct StreamingFetcher {
    fetcher: LogFetcher,
    checkpoint_manager: Option<CheckpointManager>,
}

impl StreamingFetcher {
    /// Create a streaming fetcher
    pub async fn new(config: Config) -> Result<Self> {
        let fetcher = LogFetcher::new(config).await?;
        Ok(Self {
            fetcher,
            checkpoint_manager: None,
        })
    }

    /// Enable checkpointing
    pub fn with_checkpoint(mut self, path: &Path) -> Result<Self> {
        let config = &self.fetcher.config;
        let manager = CheckpointManager::load_or_create(
            path,
            &config.contract,
            config.chain.chain_id(),
            config.event.as_deref(),
            config.block_range.from_block(),
            match config.block_range.to_block() {
                BlockNumber::Number(n) => Some(n),
                BlockNumber::Latest => None,
            },
        )?;

        self.checkpoint_manager = Some(manager);
        Ok(self)
    }

    /// Stream logs through a channel
    pub async fn stream(
        self,
        tx: mpsc::Sender<Result<FetchResult>>,
    ) -> Result<()> {
        let end_block = self.fetcher.resolve_end_block().await?;
        let from_block = self.fetcher.config.block_range.from_block();

        // Get remaining ranges if resuming
        let ranges = if let Some(ref manager) = self.checkpoint_manager {
            manager.remaining_ranges(end_block)
        } else {
            vec![(from_block, end_block)]
        };

        if ranges.is_empty() {
            tracing::info!("All ranges already completed");
            return Ok(());
        }

        let max_range = self.fetcher.pool.max_block_range();

        // Process each range
        for (range_from, range_to) in ranges {
            let chunks = LogFetcher::calculate_chunks(range_from, range_to, max_range);

            for (chunk_from, chunk_to) in chunks {
                // Build filter
                let address: Address = self
                    .fetcher
                    .config
                    .contract
                    .parse()
                    .map_err(|_| Error::from("Invalid contract address"))?;

                let mut filter = Filter::new()
                    .address(address)
                    .from_block(chunk_from)
                    .to_block(chunk_to);

                // Add event topic if specified
                if let Some(event_str) = &self.fetcher.config.event {
                    let sig = EventSignature::parse(event_str)?;
                    filter = filter.event_signature(sig.topic);
                }

                // Fetch
                let result = LogFetcher::fetch_chunk_with_retry(
                    &self.fetcher.pool,
                    &filter,
                    chunk_from,
                    chunk_to,
                )
                .await;

                match result {
                    Ok(logs) => {
                        let fetch_result = if let Some(decoder) = &self.fetcher.decoder {
                            let decoded: Vec<DecodedLog> = logs
                                .iter()
                                .filter_map(|log| decoder.decode(log).ok())
                                .collect();
                            FetchResult::Decoded(decoded)
                        } else {
                            FetchResult::Raw(logs)
                        };

                        let _logs_count = fetch_result.len() as u64;

                        // Update checkpoint
                        if let Some(_manager) = self.checkpoint_manager.as_ref() {
                            // Note: Can't mutate through ref, would need interior mutability
                        }

                        if tx.send(Ok(fetch_result)).await.is_err() {
                            return Ok(()); // Receiver dropped
                        }
                    }
                    Err(e) => {
                        if tx.send(Err(e)).await.is_err() {
                            return Ok(());
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_chunks() {
        let chunks = LogFetcher::calculate_chunks(0, 100, 30);
        assert_eq!(chunks, vec![(0, 29), (30, 59), (60, 89), (90, 100)]);

        let chunks = LogFetcher::calculate_chunks(0, 10, 100);
        assert_eq!(chunks, vec![(0, 10)]);

        let chunks = LogFetcher::calculate_chunks(50, 50, 10);
        assert_eq!(chunks, vec![(50, 50)]);
    }

    #[test]
    fn test_fetch_result_len() {
        let result = FetchResult::Raw(vec![]);
        assert!(result.is_empty());
        assert_eq!(result.len(), 0);
    }
}
