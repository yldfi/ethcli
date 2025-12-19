//! eth-log-fetcher - Fast Ethereum historical log fetcher
//!
//! A Rust library and CLI for fetching EVM logs with parallel requests across
//! multiple RPC endpoints, automatic failover, rate limiting handling, and proxy support.
//!
//! # Example
//!
//! ```rust,no_run
//! use eth_log_fetcher::{Config, LogFetcher, Chain, OutputFormat};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = Config::builder()
//!         .chain(Chain::Ethereum)
//!         .contract("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
//!         .event("Transfer(address indexed from, address indexed to, uint256 value)")
//!         .from_block(18_000_000)
//!         .to_block_number(18_001_000)
//!         .concurrency(10)
//!         .build()?;
//!
//!     let fetcher = LogFetcher::new(config).await?;
//!     let result = fetcher.fetch_all().await?;
//!
//!     println!("Fetched {} logs", result.len());
//!     Ok(())
//! }
//! ```

pub mod abi;
pub mod checkpoint;
pub mod config;
pub mod error;
pub mod fetcher;
pub mod output;
pub mod proxy;
pub mod rpc;

// Re-exports for convenience
pub use abi::{AbiFetcher, DecodedLog, EventSignature, LogDecoder};
pub use checkpoint::{Checkpoint, CheckpointManager};
pub use config::{
    BlockNumber, BlockRange, Chain, ChainId, Config, ConfigBuilder, ConfigFile, EndpointConfig,
    OutputConfig, OutputFormat, ProxyConfig, RpcConfig,
};
pub use error::{AbiError, CheckpointError, ConfigError, Error, OutputError, Result, RpcError};
pub use fetcher::{
    FetchLogs, FetchProgress, FetchResult, FetchStats, LogFetcher, StreamingFetcher,
};
pub use output::{create_writer, CsvWriter, JsonWriter, OutputWriter, SqliteWriter};
pub use proxy::{validate_proxy_url, ProxyRotator, RotationMode};
pub use rpc::{default_endpoints, Endpoint, EndpointHealth, HealthTracker, RpcPool};
