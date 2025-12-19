//! Error types for eth-log-fetcher

use thiserror::Error;

/// Main error type for the library
#[derive(Error, Debug)]
pub enum Error {
    /// RPC-related errors
    #[error("RPC error: {0}")]
    Rpc(#[from] RpcError),

    /// ABI-related errors
    #[error("ABI error: {0}")]
    Abi(#[from] AbiError),

    /// Configuration errors
    #[error("Config error: {0}")]
    Config(#[from] ConfigError),

    /// Output errors
    #[error("Output error: {0}")]
    Output(#[from] OutputError),

    /// Checkpoint errors
    #[error("Checkpoint error: {0}")]
    Checkpoint(#[from] CheckpointError),

    /// Generic IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Generic error with context
    #[error("{0}")]
    Other(String),
}

/// RPC-specific errors
#[derive(Error, Debug)]
pub enum RpcError {
    #[error("All endpoints failed for request")]
    AllEndpointsFailed,

    #[error("No healthy endpoints available")]
    NoHealthyEndpoints,

    #[error("Request timeout after {0}ms")]
    Timeout(u64),

    #[error("Rate limited by endpoint: {0}")]
    RateLimited(String),

    #[error("Block range too large: max {max}, requested {requested}")]
    BlockRangeTooLarge { max: u64, requested: u64 },

    #[error("Response too large: {0} logs exceed limit")]
    ResponseTooLarge(usize),

    #[error("Invalid response from endpoint: {0}")]
    InvalidResponse(String),

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Provider error: {0}")]
    Provider(String),
}

/// ABI-related errors
#[derive(Error, Debug)]
pub enum AbiError {
    #[error("Failed to fetch ABI from Etherscan: {0}")]
    EtherscanFetch(String),

    #[error("Contract not verified on Etherscan: {0}")]
    ContractNotVerified(String),

    #[error("Invalid event signature: {0}")]
    InvalidEventSignature(String),

    #[error("Failed to parse ABI: {0}")]
    ParseError(String),

    #[error("Event not found in ABI: {0}")]
    EventNotFound(String),

    #[error("Failed to decode log: {0}")]
    DecodeError(String),

    #[error("ABI file not found: {0}")]
    FileNotFound(String),
}

/// Configuration errors
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Invalid config file: {0}")]
    InvalidFile(String),

    #[error("Invalid address format: {0}")]
    InvalidAddress(String),

    #[error("Invalid block number: {0}")]
    InvalidBlockNumber(String),

    #[error("Invalid chain: {0}")]
    InvalidChain(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Config file parse error: {0}")]
    ParseError(#[from] toml::de::Error),
}

/// Output-related errors
#[derive(Error, Debug)]
pub enum OutputError {
    #[error("Failed to write JSON: {0}")]
    JsonWrite(String),

    #[error("Failed to write CSV: {0}")]
    CsvWrite(String),

    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("Failed to create output file: {0}")]
    FileCreate(String),

    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),
}

/// Checkpoint-related errors
#[derive(Error, Debug)]
pub enum CheckpointError {
    #[error("Failed to read checkpoint: {0}")]
    ReadError(String),

    #[error("Failed to write checkpoint: {0}")]
    WriteError(String),

    #[error("Checkpoint corrupted: {0}")]
    Corrupted(String),

    #[error("Checkpoint version mismatch: expected {expected}, found {found}")]
    VersionMismatch { expected: u32, found: u32 },
}

/// Result type alias for the library
pub type Result<T> = std::result::Result<T, Error>;

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Other(s)
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::Other(s.to_string())
    }
}
