//! Configuration management commands

use clap::Subcommand;

#[derive(Subcommand)]
pub enum ConfigCommands {
    /// Show config file path
    Path,

    /// Set Etherscan API key
    SetEtherscanKey {
        /// API key
        key: String,
    },

    /// Set Tenderly API credentials
    SetTenderly {
        /// Tenderly access key
        #[arg(long)]
        key: String,

        /// Tenderly account slug
        #[arg(long)]
        account: String,

        /// Tenderly project slug
        #[arg(long)]
        project: String,
    },

    /// Add a debug-capable RPC URL (for debug_traceCall, etc.)
    AddDebugRpc {
        /// RPC URL with debug namespace enabled
        url: String,
    },

    /// Remove a debug-capable RPC URL
    RemoveDebugRpc {
        /// RPC URL to remove
        url: String,
    },

    /// Show current config
    Show,
}
