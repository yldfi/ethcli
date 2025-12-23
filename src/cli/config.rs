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

    /// Show current config
    Show,
}
