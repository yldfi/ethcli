//! RPC endpoint management commands

use clap::Subcommand;

#[derive(Subcommand)]
pub enum EndpointCommands {
    /// List all configured endpoints
    List,

    /// Test an endpoint for archive support
    Test {
        /// RPC URL to test
        url: String,
    },
}
