//! Token-related commands
//!
//! Get token info, holders, and balances

use crate::config::Chain;
use crate::etherscan::Client;
use clap::Subcommand;

#[derive(Subcommand)]
pub enum TokenCommands {
    /// Get token info (name, symbol, decimals, supply)
    Info {
        /// Token contract address
        address: String,

        /// Output format (pretty, json)
        #[arg(long, short, default_value = "pretty")]
        output: String,
    },

    /// Get top token holders (requires API key for most tokens)
    #[command(hide = true)] // Hidden until we confirm API support
    Holders {
        /// Token contract address
        address: String,

        /// Number of holders to return
        #[arg(long, default_value = "100")]
        limit: u32,

        /// Output format (pretty, json)
        #[arg(long, short, default_value = "pretty")]
        output: String,
    },

    /// Get token balance for a holder
    #[command(hide = true)] // Hidden until we confirm API support
    Balance {
        /// Token contract address
        token: String,

        /// Holder address
        #[arg(long)]
        holder: String,

        /// Output format (pretty, json)
        #[arg(long, short, default_value = "pretty")]
        output: String,
    },
}

pub async fn handle(
    action: &TokenCommands,
    chain: Chain,
    api_key: Option<String>,
    quiet: bool,
) -> anyhow::Result<()> {
    let client = Client::new(chain, api_key)?;

    match action {
        TokenCommands::Info { address, output } => {
            if !quiet {
                eprintln!("Fetching token info for {}...", address);
            }

            // Use our custom eth_call-based metadata fetch
            let metadata = client.get_token_metadata(address).await?;

            if output == "json" {
                println!(
                    "{}",
                    serde_json::json!({
                        "address": address,
                        "name": metadata.name,
                        "symbol": metadata.symbol,
                        "decimals": metadata.decimals
                    })
                );
            } else {
                println!("Token Info");
                println!("{}", "─".repeat(40));
                println!("Address:  {}", address);
                println!(
                    "Name:     {}",
                    metadata.name.as_deref().unwrap_or("(unknown)")
                );
                println!(
                    "Symbol:   {}",
                    metadata.symbol.as_deref().unwrap_or("(unknown)")
                );
                println!(
                    "Decimals: {}",
                    metadata
                        .decimals
                        .map(|d| d.to_string())
                        .unwrap_or_else(|| "(unknown)".to_string())
                );

                // Add explorer link
                if let Some(explorer) = chain.explorer_url() {
                    println!("\nExplorer: {}/token/{}", explorer, address);
                }
            }
        }

        TokenCommands::Holders {
            address: _,
            limit: _,
            output: _,
        } => {
            // This endpoint requires API key and may have restrictions
            // Placeholder for future implementation
            return Err(anyhow::anyhow!(
                "Token holders endpoint requires Etherscan API key and may have access restrictions. \
                Use the Etherscan website for now."
            ));
        }

        TokenCommands::Balance {
            token: _,
            holder: _,
            output: _,
        } => {
            // This endpoint requires API key and may have restrictions
            // Placeholder for future implementation
            return Err(anyhow::anyhow!(
                "Token balance endpoint requires Etherscan API key. \
                Use the Etherscan website for now."
            ));
        }
    }

    Ok(())
}
