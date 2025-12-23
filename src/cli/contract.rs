//! Contract-related commands
//!
//! Fetch ABI, source code, and creation info for contracts

use crate::config::Chain;
use crate::etherscan::Client;
use alloy::primitives::Address;
use clap::Subcommand;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Subcommand)]
pub enum ContractCommands {
    /// Get verified contract ABI
    Abi {
        /// Contract address
        address: String,

        /// Save to file instead of stdout
        #[arg(long, short)]
        output: Option<PathBuf>,
    },

    /// Get verified source code
    Source {
        /// Contract address
        address: String,

        /// Save to directory instead of stdout
        #[arg(long, short)]
        output: Option<PathBuf>,
    },

    /// Get contract creation info (deployer, tx hash)
    Creation {
        /// Contract address
        address: String,

        /// Output format (pretty, json)
        #[arg(long, short = 'f', default_value = "pretty")]
        output: String,
    },
}

pub async fn handle(
    action: &ContractCommands,
    chain: Chain,
    api_key: Option<String>,
    quiet: bool,
) -> anyhow::Result<()> {
    let client = Client::new(chain, api_key)?;

    match action {
        ContractCommands::Abi { address, output } => {
            let addr = Address::from_str(address)
                .map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?;

            if !quiet {
                eprintln!("Fetching ABI for {}...", address);
            }

            let abi = client
                .contract_abi(addr)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to fetch ABI: {}", e))?;

            let json = serde_json::to_string_pretty(&abi)?;

            if let Some(path) = output {
                std::fs::write(path, &json)?;
                if !quiet {
                    eprintln!("ABI saved to {}", path.display());
                }
            } else {
                println!("{}", json);
            }
        }

        ContractCommands::Source { address, output } => {
            let addr = Address::from_str(address)
                .map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?;

            if !quiet {
                eprintln!("Fetching source code for {}...", address);
            }

            let metadata = client
                .contract_source_code(addr)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to fetch source: {}", e))?;

            if let Some(dir) = output {
                // Create directory and save files
                std::fs::create_dir_all(dir)?;

                // Get source items
                let items = metadata.items;
                if items.is_empty() {
                    return Err(anyhow::anyhow!(
                        "No source code found (contract may not be verified)"
                    ));
                }

                for item in &items {
                    // Save main source code using the source_code() method
                    let filename = format!("{}.sol", item.contract_name);
                    let file_path = dir.join(&filename);
                    let source_code_str = item.source_code.source_code();
                    std::fs::write(&file_path, &source_code_str)?;
                    if !quiet {
                        eprintln!("  Saved: {}", file_path.display());
                    }
                }

                if !quiet {
                    eprintln!("Source code saved to {}", dir.display());
                }
            } else {
                // Print to stdout
                let items = metadata.items;
                if items.is_empty() {
                    return Err(anyhow::anyhow!(
                        "No source code found (contract may not be verified)"
                    ));
                }

                for item in items {
                    println!("// Contract: {}", item.contract_name);
                    println!("// Compiler: {}", item.compiler_version);
                    println!(
                        "// Optimization: {} (runs: {})",
                        if item.optimization_used == 1 {
                            "enabled"
                        } else {
                            "disabled"
                        },
                        item.runs
                    );
                    println!("\n{}", item.source_code.source_code());
                }
            }
        }

        ContractCommands::Creation { address, output } => {
            let addr = Address::from_str(address)
                .map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?;

            if !quiet {
                eprintln!("Fetching creation info for {}...", address);
            }

            let creation = client
                .contract_creation_data(addr)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to fetch creation data: {}", e))?;

            if output == "json" {
                println!("{}", serde_json::to_string_pretty(&creation)?);
            } else {
                println!("Contract Creation Info");
                println!("{}", "─".repeat(50));
                println!("Contract:   {:#x}", creation.contract_address);
                println!("Creator:    {:#x}", creation.contract_creator);
                println!("Tx Hash:    {:#x}", creation.transaction_hash);

                // Add explorer link
                if let Some(explorer) = chain.explorer_url() {
                    println!(
                        "\nExplorer:   {}/tx/{:#x}",
                        explorer, creation.transaction_hash
                    );
                }
            }
        }
    }

    Ok(())
}
