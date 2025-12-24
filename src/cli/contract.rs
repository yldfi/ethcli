//! Contract-related commands
//!
//! Fetch ABI, source code, and creation info for contracts

use crate::config::{Chain, ConfigFile, EndpointConfig};
use crate::etherscan::Client;
use crate::rpc::Endpoint;
use alloy::dyn_abi::{DynSolType, DynSolValue, FunctionExt, JsonAbiExt};
use alloy::primitives::Address;
use alloy::providers::Provider;
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

    /// Call a contract function (auto-fetches ABI)
    ///
    /// Examples:
    ///   ethcli contract call 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 totalSupply
    ///   ethcli contract call 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 balanceOf 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045
    Call {
        /// Contract address
        address: String,

        /// Function name (e.g., "totalSupply", "balanceOf")
        function: String,

        /// Function arguments
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,

        /// Block number or "latest" (default: latest)
        #[arg(long, short, default_value = "latest")]
        block: String,

        /// Custom RPC URL (overrides config)
        #[arg(long)]
        rpc_url: Option<String>,
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

        ContractCommands::Call {
            address,
            function,
            args,
            block,
            rpc_url,
        } => {
            let addr = Address::from_str(address)
                .map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?;

            if !quiet {
                eprintln!("Fetching ABI for {}...", address);
            }

            // Fetch ABI
            let abi = client
                .contract_abi(addr)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to fetch ABI: {}", e))?;

            // contract_abi returns JsonAbi directly
            let json_abi = abi;

            // Find the function
            let func = json_abi
                .functions
                .get(function)
                .and_then(|funcs| funcs.first())
                .ok_or_else(|| anyhow::anyhow!("Function '{}' not found in ABI", function))?;

            // Validate argument count
            if func.inputs.len() != args.len() {
                return Err(anyhow::anyhow!(
                    "Function '{}' expects {} arguments, got {}",
                    function,
                    func.inputs.len(),
                    args.len()
                ));
            }

            // Coerce string arguments to DynSolValues using the function's input types
            let mut values = Vec::new();
            for (input, arg) in func.inputs.iter().zip(args.iter()) {
                let ty = DynSolType::parse(&input.ty.to_string())
                    .map_err(|e| anyhow::anyhow!("Invalid type '{}': {}", input.ty, e))?;
                let val = ty.coerce_str(arg).map_err(|e| {
                    anyhow::anyhow!("Invalid value '{}' for type '{}': {}", arg, input.ty, e)
                })?;
                values.push(val);
            }

            // Encode the call
            let calldata = func
                .abi_encode_input(&values)
                .map_err(|e| anyhow::anyhow!("Failed to encode arguments: {}", e))?;

            if !quiet {
                eprintln!("Calling {}({})...", function, args.join(", "));
            }

            // Get RPC endpoint
            let endpoint = if let Some(url) = rpc_url {
                Endpoint::new(EndpointConfig::new(url.clone()), 30, None)?
            } else {
                let config = ConfigFile::load_default()
                    .map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))?
                    .unwrap_or_default();

                let chain_endpoints: Vec<_> = config
                    .endpoints
                    .into_iter()
                    .filter(|e| e.enabled && e.chain == chain)
                    .collect();

                if chain_endpoints.is_empty() {
                    return Err(anyhow::anyhow!(
                        "No RPC endpoints configured for {}. Add one with: ethcli endpoints add <url>",
                        chain.display_name()
                    ));
                }
                Endpoint::new(chain_endpoints[0].clone(), 30, None)?
            };

            let provider = endpoint.provider();

            // Parse block
            let block_id = super::rpc::parse_block_id(block)?;

            // Make the call
            let tx = alloy::rpc::types::TransactionRequest::default()
                .to(addr)
                .input(calldata.into());

            let result = provider
                .call(tx)
                .block(block_id)
                .await
                .map_err(|e| anyhow::anyhow!("Call failed: {}", e))?;

            // Decode the result
            if func.outputs.is_empty() {
                println!("(no return value)");
            } else {
                let decoded = func
                    .abi_decode_output(&result)
                    .map_err(|e| anyhow::anyhow!("Failed to decode output: {}", e))?;

                // Format output nicely
                if decoded.len() == 1 {
                    println!("{}", format_value(&decoded[0]));
                } else {
                    for (i, (output, value)) in func.outputs.iter().zip(decoded.iter()).enumerate()
                    {
                        let name = if output.name.is_empty() {
                            format!("[{}]", i)
                        } else {
                            output.name.clone()
                        };
                        println!("{}: {}", name, format_value(value));
                    }
                }
            }
        }
    }

    Ok(())
}

/// Format a DynSolValue for display
fn format_value(value: &DynSolValue) -> String {
    match value {
        DynSolValue::Bool(b) => b.to_string(),
        DynSolValue::Int(i, _) => i.to_string(),
        DynSolValue::Uint(u, _) => u.to_string(),
        DynSolValue::FixedBytes(b, _) => format!("0x{}", hex::encode(b)),
        DynSolValue::Address(a) => a.to_checksum(None),
        DynSolValue::Function(f) => format!("0x{}", hex::encode(f)),
        DynSolValue::Bytes(b) => format!("0x{}", hex::encode(b)),
        DynSolValue::String(s) => format!("\"{}\"", s),
        DynSolValue::Array(arr) => {
            let items: Vec<String> = arr.iter().map(format_value).collect();
            format!("[{}]", items.join(", "))
        }
        DynSolValue::FixedArray(arr) => {
            let items: Vec<String> = arr.iter().map(format_value).collect();
            format!("[{}]", items.join(", "))
        }
        DynSolValue::Tuple(tuple) => {
            let items: Vec<String> = tuple.iter().map(format_value).collect();
            format!("({})", items.join(", "))
        }
    }
}
