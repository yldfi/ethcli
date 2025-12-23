//! RPC commands - direct Ethereum RPC calls
//!
//! Commands for reading blockchain state

use crate::config::{Chain, EndpointConfig};
use crate::rpc::Endpoint;
use alloy::primitives::{Address, B256, U256};
use alloy::providers::Provider;
use clap::Subcommand;
use std::str::FromStr;

#[derive(Subcommand)]
pub enum RpcCommands {
    /// Call a contract (eth_call) - read-only, no transaction
    Call {
        /// Contract address
        to: String,

        /// Calldata (hex encoded)
        data: String,

        /// Block number or "latest" (default: latest)
        #[arg(long, short, default_value = "latest")]
        block: String,

        /// Decode output as type (e.g., "uint256", "(address,uint256)")
        #[arg(long, short)]
        decode: Option<String>,
    },

    /// Get block information
    Block {
        /// Block number, hash, or "latest"
        block: String,

        /// Show full transactions
        #[arg(long, short)]
        full: bool,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Read storage slot
    Storage {
        /// Contract address
        address: String,

        /// Storage slot (hex or decimal)
        slot: String,

        /// Block number or "latest" (default: latest)
        #[arg(long, short, default_value = "latest")]
        block: String,
    },

    /// Get contract bytecode
    Code {
        /// Contract address
        address: String,

        /// Block number or "latest" (default: latest)
        #[arg(long, short, default_value = "latest")]
        block: String,
    },

    /// Get account nonce
    Nonce {
        /// Account address
        address: String,

        /// Block number or "latest" (default: latest)
        #[arg(long, short, default_value = "latest")]
        block: String,
    },

    /// Get transaction receipt
    Receipt {
        /// Transaction hash
        hash: String,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Get current chain ID
    ChainId,

    /// Get current block number
    BlockNumber,

    /// Get current gas price
    GasPrice,
}

pub async fn handle(
    action: &RpcCommands,
    chain: Chain,
    rpc_url: Option<String>,
    quiet: bool,
) -> anyhow::Result<()> {
    // Get RPC endpoint
    let endpoint = if let Some(url) = rpc_url {
        Endpoint::new(EndpointConfig::new(url), 30, None)?
    } else {
        let defaults = crate::rpc::default_endpoints(chain);
        if defaults.is_empty() {
            return Err(anyhow::anyhow!(
                "No default RPC endpoints for {}",
                chain.display_name()
            ));
        }
        Endpoint::new(defaults[0].clone(), 30, None)?
    };

    let provider = endpoint.provider();

    match action {
        RpcCommands::Call {
            to,
            data,
            block,
            decode,
        } => {
            let to_addr =
                Address::from_str(to).map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?;

            let data_hex = data.strip_prefix("0x").unwrap_or(data);
            let calldata =
                hex::decode(data_hex).map_err(|e| anyhow::anyhow!("Invalid calldata: {}", e))?;

            let block_id = parse_block_id(block)?;

            let tx = alloy::rpc::types::TransactionRequest::default()
                .to(to_addr)
                .input(calldata.into());

            let result = provider
                .call(tx)
                .block(block_id)
                .await
                .map_err(|e| anyhow::anyhow!("Call failed: {}", e))?;

            if let Some(type_sig) = decode {
                let decoded = decode_output(&result, type_sig)?;
                println!("{}", decoded);
            } else {
                println!("0x{}", hex::encode(&result));
            }
        }

        RpcCommands::Block { block, full, json } => {
            let block_id = parse_block_id(block)?;

            let block_data = if *full {
                provider
                    .get_block(block_id)
                    .full()
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to get block: {}", e))?
            } else {
                provider
                    .get_block(block_id)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to get block: {}", e))?
            };

            match block_data {
                Some(b) => {
                    if *json {
                        println!("{}", serde_json::to_string_pretty(&b)?);
                    } else {
                        println!("Block {}", b.header.number);
                        println!("{}", "─".repeat(50));
                        println!("Hash:        {:#x}", b.header.hash);
                        println!("Parent:      {:#x}", b.header.parent_hash);
                        println!("Timestamp:   {}", b.header.timestamp);
                        println!("Gas Used:    {}", b.header.gas_used);
                        println!("Gas Limit:   {}", b.header.gas_limit);
                        // Show base fee with decimal precision
                        let base_fee = b.header.base_fee_per_gas.unwrap_or(0);
                        let gwei_div = 1_000_000_000u64;
                        let base_gwei = base_fee / gwei_div;
                        let base_frac = (base_fee % gwei_div) * 1000 / gwei_div;
                        println!("Base Fee:    {}.{:03} gwei", base_gwei, base_frac);
                        println!("Txs:         {}", b.transactions.len());
                        println!("Miner:       {}", b.header.beneficiary.to_checksum(None));
                    }
                }
                None => {
                    println!("Block not found");
                }
            }
        }

        RpcCommands::Storage {
            address,
            slot,
            block,
        } => {
            let addr = Address::from_str(address)
                .map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?;

            let slot_val = if slot.starts_with("0x") {
                U256::from_str(slot).map_err(|e| anyhow::anyhow!("Invalid slot: {}", e))?
            } else {
                U256::from_str(slot).map_err(|e| anyhow::anyhow!("Invalid slot: {}", e))?
            };

            let block_id = parse_block_id(block)?;

            let value = provider
                .get_storage_at(addr, slot_val)
                .block_id(block_id)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to read storage: {}", e))?;

            println!("{:#x}", value);
        }

        RpcCommands::Code { address, block } => {
            let addr = Address::from_str(address)
                .map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?;

            let block_id = parse_block_id(block)?;

            let code = provider
                .get_code_at(addr)
                .block_id(block_id)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to get code: {}", e))?;

            if code.is_empty() {
                println!("0x (no code - EOA or empty contract)");
            } else {
                println!("0x{}", hex::encode(&code));
                if !quiet {
                    eprintln!("\n({} bytes)", code.len());
                }
            }
        }

        RpcCommands::Nonce { address, block } => {
            let addr = Address::from_str(address)
                .map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?;

            let block_id = parse_block_id(block)?;

            let nonce = provider
                .get_transaction_count(addr)
                .block_id(block_id)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to get nonce: {}", e))?;

            println!("{}", nonce);
        }

        RpcCommands::Receipt { hash, json } => {
            let tx_hash =
                B256::from_str(hash).map_err(|e| anyhow::anyhow!("Invalid tx hash: {}", e))?;

            let receipt = provider
                .get_transaction_receipt(tx_hash)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to get receipt: {}", e))?;

            match receipt {
                Some(r) => {
                    if *json {
                        println!("{}", serde_json::to_string_pretty(&r)?);
                    } else {
                        println!("Transaction Receipt");
                        println!("{}", "─".repeat(50));
                        println!("Hash:        {:#x}", r.transaction_hash);
                        println!("Block:       {}", r.block_number.unwrap_or(0));
                        println!(
                            "Status:      {}",
                            if r.status() { "Success" } else { "Failed" }
                        );
                        println!("Gas Used:    {}", r.gas_used);
                        if let Some(to) = r.to {
                            println!("To:          {}", to.to_checksum(None));
                        }
                        if let Some(addr) = r.contract_address {
                            println!("Created:     {}", addr.to_checksum(None));
                        }
                        println!("Logs:        {}", r.inner.logs().len());
                    }
                }
                None => {
                    println!("Receipt not found (tx may be pending)");
                }
            }
        }

        RpcCommands::ChainId => {
            let chain_id = provider
                .get_chain_id()
                .await
                .map_err(|e| anyhow::anyhow!("Failed to get chain ID: {}", e))?;
            println!("{}", chain_id);
        }

        RpcCommands::BlockNumber => {
            let block_num = provider
                .get_block_number()
                .await
                .map_err(|e| anyhow::anyhow!("Failed to get block number: {}", e))?;
            println!("{}", block_num);
        }

        RpcCommands::GasPrice => {
            let gas_price = provider
                .get_gas_price()
                .await
                .map_err(|e| anyhow::anyhow!("Failed to get gas price: {}", e))?;
            println!("{} gwei", gas_price / 1_000_000_000);
        }
    }

    Ok(())
}

fn parse_block_id(block: &str) -> anyhow::Result<alloy::eips::BlockId> {
    use alloy::eips::{BlockId, BlockNumberOrTag};

    match block.to_lowercase().as_str() {
        "latest" => Ok(BlockId::Number(BlockNumberOrTag::Latest)),
        "pending" => Ok(BlockId::Number(BlockNumberOrTag::Pending)),
        "earliest" => Ok(BlockId::Number(BlockNumberOrTag::Earliest)),
        "finalized" => Ok(BlockId::Number(BlockNumberOrTag::Finalized)),
        "safe" => Ok(BlockId::Number(BlockNumberOrTag::Safe)),
        _ => {
            if block.starts_with("0x") && block.len() == 66 {
                // Block hash
                let hash = B256::from_str(block)
                    .map_err(|e| anyhow::anyhow!("Invalid block hash: {}", e))?;
                Ok(BlockId::Hash(hash.into()))
            } else {
                // Block number
                let num: u64 = block
                    .parse()
                    .map_err(|e| anyhow::anyhow!("Invalid block number: {}", e))?;
                Ok(BlockId::Number(BlockNumberOrTag::Number(num)))
            }
        }
    }
}

fn decode_output(data: &[u8], type_sig: &str) -> anyhow::Result<String> {
    use alloy::dyn_abi::DynSolType;

    let ty = DynSolType::parse(type_sig).map_err(|e| anyhow::anyhow!("Invalid type: {}", e))?;

    let decoded = ty
        .abi_decode(data)
        .map_err(|e| anyhow::anyhow!("Failed to decode: {}", e))?;

    Ok(format!("{:?}", decoded))
}
