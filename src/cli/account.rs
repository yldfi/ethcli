//! Account-related commands
//!
//! Query balances, transactions, and token transfers for addresses

use crate::config::Chain;
use crate::etherscan::Client;
use alloy::primitives::Address;
use clap::Subcommand;
use std::str::FromStr;

#[derive(Subcommand)]
pub enum AccountCommands {
    /// Get native token balance for address(es)
    Balance {
        /// Address(es) to query
        addresses: Vec<String>,

        /// Output format (pretty, json)
        #[arg(long, short, default_value = "pretty")]
        output: String,
    },

    /// Get transaction history for an address
    Txs {
        /// Address to query
        address: String,

        /// Page number (1-indexed)
        #[arg(long, default_value = "1")]
        page: u64,

        /// Number of results per page
        #[arg(long, default_value = "50")]
        limit: u64,

        /// Sort order (asc, desc)
        #[arg(long, default_value = "desc")]
        sort: String,

        /// Output format (pretty, json)
        #[arg(long, short, default_value = "pretty")]
        output: String,
    },

    /// Get internal transactions for an address
    InternalTxs {
        /// Address to query
        address: String,

        /// Page number
        #[arg(long, default_value = "1")]
        page: u64,

        /// Number of results per page
        #[arg(long, default_value = "50")]
        limit: u64,

        /// Output format (pretty, json)
        #[arg(long, short, default_value = "pretty")]
        output: String,
    },

    /// Get ERC20 token transfers for an address
    Erc20 {
        /// Address to query
        address: String,

        /// Filter by token contract address
        #[arg(long)]
        token: Option<String>,

        /// Page number
        #[arg(long, default_value = "1")]
        page: u64,

        /// Number of results per page
        #[arg(long, default_value = "50")]
        limit: u64,

        /// Output format (pretty, json)
        #[arg(long, short, default_value = "pretty")]
        output: String,
    },

    /// Get ERC721 (NFT) transfers for an address
    Erc721 {
        /// Address to query
        address: String,

        /// Filter by token contract address
        #[arg(long)]
        token: Option<String>,

        /// Page number
        #[arg(long, default_value = "1")]
        page: u64,

        /// Number of results per page
        #[arg(long, default_value = "50")]
        limit: u64,

        /// Output format (pretty, json)
        #[arg(long, short, default_value = "pretty")]
        output: String,
    },

    /// Get ERC1155 transfers for an address
    Erc1155 {
        /// Address to query
        address: String,

        /// Filter by token contract address
        #[arg(long)]
        token: Option<String>,

        /// Page number
        #[arg(long, default_value = "1")]
        page: u64,

        /// Number of results per page
        #[arg(long, default_value = "50")]
        limit: u64,

        /// Output format (pretty, json)
        #[arg(long, short, default_value = "pretty")]
        output: String,
    },

    /// Get blocks mined/validated by an address
    MinedBlocks {
        /// Address to query
        address: String,

        /// Page number
        #[arg(long, default_value = "1")]
        page: u64,

        /// Number of results per page
        #[arg(long, default_value = "50")]
        limit: u64,

        /// Output format (pretty, json)
        #[arg(long, short, default_value = "pretty")]
        output: String,
    },
}

pub async fn handle(
    action: &AccountCommands,
    chain: Chain,
    api_key: Option<String>,
    quiet: bool,
) -> anyhow::Result<()> {
    let client = Client::new(chain, api_key)?;

    match action {
        AccountCommands::Balance { addresses, output } => {
            if addresses.is_empty() {
                return Err(anyhow::anyhow!("At least one address is required"));
            }

            if !quiet {
                eprintln!(
                    "Fetching balance for {} address(es) on {}...",
                    addresses.len(),
                    chain.display_name()
                );
            }

            // Parse addresses
            let parsed: Vec<Address> = addresses
                .iter()
                .map(|a| Address::from_str(a))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?;

            if parsed.len() == 1 {
                // Single address
                let balance = client.get_ether_balance_single(&parsed[0], None).await?;
                let balance_eth = format_wei_to_eth(&balance.balance.to_string());

                if output == "json" {
                    println!(
                        "{}",
                        serde_json::json!({
                            "address": format!("{:#x}", parsed[0]),
                            "balance_wei": balance.balance.to_string(),
                            "balance": balance_eth,
                            "symbol": chain.native_symbol()
                        })
                    );
                } else {
                    println!("{} {}", balance_eth, chain.native_symbol());
                }
            } else {
                // Multiple addresses
                let balances = client.get_ether_balance_multi(&parsed, None).await?;

                if output == "json" {
                    let results: Vec<serde_json::Value> = balances
                        .iter()
                        .map(|b| {
                            serde_json::json!({
                                "address": format!("{:#x}", b.account),
                                "balance_wei": b.balance.to_string(),
                                "balance": format_wei_to_eth(&b.balance.to_string()),
                                "symbol": chain.native_symbol()
                            })
                        })
                        .collect();
                    println!("{}", serde_json::to_string_pretty(&results)?);
                } else {
                    for b in &balances {
                        let eth = format_wei_to_eth(&b.balance.to_string());
                        println!("{:#x}: {} {}", b.account, eth, chain.native_symbol());
                    }
                }
            }
        }

        AccountCommands::Txs {
            address,
            page,
            limit,
            sort,
            output,
        } => {
            let addr = Address::from_str(address)
                .map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?;

            if !quiet {
                eprintln!("Fetching transactions for {}...", address);
            }

            let params = foundry_block_explorers::account::TxListParams {
                start_block: 0,
                end_block: 99999999,
                page: *page,
                offset: *limit,
                sort: if sort == "asc" {
                    foundry_block_explorers::account::Sort::Asc
                } else {
                    foundry_block_explorers::account::Sort::Desc
                },
            };

            let txs = client.get_transactions(&addr, Some(params)).await?;

            if output == "json" {
                println!("{}", serde_json::to_string_pretty(&txs)?);
            } else {
                println!("Transactions for {}", address);
                println!("{}", "─".repeat(80));
                for tx in txs.iter().take(20) {
                    let value_eth = format_wei_to_eth(&tx.value.to_string());
                    let status = if tx.is_error == "0" { "✓" } else { "✗" };
                    let to_addr = tx
                        .to
                        .map(|a| format!("{:#x}", a))
                        .unwrap_or_else(|| "contract creation".to_string());
                    let hash_str = format!("{:#x}", tx.hash.value().unwrap_or_default());
                    println!(
                        "{} {} | Block {} | {} {} → {}",
                        status,
                        &hash_str[..hash_str.len().min(12)],
                        tx.block_number,
                        value_eth,
                        chain.native_symbol(),
                        truncate_addr(&to_addr)
                    );
                }
                if txs.len() > 20 {
                    println!("... and {} more", txs.len() - 20);
                }
            }
        }

        AccountCommands::InternalTxs {
            address,
            page,
            limit,
            output,
        } => {
            let addr = Address::from_str(address)
                .map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?;

            if !quiet {
                eprintln!("Fetching internal transactions for {}...", address);
            }

            let query = foundry_block_explorers::account::InternalTxQueryOption::ByAddress(addr);
            let params = foundry_block_explorers::account::TxListParams {
                start_block: 0,
                end_block: 99999999,
                page: *page,
                offset: *limit,
                sort: foundry_block_explorers::account::Sort::Desc,
            };
            let txs = client
                .get_internal_transactions(query, Some(params))
                .await?;

            if output == "json" {
                println!("{}", serde_json::to_string_pretty(&txs)?);
            } else {
                println!("Internal Transactions for {}", address);
                println!("{}", "─".repeat(80));
                for tx in txs.iter().take(20) {
                    let value_eth = format_wei_to_eth(&tx.value.to_string());
                    let to_addr = tx
                        .to
                        .value()
                        .map(|a| format!("{:#x}", a))
                        .unwrap_or_else(|| "n/a".to_string());
                    println!(
                        "Block {} | {} {} | {} → {}",
                        tx.block_number,
                        value_eth,
                        chain.native_symbol(),
                        truncate_addr(&format!("{:#x}", tx.from)),
                        truncate_addr(&to_addr)
                    );
                }
                if txs.len() > 20 {
                    println!("... and {} more", txs.len() - 20);
                }
            }
        }

        AccountCommands::Erc20 {
            address,
            token,
            page,
            limit,
            output,
        } => {
            let addr = Address::from_str(address)
                .map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?;

            if !quiet {
                eprintln!("Fetching ERC20 transfers for {}...", address);
            }

            let query = if let Some(tok) = token {
                let tok_addr = Address::from_str(tok)
                    .map_err(|e| anyhow::anyhow!("Invalid token address: {}", e))?;
                foundry_block_explorers::account::TokenQueryOption::ByAddressAndContract(
                    addr, tok_addr,
                )
            } else {
                foundry_block_explorers::account::TokenQueryOption::ByAddress(addr)
            };

            let params = foundry_block_explorers::account::TxListParams {
                start_block: 0,
                end_block: 99999999,
                page: *page,
                offset: *limit,
                sort: foundry_block_explorers::account::Sort::Desc,
            };

            let transfers = client
                .get_erc20_token_transfer_events(query, Some(params))
                .await?;

            if output == "json" {
                println!("{}", serde_json::to_string_pretty(&transfers)?);
            } else {
                println!("ERC20 Transfers for {}", address);
                println!("{}", "─".repeat(80));
                for tx in transfers.iter().take(20) {
                    let symbol = &tx.token_symbol;
                    let to_addr = tx
                        .to
                        .as_ref()
                        .map(|a| format!("{:#x}", a))
                        .unwrap_or_else(|| "n/a".to_string());
                    println!(
                        "Block {} | {} {} | {} → {}",
                        tx.block_number,
                        tx.value,
                        symbol,
                        truncate_addr(&format!("{:#x}", tx.from)),
                        truncate_addr(&to_addr)
                    );
                }
                if transfers.len() > 20 {
                    println!("... and {} more", transfers.len() - 20);
                }
            }
        }

        AccountCommands::Erc721 {
            address,
            token,
            page,
            limit,
            output,
        } => {
            let addr = Address::from_str(address)
                .map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?;

            if !quiet {
                eprintln!("Fetching ERC721 transfers for {}...", address);
            }

            let query = if let Some(tok) = token {
                let tok_addr = Address::from_str(tok)
                    .map_err(|e| anyhow::anyhow!("Invalid token address: {}", e))?;
                foundry_block_explorers::account::TokenQueryOption::ByAddressAndContract(
                    addr, tok_addr,
                )
            } else {
                foundry_block_explorers::account::TokenQueryOption::ByAddress(addr)
            };

            let params = foundry_block_explorers::account::TxListParams {
                start_block: 0,
                end_block: 99999999,
                page: *page,
                offset: *limit,
                sort: foundry_block_explorers::account::Sort::Desc,
            };

            let transfers = client
                .get_erc721_token_transfer_events(query, Some(params))
                .await?;

            if output == "json" {
                println!("{}", serde_json::to_string_pretty(&transfers)?);
            } else {
                println!("ERC721 Transfers for {}", address);
                println!("{}", "─".repeat(80));
                for tx in transfers.iter().take(20) {
                    let name = &tx.token_name;
                    let to_addr = tx
                        .to
                        .as_ref()
                        .map(|a| format!("{:#x}", a))
                        .unwrap_or_else(|| "n/a".to_string());
                    println!(
                        "Block {} | Token ID {} | {} | {} → {}",
                        tx.block_number,
                        tx.token_id,
                        name,
                        truncate_addr(&format!("{:#x}", tx.from)),
                        truncate_addr(&to_addr)
                    );
                }
                if transfers.len() > 20 {
                    println!("... and {} more", transfers.len() - 20);
                }
            }
        }

        AccountCommands::Erc1155 {
            address,
            token,
            page,
            limit,
            output,
        } => {
            let addr = Address::from_str(address)
                .map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?;

            if !quiet {
                eprintln!("Fetching ERC1155 transfers for {}...", address);
            }

            let query = if let Some(tok) = token {
                let tok_addr = Address::from_str(tok)
                    .map_err(|e| anyhow::anyhow!("Invalid token address: {}", e))?;
                foundry_block_explorers::account::TokenQueryOption::ByAddressAndContract(
                    addr, tok_addr,
                )
            } else {
                foundry_block_explorers::account::TokenQueryOption::ByAddress(addr)
            };

            let params = foundry_block_explorers::account::TxListParams {
                start_block: 0,
                end_block: 99999999,
                page: *page,
                offset: *limit,
                sort: foundry_block_explorers::account::Sort::Desc,
            };

            let transfers = client
                .get_erc1155_token_transfer_events(query, Some(params))
                .await?;

            if output == "json" {
                println!("{}", serde_json::to_string_pretty(&transfers)?);
            } else {
                println!("ERC1155 Transfers for {}", address);
                println!("{}", "─".repeat(80));
                for tx in transfers.iter().take(20) {
                    let to_addr = tx
                        .to
                        .as_ref()
                        .map(|a| format!("{:#x}", a))
                        .unwrap_or_else(|| "n/a".to_string());
                    println!(
                        "Block {} | Token ID {} | Qty {} | {} → {}",
                        tx.block_number,
                        tx.token_id,
                        tx.token_value,
                        truncate_addr(&format!("{:#x}", tx.from)),
                        truncate_addr(&to_addr)
                    );
                }
                if transfers.len() > 20 {
                    println!("... and {} more", transfers.len() - 20);
                }
            }
        }

        AccountCommands::MinedBlocks {
            address,
            page: _page,
            limit: _limit,
            output,
        } => {
            let addr = Address::from_str(address)
                .map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?;

            if !quiet {
                eprintln!("Fetching mined blocks for {}...", address);
            }

            // Note: get_mined_blocks API expects BlockType, not page/limit
            // Using None for pagination to get default results
            let blocks = client.get_mined_blocks(&addr, None, None).await?;

            if output == "json" {
                println!("{}", serde_json::to_string_pretty(&blocks)?);
            } else {
                println!("Blocks Mined by {}", address);
                println!("{}", "─".repeat(60));
                for block in blocks.iter().take(20) {
                    let reward_eth = format_wei_to_eth(&block.block_reward.to_string());
                    println!(
                        "Block {} | Reward: {} {}",
                        block.block_number,
                        reward_eth,
                        chain.native_symbol()
                    );
                }
                if blocks.len() > 20 {
                    println!("... and {} more", blocks.len() - 20);
                }
            }
        }
    }

    Ok(())
}

/// Format wei value to ETH string
fn format_wei_to_eth(wei: &str) -> String {
    let wei_len = wei.len();
    if wei_len <= 18 {
        let padded = format!("{:0>18}", wei);
        let decimal = padded.trim_end_matches('0');
        if decimal.is_empty() {
            "0.0".to_string()
        } else {
            format!("0.{}", decimal)
        }
    } else {
        let integer_part = &wei[..wei_len - 18];
        let decimal_part = &wei[wei_len - 18..];
        let decimal_trimmed = decimal_part[..4.min(decimal_part.len())].trim_end_matches('0');
        if decimal_trimmed.is_empty() {
            format!("{}.0", integer_part)
        } else {
            format!("{}.{}", integer_part, decimal_trimmed)
        }
    }
}

/// Truncate address for display
fn truncate_addr(addr: &str) -> String {
    if addr.len() > 12 {
        format!("{}...{}", &addr[..6], &addr[addr.len() - 4..])
    } else {
        addr.to_string()
    }
}
