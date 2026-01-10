//! Token-related commands
//!
//! Get token info, holders, and balances

use crate::config::{AddressBook, Chain};
use crate::etherscan::TokenMetadataCache;
use crate::rpc::get_rpc_endpoint;
use crate::rpc::multicall::{selectors, MulticallBuilder};
use alloy::primitives::Address;
use clap::Subcommand;
use std::str::FromStr;
use std::sync::OnceLock;

/// Global token metadata cache (lazy initialized)
static TOKEN_CACHE: OnceLock<TokenMetadataCache> = OnceLock::new();

fn get_token_cache() -> &'static TokenMetadataCache {
    TOKEN_CACHE.get_or_init(TokenMetadataCache::new)
}

/// Resolve an address from label or raw address
fn resolve_address(input: &str) -> anyhow::Result<(Address, Option<String>)> {
    if input.starts_with("0x") && input.len() == 42 {
        let addr = Address::from_str(input)
            .map_err(|e| anyhow::anyhow!("Invalid address '{}': {}", input, e))?;
        return Ok((addr, None));
    }

    let book = AddressBook::load_default();
    if let Some(entry) = book.get(input) {
        let addr = Address::from_str(&entry.address)
            .map_err(|e| anyhow::anyhow!("Invalid stored address for '{}': {}", input, e))?;
        return Ok((addr, Some(input.to_string())));
    }

    Err(anyhow::anyhow!(
        "Unknown label '{}'. Use 'ethcli address add {} <address>' to save it.",
        input,
        input
    ))
}

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
    #[command(hide = true)]
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
    _api_key: Option<String>,
    quiet: bool,
) -> anyhow::Result<()> {
    match action {
        TokenCommands::Info { address, output } => {
            let (token_addr, label) = resolve_address(address)?;
            let addr_str = format!("{:#x}", token_addr);
            let display = label.as_ref().unwrap_or(&addr_str);

            let cache = get_token_cache();
            let chain_name = chain.name();

            // Check cache first
            if let Some(cached) = cache.get(chain_name, &addr_str) {
                if !quiet {
                    eprintln!("Using cached token info for {}...", display);
                }

                let formatted_supply = match (cached.total_supply.as_ref(), cached.decimals) {
                    (Some(supply), Some(dec)) => format_token_amount(supply, dec),
                    (Some(supply), None) => supply.clone(),
                    _ => "(unknown)".to_string(),
                };

                if output == "json" {
                    println!(
                        "{}",
                        serde_json::json!({
                            "address": addr_str,
                            "label": label,
                            "name": cached.name,
                            "symbol": cached.symbol,
                            "decimals": cached.decimals,
                            "totalSupply": cached.total_supply,
                            "totalSupplyFormatted": formatted_supply,
                            "cached": true
                        })
                    );
                } else {
                    println!("Token Info (cached)");
                    println!("{}", "─".repeat(40));
                    if let Some(lbl) = &label {
                        println!("Label:    {}", lbl);
                    }
                    println!("Address:  {}", addr_str);
                    println!(
                        "Name:     {}",
                        cached.name.as_deref().unwrap_or("(unknown)")
                    );
                    println!(
                        "Symbol:   {}",
                        cached.symbol.as_deref().unwrap_or("(unknown)")
                    );
                    println!(
                        "Decimals: {}",
                        cached
                            .decimals
                            .map(|d| d.to_string())
                            .unwrap_or_else(|| "(unknown)".to_string())
                    );
                    println!("Supply:   {}", formatted_supply);

                    if let Some(explorer) = chain.explorer_url() {
                        println!("\nExplorer: {}/token/{}", explorer, addr_str);
                    }
                }
                return Ok(());
            }

            if !quiet {
                eprintln!("Fetching token info for {}...", display);
            }

            // Use RPC with Multicall3 for single request
            let endpoint = get_rpc_endpoint(chain)?;
            let provider = endpoint.provider();

            let multicall = MulticallBuilder::new()
                .add_call_allow_failure(token_addr, selectors::name())
                .add_call_allow_failure(token_addr, selectors::symbol())
                .add_call_allow_failure(token_addr, selectors::decimals())
                .add_call_allow_failure(token_addr, selectors::total_supply());

            // Execute with retry (up to 3 retries with exponential backoff)
            let results = multicall.execute_with_retry(provider, 3).await?;

            let name = results.first().and_then(|r| r.decode_string());
            let symbol = results.get(1).and_then(|r| r.decode_string());
            let decimals = results.get(2).and_then(|r| r.decode_uint8());
            let total_supply = results.get(3).and_then(|r| r.decode_uint256());

            // Cache the result (token metadata is immutable)
            cache.set(
                chain_name,
                &addr_str,
                name.clone(),
                symbol.clone(),
                decimals,
                total_supply.map(|s| s.to_string()),
            );

            let formatted_supply = match (total_supply, decimals) {
                (Some(supply), Some(dec)) => format_token_amount(&supply.to_string(), dec),
                (Some(supply), None) => supply.to_string(),
                _ => "(unknown)".to_string(),
            };

            if output == "json" {
                println!(
                    "{}",
                    serde_json::json!({
                        "address": addr_str,
                        "label": label,
                        "name": name,
                        "symbol": symbol,
                        "decimals": decimals,
                        "totalSupply": total_supply.map(|s| s.to_string()),
                        "totalSupplyFormatted": formatted_supply
                    })
                );
            } else {
                println!("Token Info");
                println!("{}", "─".repeat(40));
                if let Some(lbl) = &label {
                    println!("Label:    {}", lbl);
                }
                println!("Address:  {}", addr_str);
                println!("Name:     {}", name.as_deref().unwrap_or("(unknown)"));
                println!("Symbol:   {}", symbol.as_deref().unwrap_or("(unknown)"));
                println!(
                    "Decimals: {}",
                    decimals
                        .map(|d| d.to_string())
                        .unwrap_or_else(|| "(unknown)".to_string())
                );
                println!("Supply:   {}", formatted_supply);

                if let Some(explorer) = chain.explorer_url() {
                    println!("\nExplorer: {}/token/{}", explorer, addr_str);
                }
            }
        }

        TokenCommands::Holders { .. } => {
            return Err(anyhow::anyhow!(
                "Token holders endpoint requires Etherscan API key. Use the Etherscan website for now."
            ));
        }

        TokenCommands::Balance {
            token,
            holder,
            output,
        } => {
            let (token_addr, token_label) = resolve_address(token)?;
            let (holder_addr, holder_label) = resolve_address(holder)?;

            let token_str = format!("{:#x}", token_addr);
            let holder_str = format!("{:#x}", holder_addr);
            let token_display = token_label.as_ref().unwrap_or(&token_str);
            let holder_display = holder_label.as_ref().unwrap_or(&holder_str);

            if !quiet {
                eprintln!(
                    "Fetching {} balance for {}...",
                    token_display, holder_display
                );
            }

            // Get RPC endpoint
            let endpoint = get_rpc_endpoint(chain)?;
            let provider = endpoint.provider();

            // Fetch balance and decimals in a single multicall
            let multicall = MulticallBuilder::new()
                .add_call_allow_failure(token_addr, selectors::balance_of(holder_addr))
                .add_call_allow_failure(token_addr, selectors::decimals())
                .add_call_allow_failure(token_addr, selectors::symbol());

            let results = multicall.execute_with_retry(provider, 3).await?;

            let balance = results
                .first()
                .and_then(|r| r.decode_uint256())
                .ok_or_else(|| anyhow::anyhow!("Failed to get balance"))?;
            let decimals = results.get(1).and_then(|r| r.decode_uint8()).unwrap_or(18);
            let symbol = results
                .get(2)
                .and_then(|r| r.decode_string())
                .unwrap_or_else(|| "???".to_string());

            let formatted = format_token_amount(&balance.to_string(), decimals);

            if output == "json" {
                println!(
                    "{}",
                    serde_json::json!({
                        "token": token_str,
                        "tokenLabel": token_label,
                        "holder": holder_str,
                        "holderLabel": holder_label,
                        "balance": balance.to_string(),
                        "balanceFormatted": formatted,
                        "decimals": decimals,
                        "symbol": symbol
                    })
                );
            } else {
                println!("{} {} ({})", formatted, symbol, token_display);
                println!("Holder: {} ({})", holder_display, holder_str);
                println!("Raw:    {}", balance);
            }
        }
    }

    Ok(())
}

/// Format a token amount with decimals (e.g., 1000000 with 6 decimals = "1.0")
fn format_token_amount(raw: &str, decimals: u8) -> String {
    let dec = decimals as usize;
    let len = raw.len();

    if len <= dec {
        let padded = format!("{:0>width$}", raw, width = dec);
        let trimmed = padded.trim_end_matches('0');
        if trimmed.is_empty() {
            "0".to_string()
        } else {
            format!("0.{}", trimmed)
        }
    } else {
        let integer_part = &raw[..len - dec];
        let decimal_part = &raw[len - dec..];
        let decimal_trimmed = decimal_part.trim_end_matches('0');

        let formatted_int = add_thousands_sep(integer_part);

        if decimal_trimmed.is_empty() {
            formatted_int
        } else {
            let dec_display = if decimal_trimmed.len() > 4 {
                &decimal_trimmed[..4]
            } else {
                decimal_trimmed
            };
            format!("{}.{}", formatted_int, dec_display)
        }
    }
}

/// Add thousands separators to a number string
fn add_thousands_sep(s: &str) -> String {
    let bytes = s.as_bytes();
    let len = bytes.len();

    if len <= 3 {
        return s.to_string();
    }

    let mut result = String::with_capacity(len + (len - 1) / 3);
    let first_group = len % 3;

    if first_group > 0 {
        result.push_str(&s[..first_group]);
        if len > first_group {
            result.push(',');
        }
    }

    for (i, chunk) in s.as_bytes()[first_group..].chunks(3).enumerate() {
        if i > 0 {
            result.push(',');
        }
        result.push_str(std::str::from_utf8(chunk).unwrap());
    }

    result
}
