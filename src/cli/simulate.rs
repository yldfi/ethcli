//! Simulate commands - transaction simulation and tracing
//!
//! Supports multiple backends: cast, anvil, tenderly, debug RPC

use crate::config::{AddressBook, Chain, ConfigFile};
use crate::rpc::get_rpc_url;
use clap::{Args, Subcommand, ValueEnum};
use std::process::Command;

/// Tenderly API credentials - shared across multiple subcommands
#[derive(Args, Clone, Debug)]
pub struct TenderlyArgs {
    /// Tenderly API key (or use TENDERLY_ACCESS_KEY env)
    #[arg(long, env = "TENDERLY_ACCESS_KEY")]
    pub tenderly_key: Option<String>,

    /// Tenderly account slug
    #[arg(long, env = "TENDERLY_ACCOUNT")]
    pub tenderly_account: Option<String>,

    /// Tenderly project slug
    #[arg(long, env = "TENDERLY_PROJECT")]
    pub tenderly_project: Option<String>,
}

/// Output format for dry-run mode
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum DryRunFormat {
    /// Raw JSON request payload
    #[default]
    Json,
    /// curl command
    Curl,
    /// Node.js fetch snippet
    Fetch,
    /// PowerShell Invoke-RestMethod
    Powershell,
    /// Just the endpoint URL
    Url,
    /// Python requests
    Python,
    /// HTTPie command
    Httpie,
    /// wget command
    Wget,
    /// Go net/http
    Go,
    /// Rust reqwest
    Rust,
    /// Node.js axios
    Axios,
}

/// Format a request as the specified output format
fn format_request(
    url: &str,
    method: &str,
    headers: &[(&str, &str)],
    body: &serde_json::Value,
    format: DryRunFormat,
    show_secrets: bool,
) -> String {
    // Helper to check if a header should be masked
    let should_mask = |key: &str| -> bool {
        !show_secrets
            && (key.to_lowercase().contains("key") || key.to_lowercase().contains("authorization"))
    };

    match format {
        DryRunFormat::Json => serde_json::to_string_pretty(body).unwrap_or_default(),
        DryRunFormat::Url => url.to_string(),
        DryRunFormat::Curl => {
            let mut cmd = format!("curl -X {} '{}'", method, url);
            for (key, value) in headers {
                let display_value = if should_mask(key) {
                    format!("${}", key.to_uppercase().replace("-", "_"))
                } else {
                    value.to_string()
                };
                cmd.push_str(&format!(" \\\n  -H '{}: {}'", key, display_value));
            }
            let body_str = serde_json::to_string(body).unwrap_or_default();
            cmd.push_str(&format!(" \\\n  -d '{}'", body_str));
            cmd
        }
        DryRunFormat::Fetch => {
            let mut headers_obj = String::from("{");
            for (i, (key, value)) in headers.iter().enumerate() {
                let display_value = if should_mask(key) {
                    format!("process.env.{}", key.to_uppercase().replace("-", "_"))
                } else {
                    format!("'{}'", value)
                };
                if i > 0 {
                    headers_obj.push(',');
                }
                headers_obj.push_str(&format!("\n    '{}': {}", key, display_value));
            }
            headers_obj.push_str("\n  }");

            let body_str = serde_json::to_string_pretty(body).unwrap_or_default();
            format!(
                r#"const response = await fetch('{}', {{
  method: '{}',
  headers: {},
  body: JSON.stringify({})
}});
const data = await response.json();
console.log(data);"#,
                url, method, headers_obj, body_str
            )
        }
        DryRunFormat::Powershell => {
            let mut headers_hash = String::from("@{");
            for (key, value) in headers {
                let display_value = if should_mask(key) {
                    format!("$env:{}", key.to_uppercase().replace("-", "_"))
                } else {
                    format!("'{}'", value)
                };
                headers_hash.push_str(&format!("\n    '{}' = {}", key, display_value));
            }
            headers_hash.push_str("\n}");

            let body_str = serde_json::to_string(body).unwrap_or_default();
            format!(
                r#"$headers = {}

$body = @'
{}
'@

Invoke-RestMethod -Uri '{}' -Method {} -Headers $headers -Body $body -ContentType 'application/json'"#,
                headers_hash, body_str, url, method
            )
        }
        DryRunFormat::Python => {
            let mut headers_dict = String::from("{");
            for (i, (key, value)) in headers.iter().enumerate() {
                let display_value = if should_mask(key) {
                    format!("os.environ['{}']", key.to_uppercase().replace("-", "_"))
                } else {
                    format!("'{}'", value)
                };
                if i > 0 {
                    headers_dict.push(',');
                }
                headers_dict.push_str(&format!("\n    '{}': {}", key, display_value));
            }
            headers_dict.push_str("\n}");

            let body_str = serde_json::to_string_pretty(body).unwrap_or_default();
            format!(
                r#"import requests
import os

headers = {}

data = {}

response = requests.{}('{}', headers=headers, json=data)
print(response.json())"#,
                headers_dict,
                body_str,
                method.to_lowercase(),
                url
            )
        }
        DryRunFormat::Httpie => {
            let mut cmd = format!("http {} '{}'", method, url);
            for (key, value) in headers {
                let display_value = if should_mask(key) {
                    format!("$${}", key.to_uppercase().replace("-", "_"))
                } else {
                    value.to_string()
                };
                cmd.push_str(&format!(" \\\n  '{}:{}'", key, display_value));
            }
            let body_str = serde_json::to_string(body).unwrap_or_default();
            // HTTPie uses := for raw JSON
            cmd.push_str(&format!(" \\\n  --raw '{}'", body_str));
            cmd
        }
        DryRunFormat::Wget => {
            let mut cmd = format!("wget -q -O - --method={} '{}'", method, url);
            for (key, value) in headers {
                let display_value = if should_mask(key) {
                    format!("${}", key.to_uppercase().replace("-", "_"))
                } else {
                    value.to_string()
                };
                cmd.push_str(&format!(" \\\n  --header='{}: {}'", key, display_value));
            }
            let body_str = serde_json::to_string(body).unwrap_or_default();
            cmd.push_str(&format!(" \\\n  --body-data='{}'", body_str));
            cmd
        }
        DryRunFormat::Go => {
            let body_str = serde_json::to_string_pretty(body).unwrap_or_default();
            let mut header_lines = String::new();
            for (key, value) in headers {
                let display_value = if should_mask(key) {
                    format!("os.Getenv(\"{}\")", key.to_uppercase().replace("-", "_"))
                } else {
                    format!("\"{}\"", value)
                };
                header_lines.push_str(&format!(
                    "    req.Header.Set(\"{}\", {})\n",
                    key, display_value
                ));
            }
            let mut s = String::from("package main\n\nimport (\n");
            s.push_str("    \"bytes\"\n    \"encoding/json\"\n    \"fmt\"\n");
            s.push_str("    \"net/http\"\n    \"os\"\n)\n\nfunc main() {\n");
            s.push_str(&format!("    data := `{}`\n\n", body_str));
            s.push_str(&format!(
                "    req, _ := http.NewRequest(\"{}\", \"{}\", bytes.NewBuffer([]byte(data)))\n",
                method, url
            ));
            s.push_str(&header_lines);
            s.push_str("    req.Header.Set(\"Content-Type\", \"application/json\")\n\n");
            s.push_str("    client := &http.Client{}\n");
            s.push_str("    resp, _ := client.Do(req)\n");
            s.push_str("    defer resp.Body.Close()\n\n");
            s.push_str("    var result map[string]interface{}\n");
            s.push_str("    json.NewDecoder(resp.Body).Decode(&result)\n");
            s.push_str("    fmt.Println(result)\n}");
            s
        }
        DryRunFormat::Rust => {
            let body_str = serde_json::to_string_pretty(body).unwrap_or_default();
            let mut header_lines = String::new();
            for (key, value) in headers {
                let display_value = if should_mask(key) {
                    format!(
                        "&std::env::var(\"{}\").unwrap()",
                        key.to_uppercase().replace("-", "_")
                    )
                } else {
                    format!("\"{}\"", value)
                };
                header_lines.push_str(&format!(
                    "        .header(\"{}\", {})\n",
                    key, display_value
                ));
            }
            let mut s = String::from("use reqwest::blocking::Client;\nuse serde_json::Value;\n\n");
            s.push_str("fn main() -> Result<(), Box<dyn std::error::Error>> {\n");
            s.push_str(&format!(
                "    let body: Value = serde_json::from_str(r#\"{}\"#)?;\n\n",
                body_str
            ));
            s.push_str("    let client = Client::new();\n");
            s.push_str("    let response = client\n");
            s.push_str(&format!(
                "        .{}(\"{}\")\n",
                method.to_lowercase(),
                url
            ));
            s.push_str(&header_lines);
            s.push_str("        .json(&body)\n");
            s.push_str("        .send()?\n");
            s.push_str("        .json::<Value>()?;\n\n");
            s.push_str("    println!(\"{:#?}\", response);\n");
            s.push_str("    Ok(())\n}");
            s
        }
        DryRunFormat::Axios => {
            let mut headers_obj = String::from("{");
            for (i, (key, value)) in headers.iter().enumerate() {
                let display_value = if should_mask(key) {
                    format!("process.env.{}", key.to_uppercase().replace("-", "_"))
                } else {
                    format!("'{}'", value)
                };
                if i > 0 {
                    headers_obj.push(',');
                }
                headers_obj.push_str(&format!("\n    '{}': {}", key, display_value));
            }
            headers_obj.push_str("\n  }");

            let body_str = serde_json::to_string_pretty(body).unwrap_or_default();
            let mut s = String::from("const axios = require('axios');\n\n");
            s.push_str(&format!(
                "axios.{}('{}', {}, {{\n  headers: {}\n}})\n",
                method.to_lowercase(),
                url,
                body_str,
                headers_obj
            ));
            s.push_str(".then(response => console.log(response.data))\n");
            s.push_str(".catch(error => console.error(error));");
            s
        }
    }
}

/// Resolve an address label to an address, or return the address as-is
fn resolve_address(label_or_address: &str) -> String {
    let book = AddressBook::load_default();
    book.resolve(label_or_address)
        .unwrap_or_else(|| label_or_address.to_string())
}

/// Build calldata from signature and args, or use raw data
/// Resolves address labels in args
fn build_calldata(
    sig: &Option<String>,
    data: &Option<String>,
    args: &[String],
) -> anyhow::Result<String> {
    if let Some(data) = data {
        Ok(data.clone())
    } else if let Some(sig) = sig {
        let mut cmd = Command::new("cast");
        cmd.arg("calldata").arg(sig);
        for arg in args {
            // Resolve address labels in args
            cmd.arg(resolve_address(arg));
        }
        let output = cmd.output()?;
        if !output.status.success() {
            return Err(anyhow::anyhow!("Failed to encode calldata"));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err(anyhow::anyhow!("Must provide --sig or --data"))
    }
}

/// Convert a value string to hex format for RPC calls
fn value_to_hex(value: &str) -> anyhow::Result<String> {
    if value == "0" {
        Ok("0x0".to_string())
    } else {
        Ok(format!("0x{:x}", value.parse::<u128>()?))
    }
}

/// Convert a block number or tag to RPC parameter format
fn block_to_param(block: &str) -> anyhow::Result<String> {
    if block == "latest" || block == "pending" || block == "earliest" {
        Ok(block.to_string())
    } else {
        Ok(format!("0x{:x}", block.parse::<u64>()?))
    }
}

/// Get a tracing-capable RPC URL from args or config
///
/// Priority:
/// 1. Explicit --rpc-url if provided
/// 2. First endpoint with has_debug: true for the specified chain (supports debug_traceCall)
/// 3. First endpoint with has_trace: true for the specified chain (supports trace_call)
/// 4. First entry in debug_rpc_urls (backwards compatibility)
fn get_debug_rpc_url(rpc_url: &Option<String>, chain: Chain) -> Option<String> {
    // If explicit URL provided, use it
    if rpc_url.is_some() {
        return rpc_url.clone();
    }

    // Try to get from config
    let config = ConfigFile::load_default().ok().flatten()?;

    // First, look for endpoints with has_debug: true for the specified chain
    if let Some(ep) = config
        .endpoints
        .iter()
        .find(|e| e.has_debug && e.enabled && e.chain == chain)
    {
        return Some(ep.url.clone());
    }

    // Next, look for endpoints with has_trace: true for the specified chain
    if let Some(ep) = config
        .endpoints
        .iter()
        .find(|e| e.has_trace && e.enabled && e.chain == chain)
    {
        return Some(ep.url.clone());
    }

    // Fall back to legacy debug_rpc_urls
    config.debug_rpc_urls.first().cloned()
}

/// Get a trace-capable RPC URL from args or config
///
/// Priority:
/// 1. Explicit --rpc-url if provided
/// 2. First endpoint with has_trace: true for the specified chain (supports trace_call)
/// 3. First endpoint with has_debug: true for the specified chain (some debug nodes also support trace)
fn get_trace_rpc_url(rpc_url: &Option<String>, chain: Chain) -> Option<String> {
    // If explicit URL provided, use it
    if rpc_url.is_some() {
        return rpc_url.clone();
    }

    // Try to get from config
    let config = ConfigFile::load_default().ok().flatten()?;

    // First, look for endpoints with has_trace: true for the specified chain
    if let Some(ep) = config
        .endpoints
        .iter()
        .find(|e| e.has_trace && e.enabled && e.chain == chain)
    {
        return Some(ep.url.clone());
    }

    // Fall back to endpoints with has_debug: true for the specified chain
    config
        .endpoints
        .iter()
        .find(|e| e.has_debug && e.enabled && e.chain == chain)
        .map(|e| e.url.clone())
}

/// Get Tenderly credentials from args, env, or config file
fn get_tenderly_credentials(
    key: &Option<String>,
    account: &Option<String>,
    project: &Option<String>,
) -> anyhow::Result<(String, String, String)> {
    // Try args/env first, then fall back to config
    let config = ConfigFile::load_default().ok().flatten();
    let tenderly_config = config.as_ref().and_then(|c| c.tenderly.as_ref());

    let api_key = key
        .clone()
        .or_else(|| tenderly_config.map(|t| t.access_key.clone()))
        .ok_or_else(|| anyhow::anyhow!(
            "Tenderly API key required. Set via --tenderly-key, TENDERLY_ACCESS_KEY env, or config file"
        ))?;

    let acct = account
        .clone()
        .or_else(|| tenderly_config.map(|t| t.account.clone()))
        .ok_or_else(|| anyhow::anyhow!(
            "Tenderly account required. Set via --tenderly-account, TENDERLY_ACCOUNT env, or config file"
        ))?;

    let proj = project
        .clone()
        .or_else(|| tenderly_config.map(|t| t.project.clone()))
        .ok_or_else(|| anyhow::anyhow!(
            "Tenderly project required. Set via --tenderly-project, TENDERLY_PROJECT env, or config file"
        ))?;

    Ok((api_key, acct, proj))
}

/// Simulation backend
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum SimulateVia {
    /// Use cast call --trace (default, works everywhere)
    #[default]
    Cast,
    /// Use Anvil fork (stateful, supports multiple txs)
    Anvil,
    /// Use Tenderly API (rich decoded output)
    Tenderly,
    /// Use debug_traceCall RPC (requires Geth-compatible node)
    Debug,
    /// Use trace_call RPC (requires Erigon/OpenEthereum-compatible node)
    Trace,
}

#[derive(Subcommand)]
pub enum SimulateCommands {
    /// Simulate a transaction call (without sending)
    Call {
        /// Target contract address
        to: String,

        /// Function signature (e.g., "transfer(address,uint256)")
        #[arg(long, short)]
        sig: Option<String>,

        /// Raw calldata (hex encoded, alternative to --sig)
        #[arg(long, short)]
        data: Option<String>,

        /// Function arguments (used with --sig)
        args: Vec<String>,

        /// Sender address (default: zero address)
        #[arg(long)]
        from: Option<String>,

        /// Value to send in wei
        #[arg(long, default_value = "0")]
        value: String,

        /// Block number or tag (latest, pending, etc.)
        #[arg(long, short, default_value = "latest")]
        block: String,

        /// Gas limit
        #[arg(long)]
        gas: Option<u64>,

        /// Gas price in wei
        #[arg(long)]
        gas_price: Option<u64>,

        /// State override: set balance (format: address=wei, can repeat)
        #[arg(long = "balance-override", action = clap::ArgAction::Append)]
        balance_overrides: Vec<String>,

        /// State override: set storage slot (format: address:slot=value, can repeat)
        #[arg(long = "storage-override", action = clap::ArgAction::Append)]
        storage_overrides: Vec<String>,

        /// State override: set code (format: address=bytecode, can repeat)
        #[arg(long = "code-override", action = clap::ArgAction::Append)]
        code_overrides: Vec<String>,

        /// Override block timestamp (unix seconds)
        #[arg(long)]
        block_timestamp: Option<u64>,

        /// Simulation backend
        #[arg(long, value_enum, default_value = "cast")]
        via: SimulateVia,

        /// RPC URL
        #[arg(long)]
        rpc_url: Option<String>,

        /// Show execution trace (requires debug-capable node for cast)
        #[arg(long, short)]
        trace: bool,

        /// Tenderly credentials
        #[command(flatten)]
        tenderly: TenderlyArgs,

        /// Save simulation to Tenderly (returns simulation ID)
        #[arg(long)]
        save: bool,

        /// Dry run - output request without executing (json, curl, fetch, powershell, url)
        #[arg(long, value_enum)]
        dry_run: Option<DryRunFormat>,

        /// Show API keys in dry-run output (default: masked with env var placeholders)
        #[arg(long)]
        show_secrets: bool,
    },

    /// Trace an existing transaction
    Tx {
        /// Transaction hash
        hash: String,

        /// Simulation backend
        #[arg(long, value_enum, default_value = "cast")]
        via: SimulateVia,

        /// RPC URL (for debug backend)
        #[arg(long)]
        rpc_url: Option<String>,

        /// Tenderly credentials
        #[command(flatten)]
        tenderly: TenderlyArgs,

        /// Show full opcode trace
        #[arg(long, short)]
        trace: bool,

        /// Open interactive debugger (cast only)
        #[arg(long, short)]
        debug: bool,
    },

    /// Simulate a bundle of transactions in sequence (Tenderly only)
    Bundle {
        /// JSON file with transaction array, or inline JSON
        /// Format: [{"from": "0x...", "to": "0x...", "data": "0x...", "value": "0x0"}, ...]
        #[arg(long, short)]
        txs: String,

        /// Block number or tag (latest, pending, etc.)
        #[arg(long, short, default_value = "latest")]
        block: String,

        /// State override: set balance (format: address=wei, can repeat)
        #[arg(long = "balance-override", action = clap::ArgAction::Append)]
        balance_overrides: Vec<String>,

        /// State override: set storage slot (format: address:slot=value, can repeat)
        #[arg(long = "storage-override", action = clap::ArgAction::Append)]
        storage_overrides: Vec<String>,

        /// State override: set code (format: address=bytecode, can repeat)
        #[arg(long = "code-override", action = clap::ArgAction::Append)]
        code_overrides: Vec<String>,

        /// Tenderly credentials
        #[command(flatten)]
        tenderly: TenderlyArgs,

        /// Save simulation bundle to Tenderly
        #[arg(long)]
        save: bool,
    },

    /// List saved simulations (Tenderly only)
    List {
        /// Number of simulations to list
        #[arg(long, short, default_value = "20")]
        limit: u32,

        /// Page number (0-indexed)
        #[arg(long, short, default_value = "0")]
        page: u32,

        /// Tenderly credentials
        #[command(flatten)]
        tenderly: TenderlyArgs,
    },

    /// Get a saved simulation by ID (Tenderly only)
    Get {
        /// Simulation ID
        id: String,

        /// Tenderly credentials
        #[command(flatten)]
        tenderly: TenderlyArgs,
    },

    /// Get simulation info/metadata by ID (Tenderly only)
    Info {
        /// Simulation ID
        id: String,

        /// Tenderly credentials
        #[command(flatten)]
        tenderly: TenderlyArgs,
    },

    /// Share a simulation publicly (Tenderly only)
    /// Creates a public URL to view the simulation in the dashboard
    Share {
        /// Simulation ID
        id: String,

        /// Tenderly credentials
        #[command(flatten)]
        tenderly: TenderlyArgs,
    },

    /// Unshare a simulation (make private) (Tenderly only)
    Unshare {
        /// Simulation ID
        id: String,

        /// Tenderly credentials
        #[command(flatten)]
        tenderly: TenderlyArgs,
    },
}

pub async fn handle(
    action: &SimulateCommands,
    chain: crate::config::Chain,
    quiet: bool,
) -> anyhow::Result<()> {
    match action {
        SimulateCommands::Call {
            to,
            sig,
            data,
            args,
            from,
            value,
            block,
            gas,
            gas_price,
            balance_overrides,
            storage_overrides,
            code_overrides,
            block_timestamp,
            via,
            rpc_url,
            trace,
            tenderly,
            save,
            dry_run,
            show_secrets,
        } => match via {
            SimulateVia::Cast => {
                if dry_run.is_some() {
                    return Err(anyhow::anyhow!("--dry-run not supported for cast backend. Use --via tenderly, debug, or trace"));
                }
                simulate_via_cast(
                    to, sig, data, args, from, value, block, rpc_url, *trace, quiet,
                )
                .await
            }
            SimulateVia::Anvil => {
                if dry_run.is_some() {
                    return Err(anyhow::anyhow!("--dry-run not supported for anvil backend. Use --via tenderly, debug, or trace"));
                }
                simulate_via_anvil(to, sig, data, args, from, value, rpc_url, quiet).await
            }
            SimulateVia::Tenderly => {
                simulate_via_tenderly(
                    to,
                    sig,
                    data,
                    args,
                    from,
                    value,
                    block,
                    *gas,
                    *gas_price,
                    balance_overrides,
                    storage_overrides,
                    code_overrides,
                    *block_timestamp,
                    *save,
                    &tenderly.tenderly_key,
                    &tenderly.tenderly_account,
                    &tenderly.tenderly_project,
                    *dry_run,
                    *show_secrets,
                    quiet,
                )
                .await
            }
            SimulateVia::Debug => {
                simulate_via_debug_rpc(
                    to,
                    sig,
                    data,
                    args,
                    from,
                    value,
                    block,
                    rpc_url,
                    chain,
                    *dry_run,
                    *show_secrets,
                    quiet,
                )
                .await
            }
            SimulateVia::Trace => {
                simulate_via_trace_rpc(
                    to,
                    sig,
                    data,
                    args,
                    from,
                    value,
                    block,
                    rpc_url,
                    chain,
                    *dry_run,
                    *show_secrets,
                    quiet,
                )
                .await
            }
        },

        SimulateCommands::Tx {
            hash,
            via,
            rpc_url,
            tenderly,
            trace,
            debug,
        } => match via {
            SimulateVia::Cast => trace_tx_via_cast(hash, *trace, *debug, rpc_url, quiet).await,
            SimulateVia::Anvil => {
                // Anvil doesn't directly trace existing txs, use cast run
                trace_tx_via_cast(hash, *trace, *debug, rpc_url, quiet).await
            }
            SimulateVia::Tenderly => {
                trace_tx_via_tenderly(
                    hash,
                    &tenderly.tenderly_key,
                    &tenderly.tenderly_account,
                    &tenderly.tenderly_project,
                    quiet,
                )
                .await
            }
            SimulateVia::Debug => trace_tx_via_debug_rpc(hash, rpc_url, chain, quiet).await,
            SimulateVia::Trace => trace_tx_via_trace_rpc(hash, rpc_url, chain, quiet).await,
        },

        SimulateCommands::Bundle {
            txs,
            block,
            balance_overrides,
            storage_overrides,
            code_overrides,
            tenderly,
            save,
        } => {
            simulate_bundle_tenderly(
                txs,
                block,
                balance_overrides,
                storage_overrides,
                code_overrides,
                *save,
                &tenderly.tenderly_key,
                &tenderly.tenderly_account,
                &tenderly.tenderly_project,
                quiet,
            )
            .await
        }

        SimulateCommands::List {
            limit,
            page,
            tenderly,
        } => {
            list_simulations_tenderly(
                *limit,
                *page,
                &tenderly.tenderly_key,
                &tenderly.tenderly_account,
                &tenderly.tenderly_project,
                quiet,
            )
            .await
        }

        SimulateCommands::Get { id, tenderly } => {
            get_simulation_tenderly(
                id,
                &tenderly.tenderly_key,
                &tenderly.tenderly_account,
                &tenderly.tenderly_project,
                quiet,
            )
            .await
        }

        SimulateCommands::Info { id, tenderly } => {
            get_simulation_info_tenderly(
                id,
                &tenderly.tenderly_key,
                &tenderly.tenderly_account,
                &tenderly.tenderly_project,
                quiet,
            )
            .await
        }

        SimulateCommands::Share { id, tenderly } => {
            share_simulation_tenderly(
                id,
                &tenderly.tenderly_key,
                &tenderly.tenderly_account,
                &tenderly.tenderly_project,
                quiet,
            )
            .await
        }

        SimulateCommands::Unshare { id, tenderly } => {
            unshare_simulation_tenderly(
                id,
                &tenderly.tenderly_key,
                &tenderly.tenderly_account,
                &tenderly.tenderly_project,
                quiet,
            )
            .await
        }
    }
}

/// Simulate using cast call --trace
#[allow(clippy::too_many_arguments)]
async fn simulate_via_cast(
    to: &str,
    sig: &Option<String>,
    data: &Option<String>,
    args: &[String],
    from: &Option<String>,
    value: &str,
    block: &str,
    rpc_url: &Option<String>,
    trace: bool,
    quiet: bool,
) -> anyhow::Result<()> {
    let mut cmd = Command::new("cast");
    cmd.arg("call");

    // Resolve target address
    let resolved_to = resolve_address(to);
    cmd.arg(&resolved_to);

    // Add signature or data
    if let Some(sig) = sig {
        cmd.arg(sig);
        for arg in args {
            // Resolve address labels in args
            cmd.arg(resolve_address(arg));
        }
    } else if let Some(data) = data {
        cmd.arg("--data").arg(data);
    } else {
        return Err(anyhow::anyhow!("Must provide --sig or --data"));
    }

    // Add optional params
    if let Some(from) = from {
        cmd.arg("--from").arg(from);
    }

    if value != "0" {
        cmd.arg("--value").arg(value);
    }

    cmd.arg("--block").arg(block);

    // Add RPC URL if provided
    if let Some(rpc) = rpc_url {
        cmd.arg("--rpc-url").arg(rpc);
    }

    // Only add --trace if requested (requires debug-capable node)
    if trace {
        cmd.arg("--trace");
    }

    if !quiet {
        let trace_str = if trace { " --trace" } else { "" };
        eprintln!("Running: cast call {}{} ...", to, trace_str);
    }

    let output = cmd.output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("cast call failed: {}", stderr));
    }

    print!("{}", String::from_utf8_lossy(&output.stdout));

    Ok(())
}

/// Trace existing tx using cast run
async fn trace_tx_via_cast(
    hash: &str,
    trace: bool,
    debug: bool,
    rpc_url: &Option<String>,
    quiet: bool,
) -> anyhow::Result<()> {
    let mut cmd = Command::new("cast");
    cmd.arg("run");
    cmd.arg(hash);

    if trace {
        cmd.arg("--trace-printer");
    }

    if debug {
        cmd.arg("--debug");
    }

    if let Some(rpc) = rpc_url {
        cmd.arg("--rpc-url").arg(rpc);
    }

    if !quiet {
        eprintln!("Running: cast run {} ...", hash);
    }

    let status = cmd.status()?;

    if !status.success() {
        return Err(anyhow::anyhow!("cast run failed"));
    }

    Ok(())
}

/// Simulate using Anvil fork
#[allow(clippy::too_many_arguments)]
async fn simulate_via_anvil(
    to: &str,
    sig: &Option<String>,
    data: &Option<String>,
    args: &[String],
    from: &Option<String>,
    value: &str,
    rpc_url: &Option<String>,
    quiet: bool,
) -> anyhow::Result<()> {
    use std::process::Stdio;
    use tokio::time::{sleep, Duration};

    let fork_url = rpc_url
        .clone()
        .or_else(|| {
            // Try to get URL from configured endpoints (smart selection)
            get_rpc_url(Chain::Ethereum).ok()
        })
        .unwrap_or_else(|| "https://eth.llamarpc.com".to_string());

    if !quiet {
        eprintln!("Starting Anvil fork of {}...", fork_url);
    }

    // Start anvil in background
    let mut anvil = Command::new("anvil")
        .arg("--fork-url")
        .arg(&fork_url)
        .arg("--port")
        .arg("8546") // Use non-default port to avoid conflicts
        .arg("--silent")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    // Wait for anvil to start
    sleep(Duration::from_secs(2)).await;

    // Run the simulation against local anvil
    let mut cmd = Command::new("cast");
    cmd.arg("call");

    // Resolve target address
    let resolved_to = resolve_address(to);
    cmd.arg(&resolved_to);

    if let Some(sig) = sig {
        cmd.arg(sig);
        for arg in args {
            // Resolve address labels in args
            cmd.arg(resolve_address(arg));
        }
    } else if let Some(data) = data {
        cmd.arg("--data").arg(data);
    } else {
        anvil.kill()?;
        return Err(anyhow::anyhow!("Must provide --sig or --data"));
    }

    if let Some(from) = from {
        cmd.arg("--from").arg(from);
    }

    if value != "0" {
        cmd.arg("--value").arg(value);
    }

    cmd.arg("--rpc-url").arg("http://localhost:8546");
    cmd.arg("--trace");

    let output = cmd.output()?;

    // Kill anvil
    anvil.kill()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("Simulation failed: {}", stderr));
    }

    print!("{}", String::from_utf8_lossy(&output.stdout));

    if !quiet {
        eprintln!("\nAnvil fork terminated.");
    }

    Ok(())
}

/// Simulate using Tenderly API
#[allow(clippy::too_many_arguments)]
async fn simulate_via_tenderly(
    to: &str,
    sig: &Option<String>,
    data: &Option<String>,
    args: &[String],
    from: &Option<String>,
    value: &str,
    block: &str,
    gas: Option<u64>,
    gas_price: Option<u64>,
    balance_overrides: &[String],
    storage_overrides: &[String],
    code_overrides: &[String],
    block_timestamp: Option<u64>,
    save: bool,
    tenderly_key: &Option<String>,
    tenderly_account: &Option<String>,
    tenderly_project: &Option<String>,
    dry_run: Option<DryRunFormat>,
    show_secrets: bool,
    quiet: bool,
) -> anyhow::Result<()> {
    let (api_key, account, project) =
        get_tenderly_credentials(tenderly_key, tenderly_account, tenderly_project)?;

    // Resolve target address
    let resolved_to = resolve_address(to);

    let calldata = build_calldata(sig, data, args)?;

    let from_addr = from
        .clone()
        .unwrap_or_else(|| "0x0000000000000000000000000000000000000000".to_string());

    // Parse block number
    let block_number = if block == "latest" {
        None
    } else {
        Some(block.parse::<u64>()?)
    };

    let value_wei = value_to_hex(value)?;

    // Build request
    let mut request = serde_json::json!({
        "network_id": "1",
        "from": from_addr,
        "to": resolved_to,
        "input": calldata,
        "value": value_wei,
        "save": save,
        "save_if_fails": save,
        "simulation_type": "full"
    });

    if let Some(bn) = block_number {
        request["block_number"] = serde_json::json!(bn);
    }

    // Add gas parameters
    if let Some(g) = gas {
        request["gas"] = serde_json::json!(g);
    }

    if let Some(gp) = gas_price {
        request["gas_price"] = serde_json::json!(format!("{}", gp));
    }

    // Build state overrides
    let state_objects =
        build_state_overrides(balance_overrides, storage_overrides, code_overrides)?;
    if !state_objects.is_empty() {
        request["state_objects"] = serde_json::json!(state_objects);
    }

    // Add block header overrides
    if block_timestamp.is_some() {
        let mut block_header = serde_json::Map::new();
        if let Some(ts) = block_timestamp {
            block_header.insert(
                "timestamp".to_string(),
                serde_json::json!(format!("0x{:x}", ts)),
            );
        }
        request["block_header"] = serde_json::json!(block_header);
    }

    let url = format!(
        "https://api.tenderly.co/api/v1/account/{}/project/{}/simulate",
        account, project
    );

    // Handle dry-run mode - output request without executing
    if let Some(format) = dry_run {
        let headers = vec![
            ("X-Access-Key", api_key.as_str()),
            ("Content-Type", "application/json"),
        ];
        let output = format_request(&url, "POST", &headers, &request, format, show_secrets);
        println!("{}", output);
        return Ok(());
    }

    if !quiet {
        eprintln!("Simulating via Tenderly API...");
        if save {
            eprintln!("  Saving simulation to Tenderly");
        }
        if !state_objects.is_empty() {
            eprintln!("  State overrides: {} addresses", state_objects.len());
        }
    }

    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .header("X-Access-Key", &api_key)
        .header("Content-Type", "application/json")
        .json(&request)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await?;
        return Err(anyhow::anyhow!("Tenderly API error {}: {}", status, text));
    }

    let result: serde_json::Value = response.json().await?;

    // If saved, show the simulation ID prominently
    if save {
        if let Some(sim) = result.get("simulation") {
            if let Some(id) = sim.get("id") {
                eprintln!("Simulation ID: {}", id);
            }
        }
    }

    // Pretty print the result
    println!("{}", serde_json::to_string_pretty(&result)?);

    Ok(())
}

/// Build state overrides map for Tenderly API
fn build_state_overrides(
    balance_overrides: &[String],
    storage_overrides: &[String],
    code_overrides: &[String],
) -> anyhow::Result<std::collections::HashMap<String, serde_json::Value>> {
    use std::collections::HashMap;

    let mut state_objects: HashMap<String, serde_json::Value> = HashMap::new();

    // Parse balance overrides: format "address=wei"
    for override_str in balance_overrides {
        let parts: Vec<&str> = override_str.splitn(2, '=').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!(
                "Invalid balance override format: {}. Use address=wei",
                override_str
            ));
        }
        let address = parts[0].to_lowercase();
        let balance = parts[1];

        let entry = state_objects
            .entry(address.clone())
            .or_insert_with(|| serde_json::json!({}));
        entry["balance"] = serde_json::json!(balance);
    }

    // Parse storage overrides: format "address:slot=value"
    for override_str in storage_overrides {
        let parts: Vec<&str> = override_str.splitn(2, '=').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!(
                "Invalid storage override format: {}. Use address:slot=value",
                override_str
            ));
        }
        let addr_slot: Vec<&str> = parts[0].splitn(2, ':').collect();
        if addr_slot.len() != 2 {
            return Err(anyhow::anyhow!(
                "Invalid storage override format: {}. Use address:slot=value",
                override_str
            ));
        }
        let address = addr_slot[0].to_lowercase();
        let slot = addr_slot[1];
        let value = parts[1];

        let entry = state_objects
            .entry(address.clone())
            .or_insert_with(|| serde_json::json!({}));

        // Initialize storage map if needed
        if entry.get("storage").is_none() {
            entry["storage"] = serde_json::json!({});
        }
        entry["storage"][slot] = serde_json::json!(value);
    }

    // Parse code overrides: format "address=bytecode"
    for override_str in code_overrides {
        let parts: Vec<&str> = override_str.splitn(2, '=').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!(
                "Invalid code override format: {}. Use address=bytecode",
                override_str
            ));
        }
        let address = parts[0].to_lowercase();
        let code = parts[1];

        let entry = state_objects
            .entry(address.clone())
            .or_insert_with(|| serde_json::json!({}));
        entry["code"] = serde_json::json!(code);
    }

    Ok(state_objects)
}

/// Trace existing tx via Tenderly
async fn trace_tx_via_tenderly(
    hash: &str,
    tenderly_key: &Option<String>,
    tenderly_account: &Option<String>,
    tenderly_project: &Option<String>,
    quiet: bool,
) -> anyhow::Result<()> {
    let (api_key, account, project) =
        get_tenderly_credentials(tenderly_key, tenderly_account, tenderly_project)?;

    if !quiet {
        eprintln!("Fetching trace from Tenderly API...");
    }

    let client = reqwest::Client::new();
    let url = format!(
        "https://api.tenderly.co/api/v1/account/{}/project/{}/trace/{}",
        account, project, hash
    );

    let response = client
        .get(&url)
        .header("X-Access-Key", api_key)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await?;
        return Err(anyhow::anyhow!("Tenderly API error {}: {}", status, text));
    }

    let result: serde_json::Value = response.json().await?;
    println!("{}", serde_json::to_string_pretty(&result)?);

    Ok(())
}

/// Simulate using debug_traceCall RPC
#[allow(clippy::too_many_arguments)]
async fn simulate_via_debug_rpc(
    to: &str,
    sig: &Option<String>,
    data: &Option<String>,
    args: &[String],
    from: &Option<String>,
    value: &str,
    block: &str,
    rpc_url: &Option<String>,
    chain: Chain,
    dry_run: Option<DryRunFormat>,
    show_secrets: bool,
    quiet: bool,
) -> anyhow::Result<()> {
    let rpc = get_debug_rpc_url(rpc_url, chain)
        .ok_or_else(|| anyhow::anyhow!(
            "Debug RPC URL required. Set via --rpc-url, add an endpoint with has_debug: true, or use 'config add-debug-rpc'"
        ))?;

    // Resolve target address
    let resolved_to = resolve_address(to);

    let calldata = build_calldata(sig, data, args)?;

    let from_addr = from
        .clone()
        .unwrap_or_else(|| "0x0000000000000000000000000000000000000000".to_string());

    let value_hex = value_to_hex(value)?;
    let block_param = block_to_param(block)?;

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "debug_traceCall",
        "params": [
            {
                "from": from_addr,
                "to": resolved_to,
                "data": calldata,
                "value": value_hex
            },
            block_param,
            {
                "tracer": "callTracer",
                "tracerConfig": {
                    "withLog": true
                }
            }
        ],
        "id": 1
    });

    // Handle dry-run mode - output request without executing
    if let Some(format) = dry_run {
        let headers = vec![("Content-Type", "application/json")];
        let output = format_request(&rpc, "POST", &headers, &request, format, show_secrets);
        println!("{}", output);
        return Ok(());
    }

    if !quiet {
        eprintln!("Calling debug_traceCall on {}...", rpc);
    }

    let client = reqwest::Client::new();
    let response = client
        .post(&rpc)
        .header("Content-Type", "application/json")
        .json(&request)
        .send()
        .await?;

    let result: serde_json::Value = response.json().await?;

    if let Some(error) = result.get("error") {
        return Err(anyhow::anyhow!("RPC error: {}", error));
    }

    if let Some(trace) = result.get("result") {
        println!("{}", serde_json::to_string_pretty(trace)?);
    } else {
        println!("{}", serde_json::to_string_pretty(&result)?);
    }

    Ok(())
}

/// Trace existing tx via debug_traceTransaction
async fn trace_tx_via_debug_rpc(
    hash: &str,
    rpc_url: &Option<String>,
    chain: Chain,
    quiet: bool,
) -> anyhow::Result<()> {
    let rpc = get_debug_rpc_url(rpc_url, chain)
        .ok_or_else(|| anyhow::anyhow!(
            "Debug RPC URL required. Set via --rpc-url, add an endpoint with has_debug: true, or use 'config add-debug-rpc'"
        ))?;

    if !quiet {
        eprintln!("Calling debug_traceTransaction on {}...", rpc);
    }

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "debug_traceTransaction",
        "params": [
            hash,
            {
                "tracer": "callTracer",
                "tracerConfig": {
                    "withLog": true
                }
            }
        ],
        "id": 1
    });

    let client = reqwest::Client::new();
    let response = client
        .post(&rpc)
        .header("Content-Type", "application/json")
        .json(&request)
        .send()
        .await?;

    let result: serde_json::Value = response.json().await?;

    if let Some(error) = result.get("error") {
        return Err(anyhow::anyhow!("RPC error: {}", error));
    }

    if let Some(trace) = result.get("result") {
        println!("{}", serde_json::to_string_pretty(trace)?);
    } else {
        println!("{}", serde_json::to_string_pretty(&result)?);
    }

    Ok(())
}

/// Simulate using trace_call RPC (Parity/Erigon style)
#[allow(clippy::too_many_arguments)]
async fn simulate_via_trace_rpc(
    to: &str,
    sig: &Option<String>,
    data: &Option<String>,
    args: &[String],
    from: &Option<String>,
    value: &str,
    block: &str,
    rpc_url: &Option<String>,
    chain: Chain,
    dry_run: Option<DryRunFormat>,
    show_secrets: bool,
    quiet: bool,
) -> anyhow::Result<()> {
    let rpc = get_trace_rpc_url(rpc_url, chain).ok_or_else(|| {
        anyhow::anyhow!(
            "Trace RPC URL required. Set via --rpc-url or add an endpoint with has_trace: true"
        )
    })?;

    // Resolve target address
    let resolved_to = resolve_address(to);

    let calldata = build_calldata(sig, data, args)?;

    let from_addr = from
        .clone()
        .unwrap_or_else(|| "0x0000000000000000000000000000000000000000".to_string());

    let value_hex = value_to_hex(value)?;
    let block_param = block_to_param(block)?;

    // trace_call params: [tx_object, ["trace", "vmTrace", "stateDiff"], block_number]
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "trace_call",
        "params": [
            {
                "from": from_addr,
                "to": resolved_to,
                "data": calldata,
                "value": value_hex
            },
            ["trace", "vmTrace"],
            block_param
        ],
        "id": 1
    });

    // Handle dry-run mode - output request without executing
    if let Some(format) = dry_run {
        let headers = vec![("Content-Type", "application/json")];
        let output = format_request(&rpc, "POST", &headers, &request, format, show_secrets);
        println!("{}", output);
        return Ok(());
    }

    if !quiet {
        eprintln!("Calling trace_call on {}...", rpc);
    }

    let client = reqwest::Client::new();
    let response = client
        .post(&rpc)
        .header("Content-Type", "application/json")
        .json(&request)
        .send()
        .await?;

    let result: serde_json::Value = response.json().await?;

    if let Some(error) = result.get("error") {
        return Err(anyhow::anyhow!("RPC error: {}", error));
    }

    if let Some(trace) = result.get("result") {
        println!("{}", serde_json::to_string_pretty(trace)?);
    } else {
        println!("{}", serde_json::to_string_pretty(&result)?);
    }

    Ok(())
}

/// Trace existing tx via trace_transaction (Parity/Erigon style)
async fn trace_tx_via_trace_rpc(
    hash: &str,
    rpc_url: &Option<String>,
    chain: Chain,
    quiet: bool,
) -> anyhow::Result<()> {
    let rpc = get_trace_rpc_url(rpc_url, chain).ok_or_else(|| {
        anyhow::anyhow!(
            "Trace RPC URL required. Set via --rpc-url or add an endpoint with has_trace: true"
        )
    })?;

    if !quiet {
        eprintln!("Calling trace_transaction on {}...", rpc);
    }

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "trace_transaction",
        "params": [hash],
        "id": 1
    });

    let client = reqwest::Client::new();
    let response = client
        .post(&rpc)
        .header("Content-Type", "application/json")
        .json(&request)
        .send()
        .await?;

    let result: serde_json::Value = response.json().await?;

    if let Some(error) = result.get("error") {
        return Err(anyhow::anyhow!("RPC error: {}", error));
    }

    if let Some(trace) = result.get("result") {
        println!("{}", serde_json::to_string_pretty(trace)?);
    } else {
        println!("{}", serde_json::to_string_pretty(&result)?);
    }

    Ok(())
}

/// Simulate a bundle of transactions via Tenderly API
#[allow(clippy::too_many_arguments)]
async fn simulate_bundle_tenderly(
    txs: &str,
    block: &str,
    balance_overrides: &[String],
    storage_overrides: &[String],
    code_overrides: &[String],
    save: bool,
    tenderly_key: &Option<String>,
    tenderly_account: &Option<String>,
    tenderly_project: &Option<String>,
    quiet: bool,
) -> anyhow::Result<()> {
    let (api_key, account, project) =
        get_tenderly_credentials(tenderly_key, tenderly_account, tenderly_project)?;

    // Parse transactions from JSON string or file
    let transactions: Vec<serde_json::Value> = if txs.ends_with(".json") {
        // It's a file path
        let content = std::fs::read_to_string(txs)?;
        serde_json::from_str(&content)?
    } else {
        // Inline JSON
        serde_json::from_str(txs)?
    };

    if transactions.is_empty() {
        return Err(anyhow::anyhow!("Transaction bundle cannot be empty"));
    }

    // Parse block number
    let block_number = if block == "latest" {
        None
    } else {
        Some(block.parse::<u64>()?)
    };

    // Build simulations array
    let simulations: Vec<serde_json::Value> = transactions
        .into_iter()
        .map(|tx| {
            let mut sim = serde_json::json!({
                "network_id": "1",
                "save": save,
                "save_if_fails": save,
                "simulation_type": "full"
            });

            // Copy transaction fields
            if let Some(from) = tx.get("from") {
                sim["from"] = from.clone();
            }
            if let Some(to) = tx.get("to") {
                sim["to"] = to.clone();
            }
            if let Some(data) = tx.get("data") {
                sim["input"] = data.clone();
            }
            if let Some(input) = tx.get("input") {
                sim["input"] = input.clone();
            }
            if let Some(value) = tx.get("value") {
                sim["value"] = value.clone();
            }
            if let Some(gas) = tx.get("gas") {
                sim["gas"] = gas.clone();
            }
            if let Some(gas_price) = tx.get("gas_price") {
                sim["gas_price"] = gas_price.clone();
            }

            if let Some(bn) = block_number {
                sim["block_number"] = serde_json::json!(bn);
            }

            sim
        })
        .collect();

    // Build state overrides
    let state_objects =
        build_state_overrides(balance_overrides, storage_overrides, code_overrides)?;

    let mut request = serde_json::json!({
        "simulations": simulations
    });

    if !state_objects.is_empty() {
        request["state_objects"] = serde_json::json!(state_objects);
    }

    if !quiet {
        eprintln!(
            "Simulating bundle of {} transactions via Tenderly API...",
            simulations.len()
        );
        if save {
            eprintln!("  Saving simulation bundle to Tenderly");
        }
    }

    let client = reqwest::Client::new();
    let url = format!(
        "https://api.tenderly.co/api/v1/account/{}/project/{}/simulate-bundle",
        account, project
    );

    let response = client
        .post(&url)
        .header("X-Access-Key", api_key)
        .header("Content-Type", "application/json")
        .json(&request)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await?;
        return Err(anyhow::anyhow!("Tenderly API error {}: {}", status, text));
    }

    let result: serde_json::Value = response.json().await?;

    // Show simulation IDs if saved
    if save {
        if let Some(sims) = result.get("simulation_results").and_then(|s| s.as_array()) {
            for (i, sim) in sims.iter().enumerate() {
                if let Some(id) = sim.get("simulation").and_then(|s| s.get("id")) {
                    eprintln!("Transaction {} simulation ID: {}", i + 1, id);
                }
            }
        }
    }

    println!("{}", serde_json::to_string_pretty(&result)?);

    Ok(())
}

/// List saved simulations from Tenderly
async fn list_simulations_tenderly(
    limit: u32,
    page: u32,
    tenderly_key: &Option<String>,
    tenderly_account: &Option<String>,
    tenderly_project: &Option<String>,
    quiet: bool,
) -> anyhow::Result<()> {
    let (api_key, account, project) =
        get_tenderly_credentials(tenderly_key, tenderly_account, tenderly_project)?;

    if !quiet {
        eprintln!("Fetching saved simulations from Tenderly...");
    }

    let client = reqwest::Client::new();
    // Note: Tenderly API uses 1-based page indexing and has issues with page=0
    let url = if page > 0 {
        format!(
            "https://api.tenderly.co/api/v1/account/{}/project/{}/simulations?page={}&perPage={}",
            account, project, page, limit
        )
    } else {
        format!(
            "https://api.tenderly.co/api/v1/account/{}/project/{}/simulations?perPage={}",
            account, project, limit
        )
    };

    let response = client
        .get(&url)
        .header("X-Access-Key", api_key)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await?;
        return Err(anyhow::anyhow!("Tenderly API error {}: {}", status, text));
    }

    let result: serde_json::Value = response.json().await?;

    // Format output nicely
    if let Some(simulations) = result.get("simulations").and_then(|s| s.as_array()) {
        if simulations.is_empty() {
            println!("No saved simulations found.");
        } else {
            println!("Saved Simulations (page {}, {} per page):", page, limit);
            println!("{}", "─".repeat(80));

            for sim in simulations {
                let id = sim.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                let status = sim.get("status").and_then(|v| v.as_bool());
                let status_str = match status {
                    Some(true) => "✓",
                    Some(false) => "✗",
                    None => "?",
                };
                let created = sim
                    .get("created_at")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let from = sim.get("from").and_then(|v| v.as_str()).unwrap_or("?");
                let to = sim.get("to").and_then(|v| v.as_str()).unwrap_or("?");

                println!(
                    "{} {} | {} -> {} | {}",
                    status_str,
                    id,
                    &from[..from.len().min(10)],
                    &to[..to.len().min(10)],
                    created
                );
            }
        }
    } else {
        println!("{}", serde_json::to_string_pretty(&result)?);
    }

    Ok(())
}

/// Get a saved simulation by ID from Tenderly
async fn get_simulation_tenderly(
    id: &str,
    tenderly_key: &Option<String>,
    tenderly_account: &Option<String>,
    tenderly_project: &Option<String>,
    quiet: bool,
) -> anyhow::Result<()> {
    let (api_key, account, project) =
        get_tenderly_credentials(tenderly_key, tenderly_account, tenderly_project)?;

    if !quiet {
        eprintln!("Fetching simulation {} from Tenderly...", id);
    }

    let client = reqwest::Client::new();
    let url = format!(
        "https://api.tenderly.co/api/v1/account/{}/project/{}/simulations/{}",
        account, project, id
    );

    let response = client
        .get(&url)
        .header("X-Access-Key", api_key)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await?;
        return Err(anyhow::anyhow!("Tenderly API error {}: {}", status, text));
    }

    let result: serde_json::Value = response.json().await?;
    println!("{}", serde_json::to_string_pretty(&result)?);

    Ok(())
}

/// Get simulation info/metadata by ID from Tenderly
async fn get_simulation_info_tenderly(
    id: &str,
    tenderly_key: &Option<String>,
    tenderly_account: &Option<String>,
    tenderly_project: &Option<String>,
    quiet: bool,
) -> anyhow::Result<()> {
    let (api_key, account, project) =
        get_tenderly_credentials(tenderly_key, tenderly_account, tenderly_project)?;

    if !quiet {
        eprintln!("Fetching simulation info for {} from Tenderly...", id);
    }

    let client = reqwest::Client::new();
    // The info endpoint returns just metadata without full trace
    let url = format!(
        "https://api.tenderly.co/api/v1/account/{}/project/{}/simulations/{}/info",
        account, project, id
    );

    let response = client
        .get(&url)
        .header("X-Access-Key", api_key)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await?;
        return Err(anyhow::anyhow!("Tenderly API error {}: {}", status, text));
    }

    let result: serde_json::Value = response.json().await?;

    // Format nicely if possible - info endpoint returns transaction_info, not simulation
    if let Some(tx_info) = result.get("transaction_info") {
        println!("Simulation Info");
        println!("{}", "─".repeat(50));

        if let Some(id) = tx_info.get("id").and_then(|v| v.as_str()) {
            println!("ID:          {}", id);
        }
        if let Some(status) = tx_info.get("status").and_then(|v| v.as_bool()) {
            println!("Status:      {}", if status { "Success" } else { "Failed" });
        }
        if let Some(from) = tx_info.get("from").and_then(|v| v.as_str()) {
            println!("From:        {}", from);
        }
        if let Some(to) = tx_info.get("to").and_then(|v| v.as_str()) {
            println!("To:          {}", to);
        }
        if let Some(block) = tx_info.get("block_number").and_then(|v| v.as_str()) {
            println!("Block:       {}", block);
        }
        if let Some(gas) = tx_info.get("gas_used").and_then(|v| v.as_str()) {
            println!("Gas Used:    {}", gas);
        }
        if let Some(method) = tx_info
            .get("decoded_info")
            .and_then(|d| d.get("method_name"))
            .and_then(|v| v.as_str())
        {
            println!("Method:      {}", method);
        }
        if let Some(error) = tx_info.get("error_message").and_then(|v| v.as_str()) {
            if !error.is_empty() {
                println!("Error:       {}", error);
            }
        }
        if let Some(created) = result.get("created_at").and_then(|v| v.as_str()) {
            println!("Created:     {}", created);
        }
    } else {
        println!("{}", serde_json::to_string_pretty(&result)?);
    }

    Ok(())
}

/// Share a simulation publicly via Tenderly
async fn share_simulation_tenderly(
    id: &str,
    tenderly_key: &Option<String>,
    tenderly_account: &Option<String>,
    tenderly_project: &Option<String>,
    quiet: bool,
) -> anyhow::Result<()> {
    let (api_key, account, project) =
        get_tenderly_credentials(tenderly_key, tenderly_account, tenderly_project)?;

    if !quiet {
        eprintln!("Sharing simulation {} via Tenderly...", id);
    }

    let client = reqwest::Client::new();
    let url = format!(
        "https://api.tenderly.co/api/v1/account/{}/project/{}/simulations/{}/share",
        account, project, id
    );

    let response = client
        .post(&url)
        .header("X-Access-Key", api_key)
        .header("Content-Type", "application/json")
        .body("{}") // Empty JSON body required
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await?;
        return Err(anyhow::anyhow!("Tenderly API error {}: {}", status, text));
    }

    // Show the public URL
    let public_url = format!("https://dashboard.tenderly.co/shared/simulation/{}", id);

    println!("Simulation shared successfully!");
    println!("Public URL: {}", public_url);

    Ok(())
}

/// Unshare a simulation (make private) via Tenderly
async fn unshare_simulation_tenderly(
    id: &str,
    tenderly_key: &Option<String>,
    tenderly_account: &Option<String>,
    tenderly_project: &Option<String>,
    quiet: bool,
) -> anyhow::Result<()> {
    let (api_key, account, project) =
        get_tenderly_credentials(tenderly_key, tenderly_account, tenderly_project)?;

    if !quiet {
        eprintln!("Unsharing simulation {} via Tenderly...", id);
    }

    let client = reqwest::Client::new();
    let url = format!(
        "https://api.tenderly.co/api/v1/account/{}/project/{}/simulations/{}/unshare",
        account, project, id
    );

    // POST request to unshare endpoint
    let response = client
        .post(&url)
        .header("X-Access-Key", api_key)
        .header("Content-Type", "application/json")
        .body("{}")
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await?;
        return Err(anyhow::anyhow!("Tenderly API error {}: {}", status, text));
    }

    println!("Simulation {} is now private.", id);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_to_hex_zero() {
        assert_eq!(value_to_hex("0").unwrap(), "0x0");
    }

    #[test]
    fn test_value_to_hex_small() {
        assert_eq!(value_to_hex("255").unwrap(), "0xff");
    }

    #[test]
    fn test_value_to_hex_large() {
        // 1 ETH in wei
        assert_eq!(
            value_to_hex("1000000000000000000").unwrap(),
            "0xde0b6b3a7640000"
        );
    }

    #[test]
    fn test_value_to_hex_invalid() {
        assert!(value_to_hex("not_a_number").is_err());
    }

    #[test]
    fn test_block_to_param_latest() {
        assert_eq!(block_to_param("latest").unwrap(), "latest");
    }

    #[test]
    fn test_block_to_param_pending() {
        assert_eq!(block_to_param("pending").unwrap(), "pending");
    }

    #[test]
    fn test_block_to_param_earliest() {
        assert_eq!(block_to_param("earliest").unwrap(), "earliest");
    }

    #[test]
    fn test_block_to_param_number() {
        assert_eq!(block_to_param("12345678").unwrap(), "0xbc614e");
    }

    #[test]
    fn test_block_to_param_invalid() {
        assert!(block_to_param("not_a_block").is_err());
    }

    #[test]
    fn test_build_state_overrides_empty() {
        let result = build_state_overrides(&[], &[], &[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_build_state_overrides_balance() {
        let balance = vec!["0x1234567890abcdef=1000000".to_string()];
        let result = build_state_overrides(&balance, &[], &[]).unwrap();
        assert_eq!(result.len(), 1);
        assert!(result.contains_key("0x1234567890abcdef"));
    }

    #[test]
    fn test_build_state_overrides_storage() {
        let storage = vec!["0xaddr:0x0=0x1".to_string()];
        let result = build_state_overrides(&[], &storage, &[]).unwrap();
        assert_eq!(result.len(), 1);
        let entry = result.get("0xaddr").unwrap();
        assert!(entry.get("storage").is_some());
    }

    #[test]
    fn test_build_state_overrides_code() {
        let code = vec!["0xaddr=0x6080".to_string()];
        let result = build_state_overrides(&[], &[], &code).unwrap();
        assert_eq!(result.len(), 1);
        let entry = result.get("0xaddr").unwrap();
        assert_eq!(entry.get("code").unwrap(), "0x6080");
    }

    #[test]
    fn test_build_state_overrides_invalid_balance_format() {
        let balance = vec!["invalid_format".to_string()];
        assert!(build_state_overrides(&balance, &[], &[]).is_err());
    }

    #[test]
    fn test_build_state_overrides_invalid_storage_format() {
        let storage = vec!["missing_colon=value".to_string()];
        assert!(build_state_overrides(&[], &storage, &[]).is_err());
    }

    #[test]
    fn test_build_calldata_with_data() {
        let data = Some("0x1234".to_string());
        let result = build_calldata(&None, &data, &[]).unwrap();
        assert_eq!(result, "0x1234");
    }

    #[test]
    fn test_build_calldata_no_sig_no_data() {
        let result = build_calldata(&None, &None, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_format_request_json() {
        let body = serde_json::json!({"method": "test"});
        let output = format_request(
            "https://api.example.com",
            "POST",
            &[("Content-Type", "application/json")],
            &body,
            DryRunFormat::Json,
            false,
        );
        assert!(output.contains("\"method\": \"test\""));
    }

    #[test]
    fn test_format_request_url() {
        let body = serde_json::json!({"method": "test"});
        let output = format_request(
            "https://api.example.com/simulate",
            "POST",
            &[("Content-Type", "application/json")],
            &body,
            DryRunFormat::Url,
            false,
        );
        assert_eq!(output, "https://api.example.com/simulate");
    }

    #[test]
    fn test_format_request_curl() {
        let body = serde_json::json!({"method": "test"});
        let output = format_request(
            "https://api.example.com",
            "POST",
            &[("Content-Type", "application/json")],
            &body,
            DryRunFormat::Curl,
            false,
        );
        assert!(output.starts_with("curl -X POST"));
        assert!(output.contains("'https://api.example.com'"));
        assert!(output.contains("-H 'Content-Type: application/json'"));
        assert!(output.contains("-d '{\"method\":\"test\"}'"));
    }

    #[test]
    fn test_format_request_curl_masks_api_key() {
        let body = serde_json::json!({"method": "test"});
        let output = format_request(
            "https://api.example.com",
            "POST",
            &[("X-Access-Key", "secret123")],
            &body,
            DryRunFormat::Curl,
            false,
        );
        assert!(output.contains("$X_ACCESS_KEY"));
        assert!(!output.contains("secret123"));
    }

    #[test]
    fn test_format_request_curl_shows_secrets() {
        let body = serde_json::json!({"method": "test"});
        let output = format_request(
            "https://api.example.com",
            "POST",
            &[("X-Access-Key", "secret123")],
            &body,
            DryRunFormat::Curl,
            true, // show_secrets = true
        );
        assert!(output.contains("secret123"));
        assert!(!output.contains("$X_ACCESS_KEY"));
    }

    #[test]
    fn test_format_request_fetch() {
        let body = serde_json::json!({"method": "test"});
        let output = format_request(
            "https://api.example.com",
            "POST",
            &[("Content-Type", "application/json")],
            &body,
            DryRunFormat::Fetch,
            false,
        );
        assert!(output.contains("const response = await fetch("));
        assert!(output.contains("method: 'POST'"));
        assert!(output.contains("'Content-Type': 'application/json'"));
    }

    #[test]
    fn test_format_request_powershell() {
        let body = serde_json::json!({"method": "test"});
        let output = format_request(
            "https://api.example.com",
            "POST",
            &[("Content-Type", "application/json")],
            &body,
            DryRunFormat::Powershell,
            false,
        );
        assert!(output.contains("Invoke-RestMethod"));
        assert!(output.contains("-Method POST"));
        assert!(output.contains("$headers = @{"));
    }

    #[test]
    fn test_format_request_python() {
        let body = serde_json::json!({"method": "test"});
        let output = format_request(
            "https://api.example.com",
            "POST",
            &[("Content-Type", "application/json")],
            &body,
            DryRunFormat::Python,
            false,
        );
        assert!(output.contains("import requests"));
        assert!(output.contains("requests.post("));
    }

    #[test]
    fn test_format_request_httpie() {
        let body = serde_json::json!({"method": "test"});
        let output = format_request(
            "https://api.example.com",
            "POST",
            &[("Content-Type", "application/json")],
            &body,
            DryRunFormat::Httpie,
            false,
        );
        assert!(output.starts_with("http POST"));
    }

    #[test]
    fn test_format_request_wget() {
        let body = serde_json::json!({"method": "test"});
        let output = format_request(
            "https://api.example.com",
            "POST",
            &[("Content-Type", "application/json")],
            &body,
            DryRunFormat::Wget,
            false,
        );
        assert!(output.starts_with("wget"));
        assert!(output.contains("--method=POST"));
    }

    #[test]
    fn test_format_request_go() {
        let body = serde_json::json!({"method": "test"});
        let output = format_request(
            "https://api.example.com",
            "POST",
            &[("Content-Type", "application/json")],
            &body,
            DryRunFormat::Go,
            false,
        );
        assert!(output.contains("package main"));
        assert!(output.contains("http.NewRequest"));
    }

    #[test]
    fn test_format_request_rust() {
        let body = serde_json::json!({"method": "test"});
        let output = format_request(
            "https://api.example.com",
            "POST",
            &[("Content-Type", "application/json")],
            &body,
            DryRunFormat::Rust,
            false,
        );
        assert!(output.contains("use reqwest"));
        assert!(output.contains(".post("));
    }

    #[test]
    fn test_format_request_axios() {
        let body = serde_json::json!({"method": "test"});
        let output = format_request(
            "https://api.example.com",
            "POST",
            &[("Content-Type", "application/json")],
            &body,
            DryRunFormat::Axios,
            false,
        );
        assert!(output.contains("const axios = require"));
        assert!(output.contains("axios.post("));
    }
}
