//! Simulate commands - transaction simulation and tracing
//!
//! Supports multiple backends: cast, anvil, tenderly, debug RPC

use crate::config::{AddressBook, Chain, ConfigFile};
use crate::rpc::get_rpc_url;
use clap::{Args, Subcommand, ValueEnum};
use std::process::Command;
use tndrly::simulation::{
    AccessListEntry, BlockHeaderOverride, BundleSimulationRequest, SimulationRequest,
    SimulationType as TndrlySimulationType,
};

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

/// Create a tndrly::Client from args/env/config credentials
fn create_tenderly_client(
    key: &Option<String>,
    account: &Option<String>,
    project: &Option<String>,
) -> anyhow::Result<tndrly::Client> {
    let (api_key, acct, proj) = get_tenderly_credentials(key, account, project)?;
    let config = tndrly::Config::new(api_key, acct, proj);
    tndrly::Client::new(config)
        .map_err(|e| anyhow::anyhow!("Failed to create Tenderly client: {}", e))
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

/// Simulation type (for Tenderly API)
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum SimulationType {
    /// Full simulation with decoded results
    #[default]
    Full,
    /// Quick simulation with less data (faster)
    Quick,
    /// ABI-only simulation (decode only)
    Abi,
}

impl SimulationType {
    /// Convert to tndrly SimulationType
    fn to_tndrly(self) -> TndrlySimulationType {
        match self {
            SimulationType::Full => TndrlySimulationType::Full,
            SimulationType::Quick => TndrlySimulationType::Quick,
            SimulationType::Abi => TndrlySimulationType::Abi,
        }
    }
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
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

        /// Override block number (for Tenderly)
        #[arg(long)]
        block_number_override: Option<u64>,

        /// Override block gas limit
        #[arg(long)]
        block_gas_limit: Option<u64>,

        /// Override block coinbase/miner address
        #[arg(long)]
        block_coinbase: Option<String>,

        /// Override block difficulty
        #[arg(long)]
        block_difficulty: Option<u64>,

        /// Override block base fee per gas (wei)
        #[arg(long)]
        block_base_fee: Option<u64>,

        /// Transaction index within the block
        #[arg(long)]
        transaction_index: Option<u64>,

        /// State override: set nonce (format: address=nonce, can repeat)
        #[arg(long = "nonce-override", action = clap::ArgAction::Append)]
        nonce_overrides: Vec<String>,

        /// Enable precise gas estimation (Tenderly)
        #[arg(long)]
        estimate_gas: bool,

        /// Generate EIP-2930 access list in response (Tenderly)
        #[arg(long)]
        generate_access_list: bool,

        /// Provide access list (JSON format or @file.json)
        #[arg(long)]
        access_list: Option<String>,

        /// Simulation type: full (default), quick (faster, less data), or abi (decode only)
        #[arg(long, value_enum, default_value = "full")]
        simulation_type: SimulationType,

        /// Network ID to simulate on (default: 1 for Ethereum mainnet)
        #[arg(long)]
        network_id: Option<String>,

        /// L1 block number (for L2 simulations like Optimism)
        #[arg(long)]
        l1_block_number: Option<u64>,

        /// L1 timestamp (for L2 simulations)
        #[arg(long)]
        l1_timestamp: Option<u64>,

        /// L1 message sender (for L2 cross-chain simulations)
        #[arg(long)]
        l1_message_sender: Option<String>,

        /// Mark as deposit transaction (Optimism Bedrock)
        #[arg(long)]
        deposit_tx: bool,

        /// Mark as system transaction (Optimism Bedrock)
        #[arg(long)]
        system_tx: bool,

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
            simulation_type,
            network_id,
            transaction_index,
            estimate_gas,
            generate_access_list,
            access_list,
            l1_block_number,
            l1_timestamp,
            l1_message_sender,
            deposit_tx,
            system_tx,
            block_gas_limit,
            block_coinbase,
            block_difficulty,
            block_base_fee,
            ..  // Remaining fields (nonce_overrides)
        } => {
            // Warn if Tenderly-exclusive flags are used with non-Tenderly backends
            if !matches!(via, SimulateVia::Tenderly) {
                let mut tenderly_only = Vec::new();

                // Truly Tenderly-exclusive features
                if *save { tenderly_only.push("--save"); }
                if *estimate_gas { tenderly_only.push("--estimate-gas"); }
                if *generate_access_list { tenderly_only.push("--generate-access-list"); }
                if !matches!(simulation_type, SimulationType::Full) { tenderly_only.push("--simulation-type"); }

                // L2/Optimism params - Tenderly-specific
                if l1_block_number.is_some() { tenderly_only.push("--l1-block-number"); }
                if l1_timestamp.is_some() { tenderly_only.push("--l1-timestamp"); }
                if l1_message_sender.is_some() { tenderly_only.push("--l1-message-sender"); }
                if *deposit_tx { tenderly_only.push("--deposit-tx"); }
                if *system_tx { tenderly_only.push("--system-tx"); }

                if !tenderly_only.is_empty() {
                    eprintln!("Warning: The following flags only work with --via tenderly and will be ignored:");
                    eprintln!("  {}", tenderly_only.join(", "));
                    eprintln!();
                }

                // Warn about flags that don't work with cast/anvil
                // State overrides DO work with debug/trace backends
                if matches!(via, SimulateVia::Cast | SimulateVia::Anvil) {
                    let mut not_supported = Vec::new();
                    if !balance_overrides.is_empty() || !storage_overrides.is_empty() || !code_overrides.is_empty() {
                        not_supported.push("state overrides");
                    }
                    if block_timestamp.is_some() || block_gas_limit.is_some() || block_coinbase.is_some()
                        || block_difficulty.is_some() || block_base_fee.is_some() {
                        not_supported.push("block header overrides");
                    }
                    if access_list.is_some() { not_supported.push("--access-list"); }
                    if transaction_index.is_some() { not_supported.push("--transaction-index"); }
                    if network_id.is_some() { not_supported.push("--network-id"); }

                    if !not_supported.is_empty() {
                        eprintln!("Warning: {} not supported for --via {:?}, use --via tenderly or --via debug/trace",
                            not_supported.join(", "), via);
                        eprintln!();
                    }
                }

                // Warn about flags not yet supported for debug/trace
                if matches!(via, SimulateVia::Debug | SimulateVia::Trace) {
                    let mut not_wired = Vec::new();
                    if block_timestamp.is_some() || block_gas_limit.is_some() || block_coinbase.is_some()
                        || block_difficulty.is_some() || block_base_fee.is_some() {
                        not_wired.push("block header overrides");
                    }
                    if access_list.is_some() { not_wired.push("--access-list"); }
                    if transaction_index.is_some() { not_wired.push("--transaction-index"); }
                    if network_id.is_some() { not_wired.push("--network-id"); }

                    if !not_wired.is_empty() {
                        eprintln!("Warning: {} not yet supported for --via {:?}, use --via tenderly",
                            not_wired.join(", "), via);
                        eprintln!();
                    }
                }
            }

            match via {
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
                    *simulation_type,
                    *save,
                    &tenderly.tenderly_key,
                    &tenderly.tenderly_account,
                    &tenderly.tenderly_project,
                    *dry_run,
                    *show_secrets,
                    quiet,
                    network_id,
                    *transaction_index,
                    *estimate_gas,
                    *generate_access_list,
                    access_list,
                    *l1_block_number,
                    *l1_timestamp,
                    l1_message_sender,
                    *deposit_tx,
                    *system_tx,
                    *block_gas_limit,
                    block_coinbase,
                    *block_difficulty,
                    *block_base_fee,
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
                    balance_overrides,
                    storage_overrides,
                    code_overrides,
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
                    balance_overrides,
                    storage_overrides,
                    code_overrides,
                    *dry_run,
                    *show_secrets,
                    quiet,
                )
                .await
            }
        }},

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
    simulation_type: SimulationType,
    save: bool,
    tenderly_key: &Option<String>,
    tenderly_account: &Option<String>,
    tenderly_project: &Option<String>,
    dry_run: Option<DryRunFormat>,
    show_secrets: bool,
    quiet: bool,
    network_id: &Option<String>,
    transaction_index: Option<u64>,
    estimate_gas: bool,
    generate_access_list: bool,
    access_list: &Option<String>,
    l1_block_number: Option<u64>,
    l1_timestamp: Option<u64>,
    l1_message_sender: &Option<String>,
    deposit_tx: bool,
    system_tx: bool,
    block_gas_limit: Option<u64>,
    block_coinbase: &Option<String>,
    block_difficulty: Option<u64>,
    block_base_fee: Option<u64>,
) -> anyhow::Result<()> {
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

    // Build tndrly SimulationRequest using the builder pattern
    let mut request = SimulationRequest::new(&from_addr, &resolved_to, &calldata)
        .value(&value_wei)
        .simulation_type(simulation_type.to_tndrly())
        .save(save);

    if let Some(bn) = block_number {
        request = request.block_number(bn);
    }

    if let Some(g) = gas {
        request = request.gas(g);
    }

    if let Some(gp) = gas_price {
        request = request.gas_price(gp);
    }

    // Apply state overrides
    for override_str in balance_overrides {
        let parts: Vec<&str> = override_str.splitn(2, '=').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!(
                "Invalid balance override format: {}. Use address=wei",
                override_str
            ));
        }
        request = request.override_balance(parts[0], parts[1]);
    }

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
        request = request.override_storage(addr_slot[0], addr_slot[1], parts[1]);
    }

    for override_str in code_overrides {
        let parts: Vec<&str> = override_str.splitn(2, '=').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!(
                "Invalid code override format: {}. Use address=bytecode",
                override_str
            ));
        }
        request = request.override_code(parts[0], parts[1]);
    }

    // Build block header overrides if any are specified
    let has_block_header_overrides = block_timestamp.is_some()
        || block_gas_limit.is_some()
        || block_coinbase.is_some()
        || block_difficulty.is_some()
        || block_base_fee.is_some();

    if has_block_header_overrides {
        let mut header = BlockHeaderOverride::default();

        if let Some(ts) = block_timestamp {
            header.timestamp = Some(format!("0x{:x}", ts));
        }
        if let Some(gas_limit) = block_gas_limit {
            header.gas_limit = Some(format!("0x{:x}", gas_limit));
        }
        if let Some(ref coinbase) = block_coinbase {
            header.miner = Some(coinbase.clone());
        }
        if let Some(difficulty) = block_difficulty {
            header.difficulty = Some(format!("0x{:x}", difficulty));
        }
        if let Some(base_fee) = block_base_fee {
            header.base_fee_per_gas = Some(format!("0x{:x}", base_fee));
        }

        request.block_header = Some(header);
    }

    // Apply network ID if specified
    if let Some(nid) = network_id {
        request = request.network_id(nid);
    }

    // Apply new Tenderly API parameters (tndrly 0.2+)
    if let Some(ti) = transaction_index {
        request = request.transaction_index(ti);
    }

    if estimate_gas {
        request = request.estimate_gas(true);
    }

    if generate_access_list {
        request = request.generate_access_list(true);
    }

    // Parse access list if provided (JSON format)
    if let Some(al_str) = access_list {
        let al_json = if let Some(path) = al_str.strip_prefix('@') {
            // Load from file
            std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("Failed to read access list file {}: {}", path, e))?
        } else {
            al_str.clone()
        };
        let entries: Vec<AccessListEntry> = serde_json::from_str(&al_json)
            .map_err(|e| anyhow::anyhow!("Invalid access list JSON: {}", e))?;
        request = request.access_list(entries);
    }

    // L2/Optimism parameters
    if let Some(l1_bn) = l1_block_number {
        request = request.l1_block_number(l1_bn);
    }

    if let Some(l1_ts) = l1_timestamp {
        request = request.l1_timestamp(l1_ts);
    }

    if let Some(l1_sender) = l1_message_sender {
        request = request.l1_message_sender(l1_sender);
    }

    if deposit_tx {
        request = request.deposit_tx(true);
    }

    if system_tx {
        request = request.system_tx(true);
    }

    // Handle dry-run mode - output request without executing
    // We need to serialize the request to show what would be sent
    if let Some(format) = dry_run {
        let (api_key, account, project) =
            get_tenderly_credentials(tenderly_key, tenderly_account, tenderly_project)?;
        let url = format!(
            "https://api.tenderly.co/api/v1/account/{}/project/{}/simulate",
            account, project
        );
        let json_request = serde_json::to_value(&request)?;
        let headers = vec![
            ("X-Access-Key", api_key.as_str()),
            ("Content-Type", "application/json"),
        ];
        let output = format_request(&url, "POST", &headers, &json_request, format, show_secrets);
        println!("{}", output);
        return Ok(());
    }

    let has_state_overrides = !balance_overrides.is_empty()
        || !storage_overrides.is_empty()
        || !code_overrides.is_empty();

    if !quiet {
        eprintln!("Simulating via Tenderly API...");
        if save {
            eprintln!("  Saving simulation to Tenderly");
        }
        if has_state_overrides {
            let count = balance_overrides.len() + storage_overrides.len() + code_overrides.len();
            eprintln!("  State overrides: {} addresses", count);
        }
    }

    // Create tndrly client and execute simulation
    let client = create_tenderly_client(tenderly_key, tenderly_account, tenderly_project)?;
    let result = client
        .simulation()
        .simulate(&request)
        .await
        .map_err(|e| anyhow::anyhow!("Tenderly API error: {}", e))?;

    // If saved, show the simulation ID prominently
    if save {
        eprintln!("Simulation ID: {}", result.simulation.id);
    }

    // Display generated access list prominently if requested
    if generate_access_list {
        if let Some(ref access_list) = result.generated_access_list {
            if !access_list.is_empty() {
                eprintln!("\n=== Generated Access List ===");
                for entry in access_list {
                    eprintln!("Address: {}", entry.address);
                    if !entry.storage_keys.is_empty() {
                        for key in &entry.storage_keys {
                            eprintln!("  Storage: {}", key);
                        }
                    }
                }
                eprintln!();
            }
        }
    }

    // Pretty print the result
    let json_result = serde_json::to_value(&result)?;
    println!("{}", serde_json::to_string_pretty(&json_result)?);

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
    if !quiet {
        eprintln!("Fetching trace from Tenderly API...");
    }

    let client = create_tenderly_client(tenderly_key, tenderly_account, tenderly_project)?;
    let result = client
        .simulation()
        .trace(hash)
        .await
        .map_err(|e| anyhow::anyhow!("Tenderly API error: {}", e))?;

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
    balance_overrides: &[String],
    storage_overrides: &[String],
    code_overrides: &[String],
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

    // Build state overrides if any are provided
    let state_overrides =
        build_state_overrides(balance_overrides, storage_overrides, code_overrides)?;

    // Build tracer options with optional state overrides
    let mut tracer_opts = serde_json::json!({
        "tracer": "callTracer",
        "tracerConfig": {
            "withLog": true
        }
    });

    if !state_overrides.is_empty() {
        tracer_opts["stateOverrides"] = serde_json::to_value(&state_overrides)?;
    }

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
            tracer_opts
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
    balance_overrides: &[String],
    storage_overrides: &[String],
    code_overrides: &[String],
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

    // Build state overrides if any are provided
    let state_overrides =
        build_state_overrides(balance_overrides, storage_overrides, code_overrides)?;

    // trace_call params: [tx_object, ["trace", "vmTrace", "stateDiff"], block_number, state_overrides?]
    let mut params = serde_json::json!([
        {
            "from": from_addr,
            "to": resolved_to,
            "data": calldata,
            "value": value_hex
        },
        ["trace", "vmTrace"],
        block_param
    ]);

    // Add state overrides as 4th parameter if any are provided
    if !state_overrides.is_empty() {
        params
            .as_array_mut()
            .unwrap()
            .push(serde_json::to_value(&state_overrides)?);
    }

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "trace_call",
        "params": params,
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
    // Parse transactions from JSON string or file
    let transactions: Vec<serde_json::Value> = if txs.ends_with(".json") {
        let content = std::fs::read_to_string(txs)?;
        serde_json::from_str(&content)?
    } else {
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

    // Build simulation requests for each transaction
    let simulations: Vec<SimulationRequest> = transactions
        .into_iter()
        .map(|tx| {
            let from = tx
                .get("from")
                .and_then(|v| v.as_str())
                .unwrap_or("0x0000000000000000000000000000000000000000");
            let to = tx
                .get("to")
                .and_then(|v| v.as_str())
                .unwrap_or("0x0000000000000000000000000000000000000000");
            let input = tx
                .get("data")
                .or_else(|| tx.get("input"))
                .and_then(|v| v.as_str())
                .unwrap_or("0x");

            let mut req = SimulationRequest::new(from, to, input).save(save);

            if let Some(value) = tx.get("value").and_then(|v| v.as_str()) {
                req = req.value(value);
            }
            if let Some(gas) = tx.get("gas").and_then(|v| v.as_u64()) {
                req = req.gas(gas);
            }
            if let Some(gas_price) = tx.get("gas_price").and_then(|v| v.as_u64()) {
                req = req.gas_price(gas_price);
            }
            if let Some(bn) = block_number {
                req = req.block_number(bn);
            }

            req
        })
        .collect();

    let tx_count = simulations.len();

    // Build bundle request
    let mut bundle_request = BundleSimulationRequest::new(simulations);

    // Apply state overrides
    let state_objects =
        build_state_overrides(balance_overrides, storage_overrides, code_overrides)?;
    if !state_objects.is_empty() {
        // Convert HashMap<String, serde_json::Value> to HashMap<String, tndrly::simulation::StateOverride>
        let mut overrides = std::collections::HashMap::new();
        for (addr, val) in state_objects {
            let state_override: tndrly::simulation::StateOverride = serde_json::from_value(val)?;
            overrides.insert(addr, state_override);
        }
        bundle_request = bundle_request.state_overrides(overrides);
    }

    if !quiet {
        eprintln!(
            "Simulating bundle of {} transactions via Tenderly API...",
            tx_count
        );
        if save {
            eprintln!("  Saving simulation bundle to Tenderly");
        }
    }

    let client = create_tenderly_client(tenderly_key, tenderly_account, tenderly_project)?;
    let result = client
        .simulation()
        .simulate_bundle(&bundle_request)
        .await
        .map_err(|e| anyhow::anyhow!("Tenderly API error: {}", e))?;

    // Show simulation IDs if saved
    if save {
        for (i, sim_result) in result.simulation_results.iter().enumerate() {
            eprintln!(
                "Transaction {} simulation ID: {}",
                i + 1,
                sim_result.simulation.id
            );
        }
    }

    let json_result = serde_json::to_value(&result)?;
    println!("{}", serde_json::to_string_pretty(&json_result)?);

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
    if !quiet {
        eprintln!("Fetching saved simulations from Tenderly...");
    }

    let client = create_tenderly_client(tenderly_key, tenderly_account, tenderly_project)?;
    let result = client
        .simulation()
        .list(page, limit)
        .await
        .map_err(|e| anyhow::anyhow!("Tenderly API error: {}", e))?;

    // Format output nicely
    if result.simulations.is_empty() {
        println!("No saved simulations found.");
    } else {
        println!("Saved Simulations (page {}, {} per page):", page, limit);
        println!("{}", "─".repeat(80));

        for sim in &result.simulations {
            let status_str = match sim.status {
                Some(true) => "✓",
                Some(false) => "✗",
                None => "?",
            };
            let created = sim.created_at.as_deref().unwrap_or("?");
            let from = sim.from.as_deref().unwrap_or("?");
            let to = sim.to.as_deref().unwrap_or("?");

            println!(
                "{} {} | {} -> {} | {}",
                status_str,
                sim.id,
                &from[..from.len().min(10)],
                &to[..to.len().min(10)],
                created
            );
        }
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
    if !quiet {
        eprintln!("Fetching simulation {} from Tenderly...", id);
    }

    let client = create_tenderly_client(tenderly_key, tenderly_account, tenderly_project)?;
    let result = client
        .simulation()
        .get(id)
        .await
        .map_err(|e| anyhow::anyhow!("Tenderly API error: {}", e))?;

    let json_result = serde_json::to_value(&result)?;
    println!("{}", serde_json::to_string_pretty(&json_result)?);

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
    if !quiet {
        eprintln!("Fetching simulation info for {} from Tenderly...", id);
    }

    let client = create_tenderly_client(tenderly_key, tenderly_account, tenderly_project)?;
    let result = client
        .simulation()
        .info(id)
        .await
        .map_err(|e| anyhow::anyhow!("Tenderly API error: {}", e))?;

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
    if !quiet {
        eprintln!("Sharing simulation {} via Tenderly...", id);
    }

    let client = create_tenderly_client(tenderly_key, tenderly_account, tenderly_project)?;
    let public_url = client
        .simulation()
        .share(id)
        .await
        .map_err(|e| anyhow::anyhow!("Tenderly API error: {}", e))?;

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
    if !quiet {
        eprintln!("Unsharing simulation {} via Tenderly...", id);
    }

    let client = create_tenderly_client(tenderly_key, tenderly_account, tenderly_project)?;
    client
        .simulation()
        .unshare(id)
        .await
        .map_err(|e| anyhow::anyhow!("Tenderly API error: {}", e))?;

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
