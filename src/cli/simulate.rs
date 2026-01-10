//! Simulate commands - transaction simulation and tracing
//!
//! Supports multiple backends: cast, anvil, tenderly, debug RPC

use crate::config::{Chain, ConfigFile};
use crate::rpc::get_rpc_url;
use clap::{Subcommand, ValueEnum};
use std::process::Command;

/// Get a tracing-capable RPC URL from args or config
///
/// Priority:
/// 1. Explicit --rpc-url if provided
/// 2. First endpoint with has_debug: true from config (supports debug_traceCall)
/// 3. First endpoint with has_trace: true from config (supports trace_call)
/// 4. First entry in debug_rpc_urls (backwards compatibility)
fn get_debug_rpc_url(rpc_url: &Option<String>) -> Option<String> {
    // If explicit URL provided, use it
    if rpc_url.is_some() {
        return rpc_url.clone();
    }

    // Try to get from config
    let config = ConfigFile::load_default().ok().flatten()?;

    // First, look for endpoints with has_debug: true (preferred for debug_traceCall)
    if let Some(ep) = config.endpoints.iter().find(|e| e.has_debug && e.enabled) {
        return Some(ep.url.clone());
    }

    // Next, look for endpoints with has_trace: true (trace_call support)
    if let Some(ep) = config.endpoints.iter().find(|e| e.has_trace && e.enabled) {
        return Some(ep.url.clone());
    }

    // Fall back to legacy debug_rpc_urls
    config.debug_rpc_urls.first().cloned()
}

/// Get a trace-capable RPC URL from args or config
///
/// Priority:
/// 1. Explicit --rpc-url if provided
/// 2. First endpoint with has_trace: true from config (supports trace_call)
/// 3. First endpoint with has_debug: true from config (some debug nodes also support trace)
fn get_trace_rpc_url(rpc_url: &Option<String>) -> Option<String> {
    // If explicit URL provided, use it
    if rpc_url.is_some() {
        return rpc_url.clone();
    }

    // Try to get from config
    let config = ConfigFile::load_default().ok().flatten()?;

    // First, look for endpoints with has_trace: true (preferred for trace_call)
    if let Some(ep) = config.endpoints.iter().find(|e| e.has_trace && e.enabled) {
        return Some(ep.url.clone());
    }

    // Fall back to endpoints with has_debug: true (Erigon supports both)
    config
        .endpoints
        .iter()
        .find(|e| e.has_debug && e.enabled)
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

        /// Tenderly API key (or use TENDERLY_ACCESS_KEY env)
        #[arg(long, env = "TENDERLY_ACCESS_KEY")]
        tenderly_key: Option<String>,

        /// Tenderly account slug
        #[arg(long, env = "TENDERLY_ACCOUNT")]
        tenderly_account: Option<String>,

        /// Tenderly project slug
        #[arg(long, env = "TENDERLY_PROJECT")]
        tenderly_project: Option<String>,

        /// Save simulation to Tenderly (returns simulation ID)
        #[arg(long)]
        save: bool,
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

        /// Tenderly API key
        #[arg(long, env = "TENDERLY_ACCESS_KEY")]
        tenderly_key: Option<String>,

        /// Tenderly account slug
        #[arg(long, env = "TENDERLY_ACCOUNT")]
        tenderly_account: Option<String>,

        /// Tenderly project slug
        #[arg(long, env = "TENDERLY_PROJECT")]
        tenderly_project: Option<String>,

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

        /// Tenderly API key
        #[arg(long, env = "TENDERLY_ACCESS_KEY")]
        tenderly_key: Option<String>,

        /// Tenderly account slug
        #[arg(long, env = "TENDERLY_ACCOUNT")]
        tenderly_account: Option<String>,

        /// Tenderly project slug
        #[arg(long, env = "TENDERLY_PROJECT")]
        tenderly_project: Option<String>,

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

        /// Tenderly API key
        #[arg(long, env = "TENDERLY_ACCESS_KEY")]
        tenderly_key: Option<String>,

        /// Tenderly account slug
        #[arg(long, env = "TENDERLY_ACCOUNT")]
        tenderly_account: Option<String>,

        /// Tenderly project slug
        #[arg(long, env = "TENDERLY_PROJECT")]
        tenderly_project: Option<String>,
    },

    /// Get a saved simulation by ID (Tenderly only)
    Get {
        /// Simulation ID
        id: String,

        /// Tenderly API key
        #[arg(long, env = "TENDERLY_ACCESS_KEY")]
        tenderly_key: Option<String>,

        /// Tenderly account slug
        #[arg(long, env = "TENDERLY_ACCOUNT")]
        tenderly_account: Option<String>,

        /// Tenderly project slug
        #[arg(long, env = "TENDERLY_PROJECT")]
        tenderly_project: Option<String>,
    },

    /// Get simulation info/metadata by ID (Tenderly only)
    Info {
        /// Simulation ID
        id: String,

        /// Tenderly API key
        #[arg(long, env = "TENDERLY_ACCESS_KEY")]
        tenderly_key: Option<String>,

        /// Tenderly account slug
        #[arg(long, env = "TENDERLY_ACCOUNT")]
        tenderly_account: Option<String>,

        /// Tenderly project slug
        #[arg(long, env = "TENDERLY_PROJECT")]
        tenderly_project: Option<String>,
    },

    /// Share a simulation publicly (Tenderly only)
    /// Creates a public URL to view the simulation in the dashboard
    Share {
        /// Simulation ID
        id: String,

        /// Tenderly API key
        #[arg(long, env = "TENDERLY_ACCESS_KEY")]
        tenderly_key: Option<String>,

        /// Tenderly account slug
        #[arg(long, env = "TENDERLY_ACCOUNT")]
        tenderly_account: Option<String>,

        /// Tenderly project slug
        #[arg(long, env = "TENDERLY_PROJECT")]
        tenderly_project: Option<String>,
    },

    /// Unshare a simulation (make private) (Tenderly only)
    Unshare {
        /// Simulation ID
        id: String,

        /// Tenderly API key
        #[arg(long, env = "TENDERLY_ACCESS_KEY")]
        tenderly_key: Option<String>,

        /// Tenderly account slug
        #[arg(long, env = "TENDERLY_ACCOUNT")]
        tenderly_account: Option<String>,

        /// Tenderly project slug
        #[arg(long, env = "TENDERLY_PROJECT")]
        tenderly_project: Option<String>,
    },
}

pub async fn handle(
    action: &SimulateCommands,
    _chain: crate::config::Chain,
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
            tenderly_key,
            tenderly_account,
            tenderly_project,
            save,
        } => match via {
            SimulateVia::Cast => {
                simulate_via_cast(
                    to, sig, data, args, from, value, block, rpc_url, *trace, quiet,
                )
                .await
            }
            SimulateVia::Anvil => {
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
                    tenderly_key,
                    tenderly_account,
                    tenderly_project,
                    quiet,
                )
                .await
            }
            SimulateVia::Debug => {
                simulate_via_debug_rpc(to, sig, data, args, from, value, block, rpc_url, quiet)
                    .await
            }
            SimulateVia::Trace => {
                simulate_via_trace_rpc(to, sig, data, args, from, value, block, rpc_url, quiet)
                    .await
            }
        },

        SimulateCommands::Tx {
            hash,
            via,
            rpc_url,
            tenderly_key,
            tenderly_account,
            tenderly_project,
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
                    tenderly_key,
                    tenderly_account,
                    tenderly_project,
                    quiet,
                )
                .await
            }
            SimulateVia::Debug => trace_tx_via_debug_rpc(hash, rpc_url, quiet).await,
            SimulateVia::Trace => trace_tx_via_trace_rpc(hash, rpc_url, quiet).await,
        },

        SimulateCommands::Bundle {
            txs,
            block,
            balance_overrides,
            storage_overrides,
            code_overrides,
            tenderly_key,
            tenderly_account,
            tenderly_project,
            save,
        } => {
            simulate_bundle_tenderly(
                txs,
                block,
                balance_overrides,
                storage_overrides,
                code_overrides,
                *save,
                tenderly_key,
                tenderly_account,
                tenderly_project,
                quiet,
            )
            .await
        }

        SimulateCommands::List {
            limit,
            page,
            tenderly_key,
            tenderly_account,
            tenderly_project,
        } => {
            list_simulations_tenderly(
                *limit,
                *page,
                tenderly_key,
                tenderly_account,
                tenderly_project,
                quiet,
            )
            .await
        }

        SimulateCommands::Get {
            id,
            tenderly_key,
            tenderly_account,
            tenderly_project,
        } => {
            get_simulation_tenderly(id, tenderly_key, tenderly_account, tenderly_project, quiet)
                .await
        }

        SimulateCommands::Info {
            id,
            tenderly_key,
            tenderly_account,
            tenderly_project,
        } => {
            get_simulation_info_tenderly(
                id,
                tenderly_key,
                tenderly_account,
                tenderly_project,
                quiet,
            )
            .await
        }

        SimulateCommands::Share {
            id,
            tenderly_key,
            tenderly_account,
            tenderly_project,
        } => {
            share_simulation_tenderly(id, tenderly_key, tenderly_account, tenderly_project, quiet)
                .await
        }

        SimulateCommands::Unshare {
            id,
            tenderly_key,
            tenderly_account,
            tenderly_project,
        } => {
            unshare_simulation_tenderly(id, tenderly_key, tenderly_account, tenderly_project, quiet)
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

    // Add target
    cmd.arg(to);

    // Add signature or data
    if let Some(sig) = sig {
        cmd.arg(sig);
        for arg in args {
            cmd.arg(arg);
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
    cmd.arg(to);

    if let Some(sig) = sig {
        cmd.arg(sig);
        for arg in args {
            cmd.arg(arg);
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
    quiet: bool,
) -> anyhow::Result<()> {
    let (api_key, account, project) =
        get_tenderly_credentials(tenderly_key, tenderly_account, tenderly_project)?;

    // Build calldata
    let calldata = if let Some(data) = data {
        data.clone()
    } else if let Some(sig) = sig {
        // Use cast to encode the calldata
        let mut cmd = Command::new("cast");
        cmd.arg("calldata").arg(sig);
        for arg in args {
            cmd.arg(arg);
        }
        let output = cmd.output()?;
        if !output.status.success() {
            return Err(anyhow::anyhow!("Failed to encode calldata"));
        }
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    } else {
        return Err(anyhow::anyhow!("Must provide --sig or --data"));
    };

    let from_addr = from
        .clone()
        .unwrap_or_else(|| "0x0000000000000000000000000000000000000000".to_string());

    // Parse block number
    let block_number = if block == "latest" {
        None
    } else {
        Some(block.parse::<u64>()?)
    };

    // Parse value
    let value_wei = if value == "0" {
        "0x0".to_string()
    } else {
        format!("0x{:x}", value.parse::<u128>()?)
    };

    // Build request
    let mut request = serde_json::json!({
        "network_id": "1",
        "from": from_addr,
        "to": to,
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
    let url = format!(
        "https://api.tenderly.co/api/v1/account/{}/project/{}/simulate",
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
    quiet: bool,
) -> anyhow::Result<()> {
    let rpc = get_debug_rpc_url(rpc_url)
        .ok_or_else(|| anyhow::anyhow!(
            "Debug RPC URL required. Set via --rpc-url, add an endpoint with has_debug: true, or use 'config add-debug-rpc'"
        ))?;

    // Build calldata
    let calldata = if let Some(data) = data {
        data.clone()
    } else if let Some(sig) = sig {
        let mut cmd = Command::new("cast");
        cmd.arg("calldata").arg(sig);
        for arg in args {
            cmd.arg(arg);
        }
        let output = cmd.output()?;
        if !output.status.success() {
            return Err(anyhow::anyhow!("Failed to encode calldata"));
        }
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    } else {
        return Err(anyhow::anyhow!("Must provide --sig or --data"));
    };

    let from_addr = from
        .clone()
        .unwrap_or_else(|| "0x0000000000000000000000000000000000000000".to_string());

    let value_hex = if value == "0" {
        "0x0".to_string()
    } else {
        format!("0x{:x}", value.parse::<u128>()?)
    };

    let block_param = if block == "latest" {
        "latest".to_string()
    } else {
        format!("0x{:x}", block.parse::<u64>()?)
    };

    if !quiet {
        eprintln!("Calling debug_traceCall on {}...", rpc);
    }

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "debug_traceCall",
        "params": [
            {
                "from": from_addr,
                "to": to,
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
    quiet: bool,
) -> anyhow::Result<()> {
    let rpc = get_debug_rpc_url(rpc_url)
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
    quiet: bool,
) -> anyhow::Result<()> {
    let rpc = get_trace_rpc_url(rpc_url).ok_or_else(|| {
        anyhow::anyhow!(
            "Trace RPC URL required. Set via --rpc-url or add an endpoint with has_trace: true"
        )
    })?;

    // Build calldata
    let calldata = if let Some(data) = data {
        data.clone()
    } else if let Some(sig) = sig {
        let mut cmd = Command::new("cast");
        cmd.arg("calldata").arg(sig);
        for arg in args {
            cmd.arg(arg);
        }
        let output = cmd.output()?;
        if !output.status.success() {
            return Err(anyhow::anyhow!("Failed to encode calldata"));
        }
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    } else {
        return Err(anyhow::anyhow!("Must provide --sig or --data"));
    };

    let from_addr = from
        .clone()
        .unwrap_or_else(|| "0x0000000000000000000000000000000000000000".to_string());

    let value_hex = if value == "0" {
        "0x0".to_string()
    } else {
        format!("0x{:x}", value.parse::<u128>()?)
    };

    let block_param = if block == "latest" {
        "latest".to_string()
    } else {
        format!("0x{:x}", block.parse::<u64>()?)
    };

    if !quiet {
        eprintln!("Calling trace_call on {}...", rpc);
    }

    // trace_call params: [tx_object, ["trace", "vmTrace", "stateDiff"], block_number]
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "trace_call",
        "params": [
            {
                "from": from_addr,
                "to": to,
                "data": calldata,
                "value": value_hex
            },
            ["trace", "vmTrace"],
            block_param
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

/// Trace existing tx via trace_transaction (Parity/Erigon style)
async fn trace_tx_via_trace_rpc(
    hash: &str,
    rpc_url: &Option<String>,
    quiet: bool,
) -> anyhow::Result<()> {
    let rpc = get_trace_rpc_url(rpc_url).ok_or_else(|| {
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
