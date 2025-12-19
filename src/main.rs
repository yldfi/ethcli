//! eth-log-fetch CLI - Fast Ethereum historical log fetcher

use clap::{Args, Parser, Subcommand};
use eth_log_fetcher::{
    Chain, Config, ConfigFile, EndpointConfig, FetchProgress, LogFetcher, OutputFormat,
    ProxyConfig, RpcConfig, RpcPool,
};
use indicatif::{ProgressBar, ProgressStyle};
use std::path::PathBuf;
use std::time::Instant;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(Parser)]
#[command(name = "eth-log-fetch")]
#[command(
    version,
    about = "Fast Ethereum historical log fetcher with parallel RPC requests"
)]
#[command(after_help = r#"EXAMPLES:
    # Fetch all Transfer events from USDC contract
    eth-log-fetch -c 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 \
                  -e "Transfer(address,address,uint256)" \
                  -f 18000000 -t 18100000 -o transfers.json

    # Fetch all events (auto-fetch ABI from Etherscan)
    eth-log-fetch -c 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 \
                  -f 18000000 -t latest --format csv -o events.csv

    # Resume interrupted fetch with high concurrency
    eth-log-fetch -c 0x... -f 0 -t latest -n 20 --resume

    # Use only fast endpoints
    eth-log-fetch -c 0x... -f 0 -t latest --min-priority 8

ENVIRONMENT VARIABLES:
    ETHERSCAN_API_KEY    Etherscan API key (optional, increases rate limit)

CONFIG FILE:
    Default: ~/.config/eth-log-fetcher/config.toml
"#)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Chain to query
    #[arg(long, default_value = "ethereum", global = true)]
    chain: String,

    /// Contract address to fetch logs from
    #[arg(short, long)]
    contract: Option<String>,

    /// Event signature (e.g. "Transfer(address,address,uint256)")
    #[arg(short, long)]
    event: Option<String>,

    /// Path to ABI JSON file
    #[arg(long)]
    abi: Option<PathBuf>,

    /// Start block number
    #[arg(short = 'f', long, default_value = "0")]
    from_block: u64,

    /// End block number (or "latest")
    #[arg(short = 't', long, default_value = "latest")]
    to_block: String,

    /// Output file path (stdout if not specified)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Output format
    #[arg(long, default_value = "json")]
    format: String,

    /// Fetch raw logs without decoding
    #[arg(long)]
    raw: bool,

    /// Number of parallel requests
    #[arg(short = 'n', long, default_value = "5")]
    concurrency: usize,

    /// Resume from checkpoint if available
    #[arg(long)]
    resume: bool,

    /// Checkpoint file path
    #[arg(long)]
    checkpoint: Option<PathBuf>,

    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Suppress progress output
    #[arg(short, long)]
    quiet: bool,

    /// Etherscan API key
    #[arg(long, env = "ETHERSCAN_API_KEY")]
    etherscan_key: Option<String>,

    #[command(flatten)]
    rpc: RpcArgs,

    #[command(flatten)]
    proxy: ProxyArgs,
}

#[derive(Args)]
struct RpcArgs {
    /// Use only this RPC endpoint (can be repeated)
    #[arg(long = "rpc", action = clap::ArgAction::Append)]
    rpc_urls: Vec<String>,

    /// Add RPC to default pool (can be repeated)
    #[arg(long = "add-rpc", action = clap::ArgAction::Append)]
    add_rpc: Vec<String>,

    /// Exclude RPC from pool (can be repeated)
    #[arg(long = "exclude-rpc", action = clap::ArgAction::Append)]
    exclude_rpc: Vec<String>,

    /// Load RPC URLs from file
    #[arg(long)]
    rpc_file: Option<PathBuf>,

    /// Only use endpoints with priority >= N
    #[arg(long, default_value = "1")]
    min_priority: u8,

    /// Request timeout in seconds
    #[arg(long, default_value = "30")]
    timeout: u64,

    /// Max retries per request
    #[arg(long, default_value = "3")]
    retries: u32,
}

#[derive(Args)]
struct ProxyArgs {
    /// Use proxy for all requests (http/https/socks5)
    #[arg(long)]
    proxy: Option<String>,

    /// Load proxies from file, rotate between them
    #[arg(long)]
    proxy_file: Option<PathBuf>,

    /// Rotate proxy per request
    #[arg(long)]
    proxy_rotate: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Fetch logs from a contract
    Fetch,

    /// Manage and test RPC endpoints
    Endpoints {
        #[command(subcommand)]
        action: EndpointCommands,
    },

    /// Manage configuration
    Config {
        #[command(subcommand)]
        action: ConfigCommands,
    },
}

#[derive(Subcommand)]
enum EndpointCommands {
    /// List all configured endpoints
    List,

    /// Test an endpoint for archive support
    Test {
        /// RPC URL to test
        url: String,
    },
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Show config file path
    Path,

    /// Set Etherscan API key
    SetEtherscanKey {
        /// API key
        key: String,
    },

    /// Show current config
    Show,
}

/// Format a number with thousands separators
fn format_thousands(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let len = bytes.len();

    if len <= 3 {
        return s;
    }

    let mut result = String::with_capacity(len + (len - 1) / 3);
    let first_group = len % 3;

    if first_group > 0 {
        result.push_str(&s[..first_group]);
        if len > first_group {
            result.push(',');
        }
    }

    for (i, chunk) in s[first_group..].as_bytes().chunks(3).enumerate() {
        if i > 0 {
            result.push(',');
        }
        result.push_str(std::str::from_utf8(chunk).unwrap());
    }

    result
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Set up logging
    let filter = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    tracing_subscriber::registry()
        .with(fmt::layer().with_target(false))
        .with(EnvFilter::new(filter))
        .init();

    // Handle subcommands
    match &cli.command {
        Some(Commands::Endpoints { action }) => {
            return handle_endpoints(action, &cli).await;
        }
        Some(Commands::Config { action }) => {
            return handle_config(action).await;
        }
        _ => {}
    }

    // Default: fetch logs
    run_fetch(&cli).await
}

async fn run_fetch(cli: &Cli) -> anyhow::Result<()> {
    let contract = cli
        .contract
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Contract address is required. Use -c or --contract"))?;

    // Parse chain
    let chain: Chain = cli.chain.parse()?;

    // Parse output format
    let format: OutputFormat = cli.format.parse()?;

    // Parse to_block
    let to_block = if cli.to_block.to_lowercase() == "latest" {
        eth_log_fetcher::BlockNumber::Latest
    } else {
        eth_log_fetcher::BlockNumber::Number(cli.to_block.parse()?)
    };

    // Load config file for additional settings
    let config_file = ConfigFile::load_default().ok().flatten();

    // Get Etherscan API key
    let etherscan_key = cli.etherscan_key.clone().or_else(|| {
        config_file
            .as_ref()
            .and_then(|c| c.etherscan_api_key.clone())
    });

    // Build RPC config
    let rpc_config = build_rpc_config(cli, &config_file)?;

    // Build main config
    let mut builder = Config::builder()
        .chain(chain)
        .contract(contract)
        .from_block(cli.from_block)
        .to_block(to_block)
        .output_format(format)
        .concurrency(cli.concurrency)
        .raw(cli.raw)
        .resume(cli.resume)
        .quiet(cli.quiet)
        .verbosity(cli.verbose)
        .rpc_config(rpc_config);

    if let Some(event) = &cli.event {
        builder = builder.event(event);
    }

    if let Some(abi) = &cli.abi {
        builder = builder.abi_path(abi);
    }

    if let Some(output) = &cli.output {
        builder = builder.output_path(output);
    }

    if let Some(checkpoint) = &cli.checkpoint {
        builder = builder.checkpoint_path(checkpoint);
    }

    if let Some(key) = etherscan_key {
        builder = builder.etherscan_key(key);
    }

    let config = builder.build()?;

    // Create fetcher
    if !cli.quiet {
        eprintln!("Connecting to {} endpoints...", chain.display_name());
    }

    let fetcher = LogFetcher::new(config.clone()).await?;

    if !cli.quiet {
        eprintln!("Using {} RPC endpoints", fetcher.endpoint_count());
    }

    // Set up progress bar
    let pb = if !cli.quiet {
        let pb = ProgressBar::new(100);
        pb.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}% ({msg})",
                )
                .unwrap()
                .progress_chars("#>-"),
        );
        Some(pb)
    } else {
        None
    };

    let pb_clone = pb.clone();
    let fetcher = fetcher.with_progress(move |progress: FetchProgress| {
        if let Some(ref pb) = pb_clone {
            pb.set_position(progress.percent as u64);
            pb.set_message(format!(
                "{} logs, {:.0} blocks/s",
                progress.logs_fetched, progress.blocks_per_second
            ));
        }
    });

    // Fetch logs
    let start = Instant::now();
    let result = fetcher.fetch_all().await?;
    let elapsed = start.elapsed();

    if let Some(ref pb) = pb {
        pb.finish_and_clear();
    }

    // Write output
    let mut writer = eth_log_fetcher::create_writer(format, cli.output.as_deref())?;

    writer.write_logs(&result)?;
    writer.finalize()?;

    if !cli.quiet {
        eprintln!(
            "Fetched {} logs in {:.2}s",
            result.len(),
            elapsed.as_secs_f64()
        );
    }

    Ok(())
}

fn build_rpc_config(cli: &Cli, config_file: &Option<ConfigFile>) -> anyhow::Result<RpcConfig> {
    let mut rpc_config = RpcConfig::default();

    // Custom endpoints from CLI
    if !cli.rpc.rpc_urls.is_empty() {
        rpc_config.endpoints = cli
            .rpc
            .rpc_urls
            .iter()
            .map(|url| EndpointConfig::new(url))
            .collect();
    }

    // Load from file
    if let Some(path) = &cli.rpc.rpc_file {
        let content = std::fs::read_to_string(path)?;
        for line in content.lines() {
            let url = line.trim();
            if !url.is_empty() && !url.starts_with('#') {
                rpc_config.endpoints.push(EndpointConfig::new(url));
            }
        }
    }

    // Add custom endpoints from config file
    if let Some(cf) = config_file {
        for endpoint in &cf.endpoints {
            if !rpc_config.endpoints.iter().any(|e| e.url == endpoint.url) {
                rpc_config.endpoints.push(endpoint.clone());
            }
        }
    }

    // Additional endpoints
    rpc_config.add_endpoints = cli.rpc.add_rpc.clone();

    // Excluded endpoints from CLI
    rpc_config.exclude_endpoints = cli.rpc.exclude_rpc.clone();

    // Add disabled endpoints from config file
    if let Some(cf) = config_file {
        rpc_config
            .exclude_endpoints
            .extend(cf.disabled_endpoints.urls.clone());
    }

    rpc_config.min_priority = cli.rpc.min_priority;
    rpc_config.timeout_secs = cli.rpc.timeout;
    rpc_config.max_retries = cli.rpc.retries;
    rpc_config.concurrency = cli.concurrency;

    // Proxy config
    if cli.proxy.proxy.is_some() || cli.proxy.proxy_file.is_some() {
        rpc_config.proxy = Some(ProxyConfig {
            url: cli.proxy.proxy.clone(),
            file: cli.proxy.proxy_file.clone(),
            rotate_per_request: cli.proxy.proxy_rotate,
        });
    } else if let Some(cf) = config_file {
        rpc_config.proxy = cf.proxy_config();
    }

    Ok(rpc_config)
}

async fn handle_endpoints(action: &EndpointCommands, cli: &Cli) -> anyhow::Result<()> {
    match action {
        EndpointCommands::List => {
            let chain: Chain = cli.chain.parse()?;
            let endpoints = eth_log_fetcher::default_endpoints(chain);

            println!(
                "RPC ENDPOINTS for {} ({} default)\n",
                chain.display_name(),
                endpoints.len()
            );

            // Group by priority
            let mut by_priority: std::collections::BTreeMap<u8, Vec<_>> =
                std::collections::BTreeMap::new();
            for ep in &endpoints {
                by_priority.entry(ep.priority).or_default().push(ep);
            }

            for (priority, eps) in by_priority.into_iter().rev() {
                println!("Priority {}:", priority);
                for ep in eps {
                    println!("  {} ", ep.url);
                    println!(
                        "    Block range: {:>10} | Max logs: {:>7}{}",
                        if ep.max_block_range == 0 {
                            "unlimited".to_string()
                        } else {
                            format_thousands(ep.max_block_range)
                        },
                        if ep.max_logs == 0 {
                            "unlimited".to_string()
                        } else {
                            format_thousands(ep.max_logs as u64)
                        },
                        ep.note
                            .as_ref()
                            .map(|n| format!(" ({})", n))
                            .unwrap_or_default()
                    );
                }
                println!();
            }
        }

        EndpointCommands::Test { url } => {
            println!("Testing endpoint: {}\n", url);

            // Test connectivity
            print!("[1/3] Connectivity.............. ");
            std::io::Write::flush(&mut std::io::stdout())?;

            let rpc_config = RpcConfig {
                endpoints: vec![EndpointConfig::new(url)],
                timeout_secs: 10,
                ..Default::default()
            };

            let chain: Chain = cli.chain.parse()?;
            let pool = match RpcPool::new(chain, &rpc_config) {
                Ok(p) => {
                    println!("✓ OK");
                    p
                }
                Err(e) => {
                    println!("✗ FAILED: {}", e);
                    return Ok(());
                }
            };

            // Test block number
            print!("[2/3] Current block............. ");
            std::io::Write::flush(&mut std::io::stdout())?;

            match pool.get_block_number().await {
                Ok(block) => println!("✓ Block {}", block),
                Err(e) => {
                    println!("✗ FAILED: {}", e);
                    return Ok(());
                }
            }

            // Test archive support
            print!("[3/3] Archive support........... ");
            std::io::Write::flush(&mut std::io::stdout())?;

            // Create endpoint directly to test
            let endpoint = eth_log_fetcher::Endpoint::new(EndpointConfig::new(url), 10, None)?;

            match endpoint.test_archive_support().await {
                Ok(true) => println!("✓ OK (historical state accessible)"),
                Ok(false) => println!("✗ NO (pruned node)"),
                Err(e) => println!("? UNKNOWN: {}", e),
            }

            println!("\nEndpoint test complete.");
        }
    }

    Ok(())
}

async fn handle_config(action: &ConfigCommands) -> anyhow::Result<()> {
    match action {
        ConfigCommands::Path => {
            println!("{}", ConfigFile::default_path().display());
        }

        ConfigCommands::SetEtherscanKey { key } => {
            let mut config = ConfigFile::load_default()?.unwrap_or_default();
            config.set_etherscan_key(key.clone())?;
            println!("Etherscan API key saved to config file.");
        }

        ConfigCommands::Show => {
            let path = ConfigFile::default_path();
            if path.exists() {
                let content = std::fs::read_to_string(&path)?;
                println!("# {}\n", path.display());
                println!("{}", content);
            } else {
                println!("No config file found at: {}", path.display());
                println!("\nCreate one with:");
                println!("  eth-log-fetch config set-etherscan-key YOUR_KEY");
            }
        }
    }

    Ok(())
}
