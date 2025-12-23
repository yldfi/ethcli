//! ethcli - Comprehensive Ethereum CLI

use clap::Parser;
use ethcli::cli::{
    config::ConfigCommands,
    endpoints::EndpointCommands,
    logs::{LogsArgs, ProxyArgs, RpcArgs},
    tx::TxArgs,
    Cli, Commands,
};
use ethcli::{
    default_endpoints, format_analysis, Chain, Config, ConfigFile, Endpoint, EndpointConfig,
    FetchProgress, FetchStats, LogFetcher, OutputFormat, OutputWriter, ProxyConfig, RpcConfig,
    RpcPool, StreamingFetcher, TxAnalyzer,
};
use indicatif::{ProgressBar, ProgressStyle};
use std::path::PathBuf;
use std::time::Instant;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

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

    for (i, chunk) in s.as_bytes()[first_group..].chunks(3).enumerate() {
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

    // Parse chain once for use in handlers
    let chain: Chain = cli.chain.parse()?;

    // Handle subcommands
    match &cli.command {
        Commands::Logs(args) => {
            return run_logs(args, &cli).await;
        }
        Commands::Tx(args) => {
            return handle_tx(args, &cli).await;
        }
        Commands::Account { action } => {
            return ethcli::cli::account::handle(
                action,
                chain,
                cli.etherscan_key.clone(),
                cli.quiet,
            )
            .await;
        }
        Commands::Contract { action } => {
            return ethcli::cli::contract::handle(
                action,
                chain,
                cli.etherscan_key.clone(),
                cli.quiet,
            )
            .await;
        }
        Commands::Token { action } => {
            return ethcli::cli::token::handle(action, chain, cli.etherscan_key.clone(), cli.quiet)
                .await;
        }
        Commands::Gas { action } => {
            return ethcli::cli::gas::handle(action, chain, cli.etherscan_key.clone(), cli.quiet)
                .await;
        }
        Commands::Sig { action } => {
            return ethcli::cli::sig::handle(action, chain, cli.etherscan_key.clone(), cli.quiet)
                .await;
        }
        Commands::Endpoints { action } => {
            return handle_endpoints(action, &cli).await;
        }
        Commands::Config { action } => {
            return handle_config(action).await;
        }
        Commands::Cast { action } => {
            return ethcli::cli::cast::handle(action);
        }
        Commands::Rpc { action, rpc_url } => {
            return ethcli::cli::rpc::handle(action, chain, rpc_url.clone(), cli.quiet).await;
        }
        Commands::Ens { action, rpc_url } => {
            return ethcli::cli::ens::handle(action, chain, rpc_url.clone(), cli.quiet).await;
        }
    }
}

/// Run logs command with LogsArgs
async fn run_logs(args: &LogsArgs, cli: &Cli) -> anyhow::Result<()> {
    let contract = &args.contract;

    // Parse chain
    let chain: Chain = cli.chain.parse()?;

    // Parse output format
    let format: OutputFormat = args.format.parse()?;

    // Parse to_block
    let to_block = if args.to_block.to_lowercase() == "latest" {
        ethcli::BlockNumber::Latest
    } else {
        ethcli::BlockNumber::Number(args.to_block.parse()?)
    };

    // Load config file for additional settings
    let config_file = ConfigFile::load_default().ok().flatten();

    // Get Etherscan API key
    let etherscan_key = cli.etherscan_key.clone().or_else(|| {
        config_file
            .as_ref()
            .and_then(|c| c.etherscan_api_key.clone())
    });

    // Apply defaults: CLI > config file > hardcoded defaults
    let concurrency = args.concurrency.unwrap_or_else(|| {
        config_file
            .as_ref()
            .map(|c| c.settings.concurrency)
            .unwrap_or(5)
    });

    // Build RPC config
    let rpc_config =
        build_rpc_config_from_logs_args(&args.rpc, &args.proxy, &config_file, concurrency)?;

    // Parse from_block (can be number, "auto", or omitted for auto-detect)
    let (from_block, auto_from_block) = match &args.from_block {
        Some(s) if s.to_lowercase() == "auto" => (0, true),
        Some(s) => (s.parse::<u64>()?, false),
        None => (0, true), // Default to auto-detect from contract creation
    };

    // Build main config
    let mut builder = Config::builder()
        .chain(chain)
        .contract(contract)
        .from_block(from_block)
        .to_block(to_block)
        .output_format(format)
        .concurrency(concurrency)
        .raw(args.raw)
        .resume(args.resume)
        .quiet(cli.quiet)
        .verbosity(cli.verbose)
        .auto_from_block(auto_from_block)
        .rpc_config(rpc_config);

    // Add event filters (supports multiple: -e Transfer -e Approval)
    for event in &args.event {
        builder = builder.event(event);
    }

    if let Some(abi) = &args.abi {
        builder = builder.abi_path(abi);
    }

    if let Some(output) = &args.output {
        builder = builder.output_path(output);
    }

    if let Some(checkpoint) = &args.checkpoint {
        builder = builder.checkpoint_path(checkpoint);
    }

    if let Some(key) = etherscan_key {
        builder = builder.etherscan_key(key);
    }

    let config = builder.build()?;

    // Create output writer early for streaming mode
    let mut writer = ethcli::create_writer(format, args.output.as_deref())?;

    if !cli.quiet {
        eprintln!("Connecting to {} endpoints...", chain.display_name());
    }

    let start = Instant::now();
    let (total_logs, stats) = if args.resume {
        // Use streaming mode with checkpoint support
        run_streaming_fetch(args, cli, config, &mut writer).await?
    } else {
        // Use batch mode (faster for smaller queries)
        run_batch_fetch_logs(args, cli, config, &mut writer).await?
    };
    let elapsed = start.elapsed();

    writer.finalize()?;

    // Report failures
    if !stats.is_complete() {
        if args.strict {
            eprintln!(
                "Error: {} of {} chunks failed (--strict mode)",
                stats.chunks_failed, stats.chunks_total
            );
            for (from, to, err) in &stats.failed_ranges {
                eprintln!("  - Blocks {}-{}: {}", from, to, err);
            }
            return Err(anyhow::anyhow!(
                "Fetch incomplete: {} chunks failed",
                stats.chunks_failed
            ));
        } else {
            eprintln!(
                "Warning: {} of {} chunks failed ({:.1}% success rate)",
                stats.chunks_failed,
                stats.chunks_total,
                stats.success_rate()
            );
            if cli.verbose > 0 {
                for (from, to, err) in &stats.failed_ranges {
                    eprintln!("  - Blocks {}-{}: {}", from, to, err);
                }
            }
        }
    }

    if !cli.quiet {
        let status = if stats.is_complete() {
            String::new()
        } else {
            format!(" (incomplete: {} chunks failed)", stats.chunks_failed)
        };
        let mode = if args.resume { " [streaming]" } else { "" };
        eprintln!(
            "Fetched {} logs in {:.2}s{}{}",
            total_logs,
            elapsed.as_secs_f64(),
            status,
            mode
        );
    }

    Ok(())
}

/// Run fetch in batch mode (loads all into memory, faster for small queries)
async fn run_batch_fetch_logs(
    _args: &LogsArgs,
    cli: &Cli,
    config: Config,
    writer: &mut Box<dyn ethcli::OutputWriter>,
) -> anyhow::Result<(usize, FetchStats)> {
    let fetcher = LogFetcher::new(config).await?;

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

    let result = fetcher.fetch_all().await?;

    if let Some(ref pb) = pb {
        pb.finish_and_clear();
    }

    let total_logs = result.len();
    let stats = result.stats.clone();

    writer.write_logs(&result)?;

    Ok((total_logs, stats))
}

/// Run fetch in streaming mode (writes incrementally, supports resume)
async fn run_streaming_fetch(
    args: &LogsArgs,
    cli: &Cli,
    config: Config,
    writer: &mut Box<dyn OutputWriter>,
) -> anyhow::Result<(usize, FetchStats)> {
    let mut fetcher = StreamingFetcher::new(config.clone()).await?;

    // Enable checkpointing if path specified or use default
    let checkpoint_path = args.checkpoint.clone().unwrap_or_else(|| {
        PathBuf::from(format!(
            ".eth-log-fetch-{}.checkpoint",
            &args.contract[..8.min(args.contract.len())]
        ))
    });

    fetcher = fetcher.with_checkpoint(&checkpoint_path)?;

    if !cli.quiet {
        eprintln!(
            "Using {} RPC endpoints (streaming mode)",
            fetcher.endpoint_count()
        );
        eprintln!("Checkpoint: {}", checkpoint_path.display());
    }

    // Set up progress (simplified for streaming)
    let pb = if !cli.quiet {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} [{elapsed_precise}] {msg}")
                .unwrap(),
        );
        pb.enable_steady_tick(std::time::Duration::from_millis(100));
        Some(pb)
    } else {
        None
    };

    let mut total_logs = 0usize;

    // Stream logs and write incrementally
    let stats = fetcher
        .fetch_streaming(|result| {
            total_logs += result.len();

            if let Some(ref pb) = pb {
                pb.set_message(format!("{} logs fetched", total_logs));
            }

            writer.write_logs(&result)?;
            Ok(())
        })
        .await?;

    if let Some(ref pb) = pb {
        pb.finish_and_clear();
    }

    Ok((total_logs, stats))
}

/// Build RPC config from LogsArgs (has embedded RPC/Proxy args)
fn build_rpc_config_from_logs_args(
    rpc: &RpcArgs,
    proxy: &ProxyArgs,
    config_file: &Option<ConfigFile>,
    concurrency: usize,
) -> anyhow::Result<RpcConfig> {
    let mut rpc_config = RpcConfig::default();

    // Custom endpoints from CLI
    if !rpc.rpc_urls.is_empty() {
        rpc_config.endpoints = rpc.rpc_urls.iter().map(EndpointConfig::new).collect();
    }

    // Load from file
    if let Some(path) = &rpc.rpc_file {
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
    rpc_config.add_endpoints = rpc.add_rpc.clone();

    // Excluded endpoints from CLI
    rpc_config.exclude_endpoints = rpc.exclude_rpc.clone();

    // Add disabled endpoints from config file
    if let Some(cf) = config_file {
        rpc_config
            .exclude_endpoints
            .extend(cf.disabled_endpoints.urls.clone());
    }

    rpc_config.min_priority = rpc.min_priority;

    // Apply defaults: CLI > config file > hardcoded defaults
    rpc_config.timeout_secs = rpc.timeout.unwrap_or_else(|| {
        config_file
            .as_ref()
            .map(|c| c.settings.timeout_seconds)
            .unwrap_or(30)
    });

    rpc_config.max_retries = rpc.retries.unwrap_or_else(|| {
        config_file
            .as_ref()
            .map(|c| c.settings.retry_attempts)
            .unwrap_or(3)
    });

    rpc_config.concurrency = concurrency;

    // Proxy config
    if proxy.proxy.is_some() || proxy.proxy_file.is_some() {
        rpc_config.proxy = Some(ProxyConfig {
            url: proxy.proxy.clone(),
            file: proxy.proxy_file.clone(),
            rotate_per_request: proxy.proxy_rotate,
        });
    } else if let Some(cf) = config_file {
        rpc_config.proxy = cf.proxy_config();
    }

    Ok(rpc_config)
}

/// Build default RPC config (for tx command that doesn't have RPC args)
fn build_default_rpc_config(config_file: &Option<ConfigFile>) -> anyhow::Result<RpcConfig> {
    let mut rpc_config = RpcConfig::default();

    // Add custom endpoints from config file
    if let Some(cf) = config_file {
        for endpoint in &cf.endpoints {
            if !rpc_config.endpoints.iter().any(|e| e.url == endpoint.url) {
                rpc_config.endpoints.push(endpoint.clone());
            }
        }
    }

    // Add disabled endpoints from config file
    if let Some(cf) = config_file {
        rpc_config
            .exclude_endpoints
            .extend(cf.disabled_endpoints.urls.clone());
    }

    // Apply config file defaults
    if let Some(cf) = config_file {
        rpc_config.timeout_secs = cf.settings.timeout_seconds;
        rpc_config.max_retries = cf.settings.retry_attempts;
        rpc_config.concurrency = cf.settings.concurrency;
        rpc_config.proxy = cf.proxy_config();
    }

    Ok(rpc_config)
}

async fn handle_endpoints(action: &EndpointCommands, cli: &Cli) -> anyhow::Result<()> {
    match action {
        EndpointCommands::List => {
            let chain: Chain = cli.chain.parse()?;
            let endpoints = default_endpoints(chain);

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
            let endpoint = Endpoint::new(EndpointConfig::new(url), 10, None)?;

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
                println!("  ethcli config set-etherscan-key YOUR_KEY");
            }
        }
    }

    Ok(())
}

async fn handle_tx(args: &TxArgs, cli: &Cli) -> anyhow::Result<()> {
    use std::io::BufRead;

    // Collect all hashes from various sources
    let mut all_hashes: Vec<String> = args.hashes.clone();

    // Read from file if specified
    if let Some(path) = &args.file {
        let file = std::fs::File::open(path)?;
        let reader = std::io::BufReader::new(file);
        for line in reader.lines() {
            let line = line?;
            let hash = line.trim();
            if !hash.is_empty() && !hash.starts_with('#') {
                all_hashes.push(hash.to_string());
            }
        }
    }

    // Read from stdin if specified
    if args.stdin {
        let stdin = std::io::stdin();
        let reader = stdin.lock();
        for line in reader.lines() {
            let line = line?;
            let hash = line.trim();
            if !hash.is_empty() && !hash.starts_with('#') {
                all_hashes.push(hash.to_string());
            }
        }
    }

    if all_hashes.is_empty() {
        return Err(anyhow::anyhow!(
            "No transaction hashes provided. Use positional args, --file, or --stdin"
        ));
    }

    // Parse chain
    let chain: Chain = cli.chain.parse()?;

    // Load config file for additional settings
    let config_file = ConfigFile::load_default().ok().flatten();

    // Build RPC config with defaults
    let rpc_config = build_default_rpc_config(&config_file)?;

    // Create RPC pool
    let pool = RpcPool::new(chain, &rpc_config)?;

    let tx_count = all_hashes.len();
    let endpoint_count = pool.endpoint_count();

    if !cli.quiet {
        eprintln!(
            "Analyzing {} transaction{} using {} RPC endpoints (batch size: {})...",
            tx_count,
            if tx_count == 1 { "" } else { "s" },
            endpoint_count,
            args.batch_size
        );
    }

    // Create analyzer
    let analyzer = std::sync::Arc::new(TxAnalyzer::new(pool, chain));

    let start = Instant::now();
    let mut all_analyses = Vec::new();
    let mut total_events = 0;
    let mut total_transfers = 0;
    let mut failed_count = 0;

    // Process in batches for parallelism
    for (batch_idx, batch) in all_hashes.chunks(args.batch_size).enumerate() {
        let batch_start = batch_idx * args.batch_size;

        if !cli.quiet && tx_count > 1 {
            eprint!(
                "\r[{}-{}/{}] Processing batch...",
                batch_start + 1,
                (batch_start + batch.len()).min(tx_count),
                tx_count
            );
        }

        // Process batch in parallel
        let enrich = args.enrich;
        let futures: Vec<_> = batch
            .iter()
            .enumerate()
            .map(|(i, hash)| {
                let analyzer = analyzer.clone();
                let hash = if hash.starts_with("0x") || hash.starts_with("0X") {
                    hash.to_string()
                } else {
                    format!("0x{}", hash)
                };
                let idx = batch_start + i;

                async move {
                    let result = if enrich {
                        analyzer.analyze_enriched(&hash).await
                    } else {
                        analyzer.analyze(&hash).await
                    };
                    (idx, hash.clone(), result)
                }
            })
            .collect();

        let results = futures::future::join_all(futures).await;

        for (idx, hash, result) in results {
            match result {
                Ok(analysis) => {
                    total_events += analysis.events.len();
                    total_transfers += analysis.token_flows.len();
                    all_analyses.push((idx, analysis));
                }
                Err(e) => {
                    failed_count += 1;
                    if !cli.quiet {
                        eprintln!(
                            "\n[{}] Error: {} - {}",
                            idx + 1,
                            &hash[..hash.len().min(12)],
                            e
                        );
                    }
                }
            }
        }
    }

    // Sort by original index to maintain order
    all_analyses.sort_by_key(|(idx, _)| *idx);
    let analyses: Vec<_> = all_analyses.into_iter().map(|(_, a)| a).collect();

    if !cli.quiet && tx_count > 1 {
        eprintln!(); // Clear the progress line
    }

    let elapsed = start.elapsed();

    // Output
    match args.output.as_str() {
        "json" => {
            if analyses.len() == 1 {
                let json = serde_json::to_string_pretty(&analyses[0])?;
                println!("{}", json);
            } else {
                let json = serde_json::to_string_pretty(&analyses)?;
                println!("{}", json);
            }
        }
        "ndjson" => {
            // Newline-delimited JSON - one per line, good for streaming/large datasets
            for analysis in &analyses {
                let json = serde_json::to_string(analysis)?;
                println!("{}", json);
            }
        }
        _ => {
            // Pretty print
            for (i, analysis) in analyses.iter().enumerate() {
                if i > 0 {
                    println!("\n{}", "=".repeat(80));
                    println!();
                }
                println!("{}", format_analysis(analysis));
            }
        }
    }

    if !cli.quiet {
        let failed_msg = if failed_count > 0 {
            format!(", {} failed", failed_count)
        } else {
            String::new()
        };
        eprintln!(
            "\nAnalyzed {} transaction{} in {:.2}s ({} events, {} transfers{})",
            analyses.len(),
            if analyses.len() == 1 { "" } else { "s" },
            elapsed.as_secs_f64(),
            total_events,
            total_transfers,
            failed_msg
        );
        if tx_count > 10 {
            eprintln!(
                "Throughput: {:.1} tx/s",
                analyses.len() as f64 / elapsed.as_secs_f64()
            );
        }
    }

    Ok(())
}
