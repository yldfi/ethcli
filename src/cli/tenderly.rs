//! Tenderly API commands
//!
//! Full Tenderly API access: vnets, wallets, contracts, alerts, actions, networks

use crate::cli::simulate::TenderlyArgs;
use crate::config::ConfigFile;
use clap::Subcommand;

/// Create a tndrly::Client from args/env/config credentials
fn create_client(args: &TenderlyArgs) -> anyhow::Result<tndrly::Client> {
    let config = ConfigFile::load_default().ok().flatten();
    let tenderly_config = config.as_ref().and_then(|c| c.tenderly.as_ref());

    let api_key = args
        .tenderly_key
        .clone()
        .or_else(|| tenderly_config.map(|t| t.access_key.clone()))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Tenderly API key required. Set via --tenderly-key, TENDERLY_ACCESS_KEY env, or config file"
            )
        })?;

    let account = args
        .tenderly_account
        .clone()
        .or_else(|| tenderly_config.map(|t| t.account.clone()))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Tenderly account required. Set via --tenderly-account, TENDERLY_ACCOUNT env, or config file"
            )
        })?;

    let project = args
        .tenderly_project
        .clone()
        .or_else(|| tenderly_config.map(|t| t.project.clone()))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Tenderly project required. Set via --tenderly-project, TENDERLY_PROJECT env, or config file"
            )
        })?;

    let config = tndrly::Config::new(api_key, account, project);
    tndrly::Client::new(config)
        .map_err(|e| anyhow::anyhow!("Failed to create Tenderly client: {}", e))
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum TenderlyCommands {
    /// Transaction simulation (alias for 'ethcli simulate' with --via tenderly)
    #[command(visible_alias = "sim")]
    Simulate {
        #[command(subcommand)]
        action: Box<crate::cli::simulate::SimulateCommands>,
    },

    /// Virtual TestNets management
    Vnets {
        #[command(subcommand)]
        action: VnetsCommands,

        #[command(flatten)]
        tenderly: TenderlyArgs,
    },

    /// Wallet monitoring
    Wallets {
        #[command(subcommand)]
        action: WalletsCommands,

        #[command(flatten)]
        tenderly: TenderlyArgs,
    },

    /// Contract management
    Contracts {
        #[command(subcommand)]
        action: ContractsCommands,

        #[command(flatten)]
        tenderly: TenderlyArgs,
    },

    /// Alert management
    Alerts {
        #[command(subcommand)]
        action: AlertsCommands,

        #[command(flatten)]
        tenderly: TenderlyArgs,
    },

    /// Web3 Actions
    Actions {
        #[command(subcommand)]
        action: ActionsCommands,

        #[command(flatten)]
        tenderly: TenderlyArgs,
    },

    /// Network information
    Networks {
        #[command(subcommand)]
        action: NetworksCommands,

        #[command(flatten)]
        tenderly: TenderlyArgs,
    },
}

// ============================================================================
// VNets Commands
// ============================================================================

#[derive(Subcommand)]
pub enum VnetsCommands {
    /// Create a new Virtual TestNet
    Create {
        /// Unique slug identifier
        #[arg(long)]
        slug: String,

        /// Display name
        #[arg(long)]
        name: String,

        /// Network ID to fork from (1 = mainnet, 137 = polygon, etc.)
        #[arg(long, default_value = "1")]
        network_id: u64,

        /// Block number to fork from (latest if not specified)
        #[arg(long)]
        block_number: Option<u64>,

        /// Custom chain ID for the VNet
        #[arg(long)]
        chain_id: Option<u64>,

        /// Enable state sync
        #[arg(long)]
        sync_state: bool,
    },

    /// List Virtual TestNets
    List {
        /// Filter by slug prefix
        #[arg(long)]
        slug: Option<String>,

        /// Page number
        #[arg(long, default_value = "1")]
        page: u32,

        /// Results per page
        #[arg(long, default_value = "20")]
        per_page: u32,
    },

    /// Get Virtual TestNet details
    Get {
        /// VNet ID
        id: String,
    },

    /// Delete a Virtual TestNet
    Delete {
        /// VNet ID
        id: String,
    },

    /// Fork an existing Virtual TestNet
    Fork {
        /// Source VNet ID
        #[arg(long)]
        source: String,

        /// New slug identifier
        #[arg(long)]
        slug: String,

        /// Display name
        #[arg(long)]
        name: String,

        /// Block number to fork at
        #[arg(long)]
        block_number: Option<u64>,
    },

    /// Get RPC URLs for a Virtual TestNet
    Rpc {
        /// VNet ID
        id: String,
    },

    /// List transactions on a Virtual TestNet
    Transactions {
        /// VNet ID
        id: String,

        /// Page number
        #[arg(long, default_value = "1")]
        page: u32,

        /// Results per page
        #[arg(long, default_value = "20")]
        per_page: u32,
    },

    /// Send a transaction to a Virtual TestNet
    Send {
        /// VNet ID
        #[arg(long)]
        vnet: String,

        /// From address
        #[arg(long)]
        from: String,

        /// To address
        #[arg(long)]
        to: String,

        /// Transaction data (hex)
        #[arg(long)]
        data: Option<String>,

        /// Value in wei
        #[arg(long, default_value = "0")]
        value: String,
    },
}

// ============================================================================
// Wallets Commands
// ============================================================================

#[derive(Subcommand)]
pub enum WalletsCommands {
    /// Add a wallet for monitoring
    Add {
        /// Wallet address
        address: String,

        /// Display name
        #[arg(long)]
        name: Option<String>,

        /// Network IDs to monitor on (can be repeated)
        #[arg(long = "network", action = clap::ArgAction::Append)]
        networks: Vec<String>,
    },

    /// List monitored wallets
    List,

    /// Get wallet details on a network
    Get {
        /// Wallet address
        address: String,

        /// Network ID
        #[arg(long, default_value = "1")]
        network: String,
    },
}

// ============================================================================
// Contracts Commands
// ============================================================================

#[derive(Subcommand)]
pub enum ContractsCommands {
    /// Add a contract for monitoring
    Add {
        /// Contract address
        address: String,

        /// Network ID
        #[arg(long, default_value = "1")]
        network: String,

        /// Display name
        #[arg(long)]
        name: Option<String>,
    },

    /// List monitored contracts
    List,

    /// Get contract details
    Get {
        /// Contract address
        address: String,

        /// Network ID
        #[arg(long, default_value = "1")]
        network: String,
    },

    /// Delete a contract from monitoring
    Delete {
        /// Contract address
        address: String,

        /// Network ID
        #[arg(long, default_value = "1")]
        network: String,
    },

    /// Verify contract source code
    Verify {
        /// Contract address
        address: String,

        /// Network ID
        #[arg(long, default_value = "1")]
        network: String,

        /// Contract name (as in source file)
        #[arg(long)]
        name: String,

        /// Source code file path
        #[arg(long)]
        source: String,

        /// Compiler version (e.g., "0.8.19")
        #[arg(long)]
        compiler: String,

        /// Optimization runs (omit to disable optimization)
        #[arg(long)]
        optimize_runs: Option<u32>,
    },

    /// Get contract ABI
    Abi {
        /// Contract address
        address: String,

        /// Network ID
        #[arg(long, default_value = "1")]
        network: String,
    },

    /// Add a tag to a contract
    Tag {
        /// Contract address
        address: String,

        /// Network ID
        #[arg(long, default_value = "1")]
        network: String,

        /// Tag to add
        #[arg(long)]
        tag: String,
    },

    /// Rename a contract
    Rename {
        /// Contract address
        address: String,

        /// Network ID
        #[arg(long, default_value = "1")]
        network: String,

        /// New display name
        #[arg(long)]
        name: String,
    },
}

// ============================================================================
// Alerts Commands
// ============================================================================

#[derive(Subcommand)]
pub enum AlertsCommands {
    /// Create a new alert
    Create {
        /// Alert name
        #[arg(long)]
        name: String,

        /// Alert type: successful_transaction, failed_transaction, function_call,
        /// event_emitted, erc20_transfer, erc721_transfer, state_change,
        /// balance_change, contract_deployed, block_mined, whale_alert, expression
        #[arg(long)]
        alert_type: String,

        /// Alert target type: address, network, project, tag
        #[arg(long, default_value = "address")]
        target_type: String,

        /// Target addresses (can be repeated)
        #[arg(long = "address", action = clap::ArgAction::Append)]
        addresses: Vec<String>,

        /// Network ID
        #[arg(long, default_value = "1")]
        network: String,
    },

    /// List alerts
    List,

    /// Get alert details
    Get {
        /// Alert ID
        id: String,
    },

    /// Delete an alert
    Delete {
        /// Alert ID
        id: String,
    },

    /// Enable an alert
    Enable {
        /// Alert ID
        id: String,
    },

    /// Disable an alert
    Disable {
        /// Alert ID
        id: String,
    },

    /// View alert history
    History {
        /// Page number
        #[arg(long, default_value = "1")]
        page: u32,

        /// Results per page
        #[arg(long, default_value = "20")]
        per_page: u32,
    },

    /// Test an alert
    Test {
        /// Alert ID
        id: String,

        /// Transaction hash to test with
        #[arg(long)]
        tx_hash: String,

        /// Network ID
        #[arg(long, default_value = "1")]
        network: String,
    },

    /// Manage webhooks
    Webhooks {
        #[command(subcommand)]
        action: WebhookCommands,
    },
}

#[derive(Subcommand)]
pub enum WebhookCommands {
    /// Create a webhook
    Create {
        /// Webhook name
        #[arg(long)]
        name: String,

        /// Webhook URL
        #[arg(long)]
        url: String,
    },

    /// List webhooks
    List,

    /// Get webhook details
    Get {
        /// Webhook ID
        id: String,
    },

    /// Delete a webhook
    Delete {
        /// Webhook ID
        id: String,
    },

    /// Test a webhook
    Test {
        /// Webhook ID
        id: String,

        /// Transaction hash to test with
        #[arg(long)]
        tx_hash: String,

        /// Network ID
        #[arg(long, default_value = "1")]
        network: String,
    },
}

// ============================================================================
// Actions Commands
// ============================================================================

#[derive(Subcommand)]
pub enum ActionsCommands {
    /// Create a new Web3 Action
    Create {
        /// Action name
        #[arg(long)]
        name: String,

        /// Trigger type: alert, webhook, periodic, block, transaction
        #[arg(long)]
        trigger: String,

        /// Source code file path
        #[arg(long)]
        source: String,
    },

    /// List Web3 Actions
    List,

    /// Get Action details
    Get {
        /// Action ID
        id: String,
    },

    /// Delete an Action
    Delete {
        /// Action ID
        id: String,
    },

    /// Enable an Action
    Enable {
        /// Action ID
        id: String,
    },

    /// Disable an Action
    Disable {
        /// Action ID
        id: String,
    },

    /// Invoke an Action manually
    Invoke {
        /// Action ID
        id: String,

        /// Payload JSON
        #[arg(long)]
        payload: Option<String>,
    },

    /// View Action logs
    Logs {
        /// Action ID
        id: String,
    },

    /// Get Action source code
    Source {
        /// Action ID
        id: String,
    },

    /// Update Action source code
    UpdateSource {
        /// Action ID
        id: String,

        /// Source code file path
        #[arg(long)]
        source: String,
    },

    /// Stop an Action
    Stop {
        /// Action ID
        id: String,
    },

    /// Resume a stopped Action
    Resume {
        /// Action ID
        id: String,
    },
}

// ============================================================================
// Networks Commands
// ============================================================================

#[derive(Subcommand)]
pub enum NetworksCommands {
    /// List all supported networks
    List,

    /// Get network by ID
    Get {
        /// Network ID (e.g., 1, 137)
        id: u64,
    },

    /// List mainnet networks only
    Mainnets,

    /// List testnet networks only
    Testnets,

    /// List networks with simulation support
    Simulation,

    /// List networks with VNet support
    Vnet,
}

// ============================================================================
// Handler
// ============================================================================

pub async fn handle(
    cmd: &TenderlyCommands,
    chain: crate::config::Chain,
    quiet: bool,
) -> anyhow::Result<()> {
    match cmd {
        TenderlyCommands::Simulate { action } => {
            // Delegate to the simulate handler
            crate::cli::simulate::handle(action, chain, quiet).await
        }
        TenderlyCommands::Vnets { action, tenderly } => handle_vnets(action, tenderly, quiet).await,
        TenderlyCommands::Wallets { action, tenderly } => {
            handle_wallets(action, tenderly, quiet).await
        }
        TenderlyCommands::Contracts { action, tenderly } => {
            handle_contracts(action, tenderly, quiet).await
        }
        TenderlyCommands::Alerts { action, tenderly } => {
            handle_alerts(action, tenderly, quiet).await
        }
        TenderlyCommands::Actions { action, tenderly } => {
            handle_actions(action, tenderly, quiet).await
        }
        TenderlyCommands::Networks { action, tenderly } => {
            handle_networks(action, tenderly, quiet).await
        }
    }
}

// ============================================================================
// VNets Handler
// ============================================================================

async fn handle_vnets(
    cmd: &VnetsCommands,
    tenderly: &TenderlyArgs,
    quiet: bool,
) -> anyhow::Result<()> {
    let client = create_client(tenderly)?;

    match cmd {
        VnetsCommands::Create {
            slug,
            name,
            network_id,
            block_number,
            chain_id,
            sync_state,
        } => {
            if !quiet {
                eprintln!("Creating Virtual TestNet '{}'...", slug);
            }

            let mut request = tndrly::vnets::CreateVNetRequest::new(slug, name, *network_id);

            if let Some(bn) = block_number {
                request = request.block_number(*bn);
            }
            if let Some(cid) = chain_id {
                request = request.chain_id(*cid);
            }
            if *sync_state {
                request = request.sync_state(true);
            }

            let vnet = client.vnets().create(&request).await?;
            println!("{}", serde_json::to_string_pretty(&vnet)?);
        }

        VnetsCommands::List {
            slug,
            page,
            per_page,
        } => {
            if !quiet {
                eprintln!("Listing Virtual TestNets...");
            }

            let mut query = tndrly::vnets::ListVNetsQuery::new()
                .page(*page)
                .per_page(*per_page);

            if let Some(s) = slug {
                query = query.slug(s);
            }

            let vnets = client.vnets().list(Some(query)).await?;
            println!("{}", serde_json::to_string_pretty(&vnets)?);
        }

        VnetsCommands::Get { id } => {
            if !quiet {
                eprintln!("Getting Virtual TestNet {}...", id);
            }
            let vnet = client.vnets().get(id).await?;
            println!("{}", serde_json::to_string_pretty(&vnet)?);
        }

        VnetsCommands::Delete { id } => {
            if !quiet {
                eprintln!("Deleting Virtual TestNet {}...", id);
            }
            client.vnets().delete(id).await?;
            println!("Virtual TestNet {} deleted.", id);
        }

        VnetsCommands::Fork {
            source,
            slug,
            name,
            block_number,
        } => {
            if !quiet {
                eprintln!("Forking Virtual TestNet {} as '{}'...", source, slug);
            }

            let mut request = tndrly::vnets::ForkVNetRequest::new(source, slug, name);

            if let Some(bn) = block_number {
                request = request.block_number(*bn);
            }

            let vnet = client.vnets().fork(&request).await?;
            println!("{}", serde_json::to_string_pretty(&vnet)?);
        }

        VnetsCommands::Rpc { id } => {
            if !quiet {
                eprintln!("Getting RPC URLs for VNet {}...", id);
            }
            let rpcs = client.vnets().rpc_urls(id).await?;
            println!("{}", serde_json::to_string_pretty(&rpcs)?);
        }

        VnetsCommands::Transactions { id, page, per_page } => {
            if !quiet {
                eprintln!("Listing transactions on VNet {}...", id);
            }

            let query = tndrly::vnets::ListVNetTransactionsQuery::new()
                .page(*page)
                .per_page(*per_page);

            let txs = client.vnets().transactions(id, Some(query)).await?;
            println!("{}", serde_json::to_string_pretty(&txs)?);
        }

        VnetsCommands::Send {
            vnet,
            from,
            to,
            data,
            value,
        } => {
            if !quiet {
                eprintln!("Sending transaction on VNet {}...", vnet);
            }

            let mut request = tndrly::vnets::SendVNetTransactionRequest::new(
                from,
                to,
                data.as_deref().unwrap_or("0x"),
            );

            if value != "0" {
                request = request.value(value);
            }

            let tx = client.vnets().send_transaction(vnet, &request).await?;
            println!("{}", serde_json::to_string_pretty(&tx)?);
        }
    }

    Ok(())
}

// ============================================================================
// Wallets Handler
// ============================================================================

async fn handle_wallets(
    cmd: &WalletsCommands,
    tenderly: &TenderlyArgs,
    quiet: bool,
) -> anyhow::Result<()> {
    let client = create_client(tenderly)?;

    match cmd {
        WalletsCommands::Add {
            address,
            name,
            networks,
        } => {
            if !quiet {
                eprintln!("Adding wallet {}...", address);
            }

            let mut request = tndrly::wallets::AddWalletRequest::new(address);

            if let Some(n) = name {
                request = request.display_name(n);
            }

            for network in networks {
                request = request.network(network);
            }

            let result = client.wallets().add(&request).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }

        WalletsCommands::List => {
            if !quiet {
                eprintln!("Listing wallets...");
            }
            let wallets = client.wallets().list().await?;
            println!("{}", serde_json::to_string_pretty(&wallets)?);
        }

        WalletsCommands::Get { address, network } => {
            if !quiet {
                eprintln!("Getting wallet {} on network {}...", address, network);
            }
            let wallet = client.wallets().get(address, network).await?;
            println!("{}", serde_json::to_string_pretty(&wallet)?);
        }
    }

    Ok(())
}

// ============================================================================
// Contracts Handler
// ============================================================================

async fn handle_contracts(
    cmd: &ContractsCommands,
    tenderly: &TenderlyArgs,
    quiet: bool,
) -> anyhow::Result<()> {
    let client = create_client(tenderly)?;

    match cmd {
        ContractsCommands::Add {
            address,
            network,
            name,
        } => {
            if !quiet {
                eprintln!("Adding contract {} on network {}...", address, network);
            }

            let mut request = tndrly::contracts::AddContractRequest::new(address, network);

            if let Some(n) = name {
                request = request.display_name(n);
            }

            let result = client.contracts().add(&request).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }

        ContractsCommands::List => {
            if !quiet {
                eprintln!("Listing contracts...");
            }
            let contracts = client.contracts().list(None).await?;
            println!("{}", serde_json::to_string_pretty(&contracts)?);
        }

        ContractsCommands::Get { address, network } => {
            if !quiet {
                eprintln!("Getting contract {} on network {}...", address, network);
            }
            let contract = client.contracts().get(network, address).await?;
            println!("{}", serde_json::to_string_pretty(&contract)?);
        }

        ContractsCommands::Delete { address, network } => {
            if !quiet {
                eprintln!("Deleting contract {} on network {}...", address, network);
            }
            client.contracts().delete(network, address).await?;
            println!("Contract {} deleted.", address);
        }

        ContractsCommands::Verify {
            address,
            network,
            name,
            source,
            compiler,
            optimize_runs,
        } => {
            if !quiet {
                eprintln!("Verifying contract {} on network {}...", address, network);
            }
            let source_code = std::fs::read_to_string(source)?;
            let mut request = tndrly::contracts::VerifyContractRequest::new(
                network,
                address,
                name,
                &source_code,
                compiler,
            );
            if let Some(runs) = optimize_runs {
                request = request.optimization(true, *runs);
            }
            let result = client.contracts().verify(&request).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }

        ContractsCommands::Abi { address, network } => {
            if !quiet {
                eprintln!("Getting ABI for {} on network {}...", address, network);
            }
            let abi = client.contracts().abi(network, address).await?;
            println!("{}", serde_json::to_string_pretty(&abi)?);
        }

        ContractsCommands::Tag {
            address,
            network,
            tag,
        } => {
            if !quiet {
                eprintln!("Adding tag '{}' to contract {}...", tag, address);
            }
            client.contracts().add_tag(network, address, tag).await?;
            println!("Tag '{}' added to contract {}.", tag, address);
        }

        ContractsCommands::Rename {
            address,
            network,
            name,
        } => {
            if !quiet {
                eprintln!("Renaming contract {} to '{}'...", address, name);
            }
            client.contracts().rename(network, address, name).await?;
            println!("Contract renamed successfully");
        }
    }

    Ok(())
}

// ============================================================================
// Alerts Handler
// ============================================================================

async fn handle_alerts(
    cmd: &AlertsCommands,
    tenderly: &TenderlyArgs,
    quiet: bool,
) -> anyhow::Result<()> {
    let client = create_client(tenderly)?;

    match cmd {
        AlertsCommands::Create {
            name,
            alert_type,
            target_type,
            addresses,
            network,
        } => {
            if !quiet {
                eprintln!("Creating alert '{}'...", name);
            }

            let alert_type: tndrly::alerts::AlertType =
                alert_type.parse().map_err(|e| anyhow::anyhow!("{}", e))?;
            let target: tndrly::alerts::AlertTarget =
                target_type.parse().map_err(|e| anyhow::anyhow!("{}", e))?;

            let mut request =
                tndrly::alerts::CreateAlertRequest::new(name, alert_type, network, target);

            if !addresses.is_empty() {
                request = request.addresses(addresses.clone());
            }

            let alert = client.alerts().create(&request).await?;
            println!("{}", serde_json::to_string_pretty(&alert)?);
        }

        AlertsCommands::List => {
            if !quiet {
                eprintln!("Listing alerts...");
            }
            let alerts = client.alerts().list().await?;
            println!("{}", serde_json::to_string_pretty(&alerts)?);
        }

        AlertsCommands::Get { id } => {
            if !quiet {
                eprintln!("Getting alert {}...", id);
            }
            let alert = client.alerts().get(id).await?;
            println!("{}", serde_json::to_string_pretty(&alert)?);
        }

        AlertsCommands::Delete { id } => {
            if !quiet {
                eprintln!("Deleting alert {}...", id);
            }
            client.alerts().delete(id).await?;
            println!("Alert {} deleted.", id);
        }

        AlertsCommands::Enable { id } => {
            if !quiet {
                eprintln!("Enabling alert {}...", id);
            }
            client.alerts().enable(id).await?;
            println!("Alert {} enabled.", id);
        }

        AlertsCommands::Disable { id } => {
            if !quiet {
                eprintln!("Disabling alert {}...", id);
            }
            client.alerts().disable(id).await?;
            println!("Alert {} disabled.", id);
        }

        AlertsCommands::History { page, per_page } => {
            if !quiet {
                eprintln!("Getting alert history...");
            }
            let query = tndrly::alerts::AlertHistoryQuery::new()
                .page(*page)
                .per_page(*per_page);
            let history = client.alerts().history(Some(query)).await?;
            println!("{}", serde_json::to_string_pretty(&history)?);
        }

        AlertsCommands::Test {
            id,
            tx_hash,
            network,
        } => {
            if !quiet {
                eprintln!("Testing alert {}...", id);
            }
            let request = tndrly::alerts::TestAlertRequest::new(id, tx_hash, network);
            client.alerts().test_alert(&request).await?;
            println!("Alert test triggered for {}.", id);
        }

        AlertsCommands::Webhooks { action } => {
            handle_webhooks(action, &client, quiet).await?;
        }
    }

    Ok(())
}

async fn handle_webhooks(
    cmd: &WebhookCommands,
    client: &tndrly::Client,
    quiet: bool,
) -> anyhow::Result<()> {
    match cmd {
        WebhookCommands::Create { name, url } => {
            if !quiet {
                eprintln!("Creating webhook '{}'...", name);
            }
            let request = tndrly::alerts::CreateWebhookRequest::new(name, url);
            let webhook = client.alerts().create_webhook(&request).await?;
            println!("{}", serde_json::to_string_pretty(&webhook)?);
        }

        WebhookCommands::List => {
            if !quiet {
                eprintln!("Listing webhooks...");
            }
            let webhooks = client.alerts().list_webhooks().await?;
            println!("{}", serde_json::to_string_pretty(&webhooks)?);
        }

        WebhookCommands::Get { id } => {
            if !quiet {
                eprintln!("Getting webhook {}...", id);
            }
            let webhook = client.alerts().get_webhook(id).await?;
            println!("{}", serde_json::to_string_pretty(&webhook)?);
        }

        WebhookCommands::Delete { id } => {
            if !quiet {
                eprintln!("Deleting webhook {}...", id);
            }
            client.alerts().delete_webhook(id).await?;
            println!("Webhook {} deleted.", id);
        }

        WebhookCommands::Test {
            id,
            tx_hash,
            network,
        } => {
            if !quiet {
                eprintln!("Testing webhook {}...", id);
            }
            client.alerts().test_webhook(id, tx_hash, network).await?;
            println!("Webhook test triggered for {}.", id);
        }
    }

    Ok(())
}

// ============================================================================
// Actions Handler
// ============================================================================

async fn handle_actions(
    cmd: &ActionsCommands,
    tenderly: &TenderlyArgs,
    quiet: bool,
) -> anyhow::Result<()> {
    let client = create_client(tenderly)?;

    match cmd {
        ActionsCommands::Create {
            name,
            trigger,
            source,
        } => {
            if !quiet {
                eprintln!("Creating Web3 Action '{}'...", name);
            }

            let trigger_type: tndrly::actions::ActionTrigger =
                trigger.parse().map_err(|e| anyhow::anyhow!("{}", e))?;

            let source_code = std::fs::read_to_string(source)?;
            let request =
                tndrly::actions::CreateActionRequest::new(name, trigger_type, &source_code);
            let action = client.actions().create(&request).await?;
            println!("{}", serde_json::to_string_pretty(&action)?);
        }

        ActionsCommands::List => {
            if !quiet {
                eprintln!("Listing Web3 Actions...");
            }
            let actions = client.actions().list().await?;
            println!("{}", serde_json::to_string_pretty(&actions)?);
        }

        ActionsCommands::Get { id } => {
            if !quiet {
                eprintln!("Getting Action {}...", id);
            }
            let action = client.actions().get(id).await?;
            println!("{}", serde_json::to_string_pretty(&action)?);
        }

        ActionsCommands::Delete { id } => {
            if !quiet {
                eprintln!("Deleting Action {}...", id);
            }
            client.actions().delete(id).await?;
            println!("Action {} deleted.", id);
        }

        ActionsCommands::Enable { id } => {
            if !quiet {
                eprintln!("Enabling Action {}...", id);
            }
            client.actions().enable(id).await?;
            println!("Action {} enabled.", id);
        }

        ActionsCommands::Disable { id } => {
            if !quiet {
                eprintln!("Disabling Action {}...", id);
            }
            client.actions().disable(id).await?;
            println!("Action {} disabled.", id);
        }

        ActionsCommands::Invoke { id, payload } => {
            if !quiet {
                eprintln!("Invoking Action {}...", id);
            }

            let request = match payload {
                Some(p) => {
                    let payload_value: serde_json::Value = serde_json::from_str(p)?;
                    tndrly::actions::InvokeActionRequest::with_payload(payload_value)
                }
                None => tndrly::actions::InvokeActionRequest::new(),
            };

            let result = client.actions().invoke(id, &request).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }

        ActionsCommands::Logs { id } => {
            if !quiet {
                eprintln!("Getting logs for Action {}...", id);
            }
            let logs = client.actions().logs(id).await?;
            println!("{}", serde_json::to_string_pretty(&logs)?);
        }

        ActionsCommands::Source { id } => {
            if !quiet {
                eprintln!("Getting source for Action {}...", id);
            }
            let source = client.actions().source(id).await?;
            println!("{}", source);
        }

        ActionsCommands::UpdateSource { id, source } => {
            if !quiet {
                eprintln!("Updating source for Action {}...", id);
            }
            let source_code = std::fs::read_to_string(source)?;
            client.actions().update_source(id, &source_code).await?;
            println!("Action {} source updated.", id);
        }

        ActionsCommands::Stop { id } => {
            if !quiet {
                eprintln!("Stopping Action {}...", id);
            }
            client.actions().stop(id).await?;
            println!("Action {} stopped.", id);
        }

        ActionsCommands::Resume { id } => {
            if !quiet {
                eprintln!("Resuming Action {}...", id);
            }
            client.actions().resume(id).await?;
            println!("Action {} resumed.", id);
        }
    }

    Ok(())
}

// ============================================================================
// Networks Handler
// ============================================================================

async fn handle_networks(
    cmd: &NetworksCommands,
    tenderly: &TenderlyArgs,
    quiet: bool,
) -> anyhow::Result<()> {
    let client = create_client(tenderly)?;

    match cmd {
        NetworksCommands::List => {
            if !quiet {
                eprintln!("Listing supported networks...");
            }
            let networks = client.networks().supported().await?;
            println!("{}", serde_json::to_string_pretty(&networks)?);
        }

        NetworksCommands::Get { id } => {
            if !quiet {
                eprintln!("Getting network {}...", id);
            }
            let network = client.networks().get_by_chain_id(*id).await?;
            println!("{}", serde_json::to_string_pretty(&network)?);
        }

        NetworksCommands::Mainnets => {
            if !quiet {
                eprintln!("Listing mainnet networks...");
            }
            let networks = client.networks().mainnets().await?;
            println!("{}", serde_json::to_string_pretty(&networks)?);
        }

        NetworksCommands::Testnets => {
            if !quiet {
                eprintln!("Listing testnet networks...");
            }
            let networks = client.networks().testnets().await?;
            println!("{}", serde_json::to_string_pretty(&networks)?);
        }

        NetworksCommands::Simulation => {
            if !quiet {
                eprintln!("Listing networks with simulation support...");
            }
            let networks = client.networks().with_simulation_support().await?;
            println!("{}", serde_json::to_string_pretty(&networks)?);
        }

        NetworksCommands::Vnet => {
            if !quiet {
                eprintln!("Listing networks with VNet support...");
            }
            let networks = client.networks().with_vnet_support().await?;
            println!("{}", serde_json::to_string_pretty(&networks)?);
        }
    }

    Ok(())
}
