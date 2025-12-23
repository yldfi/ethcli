//! Signature lookup commands
//!
//! Look up function selectors and event topics from 4byte.directory

use crate::config::Chain;
use crate::etherscan::Client;
use clap::Subcommand;

#[derive(Subcommand)]
pub enum SigCommands {
    /// Lookup function signature by 4-byte selector
    #[command(name = "fn")]
    Function {
        /// 4-byte selector (e.g., 0xa9059cbb)
        selector: String,
    },

    /// Lookup event signature by topic0 hash
    Event {
        /// Topic0 hash (e.g., 0xddf252ad...)
        topic: String,
    },

    /// Show signature cache statistics
    CacheStats,

    /// Clear the signature cache
    CacheClear,
}

pub async fn handle(
    action: &SigCommands,
    chain: Chain,
    api_key: Option<String>,
    quiet: bool,
) -> anyhow::Result<()> {
    match action {
        SigCommands::Function { selector } => {
            let client = Client::new(chain, api_key)?;

            if !quiet {
                eprintln!("Looking up selector {}...", selector);
            }

            match client.lookup_selector(selector).await {
                Some(sig) => {
                    println!("{}", sig);
                }
                None => {
                    eprintln!("No signature found for selector {}", selector);
                    std::process::exit(1);
                }
            }
        }

        SigCommands::Event { topic } => {
            let client = Client::new(chain, api_key)?;

            if !quiet {
                eprintln!("Looking up event topic {}...", topic);
            }

            match client.lookup_event(topic).await {
                Some(sig) => {
                    println!("{}", sig);
                }
                None => {
                    eprintln!("No signature found for topic {}", topic);
                    std::process::exit(1);
                }
            }
        }

        SigCommands::CacheStats => {
            let client = Client::new(chain, api_key)?;
            let stats = client.cache_stats();

            println!("Signature Cache");
            println!("{}", "─".repeat(40));
            println!(
                "Functions: {} cached ({} valid)",
                stats.total_functions, stats.valid_functions
            );
            println!(
                "Events:    {} cached ({} valid)",
                stats.total_events, stats.valid_events
            );
            println!("Path:      {}", stats.cache_path.display());
        }

        SigCommands::CacheClear => {
            let client = Client::new(chain, api_key)?;
            client.cache().clear();
            println!("Signature cache cleared");
        }
    }

    Ok(())
}
