//! Default RPC endpoints with tested limits
//!
//! These endpoints were tested for archive support and getLogs restrictions.
//! Priority: 10 = best (large block ranges, high log limits), 1 = limited

use crate::config::{Chain, EndpointConfig};

/// Get default endpoints for a chain
pub fn default_endpoints(chain: Chain) -> Vec<EndpointConfig> {
    match chain {
        Chain::Ethereum => ethereum_endpoints(),
        Chain::Polygon => polygon_endpoints(),
        Chain::Arbitrum => arbitrum_endpoints(),
        Chain::Optimism => optimism_endpoints(),
        Chain::Base => base_endpoints(),
        Chain::Bsc => bsc_endpoints(),
        Chain::Avalanche => avalanche_endpoints(),
        Chain::Custom(_) => Vec::new(), // Custom chains need user-provided endpoints
    }
}

/// Ethereum mainnet endpoints (22 verified archive nodes)
fn ethereum_endpoints() -> Vec<EndpointConfig> {
    vec![
        // Priority 10 - Best for large queries
        EndpointConfig {
            url: "https://eth-mainnet.public.blastapi.io".to_string(),
            max_block_range: 2_000_000,
            max_logs: 200_000,
            priority: 10,
            note: Some("Excellent - highest log limit".to_string()),
            proxy: None,
            enabled: true,
        },
        EndpointConfig {
            url: "https://api.noderpc.xyz/rpc-mainnet/public".to_string(),
            max_block_range: 2_000_000,
            max_logs: 88_000,
            priority: 10,
            note: Some("Very high limits".to_string()),
            proxy: None,
            enabled: true,
        },
        // Priority 9
        EndpointConfig {
            url: "https://mainnet.gateway.tenderly.co".to_string(),
            max_block_range: 2_000_000,
            max_logs: 20_000,
            priority: 9,
            note: None,
            proxy: None,
            enabled: true,
        },
        // Priority 8
        EndpointConfig {
            url: "https://rpc.flashbots.net".to_string(),
            max_block_range: 2_000_000,
            max_logs: 10_000,
            priority: 8,
            note: None,
            proxy: None,
            enabled: true,
        },
        EndpointConfig {
            url: "https://core.gashawk.io/rpc".to_string(),
            max_block_range: 2_000_000,
            max_logs: 10_000,
            priority: 8,
            note: None,
            proxy: None,
            enabled: true,
        },
        EndpointConfig {
            url: "https://rpc.flashbots.net/fast".to_string(),
            max_block_range: 2_000_000,
            max_logs: 10_000,
            priority: 8,
            note: None,
            proxy: None,
            enabled: true,
        },
        // Priority 7
        EndpointConfig {
            url: "https://ethereum.blinklabs.xyz".to_string(),
            max_block_range: 2_000_000,
            max_logs: 4_000,
            priority: 7,
            note: None,
            proxy: None,
            enabled: true,
        },
        EndpointConfig {
            url: "https://mainnet.infura.io/v3/84842078b09946638c03157f83405213".to_string(),
            max_block_range: 2_000_000,
            max_logs: 10_000,
            priority: 7,
            note: Some("Public demo key".to_string()),
            proxy: None,
            enabled: true,
        },
        // Priority 6 - Medium
        EndpointConfig {
            url: "https://eth.api.onfinality.io/public".to_string(),
            max_block_range: 500_000,
            max_logs: 50_000,
            priority: 6,
            note: None,
            proxy: None,
            enabled: true,
        },
        EndpointConfig {
            url: "https://rpc.mevblocker.io".to_string(),
            max_block_range: 100_000,
            max_logs: 10_000,
            priority: 6,
            note: None,
            proxy: None,
            enabled: true,
        },
        EndpointConfig {
            url: "https://rpc.tornadoeth.cash/eth".to_string(),
            max_block_range: 100_000,
            max_logs: 50_000,
            priority: 6,
            note: None,
            proxy: None,
            enabled: true,
        },
        // Priority 5
        EndpointConfig {
            url: "https://openapi.bitstack.com/v1/wNFxbiJyQsSeLrX8RRCHi7NpRxrlErZk/DjShIqLishPCTB9HiMkPHXjUM9CNM9Na/ETH/mainnet".to_string(),
            max_block_range: 100_000,
            max_logs: 50_000,
            priority: 5,
            note: None,
            proxy: None,
            enabled: true,
        },
        EndpointConfig {
            url: "https://ethereum.publicnode.com".to_string(),
            max_block_range: 50_000,
            max_logs: 20_000,
            priority: 5,
            note: None,
            proxy: None,
            enabled: true,
        },
        EndpointConfig {
            url: "https://eth-mainnet.nodereal.io/v1/1659dfb40aa24bbb8153a677b98064d7".to_string(),
            max_block_range: 25_000,
            max_logs: 50_000,
            priority: 5,
            note: None,
            proxy: None,
            enabled: true,
        },
        EndpointConfig {
            url: "https://eth-mainnet.alchemyapi.io/v2/demo".to_string(),
            max_block_range: 25_000,
            max_logs: 50_000,
            priority: 5,
            note: Some("Public demo key".to_string()),
            proxy: None,
            enabled: true,
        },
        // Priority 4 - Lower
        EndpointConfig {
            url: "https://eth.drpc.org".to_string(),
            max_block_range: 10_000,
            max_logs: 50_000,
            priority: 4,
            note: Some("Timeouts on free tier for large ranges".to_string()),
            proxy: None,
            enabled: true,
        },
        EndpointConfig {
            url: "https://gateway.tenderly.co/public/mainnet".to_string(),
            max_block_range: 2_000_000,
            max_logs: 20_000,
            priority: 4,
            note: None,
            proxy: None,
            enabled: true,
        },
        // Priority 3
        EndpointConfig {
            url: "https://ethereum.rpc.subquery.network/public".to_string(),
            max_block_range: 1_000,
            max_logs: 10_000,
            priority: 3,
            note: None,
            proxy: None,
            enabled: true,
        },
        EndpointConfig {
            url: "https://ethereum.rpc.thirdweb.com".to_string(),
            max_block_range: 1_000,
            max_logs: 10_000,
            priority: 3,
            note: None,
            proxy: None,
            enabled: true,
        },
        EndpointConfig {
            url: "https://eth.api.pocket.network".to_string(),
            max_block_range: 50_000,
            max_logs: 10_000,
            priority: 3,
            note: Some("Can be unreliable".to_string()),
            proxy: None,
            enabled: true,
        },
        // Priority 2 - Most limited
        EndpointConfig {
            url: "https://eth-pokt.nodies.app".to_string(),
            max_block_range: 800,
            max_logs: 10_000,
            priority: 2,
            note: None,
            proxy: None,
            enabled: true,
        },
        EndpointConfig {
            url: "https://ethereum-public.nodies.app".to_string(),
            max_block_range: 800,
            max_logs: 10_000,
            priority: 2,
            note: None,
            proxy: None,
            enabled: true,
        },
    ]
}

/// Polygon mainnet endpoints
fn polygon_endpoints() -> Vec<EndpointConfig> {
    vec![
        EndpointConfig {
            url: "https://polygon-mainnet.public.blastapi.io".to_string(),
            max_block_range: 100_000,
            max_logs: 10_000,
            priority: 10,
            note: None,
            proxy: None,
            enabled: true,
        },
        EndpointConfig {
            url: "https://polygon.api.onfinality.io/public".to_string(),
            max_block_range: 100_000,
            max_logs: 10_000,
            priority: 8,
            note: None,
            proxy: None,
            enabled: true,
        },
        EndpointConfig {
            url: "https://polygon-rpc.com".to_string(),
            max_block_range: 10_000,
            max_logs: 10_000,
            priority: 6,
            note: None,
            proxy: None,
            enabled: true,
        },
        EndpointConfig {
            url: "https://polygon.publicnode.com".to_string(),
            max_block_range: 10_000,
            max_logs: 10_000,
            priority: 5,
            note: None,
            proxy: None,
            enabled: true,
        },
        EndpointConfig {
            url: "https://polygon.drpc.org".to_string(),
            max_block_range: 10_000,
            max_logs: 10_000,
            priority: 4,
            note: None,
            proxy: None,
            enabled: true,
        },
    ]
}

/// Arbitrum One endpoints
fn arbitrum_endpoints() -> Vec<EndpointConfig> {
    vec![
        EndpointConfig {
            url: "https://arbitrum-mainnet.public.blastapi.io".to_string(),
            max_block_range: 100_000,
            max_logs: 10_000,
            priority: 10,
            note: None,
            proxy: None,
            enabled: true,
        },
        EndpointConfig {
            url: "https://arb1.arbitrum.io/rpc".to_string(),
            max_block_range: 10_000,
            max_logs: 10_000,
            priority: 8,
            note: Some("Official Arbitrum RPC".to_string()),
            proxy: None,
            enabled: true,
        },
        EndpointConfig {
            url: "https://arbitrum.publicnode.com".to_string(),
            max_block_range: 10_000,
            max_logs: 10_000,
            priority: 5,
            note: None,
            proxy: None,
            enabled: true,
        },
        EndpointConfig {
            url: "https://arbitrum.drpc.org".to_string(),
            max_block_range: 10_000,
            max_logs: 10_000,
            priority: 4,
            note: None,
            proxy: None,
            enabled: true,
        },
    ]
}

/// Optimism endpoints
fn optimism_endpoints() -> Vec<EndpointConfig> {
    vec![
        EndpointConfig {
            url: "https://optimism-mainnet.public.blastapi.io".to_string(),
            max_block_range: 100_000,
            max_logs: 10_000,
            priority: 10,
            note: None,
            proxy: None,
            enabled: true,
        },
        EndpointConfig {
            url: "https://mainnet.optimism.io".to_string(),
            max_block_range: 10_000,
            max_logs: 10_000,
            priority: 8,
            note: Some("Official Optimism RPC".to_string()),
            proxy: None,
            enabled: true,
        },
        EndpointConfig {
            url: "https://optimism.publicnode.com".to_string(),
            max_block_range: 10_000,
            max_logs: 10_000,
            priority: 5,
            note: None,
            proxy: None,
            enabled: true,
        },
        EndpointConfig {
            url: "https://optimism.drpc.org".to_string(),
            max_block_range: 10_000,
            max_logs: 10_000,
            priority: 4,
            note: None,
            proxy: None,
            enabled: true,
        },
    ]
}

/// Base endpoints
fn base_endpoints() -> Vec<EndpointConfig> {
    vec![
        EndpointConfig {
            url: "https://base-mainnet.public.blastapi.io".to_string(),
            max_block_range: 100_000,
            max_logs: 10_000,
            priority: 10,
            note: None,
            proxy: None,
            enabled: true,
        },
        EndpointConfig {
            url: "https://mainnet.base.org".to_string(),
            max_block_range: 10_000,
            max_logs: 10_000,
            priority: 8,
            note: Some("Official Base RPC".to_string()),
            proxy: None,
            enabled: true,
        },
        EndpointConfig {
            url: "https://base.publicnode.com".to_string(),
            max_block_range: 10_000,
            max_logs: 10_000,
            priority: 5,
            note: None,
            proxy: None,
            enabled: true,
        },
        EndpointConfig {
            url: "https://base.drpc.org".to_string(),
            max_block_range: 10_000,
            max_logs: 10_000,
            priority: 4,
            note: None,
            proxy: None,
            enabled: true,
        },
    ]
}

/// BSC (BNB Smart Chain) endpoints
fn bsc_endpoints() -> Vec<EndpointConfig> {
    vec![
        EndpointConfig {
            url: "https://bsc-mainnet.public.blastapi.io".to_string(),
            max_block_range: 100_000,
            max_logs: 10_000,
            priority: 10,
            note: None,
            proxy: None,
            enabled: true,
        },
        EndpointConfig {
            url: "https://bsc-dataseed.binance.org".to_string(),
            max_block_range: 5_000,
            max_logs: 10_000,
            priority: 8,
            note: Some("Official BSC RPC".to_string()),
            proxy: None,
            enabled: true,
        },
        EndpointConfig {
            url: "https://bsc.publicnode.com".to_string(),
            max_block_range: 5_000,
            max_logs: 10_000,
            priority: 5,
            note: None,
            proxy: None,
            enabled: true,
        },
        EndpointConfig {
            url: "https://bsc.drpc.org".to_string(),
            max_block_range: 5_000,
            max_logs: 10_000,
            priority: 4,
            note: None,
            proxy: None,
            enabled: true,
        },
    ]
}

/// Avalanche C-Chain endpoints
fn avalanche_endpoints() -> Vec<EndpointConfig> {
    vec![
        EndpointConfig {
            url: "https://avalanche-mainnet.public.blastapi.io/ext/bc/C/rpc".to_string(),
            max_block_range: 100_000,
            max_logs: 10_000,
            priority: 10,
            note: None,
            proxy: None,
            enabled: true,
        },
        EndpointConfig {
            url: "https://api.avax.network/ext/bc/C/rpc".to_string(),
            max_block_range: 2048,
            max_logs: 10_000,
            priority: 8,
            note: Some("Official Avalanche RPC".to_string()),
            proxy: None,
            enabled: true,
        },
        EndpointConfig {
            url: "https://avalanche-c-chain.publicnode.com".to_string(),
            max_block_range: 2048,
            max_logs: 10_000,
            priority: 5,
            note: None,
            proxy: None,
            enabled: true,
        },
        EndpointConfig {
            url: "https://avalanche.drpc.org".to_string(),
            max_block_range: 2048,
            max_logs: 10_000,
            priority: 4,
            note: None,
            proxy: None,
            enabled: true,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethereum_endpoints() {
        let endpoints = ethereum_endpoints();
        assert_eq!(endpoints.len(), 22);

        // Check highest priority endpoints
        let high_priority: Vec<_> = endpoints.iter().filter(|e| e.priority >= 10).collect();
        assert!(!high_priority.is_empty());
    }

    #[test]
    fn test_all_chains_have_endpoints() {
        assert!(!default_endpoints(Chain::Ethereum).is_empty());
        assert!(!default_endpoints(Chain::Polygon).is_empty());
        assert!(!default_endpoints(Chain::Arbitrum).is_empty());
        assert!(!default_endpoints(Chain::Optimism).is_empty());
        assert!(!default_endpoints(Chain::Base).is_empty());
        assert!(!default_endpoints(Chain::Bsc).is_empty());
        assert!(!default_endpoints(Chain::Avalanche).is_empty());

        // Custom chain should return empty (user must provide endpoints)
        assert!(default_endpoints(Chain::Custom(12345)).is_empty());
    }
}
