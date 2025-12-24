# ethcli

Comprehensive Ethereum CLI for logs, transactions, accounts, and contracts.

## Build Commands

```bash
# Development build
cargo build

# Release build (optimized)
cargo build --release

# Run tests
cargo test

# Check without building
cargo check

# Format code
cargo fmt

# Lint
cargo clippy
```

## Binary Location

- Debug: `./target/debug/ethcli`
- Release: `./target/release/ethcli`
- Legacy alias: `./target/release/eth-log-fetch`

## Available Commands

```
ethcli logs       # Fetch historical logs from contracts
ethcli tx         # Analyze transaction(s)
ethcli account    # Account operations (balance, transactions, transfers)
ethcli contract   # Contract operations (ABI, source, creation)
ethcli token      # Token operations (info, holders, balance)
ethcli gas        # Gas price oracle and estimates
ethcli sig        # Signature lookup (function selectors, event topics)
ethcli simulate   # Transaction simulation and tracing
ethcli cast       # Type conversions, hashing, encoding
ethcli rpc        # Direct RPC calls
ethcli ens        # ENS name resolution
ethcli endpoints  # Manage RPC endpoints
ethcli config     # Manage configuration
```

## Simulation Commands

```bash
# Simulate a contract call (uses cast by default)
ethcli simulate call <contract> --sig "balanceOf(address)" <address> --rpc-url https://eth.llamarpc.com

# Simulate with trace (requires debug-capable node)
ethcli simulate call <contract> --sig "transfer(address,uint256)" <to> <amount> --trace

# Trace an existing transaction
ethcli simulate tx <tx_hash> --rpc-url https://eth.llamarpc.com

# Use different backends
ethcli simulate call ... --via cast      # Default: uses cast call
ethcli simulate call ... --via anvil     # Forks mainnet with Anvil
ethcli simulate call ... --via tenderly  # Uses Tenderly API (rich output)
ethcli simulate call ... --via debug     # Uses debug_traceCall RPC
```

## Project Structure

```
src/
├── main.rs           # CLI entry point (clap)
├── lib.rs            # Library exports
├── error.rs          # Error types (thiserror)
├── fetcher.rs        # Main LogFetcher coordinator
├── checkpoint.rs     # Resume/checkpoint system
├── proxy.rs          # Proxy rotation support
├── tx.rs             # Transaction analysis
├── config/
│   ├── mod.rs        # Config structs, builder pattern
│   ├── chain.rs      # Chain enum (Ethereum, Polygon, etc.)
│   ├── endpoint.rs   # EndpointConfig
│   └── file.rs       # TOML config file handling
├── rpc/
│   ├── mod.rs
│   ├── endpoint.rs   # Single RPC endpoint wrapper (alloy)
│   ├── pool.rs       # RPC pool with parallel requests
│   ├── health.rs     # Endpoint health tracking
│   └── defaults.rs   # 22 pre-configured archive endpoints
├── abi/
│   ├── mod.rs
│   ├── parser.rs     # Event signature parser
│   ├── fetcher.rs    # Etherscan ABI fetcher (v2 API)
│   └── decoder.rs    # Log decoder (alloy dyn-abi)
├── output/
│   ├── mod.rs        # OutputWriter trait
│   ├── json.rs       # JSON/NDJSON output
│   ├── csv.rs        # CSV output
│   └── sqlite.rs     # SQLite output
├── etherscan/
│   ├── mod.rs        # Etherscan client wrapper
│   ├── client.rs     # Extended Etherscan API client
│   └── cache.rs      # Signature caching
└── cli/
    ├── mod.rs        # CLI command structure
    ├── logs.rs       # Log fetching arguments
    ├── tx.rs         # Transaction analysis args
    ├── account.rs    # Account commands
    ├── contract.rs   # Contract commands
    ├── token.rs      # Token commands
    ├── gas.rs        # Gas oracle commands
    ├── sig.rs        # Signature lookup commands
    ├── endpoints.rs  # Endpoint management
    └── config.rs     # Config management
```

## Key Dependencies

- **alloy 1.0**: Ethereum provider, types, ABI decoding
- **foundry-block-explorers**: Etherscan API client
- **tokio**: Async runtime
- **clap**: CLI parsing
- **serde/serde_json**: Serialization
- **rusqlite**: SQLite output
- **indicatif**: Progress bars

## Testing Locally

```bash
# Fetch USDC Transfer events (small range)
ethcli logs -c 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 \
  -e "Transfer(address,address,uint256)" \
  -f 21500000 -t 21500010

# Analyze a transaction
ethcli tx 0x123abc...

# Get account balance
ethcli account balance 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045

# Get recent transactions for an address
ethcli account txs 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045

# Get contract ABI
ethcli contract abi 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48

# Get verified source code
ethcli contract source 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48

# Lookup function selector
ethcli sig fn 0xa9059cbb

# Get gas prices
ethcli gas oracle

# Get token info
ethcli token info 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48

# List available RPC endpoints
ethcli endpoints list

# Test a specific RPC endpoint
ethcli endpoints test https://eth.llamarpc.com
```

## Environment Variables

- `ETHERSCAN_API_KEY`: Etherscan API key (optional, increases rate limit)

## Release Process

**Automated with release-please:**
- Use [Conventional Commits](https://www.conventionalcommits.org/) in commit messages
- `feat:` - triggers minor version bump
- `fix:` - triggers patch version bump
- `feat!:` or `BREAKING CHANGE:` - triggers major version bump
- Release-please creates a PR with version bump and CHANGELOG
- Merging the PR triggers binary builds for all platforms

**Manual release (alternative):**
```bash
git tag v0.x.x
git push origin v0.x.x
```

## Pre-commit Hooks

Installed hooks run automatically on commit:
- `cargo fmt --check` - formatting check
- `cargo clippy -- -D warnings` - lint check

## Architecture Notes

- Uses 22 pre-configured free archive RPC endpoints with known limits
- Parallel requests with automatic failover on errors
- Health tracking disables failing endpoints temporarily
- Checkpoint system allows resuming interrupted fetches
- Etherscan API v2 for ABI fetching (works without API key, rate limited)
- foundry-block-explorers for account, contract, token, and gas commands
