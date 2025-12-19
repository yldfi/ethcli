# eth-log-fetcher

Fast Ethereum historical log fetcher with parallel RPC requests.

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

- Debug: `./target/debug/eth-log-fetch`
- Release: `./target/release/eth-log-fetch`

## Project Structure

```
src/
├── main.rs           # CLI entry point (clap)
├── lib.rs            # Library exports
├── error.rs          # Error types (thiserror)
├── fetcher.rs        # Main LogFetcher coordinator
├── checkpoint.rs     # Resume/checkpoint system
├── proxy.rs          # Proxy rotation support
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
└── output/
    ├── mod.rs        # OutputWriter trait
    ├── json.rs       # JSON/NDJSON output
    ├── csv.rs        # CSV output
    └── sqlite.rs     # SQLite output
```

## Key Dependencies

- **alloy 1.0**: Ethereum provider, types, ABI decoding
- **tokio**: Async runtime
- **clap**: CLI parsing
- **serde/serde_json**: Serialization
- **rusqlite**: SQLite output
- **indicatif**: Progress bars

## Testing Locally

```bash
# Fetch USDC Transfer events (small range)
./target/release/eth-log-fetch \
  -c 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 \
  -e "Transfer(address,address,uint256)" \
  -f 21500000 -t 21500010

# List available RPC endpoints
./target/release/eth-log-fetch endpoints list

# Test a specific RPC endpoint
./target/release/eth-log-fetch endpoints test https://eth.llamarpc.com
```

## Release Process

1. Update version in `Cargo.toml`
2. Commit changes
3. Tag and push:
   ```bash
   git tag v0.x.x
   git push origin v0.x.x
   ```
4. GitHub Actions builds binaries for Linux/macOS/Windows

## Architecture Notes

- Uses 22 pre-configured free archive RPC endpoints with known limits
- Parallel requests with automatic failover on errors
- Health tracking disables failing endpoints temporarily
- Checkpoint system allows resuming interrupted fetches
- Etherscan API v2 for ABI fetching (works without API key, rate limited)
