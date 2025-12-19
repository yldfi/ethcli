# eth-log-fetcher

Fast Ethereum historical log fetcher with parallel RPC requests across multiple free archive nodes.

## Features

- **22 pre-configured free archive RPC endpoints** with known limits
- **Parallel requests** with automatic failover and health tracking
- **Multi-chain support**: Ethereum, Polygon, Arbitrum, Optimism, Base, BSC, Avalanche
- **Auto-fetch ABI** from Etherscan API v2 (works without API key)
- **Multiple output formats**: JSON, NDJSON, CSV, SQLite
- **Checkpoint/resume** for large fetches
- **Proxy support** with rotation

## Installation

### Download Binary

```bash
# macOS (Apple Silicon)
curl -sL https://github.com/michaeldim/eth-log-fetcher/releases/latest/download/eth-log-fetch-macos-aarch64.tar.gz | tar xz
sudo mv eth-log-fetch /usr/local/bin/

# macOS (Intel)
curl -sL https://github.com/michaeldim/eth-log-fetcher/releases/latest/download/eth-log-fetch-macos-x86_64.tar.gz | tar xz
sudo mv eth-log-fetch /usr/local/bin/

# Linux (x86_64)
curl -sL https://github.com/michaeldim/eth-log-fetcher/releases/latest/download/eth-log-fetch-linux-x86_64.tar.gz | tar xz
sudo mv eth-log-fetch /usr/local/bin/

# Linux (ARM64)
curl -sL https://github.com/michaeldim/eth-log-fetcher/releases/latest/download/eth-log-fetch-linux-aarch64.tar.gz | tar xz
sudo mv eth-log-fetch /usr/local/bin/
```

### Install with Cargo

```bash
cargo install --git https://github.com/michaeldim/eth-log-fetcher.git
```

### Build from Source

```bash
git clone https://github.com/michaeldim/eth-log-fetcher.git
cd eth-log-fetcher
cargo build --release
# Binary at ./target/release/eth-log-fetch
```

## CLI Usage

### Basic Examples

```bash
# Fetch Transfer events from USDC
eth-log-fetch -c 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 \
  -e "Transfer(address,address,uint256)" \
  -f 18000000 -t 18100000 -o transfers.json

# Fetch all events (auto-fetches ABI from Etherscan)
eth-log-fetch -c 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 \
  -f 18000000 -t latest --format csv -o events.csv

# Output to SQLite database
eth-log-fetch -c 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 \
  -f 18000000 -t 18100000 --format sqlite -o events.db

# High concurrency with resume support
eth-log-fetch -c 0x... -f 0 -t latest -n 20 --resume

# Raw logs without ABI decoding
eth-log-fetch -c 0x... -f 0 -t latest --raw
```

### DEX Swap Events

```bash
# Uniswap V3 swaps
eth-log-fetch -c 0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640 \
  -e "Swap(address,address,int256,int256,uint160,uint128,int24)" \
  -f 21500000 -t latest

# Curve 3pool swaps
eth-log-fetch -c 0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7 \
  -e "TokenExchange(address,int128,uint256,int128,uint256)" \
  -f 21500000 -t latest

# Balancer V2 swaps
eth-log-fetch -c 0xBA12222222228d8Ba445958a75a0704d566BF2C8 \
  -e "Swap(bytes32,address,address,uint256,uint256)" \
  -f 21500000 -t latest
```

### Endpoint Management

```bash
# List all configured RPC endpoints
eth-log-fetch endpoints list

# Test a specific endpoint
eth-log-fetch endpoints test https://eth.llamarpc.com
```

### Options

```
-c, --contract <ADDRESS>     Contract address to fetch logs from
-e, --event <SIGNATURE>      Event signature (e.g. "Transfer(address,address,uint256)")
    --abi <FILE>             Path to ABI JSON file
-f, --from-block <BLOCK>     Start block number [default: 0]
-t, --to-block <BLOCK>       End block number or "latest" [default: latest]
-o, --output <FILE>          Output file path (stdout if not specified)
    --format <FORMAT>        Output format: json, ndjson, csv, sqlite [default: json]
-n, --concurrency <N>        Number of parallel requests [default: 5]
    --resume                 Resume from checkpoint if available
    --raw                    Fetch raw logs without decoding
    --chain <CHAIN>          Chain: ethereum, polygon, arbitrum, optimism, base, bsc, avalanche
-q, --quiet                  Suppress progress output
-v, --verbose                Increase verbosity (-v, -vv, -vvv)
```

## Library Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
eth-log-fetcher = { git = "https://github.com/michaeldim/eth-log-fetcher.git" }
tokio = { version = "1", features = ["full"] }
```

### Basic Example

```rust
use eth_log_fetcher::{Config, LogFetcher, BlockNumber, Chain};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::builder()
        .chain(Chain::Ethereum)
        .contract("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
        .event("Transfer(address,address,uint256)")
        .from_block(18_000_000)
        .to_block(BlockNumber::Number(18_100_000))
        .concurrency(10)
        .build()?;

    let fetcher = LogFetcher::new(config).await?;
    let result = fetcher.fetch_all().await?;

    println!("Fetched {} logs", result.len());

    // Access decoded logs
    if let eth_log_fetcher::FetchResult::Decoded(logs) = &result {
        for log in logs.iter().take(5) {
            println!(
                "Block {}: {} -> {:?}",
                log.block_number,
                log.event_name,
                log.params
            );
        }
    }

    Ok(())
}
```

### With Progress Callback

```rust
let fetcher = LogFetcher::new(config).await?;
let fetcher = fetcher.with_progress(|progress| {
    println!(
        "{}% complete - {} logs fetched ({:.0} blocks/sec)",
        progress.percent,
        progress.logs_fetched,
        progress.blocks_per_second
    );
});

let result = fetcher.fetch_all().await?;
```

### Write to File

```rust
use eth_log_fetcher::{create_writer, OutputFormat};
use std::path::Path;

let result = fetcher.fetch_all().await?;

// Write as JSON
let mut writer = create_writer(OutputFormat::Json, Some(Path::new("output.json")))?;
writer.write_logs(&result)?;
writer.finalize()?;
```

### Shell Out from Node.js/TypeScript

```typescript
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

async function getSwapLogs(contract: string, fromBlock: number, toBlock: number) {
  const { stdout } = await execAsync(
    `eth-log-fetch -c ${contract} \
      -e "Swap(address,address,int256,int256,uint160,uint128,int24)" \
      -f ${fromBlock} -t ${toBlock} -q`
  );
  return JSON.parse(stdout);
}

const swaps = await getSwapLogs('0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640', 21500000, 21500100);
console.log(`Found ${swaps.length} swaps`);
```

## Common Event Signatures

| Protocol | Event | Signature |
|----------|-------|-----------|
| ERC20 | Transfer | `Transfer(address,address,uint256)` |
| ERC20 | Approval | `Approval(address,address,uint256)` |
| Uniswap V2 | Swap | `Swap(address,uint256,uint256,uint256,uint256,address)` |
| Uniswap V3 | Swap | `Swap(address,address,int256,int256,uint160,uint128,int24)` |
| Curve | TokenExchange | `TokenExchange(address,int128,uint256,int128,uint256)` |
| Balancer V2 | Swap | `Swap(bytes32,address,address,uint256,uint256)` |
| AAVE V3 | Supply | `Supply(address,address,address,uint256,uint16)` |
| AAVE V3 | Borrow | `Borrow(address,address,address,uint256,uint8,uint256,uint16)` |

## Configuration

Config file location: `~/.config/eth-log-fetcher/config.toml`

```toml
# Set Etherscan API key (optional, increases rate limit)
etherscan_api_key = "YOUR_KEY"

# Add custom endpoints
[[endpoints]]
url = "https://my-private-node.example.com"
max_block_range = 10000000
max_logs = 1000000
priority = 100

# Disable specific endpoints
[disabled_endpoints]
urls = ["https://eth.drpc.org"]
```

Or set via CLI:
```bash
eth-log-fetch config set-etherscan-key YOUR_KEY
```

## License

MIT
