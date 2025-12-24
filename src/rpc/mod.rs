//! RPC endpoint management and parallel request handling

mod endpoint;
mod health;
mod optimizer;
mod pool;

pub use endpoint::Endpoint;
pub use health::{EndpointHealth, HealthTracker};
pub use optimizer::{optimize_endpoint, test_connectivity, OptimizationResult};
pub use pool::RpcPool;
