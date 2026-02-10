//! Stateless Block Verifier core library.

#[macro_use]
extern crate sbv_helpers;

/// Witness type
pub mod witness;
pub use witness::BlockWitness;
/// codec for BlockWitness
pub mod codec;

mod database;
mod executor;
mod utils;
mod witness_data;
pub use executor::EvmExecutor;

pub mod verifier;

#[cfg(test)]
#[ctor::ctor]
fn init() {
    use tracing_subscriber::EnvFilter;
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
}
