//! The Eye of Satoshi - Lightning watchtower.
//!
//! A watchtower implementation written in Rust.

// FIXME: This is a temporary fix. See https://github.com/tokio-rs/prost/issues/661
#[allow(clippy::derive_partial_eq_without_eq)]
pub mod protos {
    tonic::include_proto!("teos.v2");
}
pub mod api;
pub mod async_listener;
pub mod bitcoin_cli;
pub mod carrier;
pub mod chain_monitor;
pub mod cli_config;
pub mod config;
pub mod dbm;
#[doc(hidden)]
mod errors;
mod extended_appointment;
pub mod gatekeeper;
pub mod responder;
#[doc(hidden)]
mod rpc_errors;
pub mod tls;
mod tx_index;
pub mod watcher;

#[cfg(test)]
mod test_utils;
