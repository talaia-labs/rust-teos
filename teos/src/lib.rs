//! The Eye of Satoshi
//!
//! A lightning watchtower implementation written in Rust.

pub mod bitcoin_cli;
pub mod carrier;
pub mod chain_monitor;
pub mod config;
pub mod dbm;
#[doc(hidden)]
mod errors;
mod extended_appointment;
pub mod gatekeeper;
pub mod responder;
#[doc(hidden)]
mod rpc_errors;
pub mod watcher;

#[cfg(test)]
mod test_utils;
