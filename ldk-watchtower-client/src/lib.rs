//! Watchtower client for ldk-server nodes.
//!
//! Polls an ldk-server node's `WatchtowerStateExport` endpoint and ships teos
//! (Eye of Satoshi) appointments for new signed justice transactions to a tower,
//! possibly over Tor. The ldk-server analogue of the CLN `watchtower-plugin`.

pub mod appointments;
pub mod config;
pub mod dbm;
pub mod ldk_client;
pub mod poller;
pub mod proto;
pub mod retrier;
pub mod tower;
