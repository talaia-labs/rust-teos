use std::cell::RefCell;
use std::ops::Deref;
use std::rc::Rc;
use std::sync::Arc;

use bitcoin::network::constants::Network;
use bitcoin::secp256k1::key::ONE_KEY;
use bitcoin::secp256k1::SecretKey;
use lightning_block_sync::init::validate_best_block_header;
use lightning_block_sync::poll::ChainPoller;
use lightning_block_sync::{SpvClient, UnboundedCache};

use rusty_teos::bitcoin_cli::BitcoindClient;
use rusty_teos::chain_monitor::ChainMonitor;
use rusty_teos::gatekeeper::Gatekeeper;
use rusty_teos::responder::Responder;
use rusty_teos::watcher::Watcher;

#[tokio::main]
pub async fn main() {
    let host = String::from("localhost");
    let port = 18443;
    let user = String::from("user");
    let password = String::from("passwd");

    const TOWER_SK: SecretKey = ONE_KEY;
    const SLOTS: u32 = 21;
    const DURATION: u32 = 500;
    const EXPIRY_DELTA: u32 = 42;

    // // Initialize our bitcoind client.
    let bitcoin_cli =
        match BitcoindClient::new(host.clone(), port.clone(), user.clone(), password.clone()).await
        {
            Ok(client) => Arc::new(client),
            Err(e) => {
                println!("Failed to connect to bitcoind client: {}", e);
                return;
            }
        };

    let mut derefed = bitcoin_cli.deref();
    let tip = validate_best_block_header(&mut derefed).await.unwrap();

    let gatekeeper = Rc::new(RefCell::new(Gatekeeper::new(
        tip,
        SLOTS,
        DURATION,
        EXPIRY_DELTA,
    )));
    let responder = Responder::new(gatekeeper.clone(), tip);
    let watcher = Watcher::new(gatekeeper.clone(), responder, Vec::new(), tip, TOWER_SK).await;

    let poller = ChainPoller::new(&mut derefed, Network::Bitcoin);
    let cache = &mut UnboundedCache::new();

    //  FIXME: Not completely sure if borrowing the gatekeeper here may make this potentially panic
    let listener = &(&watcher, gatekeeper.borrow_mut());
    let spv_client = SpvClient::new(tip, poller, cache, listener);

    let mut chain_monitor = ChainMonitor::new(spv_client, tip, 1).await;
    chain_monitor.monitor_chain().await.unwrap();
}
