use std::cell::RefCell;
use std::ops::Deref;
use std::rc::Rc;
use std::sync::Arc;
use tokio::sync::broadcast;

use bitcoin::network::constants::Network;
use bitcoin::secp256k1::key::ONE_KEY;
use bitcoin::secp256k1::SecretKey;
use lightning_block_sync::init::validate_best_block_header;
use lightning_block_sync::poll::ChainPoller;

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

    // Create a communication  channel for message passing
    let (tx, rx) = broadcast::channel(100);
    let rx2 = tx.subscribe();
    let rx3 = tx.subscribe();

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

    let cloned_cli = Arc::clone(&bitcoin_cli);

    let mut derefed = bitcoin_cli.deref();
    let tip = validate_best_block_header(&mut derefed).await.unwrap();
    let poller = Rc::new(RefCell::new(ChainPoller::new(
        &mut derefed,
        Network::Bitcoin,
    )));

    let gatekeeper = Rc::new(RefCell::new(Gatekeeper::new(
        tip,
        rx,
        SLOTS,
        DURATION,
        EXPIRY_DELTA,
    )));

    let responder = Responder::new(rx2, poller.clone(), gatekeeper.clone(), tip);
    let mut watcher = Watcher::new(rx3, poller.clone(), gatekeeper, responder, tip, TOWER_SK).await;

    tokio::spawn(async move {
        let mut derefed = cloned_cli.deref();
        let poller = ChainPoller::new(&mut derefed, Network::Bitcoin);
        let mut chain_monitor = ChainMonitor::new(poller, tip, 1, tx).await;
        chain_monitor.monitor_chain().await.unwrap();
    });

    watcher.do_watch().await;
}
