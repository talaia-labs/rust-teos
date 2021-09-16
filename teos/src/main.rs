use simple_logger::init_with_level;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use bitcoin::network::constants::Network;
use bitcoin::secp256k1::key::ONE_KEY;
use bitcoin::secp256k1::SecretKey;
use bitcoincore_rpc::{Auth, Client};
use lightning_block_sync::init::validate_best_block_header;
use lightning_block_sync::poll::{ChainPoller, Poll, ValidatedBlock, ValidatedBlockHeader};
use lightning_block_sync::{BlockSource, SpvClient, UnboundedCache};

use rusty_teos::bitcoin_cli::BitcoindClient;
use rusty_teos::carrier::Carrier;
use rusty_teos::chain_monitor::ChainMonitor;
use rusty_teos::gatekeeper::Gatekeeper;
use rusty_teos::responder::Responder;
use rusty_teos::watcher::Watcher;

async fn get_last_n_blocks<B, T>(
    poller: &mut ChainPoller<B, T>,
    tip: ValidatedBlockHeader,
    n: usize,
) -> Vec<ValidatedBlock>
where
    B: DerefMut<Target = T> + Sized + Send + Sync,
    T: BlockSource,
{
    let mut last_n_blocks = Vec::new();
    let mut last_known_block = tip;
    for _ in 0..n {
        let block = poller.fetch_block(&last_known_block).await.unwrap();
        last_known_block = poller
            .look_up_previous_header(&last_known_block)
            .await
            .unwrap();
        last_n_blocks.push(block);
    }

    last_n_blocks
}

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

    // Init with loglevel=Error for now, make it configurable later on.
    init_with_level(log::Level::Error).unwrap();

    // // Initialize our bitcoind client.
    let bitcoin_cli =
        match BitcoindClient::new(host.clone(), port.clone(), user.clone(), password.clone()).await
        {
            Ok(client) => Arc::new(client),
            Err(e) => {
                log::error!("Failed to connect to bitcoind client: {}", e);
                return;
            }
        };

    // FIXME: Temporary. We're using bitcoin_core_rpc and rust-lightning's rpc until they both get merged
    // https://github.com/rust-bitcoin/rust-bitcoincore-rpc/issues/166
    let rpc = Arc::new(
        Client::new(
            "http://localhost:18443".to_string(),
            Auth::UserPass("user".to_string(), "passwd".to_string()),
        )
        .unwrap(),
    );

    let mut derefed = bitcoin_cli.deref();
    let tip = validate_best_block_header(&mut derefed).await.unwrap();
    let mut poller = ChainPoller::new(&mut derefed, Network::Bitcoin);
    let cache = &mut UnboundedCache::new();
    let last_n_blocks = get_last_n_blocks(&mut poller, tip, 6).await;

    let gatekeeper = Gatekeeper::new(tip, SLOTS, DURATION, EXPIRY_DELTA);
    let carrier = Carrier::new(rpc.clone());
    let responder = Responder::new(carrier, &gatekeeper, tip);
    let watcher = Watcher::new(&gatekeeper, responder, last_n_blocks, tip, TOWER_SK).await;

    let listener = &(&watcher, &gatekeeper);
    let spv_client = SpvClient::new(tip, poller, cache, listener);

    let mut chain_monitor = ChainMonitor::new(spv_client, tip, 1).await;
    chain_monitor.monitor_chain().await.unwrap();
}
