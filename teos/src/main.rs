use simple_logger::init_with_level;
use std::fs;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex};
use structopt::StructOpt;

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
use rusty_teos::config::{Config, Opt};
use rusty_teos::dbm::DBM;
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
    let opt = Opt::from_args();

    // Create data dir if it does not exist
    fs::create_dir_all(opt.data_dir_absolute_path()).unwrap_or_else(|e| {
        eprint!("Cannot create data dir: {:?}", e);
        std::process::exit(-1);
    });

    // Load conf (from file or defaults) and patch it with the command line parameters received (if any)
    let mut conf = Config::from_file(opt.data_dir_absolute_path().join("teos.toml"));
    conf.patch_with_options(opt);

    if conf.debug {
        init_with_level(log::Level::Debug).unwrap()
    } else {
        init_with_level(log::Level::Info).unwrap()
    }

    // FIXME: Load/ Create a new private key (use the db for this or create a key file?)
    const TOWER_SK: SecretKey = ONE_KEY;

    // Initialize our bitcoind client
    let bitcoin_cli = match BitcoindClient::new(
        conf.btc_rpc_connect.clone(),
        conf.btc_rpc_port,
        conf.btc_rpc_user.clone(),
        conf.btc_rpc_password.clone(),
    )
    .await
    {
        Ok(client) => Arc::new(client),
        Err(e) => {
            log::error!("Failed to connect to bitcoind client: {}", e);
            return;
        }
    };

    // FIXME: Temporary. We're using bitcoin_core_rpc and rust-lightning's rpc until they both get merged
    // https://github.com/rust-bitcoin/rust-bitcoincore-rpc/issues/166
    let schema = if !conf.btc_rpc_connect.starts_with("http") {
        "http://"
    } else {
        ""
    };
    let rpc = Arc::new(
        Client::new(
            format!("{}{}:{}", schema, conf.btc_rpc_connect, conf.btc_rpc_port).to_string(),
            Auth::UserPass(conf.btc_rpc_user, conf.btc_rpc_password),
        )
        .unwrap(),
    );

    let mut derefed = bitcoin_cli.deref();
    let tip = validate_best_block_header(&mut derefed).await.unwrap();
    let mut poller = ChainPoller::new(&mut derefed, Network::Bitcoin);
    let cache = &mut UnboundedCache::new();
    let last_n_blocks = get_last_n_blocks(&mut poller, tip, 6).await;

    let dbm = Arc::new(Mutex::new(DBM::new("teos_db.sql3").unwrap()));

    let gatekeeper = Gatekeeper::new(
        tip,
        conf.subscription_slots,
        conf.subscription_duration,
        conf.expiry_delta,
        dbm.clone(),
    );
    let carrier = Carrier::new(rpc.clone());
    let responder = Responder::new(carrier, &gatekeeper, dbm.clone(), tip);
    let watcher = Watcher::new(
        &gatekeeper,
        &responder,
        last_n_blocks,
        tip,
        TOWER_SK,
        dbm.clone(),
    )
    .await;

    let listener = &(&watcher, &(&responder, &gatekeeper));
    let spv_client = SpvClient::new(tip, poller, cache, listener);

    // DISCUSS: the CM may not be necessary since it's only being used to log stuff. Doing spv_client.poll_best_tip().await will
    // have the same functionality. Consider whether to get rid of it of to massively simplify it.
    let mut chain_monitor = ChainMonitor::new(spv_client, tip, 1).await;
    chain_monitor.monitor_chain().await.unwrap();
}
