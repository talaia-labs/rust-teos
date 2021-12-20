use simple_logger::init_with_level;
use std::fs;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex};
use structopt::StructOpt;

use bitcoin::network::constants::Network;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
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
use teos_common::cryptography::get_random_keypair;

async fn get_last_n_blocks<B, T>(
    poller: &mut ChainPoller<B, T>,
    mut last_known_block: ValidatedBlockHeader,
    n: usize,
) -> Vec<ValidatedBlock>
where
    B: DerefMut<Target = T> + Sized + Send + Sync,
    T: BlockSource,
{
    let mut last_n_blocks = Vec::new();
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

fn create_new_tower_keypair(db: &DBM) -> (SecretKey, PublicKey) {
    let (sk, pk) = get_random_keypair();
    db.store_tower_key(&sk).unwrap();
    (sk, pk)
}

#[tokio::main]
pub async fn main() {
    let opt = Opt::from_args();
    let path = opt.data_dir_absolute_path();

    // Create data dir if it does not exist
    fs::create_dir_all(&path).unwrap_or_else(|e| {
        eprint!("Cannot create data dir: {:?}\n", e);
        std::process::exit(1);
    });

    // Load conf (from file or defaults) and patch it with the command line parameters received (if any)
    let mut conf = Config::from_file(path.join("teos.toml"));
    conf.patch_with_options(opt);
    conf.verify().unwrap_or_else(|e| {
        eprint!("{}\n", e);
        std::process::exit(1);
    });

    // Set log level
    if conf.debug {
        init_with_level(log::Level::Debug).unwrap()
    } else {
        init_with_level(log::Level::Info).unwrap()
    }

    let dbm = Arc::new(Mutex::new(DBM::new(path.join("teos_db.sql3")).unwrap()));

    // Load tower secret key or create a fresh one if none is found. If overwrite key is set, create a new
    // key straightaway
    let locked_db = dbm.lock().unwrap();

    let (tower_sk, tower_pk) = if conf.overwrite_key {
        log::info!("Overwriting tower keys");
        create_new_tower_keypair(&locked_db)
    } else {
        match locked_db.load_tower_key() {
            Ok(sk) => (sk, PublicKey::from_secret_key(&Secp256k1::new(), &sk)),
            Err(_) => {
                log::info!("Tower keys not found. Creating a fresh set");
                create_new_tower_keypair(&locked_db)
            }
        }
    };

    log::info!("tower_id = {}", tower_pk);

    // Initialize our bitcoind client
    let bitcoin_cli = match BitcoindClient::new(
        &conf.btc_rpc_connect,
        conf.btc_rpc_port,
        &conf.btc_rpc_user,
        &conf.btc_rpc_password,
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
            Auth::UserPass(conf.btc_rpc_user.clone(), conf.btc_rpc_password.clone()),
        )
        .unwrap(),
    );

    let mut derefed = bitcoin_cli.deref();
    let tip = validate_best_block_header(&mut derefed).await.unwrap();
    let mut poller = ChainPoller::new(&mut derefed, Network::Bitcoin);
    let cache = &mut UnboundedCache::new();
    let last_n_blocks = get_last_n_blocks(&mut poller, tip, 6).await;

    let gatekeeper = Arc::new(Gatekeeper::new(
        tip,
        conf.subscription_slots,
        conf.subscription_duration,
        conf.expiry_delta,
        dbm.clone(),
    ));
    let carrier = Carrier::new(rpc.clone());
    let responder = Arc::new(Responder::new(
        carrier,
        gatekeeper.clone(),
        dbm.clone(),
        tip,
    ));
    let watcher = Arc::new(
        Watcher::new(
            gatekeeper.clone(),
            responder.clone(),
            last_n_blocks,
            tip,
            tower_sk,
            dbm.clone(),
        )
        .await,
    );

    let listener = &(watcher, &(responder, gatekeeper));
    let spv_client = SpvClient::new(tip, poller, cache, listener);

    // DISCUSS: the CM may not be necessary since it's only being used to log stuff. Doing spv_client.poll_best_tip().await will
    // have the same functionality. Consider whether to get rid of it of to massively simplify it.
    let mut chain_monitor = ChainMonitor::new(spv_client, tip, 60).await;
    chain_monitor.monitor_chain().await.unwrap();
}
