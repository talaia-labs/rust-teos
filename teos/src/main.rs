use rusty_teos::bitcoin_cli::BitcoindClient;
use rusty_teos::chain_monitor::ChainMonitor;
use std::sync::Arc;
use tokio::sync::broadcast;

#[tokio::main]
pub async fn main() {
    let host = String::from("localhost");
    let port = 18443;
    let user = String::from("user");
    let password = String::from("passwd");

    // Create a communication  channel for message passing
    let (tx, mut rx) = broadcast::channel(100);

    let mut rx2 = tx.subscribe();

    tokio::spawn(async move {
        loop {
            let block = rx.recv().await.unwrap();
            println!("r1: received = {:?}", block);
        }
    });

    tokio::spawn(async move {
        loop {
            let block = rx2.recv().await.unwrap();
            println!("r2: received = {:?}", block);
        }
    });

    // Initialize our bitcoind client.
    let bitcoin_cli = match BitcoindClient::new(host, port, user, password).await {
        Ok(client) => Arc::new(client),
        Err(e) => {
            println!("Failed to connect to bitcoind client: {}", e);
            return;
        }
    };

    let chain_monitor = ChainMonitor::new(bitcoin_cli, 1, tx).await;
    chain_monitor.monitor_chain().await.unwrap();
}
