use rusty_teos::bitcoin_cli::BitcoindClient;
use rusty_teos::chain_monitor::ChainMonitor;
use std::sync::Arc;

#[tokio::main]
pub async fn main() {
    let host = String::from("localhost");
    let port = 18443;
    let user = String::from("user");
    let password = String::from("passwd");

    // Initialize our bitcoind client.
    let bitcoin_cli = match BitcoindClient::new(host, port, user, password).await {
        Ok(client) => Arc::new(client),
        Err(e) => {
            println!("Failed to connect to bitcoind client: {}", e);
            return;
        }
    };

    let chain_monitor = ChainMonitor::new(bitcoin_cli, 1).await;
    chain_monitor.monitor_chain().await;
}
