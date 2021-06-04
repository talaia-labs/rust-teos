use crate::bitcoin_cli::BitcoindClient;
use std::sync::Arc;
use std::{thread, time};
use tokio::sync::broadcast::Sender;

pub struct ChainMonitor {
    bitcoin_cli: Arc<BitcoindClient>,
    polling_delta: time::Duration,
    tx: Sender<bitcoin::BlockHash>,
}

impl ChainMonitor {
    pub async fn new(
        bitcoin_cli: Arc<BitcoindClient>,
        polling_delta_sec: u64,
        tx: Sender<bitcoin::BlockHash>,
    ) -> Self {
        ChainMonitor {
            bitcoin_cli,
            polling_delta: time::Duration::from_secs(polling_delta_sec),
            tx,
        }
    }
    pub async fn monitor_chain(self) -> Result<(), std::io::Error> {
        match self.bitcoin_cli.get_best_block_hash().await {
            Ok(mut prev_tip) => loop {
                match self.bitcoin_cli.get_best_block_hash().await {
                    Ok(current_tip) => {
                        if current_tip == prev_tip {
                            println!("No new tip found");
                        } else {
                            println!("New tip found: {}", current_tip);
                            self.tx.send(current_tip).unwrap();
                            prev_tip = current_tip;
                        }
                    }
                    Err(_) => println!("Connection lost with bitcoind"),
                };

                thread::sleep(self.polling_delta);
            },
            Err(e) => Err(e),
        }
    }
}
