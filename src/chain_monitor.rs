use crate::bitcoin_cli::BitcoindClient;
use futures::executor::block_on;
use std::sync::Arc;
use std::{thread, time};

pub struct ChainMonitor {
    bitcoin_cli: Arc<BitcoindClient>,
    polling_delta: time::Duration,
}

impl ChainMonitor {
    pub async fn new(bitcoin_cli: Arc<BitcoindClient>, polling_delta_sec: u64) -> Self {
        ChainMonitor {
            bitcoin_cli,
            polling_delta: time::Duration::from_secs(polling_delta_sec),
        }
    }
    pub async fn monitor_chain(self) {
        let mut prev_tip = block_on(self.bitcoin_cli.get_best_block_hash()).unwrap();

        loop {
            match block_on(self.bitcoin_cli.get_best_block_hash()) {
                Ok(current_tip) => {
                    if current_tip == prev_tip {
                        println!("No new tip found");
                    } else {
                        println!("New tip found: {}", current_tip);
                        prev_tip = current_tip;
                    }
                }
                Err(_) => println!("Connection lost with bitcoind"),
            };

            thread::sleep(self.polling_delta);
        }
    }
}
