use std::ops::Deref;
use std::sync::Arc;
use std::{thread, time};
use tokio::sync::broadcast::Sender;

use bitcoin::network::constants::Network;
use lightning_block_sync::init::validate_best_block_header;
use lightning_block_sync::poll::{ChainPoller, ChainTip, Poll, ValidatedBlockHeader};
use lightning_block_sync::BlockSourceError;

use crate::bitcoin_cli::BitcoindClient;

pub struct ChainMonitor {
    bitcoin_cli: Arc<BitcoindClient>,
    polling_delta: time::Duration,
    tx: Sender<ValidatedBlockHeader>,
}

impl ChainMonitor {
    pub async fn new(
        bitcoin_cli: Arc<BitcoindClient>,
        polling_delta_sec: u64,
        tx: Sender<ValidatedBlockHeader>,
    ) -> Self {
        ChainMonitor {
            bitcoin_cli,
            polling_delta: time::Duration::from_secs(polling_delta_sec),
            tx,
        }
    }

    pub async fn monitor_chain(self) -> Result<(), BlockSourceError> {
        let mut derefed = self.bitcoin_cli.deref();
        let mut current_best = validate_best_block_header(&mut derefed).await.unwrap();
        let mut poller = ChainPoller::new(&mut derefed, Network::Bitcoin);

        loop {
            match poller.poll_chain_tip(current_best).await {
                Ok(chain_tip) => match chain_tip {
                    ChainTip::Common => {
                        println!("No new tip found");
                    }
                    ChainTip::Better(new_best) => {
                        println!("New tip found: {:?}", new_best);
                        current_best = new_best;
                        self.tx.send(current_best).unwrap();
                    }

                    ChainTip::Worse(worse) => {
                        // This would happen both if a block has less chainwork than the previous one, or if it has the same chainwork
                        // but it forks from the parent. The former should not matter, given a reorg will be detected by the subscribers
                        // once we reach the same work*. The latter is a valid case and should be passed along.
                        // The only caveat here would be that the caches of the subscribers are smaller than the reorg, which should
                        // never happen under reasonable assumptions (e.g. cache of 6 blocks).
                        println!("Worse tip found: {:?}", worse);

                        if worse.chainwork == current_best.chainwork {
                            current_best = worse;
                            self.tx.send(current_best).unwrap();
                        } else {
                            println!("New tip has less work than the previous one")
                        }
                    }
                },
                Err(_) => println!("Connection lost with bitcoind"),
            };

            thread::sleep(self.polling_delta);
        }
    }
}
