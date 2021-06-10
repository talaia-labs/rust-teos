use crate::bitcoin_cli::BitcoindClient;
use bitcoin::network::constants::Network;
use lightning_block_sync::init::validate_best_block_header;
use lightning_block_sync::poll::{ChainPoller, ChainTip, Poll, ValidatedBlockHeader};
use lightning_block_sync::BlockSourceError;
use std::ops::Deref;
use std::sync::Arc;
use std::{thread, time};
use tokio::sync::broadcast::Sender;

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
                        self.tx.send(new_best).unwrap();
                    }

                    ChainTip::Worse(x) => {
                        // I don't think this is actually possible using bitcoind as block source, but if so we can at least log it
                        println!("Worse tip found: {:?}", x);
                    }
                },
                Err(_) => println!("Connection lost with bitcoind"),
            };

            thread::sleep(self.polling_delta);
        }
    }
}
