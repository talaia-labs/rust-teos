use std::ops::DerefMut;
use std::{thread, time};
use tokio::sync::broadcast::Sender;

use lightning_block_sync::poll::{ChainPoller, ChainTip, Poll, ValidatedBlockHeader};
use lightning_block_sync::BlockSource;
use lightning_block_sync::BlockSourceError;

pub struct ChainMonitor<B: DerefMut<Target = T> + Sized, T: BlockSource> {
    poller: ChainPoller<B, T>,
    last_known_block_header: ValidatedBlockHeader,
    polling_delta: time::Duration,
    tx: Sender<ValidatedBlockHeader>,
}

impl<B, T> ChainMonitor<B, T>
where
    B: DerefMut<Target = T> + Sized + Send + Sync,
    T: BlockSource,
{
    pub async fn new(
        poller: ChainPoller<B, T>,
        last_known_block_header: ValidatedBlockHeader,
        polling_delta_sec: u64,
        tx: Sender<ValidatedBlockHeader>,
    ) -> Self {
        ChainMonitor {
            poller,
            last_known_block_header,
            polling_delta: time::Duration::from_secs(polling_delta_sec),
            tx,
        }
    }

    pub async fn monitor_chain(&mut self) -> Result<(), BlockSourceError> {
        loop {
            match self
                .poller
                .poll_chain_tip(self.last_known_block_header)
                .await
            {
                Ok(chain_tip) => match chain_tip {
                    ChainTip::Common => {
                        println!("No new tip found");
                    }
                    ChainTip::Better(new_best) => {
                        println!("New tip found: {}", new_best.header.block_hash());
                        self.last_known_block_header = new_best;
                        self.tx.send(new_best).unwrap();
                    }

                    ChainTip::Worse(worse) => {
                        // This would happen both if a block has less chainwork than the previous one, or if it has the same chainwork
                        // but it forks from the parent. The former should not matter, given a reorg will be detected by the subscribers
                        // once we reach the same work*. The latter is a valid case and should be passed along.
                        // The only caveat here would be that the caches of the subscribers are smaller than the reorg, which should
                        // never happen under reasonable assumptions (e.g. cache of 6 blocks).
                        println!("Worse tip found: {:?}", worse);

                        if worse.chainwork == self.last_known_block_header.chainwork {
                            self.last_known_block_header = worse;
                            self.tx.send(worse).unwrap();
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
