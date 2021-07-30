use std::ops::Deref;
use std::{thread, time};

use lightning::chain;
use lightning_block_sync::poll::{ChainTip, Poll, ValidatedBlockHeader};
use lightning_block_sync::BlockSourceError;
use lightning_block_sync::{Cache, SpvClient};

pub struct ChainMonitor<'a, P, C, L>
where
    P: Poll,
    C: Cache,
    L: Deref,
    L::Target: chain::Listen,
{
    spv_client: SpvClient<'a, P, C, L>,
    last_known_block_header: ValidatedBlockHeader,
    polling_delta: time::Duration,
}

impl<'a, P, C, L> ChainMonitor<'a, P, C, L>
where
    P: Poll,
    C: Cache,
    L: Deref,
    L::Target: chain::Listen,
{
    pub async fn new(
        spv_client: SpvClient<'a, P, C, L>,
        last_known_block_header: ValidatedBlockHeader,
        polling_delta_sec: u64,
    ) -> ChainMonitor<'a, P, C, L> {
        ChainMonitor {
            spv_client,
            last_known_block_header,
            polling_delta: time::Duration::from_secs(polling_delta_sec),
        }
    }

    // TODO: Most of the logic here may be redundant. Leave it for now in case we'd like to log stuff
    pub async fn monitor_chain(&mut self) -> Result<(), BlockSourceError> {
        loop {
            match self.spv_client.poll_best_tip().await {
                Ok((chain_tip, _)) => match chain_tip {
                    ChainTip::Common => {
                        println!("No new tip found");
                    }
                    ChainTip::Better(new_best) => {
                        println!("New tip found: {}", new_best.header.block_hash());
                        self.last_known_block_header = new_best;
                    }

                    ChainTip::Worse(worse) => {
                        // This would happen both if a block has less chainwork than the previous one, or if it has the same chainwork
                        // but it forks from the parent. The former should not matter, given a reorg will be detected by the subscribers
                        // once we reach the same work*. The latter is a valid case and should be passed along.
                        // The only caveat here would be that the caches of the subscribers are smaller than the reorg, which should
                        // never happen under reasonable assumptions (e.g. cache of 6 blocks).
                        println!("Worse tip found: {:?}", worse);

                        if worse.chainwork == self.last_known_block_header.chainwork {
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
