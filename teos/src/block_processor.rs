use crate::bitcoin_cli::BitcoindClient;
use bitcoin::Network;
use lightning_block_sync::poll::ChainPoller;
use lightning_block_sync::poll::ValidatedBlockHeader;
use lightning_block_sync::poll::{Poll, ValidatedBlock};
use lightning_block_sync::BlockSourceError;
use std::ops::Deref;
use std::sync::Arc;

#[derive(Clone)]
pub struct BlockProcessor {
    bitcoin_cli: Arc<BitcoindClient>,
}

// FIXME: This should be implemented so, if bitcoind is unreachable, it either returns an error or blocks and retries until
// bitcoind is reachable again. There could be a flag on the queries for that.
// I've been looking into sync primitives similar to Event for Python but still haven't found what to use.
// For now, it'll have no retry, so methods will either return what's expected or fail
impl BlockProcessor {
    pub async fn new(bitcoin_cli: Arc<BitcoindClient>) -> Self {
        BlockProcessor { bitcoin_cli }
    }

    pub async fn get_block(
        &self,
        block_header: &ValidatedBlockHeader,
    ) -> Result<ValidatedBlock, BlockSourceError> {
        let mut derefed = self.bitcoin_cli.deref();
        let mut poller = ChainPoller::new(&mut derefed, Network::Bitcoin);
        poller.fetch_block(block_header).await
    }

    pub async fn get_block_count(&self) -> u64 {
        self.bitcoin_cli.get_block_count().await.unwrap()
    }
}