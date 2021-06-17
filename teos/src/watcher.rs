use bitcoin::hash_types::BlockHash;
use bitcoin::Transaction;
use lightning_block_sync::poll::{ChainPoller, Poll, ValidatedBlockHeader};
use lightning_block_sync::BlockSource;
use std::collections::HashMap;
use std::fmt;
use std::ops::DerefMut;
use teos_common::appointment::Locator;

struct LocatorCache<B: DerefMut<Target = T> + Sized, T: BlockSource> {
    poller: ChainPoller<B, T>,
    cache: HashMap<Locator, Transaction>,
    blocks: Vec<BlockHash>,
    tx_in_block: HashMap<BlockHash, Vec<Locator>>,
    size: u8,
}

impl<B, T> fmt::Display for LocatorCache<B, T>
where
    B: DerefMut<Target = T> + Sized + Send + Sync,
    T: BlockSource,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "cache: {:?}\n\nblocks: {:?}\n\ntx_in_block: {:?}\n\nsize: {}",
            self.cache, self.blocks, self.tx_in_block, self.size
        )
    }
}

impl<B, T> LocatorCache<B, T>
where
    B: DerefMut<Target = T> + Sized + Send + Sync,
    T: BlockSource,
{
    async fn new(
        last_known_block_header: ValidatedBlockHeader,
        cache_size: u8,
        mut poller: ChainPoller<B, T>,
    ) -> LocatorCache<B, T> {
        let mut cache = HashMap::new();
        let mut blocks = Vec::new();
        let mut tx_in_block = HashMap::new();

        let mut target_block_header = last_known_block_header;
        for _ in 0..cache_size {
            let block = poller.fetch_block(&target_block_header).await.unwrap();
            let mut locators = Vec::new();
            for tx in block.txdata.clone() {
                let locator = Locator::new(tx.txid());
                cache.insert(locator.clone(), tx);
                locators.push(locator);
            }

            tx_in_block.insert(block.block_hash(), locators);
            blocks.push(block.block_hash());

            target_block_header = poller
                .look_up_previous_header(&target_block_header)
                .await
                .unwrap();
        }

        LocatorCache {
            poller: poller,
            cache,
            blocks,
            tx_in_block,
            size: cache_size,
        }
    }

    // FIXME: This needs mutex
    pub fn get_tx(&self, locator: &Locator) -> Option<&Transaction> {
        self.cache.get(locator)
    }

    // FIXME: This needs mutex
    pub fn update(
        &mut self,
        new_tip: ValidatedBlockHeader,
        locator_tx_map: HashMap<Locator, Transaction>,
    ) {
        self.blocks.push(new_tip.header.block_hash());

        let mut locators = Vec::new();
        for (locator, tx) in locator_tx_map {
            self.cache.insert(locator.clone(), tx);
            locators.push(locator);
        }

        self.tx_in_block
            .insert(new_tip.header.block_hash(), locators);

        println!("Block added to cache {}", new_tip.header.block_hash());

        if self.is_full() {
            self.remove_oldest_block();
        }
    }

    // FIXME: This needs mutex
    pub fn is_full(&self) -> bool {
        self.blocks.len() > self.size as usize
    }

    // FIXME: This needs mutex
    pub fn remove_oldest_block(&mut self) {
        let oldest = self.blocks.pop().unwrap();
        for locator in self.tx_in_block.remove(&oldest).unwrap() {
            self.cache.remove(&locator);
        }

        println!("Block removed from cache {}", oldest);
    }

    // FIXME: This needs mutex
    pub async fn fix(&mut self, new_tip: ValidatedBlockHeader) {
        let mut tmp_cache = HashMap::new();
        let mut tmp_blocks = Vec::new();
        let mut tmp_tx_in_block = HashMap::new();

        let mut target_block_header = new_tip;
        for _ in 0..self.size {
            match self
                .tx_in_block
                .get(&target_block_header.header.block_hash())
                .cloned()
            {
                Some(locators) => {
                    tmp_tx_in_block
                        .insert(target_block_header.header.block_hash(), locators.clone());
                    tmp_blocks.push(target_block_header.header.block_hash());
                    for locator in locators {
                        tmp_cache
                            .insert(locator.clone(), self.cache.get(&locator).unwrap().clone());
                    }
                }
                None => {
                    let block = self.poller.fetch_block(&target_block_header).await.unwrap();
                    let mut locators = Vec::new();
                    for tx in block.txdata.clone() {
                        let locator = Locator::new(tx.txid());
                        tmp_cache.insert(locator.clone(), tx);
                        locators.push(locator);
                    }

                    tmp_tx_in_block.insert(block.block_hash(), locators);
                    tmp_blocks.push(block.block_hash());
                }
            }

            target_block_header = self
                .poller
                .look_up_previous_header(&target_block_header)
                .await
                .unwrap();
        }

        self.cache = tmp_cache;
        self.tx_in_block = tmp_tx_in_block;
        self.blocks = tmp_blocks;
        self.blocks.reverse();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::network::constants::Network;
    use lightning_block_sync::test_utils::Blockchain;

    #[tokio::test]
    async fn test_cache() {
        let mut chain = Blockchain::default().with_height(10);
        let tip = chain.tip();
        let size = 6;

        let poller = ChainPoller::new(&mut chain, Network::Bitcoin);
        let cache = LocatorCache::new(tip, size, poller).await;

        assert_eq!(size, cache.size)
    }
}
