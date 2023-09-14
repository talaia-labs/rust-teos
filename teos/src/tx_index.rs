use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::hash::Hash;

use bitcoin::hash_types::BlockHash;
use bitcoin::{BlockHeader, Transaction, Txid};
use lightning_block_sync::poll::ValidatedBlock;

use teos_common::appointment::Locator;

/// A trait implemented by types that can be used as key in a [TxIndex].
pub trait Key: Hash + Eq {
    fn from_txid(txid: Txid) -> Self;
}

impl Key for Txid {
    fn from_txid(txid: Txid) -> Self {
        txid
    }
}

impl Key for Locator {
    fn from_txid(txid: Txid) -> Self {
        Locator::new(txid)
    }
}

pub enum Type {
    Transaction,
    BlockHash,
}

pub enum Data {
    Transaction(Transaction),
    BlockHash(BlockHash),
}

impl fmt::Display for Data {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Data::Transaction(_) => write!(f, "Transaction"),
            Data::BlockHash(_) => write!(f, "BlockHash"),
        }
    }
}

/// A trait implemented by types that can be used as value in a [TxIndex].
pub trait Value {
    fn get_type() -> Type;
    fn from_data(d: Data) -> Self;
}

impl Value for BlockHash {
    fn get_type() -> Type {
        Type::BlockHash
    }

    fn from_data(d: Data) -> Self {
        match d {
            Data::BlockHash(b) => b,
            other => panic!("Cannot build a BlockHash from {}", other),
        }
    }
}

impl Value for Transaction {
    fn get_type() -> Type {
        Type::Transaction
    }

    fn from_data(d: Data) -> Self {
        match d {
            Data::Transaction(t) => t,
            other => panic!("Cannot build a BlockHash from {}", other),
        }
    }
}

/// Data structure used to index locators computed from parsed blocks.
///
/// Holds up to `size` blocks with their corresponding computed [Locator]s.
#[derive(Debug, PartialEq, Eq)]
pub struct TxIndex<K: Key, V: Value> {
    /// A [K]:[V] map.
    index: HashMap<K, V>,
    /// Vector of block hashes covered by the index.
    blocks: VecDeque<BlockHash>,
    /// Map of [BlockHash]:[Vec<K>]. Used to remove data from the index.
    tx_in_block: HashMap<BlockHash, Vec<K>>,
    /// The height of the last block included in the index.
    tip: u32,
    /// Maximum size of the index.
    size: usize,
}

impl<K, V> TxIndex<K, V>
where
    K: Key + Copy,
    V: Value + Clone,
    Self: Sized,
{
    pub fn new(last_n_blocks: &[ValidatedBlock], height: u32) -> Self {
        let size = last_n_blocks.len();
        let mut tx_index = Self {
            index: HashMap::new(),
            blocks: VecDeque::with_capacity(size),
            tx_in_block: HashMap::new(),
            tip: height,
            size,
        };

        for block in last_n_blocks.iter().rev() {
            if let Some(prev_block_hash) = tx_index.blocks.back() {
                if block.header.prev_blockhash != *prev_block_hash {
                    panic!("last_n_blocks contains unchained blocks");
                }
            };

            let map = block
                .txdata
                .iter()
                .map(|tx| {
                    (
                        K::from_txid(tx.txid()),
                        match V::get_type() {
                            Type::Transaction => V::from_data(Data::Transaction(tx.clone())),
                            Type::BlockHash => {
                                V::from_data(Data::BlockHash(block.header.block_hash()))
                            }
                        },
                    )
                })
                .collect();

            tx_index.update(block.header, &map);
        }

        tx_index
    }

    /// Gets an item from the index if present. [None] otherwise.
    pub fn get<'a>(&'a self, k: &'a K) -> Option<&V> {
        self.index.get(k)
    }

    /// Checks if the index if full.
    pub fn is_full(&self) -> bool {
        self.blocks.len() > self.size
    }

    /// Get's the height of a given block based on its position in the block queue.
    pub fn get_height(&self, block_hash: &BlockHash) -> Option<usize> {
        let pos = self.blocks.iter().position(|x| x == block_hash)?;
        Some(self.tip as usize + pos + 1 - self.blocks.len())
    }

    /// Updates the index by adding data from a new block. Removes the oldest block if the index is full afterwards.
    pub fn update(&mut self, block_header: BlockHeader, data: &HashMap<K, V>) {
        self.blocks.push_back(block_header.block_hash());

        let ks = data
            .iter()
            .map(|(k, v)| {
                self.index.insert(*k, v.clone());
                *k
            })
            .collect();

        self.tx_in_block.insert(block_header.block_hash(), ks);

        if self.is_full() {
            // Avoid logging during bootstrap
            log::debug!("New block added to index: {}", block_header.block_hash());
            self.tip += 1;
            self.remove_oldest_block();
        }
    }

    /// Fixes the index by removing disconnected data.
    pub fn remove_disconnected_block(&mut self, block_hash: &BlockHash) {
        if let Some(ks) = self.tx_in_block.remove(block_hash) {
            self.index.retain(|k, _| !ks.contains(k));

            // Blocks should be disconnected from last backwards. Log if that's not the case so we can revisit this and fix it.
            if let Some(ref h) = self.blocks.pop_back() {
                if h != block_hash {
                    log::error!("Disconnected block does not match the oldest block stored in the TxIndex ({block_hash} != {h})");
                }
            }
        } else {
            log::warn!("The index is already empty");
        }
    }

    /// Removes the oldest block from the index.
    /// This removes data from `self.blocks`, `self.tx_in_block` and `self.index`.
    pub fn remove_oldest_block(&mut self) {
        let h = self.blocks.pop_front().unwrap();
        let ks = self.tx_in_block.remove(&h).unwrap();
        self.index.retain(|k, _| !ks.contains(k));

        log::debug!("Oldest block removed from index: {h}");
    }
}

impl<K: std::fmt::Debug + Key, V: std::fmt::Debug + Value> fmt::Display for TxIndex<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "index: {:?}\n\nblocks: {:?}\n\ntx_in_block: {:?}\n\nsize: {}",
            self.index, self.blocks, self.tx_in_block, self.size
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::Deref;

    use crate::test_utils::{get_last_n_blocks, Blockchain};

    use bitcoin::Block;

    impl<K, V> TxIndex<K, V>
    where
        K: Key + std::cmp::Eq + Copy,
        V: Value + Clone,
        Self: Sized,
    {
        pub fn index_mut(&mut self) -> &mut HashMap<K, V> {
            &mut self.index
        }

        pub fn blocks(&self) -> &VecDeque<BlockHash> {
            &self.blocks
        }

        pub fn contains_key(&self, k: &K) -> bool {
            self.index.contains_key(k)
        }
    }

    #[tokio::test]
    async fn test_new() {
        let height = 10;
        let mut chain = Blockchain::default().with_height(height as usize);
        let last_six_blocks = get_last_n_blocks(&mut chain, 6).await;
        let blocks: Vec<Block> = last_six_blocks
            .iter()
            .map(|block| block.deref().clone())
            .collect();

        let cache: TxIndex<Locator, Transaction> = TxIndex::new(&last_six_blocks, height);
        assert_eq!(blocks.len(), cache.size);
        for block in blocks.iter() {
            assert!(cache.blocks().contains(&block.block_hash()));

            let mut locators = Vec::new();
            for tx in block.txdata.iter() {
                let locator = Locator::new(tx.txid());
                assert!(cache.contains_key(&locator));
                locators.push(locator);
            }

            assert_eq!(cache.tx_in_block[&block.block_hash()], locators);
        }
    }

    #[tokio::test]
    async fn test_get_height() {
        let cache_size = 10;
        let height = 50;
        let mut chain = Blockchain::default().with_height_and_txs(height, 42);
        let last_n_blocks = get_last_n_blocks(&mut chain, cache_size).await;

        // last_n_blocks is ordered from latest to earliest
        let first_block = last_n_blocks.get(cache_size - 1).unwrap();
        let last_block = last_n_blocks.get(0).unwrap();
        let mid = last_n_blocks.get(cache_size / 2).unwrap();

        let cache: TxIndex<Locator, Transaction> = TxIndex::new(&last_n_blocks, height as u32);

        assert_eq!(
            cache.get_height(&first_block.block_hash()).unwrap(),
            height - cache_size + 1
        );
        assert_eq!(cache.get_height(&last_block.block_hash()).unwrap(), height);
        assert_eq!(
            cache.get_height(&mid.block_hash()).unwrap(),
            height - cache_size / 2
        );
    }

    #[tokio::test]
    async fn test_get_height_not_found() {
        let cache_size = 10;
        let height = 50;
        let mut chain = Blockchain::default().with_height_and_txs(height, 42);
        let cache: TxIndex<Locator, Transaction> = TxIndex::new(
            &get_last_n_blocks(&mut chain, cache_size).await,
            height as u32,
        );

        let fake_hash = BlockHash::default();
        assert!(cache.get_height(&fake_hash).is_none());
    }

    #[tokio::test]
    async fn test_update() {
        let height = 10;
        let mut chain = Blockchain::default().with_height(height as usize);
        let mut last_n_blocks = get_last_n_blocks(&mut chain, 7).await;

        // Store the last block to use it for an update and the first to check eviction
        // Notice that the list of blocks is ordered from last to first.
        let last_block = last_n_blocks.remove(0);
        let first_block = last_n_blocks.last().unwrap().deref().clone();

        // Init the cache with the 6 block before the last
        let mut cache = TxIndex::new(&last_n_blocks, height);

        // Update the cache with the last block
        let locator_tx_map = last_block
            .txdata
            .iter()
            .map(|tx| (Locator::new(tx.txid()), tx.clone()))
            .collect();

        cache.update(last_block.deref().header, &locator_tx_map);

        // Check that the new data is in the cache
        assert!(cache.blocks().contains(&last_block.block_hash()));
        for (locator, _) in locator_tx_map.iter() {
            assert!(cache.contains_key(locator));
        }
        assert_eq!(
            cache.tx_in_block[&last_block.block_hash()],
            locator_tx_map.keys().cloned().collect::<Vec<Locator>>()
        );

        // Check that the data from the first block has been evicted
        assert!(!cache.blocks().contains(&first_block.block_hash()));
        for tx in first_block.txdata.iter() {
            assert!(!cache.contains_key(&Locator::new(tx.txid())));
        }
        assert!(!cache.tx_in_block.contains_key(&first_block.block_hash()));
    }

    #[tokio::test]
    async fn test_remove_disconnected_block() {
        let cache_size = 6;
        let height = cache_size * 2;
        let mut chain = Blockchain::default().with_height_and_txs(height, 42);
        let mut cache: TxIndex<Locator, Transaction> = TxIndex::new(
            &get_last_n_blocks(&mut chain, cache_size).await,
            height as u32,
        );

        // TxIndex::fix removes the last connected block and removes all the associated data
        for i in 0..cache_size {
            let header = chain
                .at_height(chain.get_block_count() as usize - i)
                .deref()
                .header;
            let locators = cache.tx_in_block.get(&header.block_hash()).unwrap().clone();

            // Make sure there's data regarding the target block in the cache before fixing it
            assert_eq!(cache.blocks().len(), cache.size - i);
            assert!(cache.blocks().contains(&header.block_hash()));
            assert!(!locators.is_empty());
            for locator in locators.iter() {
                assert!(cache.contains_key(locator));
            }

            cache.remove_disconnected_block(&header.block_hash());

            // Check that the block data is not in the cache anymore
            assert_eq!(cache.blocks().len(), cache.size - i - 1);
            assert!(!cache.blocks().contains(&header.block_hash()));
            assert!(cache.tx_in_block.get(&header.block_hash()).is_none());
            for locator in locators.iter() {
                assert!(!cache.contains_key(locator));
            }
        }

        // At this point the cache should be empty, fixing it further shouldn't do anything
        for i in cache_size..cache_size * 2 {
            assert!(cache.index.is_empty());
            assert!(cache.blocks().is_empty());
            assert!(cache.tx_in_block.is_empty());

            let header = chain
                .at_height(chain.get_block_count() as usize - i)
                .deref()
                .header;
            cache.remove_disconnected_block(&header.block_hash());
        }
    }
}
