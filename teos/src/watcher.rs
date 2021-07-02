use crate::extended_appointment::ExtendedAppointment;
use bitcoin::hash_types::BlockHash;
use bitcoin::{BlockHeader, Transaction};
use lightning_block_sync::poll::{ChainPoller, Poll, ValidatedBlockHeader};
use lightning_block_sync::BlockSource;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::ops::DerefMut;
use std::rc::Rc;
use teos_common::appointment::Locator;
use teos_common::cryptography;
use tokio::sync::broadcast::Receiver;
use uuid::Uuid;

struct LocatorCache<B: DerefMut<Target = T> + Sized, T: BlockSource> {
    poller: Rc<RefCell<ChainPoller<B, T>>>,
    cache: HashMap<Locator, Transaction>,
    blocks: Vec<BlockHeader>,
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

#[derive(Debug)]
struct Breach<'a> {
    locator: &'a Locator,
    dispute_tx: &'a Transaction,
    penalty_tx: Transaction,
}

impl<'a> Breach<'a> {
    fn new(locator: &'a Locator, dispute_tx: &'a Transaction, penalty_tx: Transaction) -> Self {
        Breach {
            locator,
            dispute_tx,
            penalty_tx,
        }
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
        poller: Rc<RefCell<ChainPoller<B, T>>>,
    ) -> LocatorCache<B, T> {
        let mut cache = HashMap::new();
        let mut blocks = Vec::new();
        let mut tx_in_block = HashMap::new();
        let mut derefed = poller.borrow_mut();

        let mut target_block_header = last_known_block_header;
        for _ in 0..cache_size {
            let block = derefed.fetch_block(&target_block_header).await.unwrap();
            let mut locators = Vec::new();
            for tx in block.txdata.clone() {
                let locator = Locator::new(tx.txid());
                cache.insert(locator.clone(), tx);
                locators.push(locator);
            }

            tx_in_block.insert(block.block_hash(), locators);
            blocks.push(block.header);

            target_block_header = derefed
                .look_up_previous_header(&target_block_header)
                .await
                .unwrap();
        }

        LocatorCache {
            poller: poller.clone(),
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
        tip_header: ValidatedBlockHeader,
        locator_tx_map: HashMap<Locator, Transaction>,
    ) {
        self.blocks.push(tip_header.header);

        let mut locators = Vec::new();
        for (locator, tx) in locator_tx_map {
            self.cache.insert(locator.clone(), tx);
            locators.push(locator);
        }

        self.tx_in_block
            .insert(tip_header.header.block_hash(), locators);

        println!("Block added to cache {}", tip_header.header.block_hash());
        println!("Cache :{:#?}", self.blocks);

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
        let oldest = self.blocks.remove(0);
        let oldest_hash = oldest.block_hash();
        for locator in self.tx_in_block.remove(&oldest_hash).unwrap() {
            self.cache.remove(&locator);
        }

        println!("Block removed from cache {}", oldest_hash);
    }

    // FIXME: This needs mutex
    pub async fn fix(&mut self, mut tip_header: ValidatedBlockHeader) {
        let mut tmp_cache = HashMap::new();
        let mut tmp_blocks = Vec::new();
        let mut tmp_tx_in_block = HashMap::new();
        let mut derefed = self.poller.borrow_mut();

        for _ in 0..self.size {
            match self
                .tx_in_block
                .get(&tip_header.header.block_hash())
                .cloned()
            {
                Some(locators) => {
                    tmp_tx_in_block.insert(tip_header.header.block_hash(), locators.clone());
                    tmp_blocks.push(tip_header.header);
                    for locator in locators {
                        tmp_cache
                            .insert(locator.clone(), self.cache.get(&locator).unwrap().clone());
                    }
                }
                None => {
                    let block = derefed.fetch_block(&tip_header).await.unwrap();
                    let mut locators = Vec::new();
                    for tx in block.txdata.clone() {
                        let locator = Locator::new(tx.txid());
                        tmp_cache.insert(locator.clone(), tx);
                        locators.push(locator);
                    }

                    tmp_tx_in_block.insert(block.block_hash(), locators);
                    tmp_blocks.push(block.header);
                }
            }

            tip_header = derefed.look_up_previous_header(&tip_header).await.unwrap();
        }

        self.cache = tmp_cache;
        self.tx_in_block = tmp_tx_in_block;
        self.blocks = tmp_blocks;
        self.blocks.reverse();
    }
}

pub struct Watcher<B: DerefMut<Target = T> + Sized, T: BlockSource> {
    appointments: HashMap<Uuid, ExtendedAppointment>,
    locator_uuid_map: HashMap<Locator, Uuid>,
    block_queue: Receiver<ValidatedBlockHeader>,
    poller: Rc<RefCell<ChainPoller<B, T>>>,
    last_known_block_header: ValidatedBlockHeader,
    locator_cache: LocatorCache<B, T>,
}

impl<B, T> Watcher<B, T>
where
    B: DerefMut<Target = T> + Sized + Send + Sync,
    T: BlockSource,
{
    pub async fn new(
        block_queue: Receiver<ValidatedBlockHeader>,
        poller: Rc<RefCell<ChainPoller<B, T>>>,
        last_known_block_header: ValidatedBlockHeader,
    ) -> Self {
        let appointments = HashMap::new();
        let locator_uuid_map = HashMap::new();
        let locator_cache = LocatorCache::new(last_known_block_header, 6, poller.clone()).await;

        Watcher {
            appointments,
            locator_uuid_map,
            block_queue,
            poller,
            last_known_block_header,
            locator_cache,
        }
    }

    pub async fn do_watch(&mut self) {
        println!("Starting to watch");
        loop {
            let new_tip_header = self.block_queue.recv().await.unwrap();
            let new_tip = {
                let mut derefed = self.poller.borrow_mut();
                derefed.fetch_block(&new_tip_header).await.unwrap()
            };

            let mut locator_tx_map = HashMap::new();
            for tx in new_tip.txdata.iter() {
                locator_tx_map.insert(Locator::new(tx.txid()), tx.clone());
            }

            if self.appointments.len() > 0 {
                let (valid_breaches, invalid_breaches) =
                    self.filter_breaches(self.get_breaches(&locator_tx_map));
                println!("BREACHES: {:?}, {:?}", valid_breaches, invalid_breaches);
            }

            // Update the cache
            if new_tip.header.prev_blockhash == self.last_known_block_header.header.block_hash() {
                self.locator_cache.update(new_tip_header, locator_tx_map);
            } else {
                println!("Reorg");
                self.locator_cache.fix(new_tip_header).await;
            }

            self.last_known_block_header = new_tip_header;
        }
    }

    fn get_breaches<'a>(
        &self,
        locator_tx_map: &'a HashMap<Locator, Transaction>,
    ) -> HashMap<&'a Locator, &'a Transaction> {
        let local_set: HashSet<Locator> = self.locator_uuid_map.keys().cloned().collect();
        let new_set = locator_tx_map.keys().cloned().collect();
        let intersection = local_set.intersection(&new_set);

        let mut breaches = HashMap::new();
        for locator in intersection {
            let (k, v) = locator_tx_map.get_key_value(locator).unwrap();
            breaches.insert(k, v);
        }

        if breaches.len() > 0 {
            println!("List of breaches: {:?}", breaches.keys());
        } else {
            println!("No breaches found")
        }

        breaches
    }

    fn filter_breaches<'a>(
        &'a self,
        breaches: HashMap<&'a Locator, &'a Transaction>,
    ) -> (
        HashMap<&'a Uuid, Breach>,
        HashMap<&'a Uuid, cryptography::DecryptingError>,
    ) {
        let mut valid_breaches = HashMap::new();
        let mut invalid_breaches = HashMap::new();

        // A cache of the already decrypted blobs so replicate decryption can be avoided
        let mut decrypted_blobs: HashMap<Vec<u8>, Transaction> = HashMap::new();

        for (locator, tx) in breaches.into_iter() {
            for uuid in self.locator_uuid_map.get(locator) {
                // FIXME: this should load data from the DB
                let appointment = self.appointments.get(uuid).unwrap();

                if decrypted_blobs.contains_key(&appointment.inner.encrypted_blob) {
                    let penalty_tx = decrypted_blobs
                        .get(&appointment.inner.encrypted_blob)
                        .unwrap();
                    valid_breaches.insert(uuid, Breach::new(locator, tx, penalty_tx.clone()));
                } else {
                    match cryptography::decrypt(&appointment.inner.encrypted_blob, &tx.txid()) {
                        Ok(penalty_tx) => {
                            decrypted_blobs.insert(
                                appointment.inner.encrypted_blob.clone(),
                                penalty_tx.clone(),
                            );
                            valid_breaches.insert(uuid, Breach::new(locator, tx, penalty_tx));
                        }
                        Err(e) => {
                            invalid_breaches.insert(uuid, e);
                        }
                    }
                }
            }
        }

        (valid_breaches, invalid_breaches)
    }
}

#[cfg(test)]
mod tests {
    use std::iter::FromIterator;

    use super::*;
    use crate::test_utils::generate_dummy_appointment;
    use crate::test_utils::Blockchain;

    use bitcoin::network::constants::Network;
    use tokio::sync::broadcast;

    #[tokio::test]
    async fn test_cache() {
        let mut chain = Blockchain::default().with_height(10);
        let tip = chain.tip();
        let size = 6;

        let poller = Rc::new(RefCell::new(ChainPoller::new(&mut chain, Network::Bitcoin)));
        let cache = LocatorCache::new(tip, size, poller).await;

        assert_eq!(size, cache.size);
    }

    #[tokio::test]
    async fn test_get_breaches() {
        let (_, rx) = broadcast::channel(100);

        let mut chain = Blockchain::default().with_height_and_txs(12, None);
        let tip = chain.tip();
        let txs = chain.blocks.last().unwrap().txdata.clone();

        let poller = Rc::new(RefCell::new(ChainPoller::new(&mut chain, Network::Bitcoin)));
        let mut watcher = Watcher::new(rx, poller.clone(), tip).await;

        // Let's create some locators based on the transactions in the last block
        let mut locator_tx_map = HashMap::new();
        for tx in txs {
            locator_tx_map.insert(Locator::new(tx.txid()), tx.clone());
        }

        // Add some of them to the Watcher
        for (i, locator) in locator_tx_map.keys().enumerate() {
            if i % 2 == 0 {
                watcher
                    .locator_uuid_map
                    .insert(locator.clone(), Uuid::new_v4());
            }
        }

        // Check that breaches are correctly detected
        let breaches = watcher.get_breaches(&locator_tx_map);
        assert!(
            breaches.len() == watcher.locator_uuid_map.len()
                && breaches
                    .keys()
                    .all(|k| watcher.locator_uuid_map.contains_key(k))
        );
    }

    #[tokio::test]
    async fn test_filter_breaches() {
        let (_, rx) = broadcast::channel(100);

        let mut chain = Blockchain::default().with_height_and_txs(10, Some(12));
        let tip = chain.tip();
        let txs = chain.blocks.last().unwrap().txdata.clone();

        let poller = Rc::new(RefCell::new(ChainPoller::new(&mut chain, Network::Bitcoin)));
        let mut watcher = Watcher::new(rx, poller.clone(), tip).await;

        // Let's create some locators based on the transactions in the last block
        let mut locator_tx_map = HashMap::new();
        for tx in txs {
            locator_tx_map.insert(Locator::new(tx.txid()), tx.clone());
        }

        // Add some of them to the Watcher
        let mut local_valid = Vec::new();
        let mut local_invalid = Vec::new();

        for (i, (locator, tx)) in locator_tx_map.iter().enumerate() {
            let uuid = Uuid::new_v4();
            let tx_id = tx.txid();
            let mut dispute_txid = None;

            // Add 1/3 as valid breaches, 1/3 as invalid, leave 1/3 out
            if i % 3 < 2 {
                match i % 3 {
                    0 => {
                        dispute_txid = Some(&tx_id);
                        local_valid.push(uuid);
                    }
                    _ => local_invalid.push(uuid),
                }

                watcher
                    .appointments
                    .insert(uuid, generate_dummy_appointment(dispute_txid));
                watcher.locator_uuid_map.insert(locator.clone(), uuid);
            }
        }

        let breaches = watcher.get_breaches(&locator_tx_map);
        let (valid, invalid) = watcher.filter_breaches(breaches);

        // Check valid + invalid add up to 2/3
        assert_eq!(2 * locator_tx_map.len() / 3, valid.len() + invalid.len());

        // Check valid breaches match
        assert!(valid.len() == local_valid.len() && valid.keys().all(|k| local_valid.contains(k)));

        // Check invalid breaches match
        assert!(
            invalid.len() == local_invalid.len()
                && invalid.keys().all(|k| local_invalid.contains(k))
        );

        // All invalid breaches should be AED errors (the decryption key was invalid)
        invalid
            .values()
            .all(|v| matches!(v, cryptography::DecryptingError::AED { .. }));
    }
}
