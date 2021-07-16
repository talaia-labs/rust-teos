use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::ops::DerefMut;
use std::rc::Rc;
use tokio::sync::broadcast::Receiver;

use bitcoin::hash_types::BlockHash;
use bitcoin::hashes::{ripemd160, Hash};
use bitcoin::secp256k1::SecretKey;
use bitcoin::{BlockHeader, Transaction};
use lightning_block_sync::poll::{ChainPoller, Poll, ValidatedBlockHeader};
use lightning_block_sync::BlockSource;

use teos_common::appointment::{Appointment, Locator};
use teos_common::cryptography;
use teos_common::receipts::{AppointmentReceipt, RegistrationReceipt};
use teos_common::UserId;

use crate::extended_appointment::{ExtendedAppointment, UUID};
use crate::gatekeeper::{Gatekeeper, MaxSlotsReached};

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

//TODO: Check if calls to the LocatorCache needs explicit Mutex of if Rust already prevents race conditions in this case.
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

    pub fn get_tx(&self, locator: &Locator) -> Option<&Transaction> {
        self.cache.get(locator)
    }

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

    pub fn is_full(&self) -> bool {
        self.blocks.len() > self.size as usize
    }

    pub fn remove_oldest_block(&mut self) {
        let oldest = self.blocks.remove(0);
        let oldest_hash = oldest.block_hash();
        for locator in self.tx_in_block.remove(&oldest_hash).unwrap() {
            self.cache.remove(&locator);
        }

        println!("Block removed from cache {}", oldest_hash);
    }

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

// TODO: It may be nice to create richer errors so the API can return richer rejection
#[derive(Debug)]
pub enum AddAppointmentFailure {
    AuthenticationFailure,
    NotEnoughSlots,
    SubscriptionExpired(u32),
    AlreadyTriggered,
}
pub struct Watcher<B: DerefMut<Target = T> + Sized, T: BlockSource> {
    appointments: HashMap<UUID, ExtendedAppointment>,
    locator_uuid_map: HashMap<Locator, Vec<UUID>>,
    block_queue: Receiver<ValidatedBlockHeader>,
    poller: Rc<RefCell<ChainPoller<B, T>>>,
    gatekeeper: Gatekeeper,
    last_known_block_header: ValidatedBlockHeader,
    locator_cache: LocatorCache<B, T>,
    signing_key: SecretKey,
}

impl<B, T> Watcher<B, T>
where
    B: DerefMut<Target = T> + Sized + Send + Sync,
    T: BlockSource,
{
    pub async fn new(
        block_queue: Receiver<ValidatedBlockHeader>,
        poller: Rc<RefCell<ChainPoller<B, T>>>,
        gatekeeper: Gatekeeper,
        last_known_block_header: ValidatedBlockHeader,
        signing_key: SecretKey,
    ) -> Self {
        let appointments = HashMap::new();
        let locator_uuid_map = HashMap::new();
        let locator_cache = LocatorCache::new(last_known_block_header, 6, poller.clone()).await;

        Watcher {
            appointments,
            locator_uuid_map,
            block_queue,
            poller,
            gatekeeper,
            last_known_block_header,
            locator_cache,
            signing_key,
        }
    }

    pub fn register(&mut self, user_id: &UserId) -> Result<RegistrationReceipt, MaxSlotsReached> {
        match self.gatekeeper.add_update_user(user_id) {
            Ok(mut receipt) => {
                receipt.sign(self.signing_key);
                Ok(receipt)
            }
            Err(e) => Err(e),
        }
    }

    pub fn add_appointment(
        &mut self,
        appointment: Appointment,
        user_signature: String,
    ) -> Result<(AppointmentReceipt, u32, u32), AddAppointmentFailure> {
        let user_id = self
            .gatekeeper
            .authenticate_user(&appointment.serialize(), &user_signature)
            .map_err(|_| AddAppointmentFailure::AuthenticationFailure)?;

        let (has_subscription_expired, expiry) =
            self.gatekeeper.has_subscription_expired(&user_id).unwrap();

        if has_subscription_expired {
            return Err(AddAppointmentFailure::SubscriptionExpired(expiry));
        }

        let extended_appointment = ExtendedAppointment::new(
            appointment,
            user_id,
            user_signature,
            self.last_known_block_header.height,
        );

        let mut uui_data = extended_appointment.inner.locator.to_vec();
        uui_data.extend(&user_id.0.serialize());
        let uuid = UUID(ripemd160::Hash::hash(&uui_data).into_inner());

        // TODO: Skip if appointment already in Responder

        let available_slots = self
            .gatekeeper
            .add_update_appointment(&user_id, uuid, extended_appointment.clone())
            .map_err(|_| AddAppointmentFailure::NotEnoughSlots)?;

        let locator = &extended_appointment.inner.locator;
        match self.locator_cache.get_tx(locator) {
            // Appointments that were triggered in blocks held in the cache
            Some(dispute_tx) => {
                println!("{:?} already in cache", locator);
                match cryptography::decrypt(
                    &extended_appointment.inner.encrypted_blob,
                    &dispute_tx.txid(),
                ) {
                    // TODO: Add data to the Responder once it's created
                    Ok(penalty_tx) => (),

                    // DISCUSS: Check if this makes sense or if we should just drop the data altogether
                    // If data inside the encrypted blob is invalid, the appointment is accepted but the data is dropped.
                    // (same as with data that bounces in the Responder). This reduces the appointment slot count so it
                    // could be used to discourage user misbehavior.
                    Err(_) => (),
                }
            }
            // Regular appointments that have not been triggered (or, at least, not recently)
            None => {
                self.appointments.insert(uuid, extended_appointment.clone());

                if self.locator_uuid_map.contains_key(locator) {
                    // If the uuid is already in the map it means this is an update, so no need to modify the map
                    if !self.locator_uuid_map[locator].contains(&uuid) {
                        // Otherwise two users have sent an appointment with the same locator, so we need to store both.
                        self.locator_uuid_map.get_mut(locator).unwrap().push(uuid);
                    }
                } else {
                    // The locator is not in the map, so we need to create a new entry for it
                    self.locator_uuid_map.insert(locator.clone(), vec![uuid]);
                }
            }
        }

        let mut receipt = AppointmentReceipt::new(
            extended_appointment.user_signature.clone(),
            extended_appointment.start_block.clone(),
        );
        receipt.sign(self.signing_key);

        Ok((receipt, available_slots, expiry))
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
        HashMap<&'a UUID, Breach>,
        HashMap<&'a UUID, cryptography::DecryptingError>,
    ) {
        let mut valid_breaches = HashMap::new();
        let mut invalid_breaches = HashMap::new();

        // A cache of the already decrypted blobs so replicate decryption can be avoided
        let mut decrypted_blobs: HashMap<Vec<u8>, Transaction> = HashMap::new();

        for (locator, tx) in breaches.into_iter() {
            for uuid in self.locator_uuid_map.get(locator).unwrap() {
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
    use super::*;
    use crate::test_utils::Blockchain;
    use crate::test_utils::{generate_dummy_appointment, generate_uuid};

    use bitcoin::hash_types::Txid;
    use bitcoin::network::constants::Network;
    use bitcoin::secp256k1::key::ONE_KEY;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use tokio::sync::broadcast;

    const TOWER_SK: SecretKey = ONE_KEY;
    const SLOTS: u32 = 21;
    const DURATION: u32 = 500;
    const EXPIRY_DELTA: u32 = 42;
    const START_HEIGHT: usize = 100;

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
    async fn test_register() {
        let (tx, rx) = broadcast::channel(100);
        let rx2 = tx.subscribe();

        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, None);
        let tip = chain.tip();

        let poller = Rc::new(RefCell::new(ChainPoller::new(&mut chain, Network::Bitcoin)));
        let gatekeeper = Gatekeeper::new(tip, rx, SLOTS, DURATION, EXPIRY_DELTA);
        let mut watcher = Watcher::new(rx2, poller.clone(), gatekeeper, tip, TOWER_SK).await;

        // register calls Gatekeeper::add_update_user and signs the UserInfo returned by it.
        // Not testing the update / rejection logic, since that's already covered in the Gatekeeper, just that the data makes
        // sense and the signature verifies.

        let user_pk = PublicKey::from_secret_key(&Secp256k1::new(), &ONE_KEY);
        let user_id = UserId(user_pk);
        let receipt = watcher.register(&user_id).unwrap();

        assert_eq!(receipt.user_id(), &user_id);
        assert_eq!(receipt.available_slots(), SLOTS);
        assert_eq!(
            receipt.subscription_expiry(),
            START_HEIGHT as u32 + DURATION
        );

        assert!(cryptography::verify(
            &receipt.serialize(),
            &receipt.signature().unwrap(),
            user_pk
        ));
    }

    #[tokio::test]
    async fn test_add_appointment() {
        let (tx, rx) = broadcast::channel(100);
        let rx2 = tx.subscribe();
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, None);
        let tip = chain.tip();
        let tip_txs = chain.blocks.last().unwrap().txdata.clone();

        let poller = Rc::new(RefCell::new(ChainPoller::new(&mut chain, Network::Bitcoin)));
        let gatekeeper = Gatekeeper::new(tip, rx, SLOTS, DURATION, EXPIRY_DELTA);
        let mut watcher = Watcher::new(rx2, poller.clone(), gatekeeper, tip, TOWER_SK).await;

        // add_appointment should add a given appointment to the Watcher given the following logic:
        //      - if the appointment does not exist for a given user, add the appointment
        //      - if the appointment already exists for a given user, update the data
        //      - if the appointment is already in the Responder, reject (TODO: pending)
        //      - if the trigger for the appointment is in the cache, trigger straightaway
        // In any of the cases where the appointment should be added to the Watcher, the appointment will be rejected if:
        //      - the user does not have enough slots (either to add or update)
        //      - the subscription has expired

        let tower_id: UserId = UserId(PublicKey::from_secret_key(
            &Secp256k1::new(),
            &watcher.signing_key,
        ));
        let user_sk = SecretKey::from_slice(&[2; 32]).unwrap();
        let user_id = UserId(PublicKey::from_secret_key(&Secp256k1::new(), &user_sk));
        watcher.register(&user_id).unwrap();
        let appointment = generate_dummy_appointment(None).inner;

        // Add the appointment for a new user (twice so we can check that updates work)
        for _ in 0..1 {
            let user_sig = cryptography::sign(&appointment.serialize(), user_sk).unwrap();
            let (receipt, slots, expiry) = watcher
                .add_appointment(appointment.clone(), user_sig.clone())
                .unwrap();

            assert_eq!(slots, SLOTS - 1);
            assert_eq!(expiry, START_HEIGHT as u32 + DURATION);
            assert_eq!(receipt.start_block(), START_HEIGHT as u32);
            assert_eq!(receipt.user_signature(), user_sig);
            let recovered_pk =
                cryptography::recover_pk(&receipt.serialize(), &receipt.signature().unwrap())
                    .unwrap();
            assert_eq!(UserId(recovered_pk), tower_id);
        }

        // Add the same appointment but for another user
        let user2_sk = SecretKey::from_slice(&[3; 32]).unwrap();
        let user2_id = UserId(PublicKey::from_secret_key(&Secp256k1::new(), &user2_sk));
        watcher.register(&user2_id).unwrap();

        let user2_sig = cryptography::sign(&appointment.serialize(), user2_sk).unwrap();
        let (receipt, slots, expiry) = watcher
            .add_appointment(appointment.clone(), user2_sig.clone())
            .unwrap();

        assert_eq!(slots, SLOTS - 1);
        assert_eq!(expiry, START_HEIGHT as u32 + DURATION);
        assert_eq!(receipt.start_block(), START_HEIGHT as u32);
        assert_eq!(receipt.user_signature(), user2_sig);
        let recovered_pk =
            cryptography::recover_pk(&receipt.serialize(), &receipt.signature().unwrap()).unwrap();
        assert_eq!(UserId(recovered_pk), tower_id);

        // There should be now two appointments in the Watcher and the same locator should have two different uuids
        assert_eq!(watcher.appointments.len(), 2);
        assert_eq!(watcher.locator_uuid_map[&appointment.locator].len(), 2);

        // TODO: test appointment already in Responder

        // If the trigger is already in the cache, the appointment will go straight to the Responder
        // TODO: Since we have no Responder yet, test that the data is not kept in the Watcher
        let dispute_tx = tip_txs.last().unwrap();
        let appointment_in_cache = generate_dummy_appointment(Some(&dispute_tx.txid())).inner;
        let user_sig = cryptography::sign(&appointment_in_cache.serialize(), user_sk).unwrap();
        let (receipt, slots, expiry) = watcher
            .add_appointment(appointment_in_cache.clone(), user_sig.clone())
            .unwrap();

        // The appointment should have been accepted, slots should have been decreased, but data should not be in the Watcher
        assert_eq!(slots, SLOTS - 2);
        assert_eq!(expiry, START_HEIGHT as u32 + DURATION);
        assert_eq!(receipt.start_block(), START_HEIGHT as u32);
        assert_eq!(receipt.user_signature(), user_sig);
        let recovered_pk =
            cryptography::recover_pk(&receipt.serialize(), &receipt.signature().unwrap()).unwrap();
        assert_eq!(UserId(recovered_pk), tower_id);
        assert_eq!(watcher.appointments.len(), 2);
        assert!(!watcher
            .locator_uuid_map
            .contains_key(&appointment_in_cache.locator));

        // FAIL cases (non-registered, subscription expired and not enough slots)

        // If the user is not registered, trying to add an appointment should fail. Since user_ids are
        // computed using ECRecovery, we can simulate a non-registered user by creating a "random" signature
        let user3_sig = String::from(" ");

        assert!(matches!(
            watcher.add_appointment(appointment.clone(), user3_sig.clone()),
            Err(AddAppointmentFailure::AuthenticationFailure)
        ));

        // If the user has no enough slots, the appointment is rejected. We do not test all possible cases since updates are
        // already tested int he Gatekeeper. Testing that it is  rejected if the condition is met should suffice.
        watcher
            .gatekeeper
            .registered_users
            .get_mut(&user_id)
            .unwrap()
            .available_slots = 0;

        let dispute_txid = Txid::from_slice(&[2; 32]).unwrap();
        let new_appointment = generate_dummy_appointment(Some(&dispute_txid)).inner;
        let new_app_sig = cryptography::sign(&new_appointment.serialize(), user_sk).unwrap();

        assert!(matches!(
            watcher.add_appointment(new_appointment, new_app_sig),
            Err(AddAppointmentFailure::NotEnoughSlots)
        ));

        // If the user subscription has expired, the appointment should be rejected.
        watcher
            .gatekeeper
            .registered_users
            .get_mut(&user2_id)
            .unwrap()
            .subscription_expiry = START_HEIGHT as u32 - EXPIRY_DELTA;

        assert!(matches!(
            watcher.add_appointment(appointment.clone(), user2_sig.clone()),
            Err(AddAppointmentFailure::SubscriptionExpired { .. })
        ));
    }

    #[tokio::test]
    async fn test_get_breaches() {
        let (tx, rx) = broadcast::channel(100);
        let rx2 = tx.subscribe();

        let mut chain = Blockchain::default().with_height_and_txs(12, None);
        let tip = chain.tip();
        let txs = chain.blocks.last().unwrap().txdata.clone();

        let poller = Rc::new(RefCell::new(ChainPoller::new(&mut chain, Network::Bitcoin)));
        let gatekeeper = Gatekeeper::new(tip, rx, 1000, 1000, 42);

        let mut watcher = Watcher::new(rx2, poller.clone(), gatekeeper, tip, TOWER_SK).await;

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
                    .insert(locator.clone(), vec![generate_uuid()]);
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
        let (tx, rx) = broadcast::channel(100);
        let rx2 = tx.subscribe();

        let mut chain = Blockchain::default().with_height_and_txs(10, Some(12));
        let tip = chain.tip();
        let txs = chain.blocks.last().unwrap().txdata.clone();

        let poller = Rc::new(RefCell::new(ChainPoller::new(&mut chain, Network::Bitcoin)));
        let gatekeeper = Gatekeeper::new(tip, rx, 1000, 1000, 42);

        let mut watcher = Watcher::new(rx2, poller.clone(), gatekeeper, tip, TOWER_SK).await;

        // Let's create some locators based on the transactions in the last block
        let mut locator_tx_map = HashMap::new();
        for tx in txs {
            locator_tx_map.insert(Locator::new(tx.txid()), tx.clone());
        }

        // Add some of them to the Watcher
        let mut local_valid = Vec::new();
        let mut local_invalid = Vec::new();

        for (i, (locator, tx)) in locator_tx_map.iter().enumerate() {
            let uuid = generate_uuid();
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
                watcher.locator_uuid_map.insert(locator.clone(), vec![uuid]);
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
