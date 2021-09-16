use futures::executor::block_on;
use log;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::iter::FromIterator;
use std::ops::Deref;

use bitcoin::hash_types::BlockHash;
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Block, BlockHeader, Transaction};
use lightning::chain;
use lightning_block_sync::poll::{ValidatedBlock, ValidatedBlockHeader};
use lightning_block_sync::BlockHeaderData;

use teos_common::appointment::{Appointment, Locator};
use teos_common::cryptography;
use teos_common::receipts::{AppointmentReceipt, RegistrationReceipt};
use teos_common::UserId;

use crate::extended_appointment::{ExtendedAppointment, UUID};
use crate::gatekeeper::{Gatekeeper, MaxSlotsReached};
use crate::responder::Responder;

struct LocatorCache {
    cache: HashMap<Locator, Transaction>,
    blocks: Vec<BlockHeader>,
    tx_in_block: HashMap<BlockHash, Vec<Locator>>,
    size: usize,
}

impl fmt::Display for LocatorCache {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "cache: {:?}\n\nblocks: {:?}\n\ntx_in_block: {:?}\n\nsize: {}",
            self.cache, self.blocks, self.tx_in_block, self.size
        )
    }
}

#[derive(Debug)]
pub struct Breach {
    pub locator: Locator,
    pub dispute_tx: Transaction,
    pub penalty_tx: Transaction,
}

impl Breach {
    fn new(locator: Locator, dispute_tx: Transaction, penalty_tx: Transaction) -> Self {
        Breach {
            locator,
            dispute_tx,
            penalty_tx,
        }
    }
}

//TODO: Check if calls to the LocatorCache needs explicit Mutex of if Rust already prevents race conditions in this case.
impl LocatorCache {
    fn new(last_n_blocks: Vec<ValidatedBlock>) -> LocatorCache {
        let mut cache = HashMap::new();
        let mut blocks = Vec::new();
        let mut tx_in_block = HashMap::new();

        for block in last_n_blocks.iter().rev() {
            blocks.last().map(|prev_block_header: &BlockHeader| {
                if block.header.prev_blockhash != prev_block_header.block_hash() {
                    panic!("last_n_blocks contains unchained blocks");
                }
            });

            let mut locators = Vec::new();
            for tx in block.txdata.clone() {
                let locator = Locator::new(tx.txid());
                cache.insert(locator.clone(), tx);
                locators.push(locator);
            }

            tx_in_block.insert(block.block_hash(), locators);
            blocks.push(block.header);
        }

        LocatorCache {
            cache,
            blocks,
            tx_in_block,
            size: last_n_blocks.len(),
        }
    }

    pub fn get_tx(&self, locator: &Locator) -> Option<&Transaction> {
        self.cache.get(locator)
    }

    pub fn is_full(&self) -> bool {
        self.blocks.len() > self.size as usize
    }

    pub fn update(
        &mut self,
        block_header: BlockHeader,
        locator_tx_map: &HashMap<Locator, Transaction>,
    ) {
        self.blocks.push(block_header);

        let mut locators = Vec::new();
        for (locator, tx) in locator_tx_map {
            self.cache.insert(locator.clone(), tx.clone());
            locators.push(locator.clone());
        }

        self.tx_in_block.insert(block_header.block_hash(), locators);

        log::info!("New block added to cache: {}", block_header.block_hash());

        if self.is_full() {
            self.remove_oldest_block();
        }
    }

    // TODO: This should be called within Watcher::block_disconnected
    pub async fn fix(&mut self, header: &BlockHeader) {
        for locator in self.tx_in_block[&header.block_hash()].iter() {
            self.cache.remove(locator);
        }
        self.tx_in_block.remove(&header.block_hash());

        //DISCUSS: Given blocks are disconnected in order by bitcoind we should always get them in order.
        // Log if that's not the case so we can revisit this and fix it.
        match self.blocks.pop() {
            Some(h) => {
                if h.block_hash() != header.block_hash() {
                    log::error!("Disconnected block does not match the oldest block stored in the LocatorCache ({} != {})", header.block_hash(), h.block_hash())
                };
            }
            None => log::warn!("The cache is already empty"),
        }
    }

    pub fn remove_oldest_block(&mut self) {
        let oldest = self.blocks.remove(0);
        let oldest_hash = oldest.block_hash();
        for locator in self.tx_in_block.remove(&oldest_hash).unwrap() {
            self.cache.remove(&locator);
        }

        log::info!("Oldest block removed from cache: {}", oldest_hash);
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

#[derive(Debug)]
pub enum GetAppointmentFailure {
    AuthenticationFailure,
    SubscriptionExpired(u32),
    NotFound,
}

pub struct Watcher<'a> {
    appointments: RefCell<HashMap<UUID, ExtendedAppointment>>,
    locator_uuid_map: RefCell<HashMap<Locator, HashSet<UUID>>>,
    locator_cache: RefCell<LocatorCache>,
    responder: Responder<'a>,
    gatekeeper: &'a Gatekeeper,
    last_known_block_header: RefCell<BlockHeaderData>,
    signing_key: SecretKey,
}

impl<'a> Watcher<'a> {
    pub async fn new(
        gatekeeper: &'a Gatekeeper,
        responder: Responder<'a>,
        last_n_blocks: Vec<ValidatedBlock>,
        last_known_block_header: ValidatedBlockHeader,
        signing_key: SecretKey,
    ) -> Watcher<'a> {
        let appointments = RefCell::new(HashMap::new());
        let locator_uuid_map = RefCell::new(HashMap::new());
        let locator_cache = RefCell::new(LocatorCache::new(last_n_blocks));

        Watcher {
            appointments,
            locator_uuid_map,
            locator_cache,
            responder,
            gatekeeper,
            last_known_block_header: RefCell::new(last_known_block_header.deref().clone()),
            signing_key,
        }
    }

    pub fn register(&mut self, user_id: &UserId) -> Result<RegistrationReceipt, MaxSlotsReached> {
        let mut receipt = self.gatekeeper.add_update_user(user_id)?;
        receipt.sign(&self.signing_key);

        Ok(receipt)
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
            self.last_known_block_header.borrow().height,
        );

        let uuid = UUID::new(&extended_appointment.inner.locator, &user_id);

        // TODO: Skip if appointment already in Responder

        let available_slots = self
            .gatekeeper
            .add_update_appointment(&user_id, uuid, extended_appointment.clone())
            .map_err(|_| AddAppointmentFailure::NotEnoughSlots)?;

        let locator = &extended_appointment.inner.locator;
        match self.locator_cache.borrow().get_tx(locator) {
            // Appointments that were triggered in blocks held in the cache
            Some(dispute_tx) => {
                log::info!("Trigger for locator {:?} found in cache", locator);
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
                self.appointments
                    .borrow_mut()
                    .insert(uuid, extended_appointment.clone());

                if self.locator_uuid_map.borrow().contains_key(locator) {
                    // If the uuid is already in the map it means this is an update, so no need to modify the map
                    if !self.locator_uuid_map.borrow()[locator].contains(&uuid) {
                        // Otherwise two users have sent an appointment with the same locator, so we need to store both.
                        self.locator_uuid_map
                            .borrow_mut()
                            .get_mut(locator)
                            .unwrap()
                            .insert(uuid);
                    }
                } else {
                    // The locator is not in the map, so we need to create a new entry for it
                    self.locator_uuid_map
                        .borrow_mut()
                        .insert(locator.clone(), HashSet::from_iter(vec![uuid]));
                }
            }
        }

        let mut receipt = AppointmentReceipt::new(
            extended_appointment.user_signature.clone(),
            extended_appointment.start_block.clone(),
        );
        receipt.sign(&self.signing_key);

        Ok((receipt, available_slots, expiry))
    }

    pub fn get_appointment(
        &self,
        locator: Locator,
        user_signature: String,
    ) -> Result<ExtendedAppointment, GetAppointmentFailure> {
        let message = format!("get appointment {}", locator);

        let user_id = self
            .gatekeeper
            .authenticate_user(message.as_bytes(), &user_signature)
            .map_err(|_| GetAppointmentFailure::AuthenticationFailure)?;

        let (has_subscription_expired, expiry) =
            self.gatekeeper.has_subscription_expired(&user_id).unwrap();

        if has_subscription_expired {
            return Err(GetAppointmentFailure::SubscriptionExpired(expiry));
        }

        let uuid = UUID::new(&locator, &user_id);

        // TODO: This should also check if the appointment is in the Responder
        match self.appointments.borrow().get(&uuid) {
            Some(extended_appointment) => Ok(extended_appointment.clone()),
            None => {
                log::info! {"Cannot find {}", locator};
                Err(GetAppointmentFailure::NotFound)
            }
        }
    }

    fn get_breaches(
        &self,
        locator_tx_map: HashMap<Locator, Transaction>,
    ) -> HashMap<Locator, Transaction> {
        let local_set: HashSet<Locator> = self.locator_uuid_map.borrow().keys().cloned().collect();
        let new_set = locator_tx_map.keys().cloned().collect();
        let intersection = local_set.intersection(&new_set);

        let mut breaches = HashMap::new();
        for locator in intersection {
            let (k, v) = locator_tx_map.get_key_value(locator).unwrap();
            breaches.insert(k.clone(), v.clone());
        }

        if breaches.len() > 0 {
            log::debug!("List of breaches: {:?}", breaches.keys());
        } else {
            log::info!("No breaches found")
        }

        breaches
    }

    fn filter_breaches(
        &self,
        breaches: HashMap<Locator, Transaction>,
    ) -> (
        HashMap<UUID, Breach>,
        HashMap<UUID, cryptography::DecryptingError>,
    ) {
        let mut valid_breaches = HashMap::new();
        let mut invalid_breaches = HashMap::new();

        // A cache of the already decrypted blobs so replicate decryption can be avoided
        let mut decrypted_blobs: HashMap<Vec<u8>, Transaction> = HashMap::new();

        for (locator, tx) in breaches.into_iter() {
            for uuid in self
                .locator_uuid_map
                .borrow()
                .get(&locator)
                .unwrap()
                .clone()
            {
                // FIXME: this should load data from the DB
                let borrowed = self.appointments.borrow();
                let appointment = borrowed.get(&uuid).unwrap();

                if decrypted_blobs.contains_key(&appointment.inner.encrypted_blob) {
                    let penalty_tx = decrypted_blobs
                        .get(&appointment.inner.encrypted_blob)
                        .unwrap();
                    valid_breaches.insert(
                        uuid,
                        Breach::new(locator.clone(), tx.clone(), penalty_tx.clone()),
                    );
                } else {
                    match cryptography::decrypt(&appointment.inner.encrypted_blob, &tx.txid()) {
                        Ok(penalty_tx) => {
                            decrypted_blobs.insert(
                                appointment.inner.encrypted_blob.clone(),
                                penalty_tx.clone(),
                            );
                            valid_breaches
                                .insert(uuid, Breach::new(locator.clone(), tx.clone(), penalty_tx));
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

impl<'a> chain::Listen for Watcher<'a> {
    fn block_connected(&self, block: &Block, height: u32) {
        log::info!("New block received: {}", block.header.block_hash());

        let mut locator_tx_map = HashMap::new();
        for tx in block.txdata.iter() {
            locator_tx_map.insert(Locator::new(tx.txid()), tx.clone());
        }

        self.locator_cache
            .borrow_mut()
            .update(block.header, &locator_tx_map);

        if self.appointments.borrow().len() > 0 {
            // Get a list of outdated appointments from the Gatekeeper. This appointments may be either in the Watcher
            // or in the Responder.
            let outdated_appointments = self.gatekeeper.get_outdated_appointments(&height);

            for uuid in outdated_appointments {
                // DISCUSS: we may not need to check if the key is in the map given it won't panic if so.
                if self.appointments.borrow().contains_key(&uuid) {
                    self.appointments.borrow_mut().remove(&uuid);
                }
            }

            // Filter out those breaches that do not yield a valid transaction
            let (valid_breaches, invalid_breaches) =
                self.filter_breaches(self.get_breaches(locator_tx_map));

            let mut appointments_to_delete: Vec<UUID> = Vec::new();
            let mut appointments_to_delete_gatekeeper: HashMap<UUID, UserId> = HashMap::new();
            for uuid in invalid_breaches.keys() {
                appointments_to_delete_gatekeeper
                    .insert(uuid.clone(), self.appointments.borrow()[&uuid].user_id);
                appointments_to_delete.push(uuid.clone());
            }

            // Send data to the Responder and remove it from the Watcher
            for (uuid, breach) in valid_breaches {
                log::info!(
                    "Notifying Responder and deleting appointment (uuid: {})",
                    uuid
                );

                //DISCUSS: This cannot be async given block_connected is not.
                // Is there any alternative? Remove async from here altogether?
                block_on(self.responder.handle_breach(
                    uuid.clone(),
                    breach,
                    self.appointments.borrow()[&uuid].user_id,
                    block.header,
                ));

                // DISCUSS: Not using triggered flags from now (i.e. this is one way atm)
                appointments_to_delete.push(uuid.clone());
            }

            // Delete data from the Watcher (invalid + triggered)
            for uuid in appointments_to_delete.iter() {
                {
                    let locator = &self.appointments.borrow()[&uuid].inner.locator;

                    if self.locator_uuid_map.borrow()[locator].len() == 1 {
                        self.locator_uuid_map.borrow_mut().remove(locator);
                    } else {
                        self.locator_uuid_map
                            .borrow_mut()
                            .get_mut(locator)
                            .unwrap()
                            .remove(&uuid);
                    }
                }

                self.appointments.borrow_mut().remove(&uuid);
            }

            // Delete data from the Gatekeeper
            self.gatekeeper
                .delete_appointments(&appointments_to_delete_gatekeeper);

            if self.appointments.borrow().is_empty() {
                log::info!("No more pending appointments");
            }
        }

        *self.last_known_block_header.borrow_mut() = BlockHeaderData {
            header: block.header,
            height,
            chainwork: block.header.work(),
        };
    }

    fn block_disconnected(&self, header: &BlockHeader, height: u32) {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use crate::carrier::Carrier;
    use crate::extended_appointment::AppointmentStatus;
    use crate::test_utils::{generate_dummy_appointment, generate_uuid, get_random_tx, Blockchain};

    use bitcoin::hash_types::Txid;
    use bitcoin::hashes::Hash;
    use bitcoin::network::constants::Network;
    use bitcoin::secp256k1::key::ONE_KEY;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use bitcoincore_rpc::{Auth, Client};
    use lightning::chain::Listen;
    use lightning_block_sync::poll::{ChainPoller, Poll};

    const TOWER_SK: SecretKey = ONE_KEY;
    const SLOTS: u32 = 21;
    const DURATION: u32 = 500;
    const EXPIRY_DELTA: u32 = 42;
    const START_HEIGHT: usize = 100;

    async fn get_last_n_blocks(chain: &mut Blockchain, n: usize) -> Vec<ValidatedBlock> {
        let tip = chain.tip();
        let mut poller = ChainPoller::new(chain, Network::Bitcoin);

        let mut last_n_blocks = Vec::new();
        let mut last_known_block = tip;
        for _ in 0..n {
            let block = poller.fetch_block(&last_known_block).await.unwrap();
            last_known_block = poller
                .look_up_previous_header(&last_known_block)
                .await
                .unwrap();
            last_n_blocks.push(block);
        }

        last_n_blocks
    }

    async fn create_watcher<'a>(chain: &mut Blockchain, gatekeeper: &'a Gatekeeper) -> Watcher<'a> {
        let tip = chain.tip();
        let last_n_blocks = get_last_n_blocks(chain, 6).await;

        let bitcoin_cli = Arc::new(
            Client::new(
                "http://localhost:18443".to_string(),
                Auth::UserPass("user".to_string(), "passwd".to_string()),
            )
            .unwrap(),
        );
        let carrier = Carrier::new(bitcoin_cli);

        let responder = Responder::new(carrier, &gatekeeper, tip);
        Watcher::new(&gatekeeper, responder, last_n_blocks, tip, TOWER_SK).await
    }

    #[tokio::test]
    async fn test_cache() {
        let mut chain = Blockchain::default().with_height(10);
        let size = 6;

        let cache = LocatorCache::new(get_last_n_blocks(&mut chain, size).await);
        assert_eq!(size, cache.size);
    }

    #[tokio::test]
    async fn test_register() {
        // register calls Gatekeeper::add_update_user and signs the UserInfo returned by it.
        // Not testing the update / rejection logic, since that's already covered in the Gatekeeper, just that the data makes
        // sense and the signature verifies.

        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, None);
        let gk = Gatekeeper::new(chain.tip(), SLOTS, DURATION, EXPIRY_DELTA);
        let mut watcher = create_watcher(&mut chain, &gk).await;

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
            &user_pk
        ));
    }

    #[tokio::test]
    async fn test_add_appointment() {
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, None);
        let tip_txs = chain.blocks.last().unwrap().txdata.clone();

        let gk = Gatekeeper::new(chain.tip(), SLOTS, DURATION, EXPIRY_DELTA);
        let mut watcher = create_watcher(&mut chain, &gk).await;

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
            let user_sig = cryptography::sign(&appointment.serialize(), &user_sk).unwrap();
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

        let user2_sig = cryptography::sign(&appointment.serialize(), &user2_sk).unwrap();
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
        assert_eq!(watcher.appointments.borrow().len(), 2);
        assert_eq!(
            watcher.locator_uuid_map.borrow()[&appointment.locator].len(),
            2
        );

        // TODO: test appointment already in Responder

        // If the trigger is already in the cache, the appointment will go straight to the Responder
        // TODO: Since we have no Responder yet, test that the data is not kept in the Watcher
        let dispute_tx = tip_txs.last().unwrap();
        let appointment_in_cache = generate_dummy_appointment(Some(&dispute_tx.txid())).inner;
        let user_sig = cryptography::sign(&appointment_in_cache.serialize(), &user_sk).unwrap();
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
        assert_eq!(watcher.appointments.borrow().len(), 2);
        assert!(!watcher
            .locator_uuid_map
            .borrow()
            .contains_key(&appointment_in_cache.locator));

        // FAIL cases (non-registered, subscription expired and not enough slots)

        // If the user is not registered, trying to add an appointment should fail. Since user_ids are
        // computed using ECRecovery, we can simulate a non-registered user by creating a "random" signature
        let user3_sig = String::from_utf8((0..65).collect()).unwrap();

        assert!(matches!(
            watcher.add_appointment(appointment.clone(), user3_sig.clone()),
            Err(AddAppointmentFailure::AuthenticationFailure)
        ));

        // If the user has no enough slots, the appointment is rejected. We do not test all possible cases since updates are
        // already tested int he Gatekeeper. Testing that it is  rejected if the condition is met should suffice.
        watcher
            .gatekeeper
            .registered_users
            .borrow_mut()
            .get_mut(&user_id)
            .unwrap()
            .available_slots = 0;

        let dispute_txid = Txid::from_slice(&[2; 32]).unwrap();
        let new_appointment = generate_dummy_appointment(Some(&dispute_txid)).inner;
        let new_app_sig = cryptography::sign(&new_appointment.serialize(), &user_sk).unwrap();

        assert!(matches!(
            watcher.add_appointment(new_appointment, new_app_sig),
            Err(AddAppointmentFailure::NotEnoughSlots)
        ));

        // If the user subscription has expired, the appointment should be rejected.
        watcher
            .gatekeeper
            .registered_users
            .borrow_mut()
            .get_mut(&user2_id)
            .unwrap()
            .subscription_expiry = START_HEIGHT as u32;

        assert!(matches!(
            watcher.add_appointment(appointment.clone(), user2_sig.clone()),
            Err(AddAppointmentFailure::SubscriptionExpired { .. })
        ));
    }

    #[tokio::test]
    async fn test_get_appointment() {
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, None);
        let gk = Gatekeeper::new(chain.tip(), SLOTS, DURATION, EXPIRY_DELTA);
        let mut watcher = create_watcher(&mut chain, &gk).await;

        let appointment = generate_dummy_appointment(None).inner;

        //  If the user cannot be properly identified, the request will fail. This can be simulated by providing a wrong signature
        let wrong_sig = String::from_utf8((0..65).collect()).unwrap();
        assert!(matches!(
            watcher.get_appointment(appointment.locator.clone(), wrong_sig),
            Err(GetAppointmentFailure::AuthenticationFailure)
        ));

        // If the user does exist and there's an appointment with the given locator belonging to him, it will be returned
        let user_sk = ONE_KEY;
        let user_id = UserId(PublicKey::from_secret_key(&Secp256k1::new(), &user_sk));
        watcher.register(&user_id).unwrap();
        watcher
            .add_appointment(
                appointment.clone(),
                cryptography::sign(&appointment.serialize(), &user_sk).unwrap(),
            )
            .unwrap();

        let message = format!("get appointment {}", appointment.locator.clone());
        let signature = cryptography::sign(message.as_bytes(), &user_sk).unwrap();
        let r_app = watcher
            .get_appointment(appointment.locator.clone(), signature.clone())
            .unwrap();
        assert_eq!(r_app.status, AppointmentStatus::BeingWatched);

        // If the user does exists but the requested locator does not belong to any of their associated appointments, NotFound
        // should be returned.
        let user2_sk = SecretKey::from_slice(&[2; 32]).unwrap();
        let user2_id = UserId(PublicKey::from_secret_key(&Secp256k1::new(), &user2_sk));
        watcher.register(&user2_id).unwrap();

        let signature2 = cryptography::sign(message.as_bytes(), &user2_sk).unwrap();
        assert!(matches!(
            watcher.get_appointment(appointment.locator.clone(), signature2),
            Err(GetAppointmentFailure::NotFound { .. })
        ));

        // If the user subscription has expired, the request will fail
        watcher
            .gatekeeper
            .registered_users
            .borrow_mut()
            .get_mut(&user_id)
            .unwrap()
            .subscription_expiry = START_HEIGHT as u32;

        assert!(matches!(
            watcher.get_appointment(appointment.locator.clone(), signature),
            Err(GetAppointmentFailure::SubscriptionExpired { .. })
        ));
    }

    #[tokio::test]
    async fn test_get_breaches() {
        let mut chain = Blockchain::default().with_height_and_txs(12, None);
        let txs = chain.blocks.last().unwrap().txdata.clone();
        let gk = Gatekeeper::new(chain.tip(), SLOTS, DURATION, EXPIRY_DELTA);
        let watcher = create_watcher(&mut chain, &gk).await;

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
                    .borrow_mut()
                    .insert(locator.clone(), HashSet::from_iter(vec![generate_uuid()]));
            }
        }

        // Check that breaches are correctly detected
        let breaches = watcher.get_breaches(locator_tx_map);
        assert!(
            breaches.len() == watcher.locator_uuid_map.borrow().len()
                && breaches
                    .keys()
                    .all(|k| watcher.locator_uuid_map.borrow().contains_key(k))
        );
    }

    #[tokio::test]
    async fn test_filter_breaches() {
        let mut chain = Blockchain::default().with_height_and_txs(10, Some(12));
        let txs = chain.blocks.last().unwrap().txdata.clone();
        let gk = Gatekeeper::new(chain.tip(), SLOTS, DURATION, EXPIRY_DELTA);
        let watcher = create_watcher(&mut chain, &gk).await;

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
                    .borrow_mut()
                    .insert(uuid, generate_dummy_appointment(dispute_txid));
                watcher
                    .locator_uuid_map
                    .borrow_mut()
                    .insert(locator.clone(), HashSet::from_iter(vec![uuid]));
            }
        }

        let breaches = watcher.get_breaches(locator_tx_map.clone());
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

    #[tokio::test]
    async fn test_block_connected() {
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, Some(12));
        let gk = Gatekeeper::new(chain.tip(), SLOTS, DURATION, EXPIRY_DELTA);
        let mut watcher = create_watcher(&mut chain, &gk).await;

        // block_connected for the Watcher is used to keep track of what new transactions has been mined whose may be potential
        // channel breaches.

        // If the Watcher is not watching any appointment, block_connected will only be used to keep track of the last known block
        // by the Watcher.
        assert_eq!(
            watcher.last_known_block_header.borrow().header,
            chain.tip().header
        );
        watcher.block_connected(&chain.generate(None), chain.blocks.len() as u32);
        assert_eq!(
            watcher.last_known_block_header.borrow().header,
            chain.tip().header
        );

        // If there are appointments to watch, the Watcher will:
        //  - Check if any new transaction is a trigger
        //      - Check if a trigger is valid, if so pass the data to the Responder
        //  - Delete invalid appointments.
        //  - Delete appointments that have been outdated (i.e. have expired without a trigger)
        //  - Delete invalid appointments also from the Gatekeeper (not outdated tough, the GK will take care of those via it's own Listen)

        // Let's first check how data gets outdated (create two users, add an appointment to both and outdate only one)
        let all_two_sk = SecretKey::from_slice(&[2; 32]).unwrap();
        let user_id = UserId(PublicKey::from_secret_key(&Secp256k1::new(), &ONE_KEY));
        let user2_id = UserId(PublicKey::from_secret_key(&Secp256k1::new(), &all_two_sk));
        watcher.register(&user_id).unwrap();
        watcher.register(&user2_id).unwrap();

        let appointment = generate_dummy_appointment(None);
        let uuid1 = UUID::new(&appointment.inner.locator, &user_id);
        let uuid2 = UUID::new(&appointment.inner.locator, &user2_id);

        let user_sig = cryptography::sign(&appointment.inner.serialize(), &ONE_KEY).unwrap();
        watcher
            .add_appointment(appointment.inner.clone(), user_sig)
            .unwrap();
        let user2_sig = cryptography::sign(&appointment.inner.serialize(), &all_two_sk).unwrap();
        watcher
            .add_appointment(appointment.inner.clone(), user2_sig)
            .unwrap();

        watcher
            .gatekeeper
            .registered_users
            .borrow_mut()
            .get_mut(&user_id)
            .unwrap()
            .subscription_expiry = (chain.blocks.len() as u32) - EXPIRY_DELTA + 1;

        // Both appointments can be found before mining a block, only the user's 2 can be found afterwards
        for uuid in vec![uuid1, uuid2] {
            assert!(watcher.appointments.borrow().contains_key(&uuid));
        }
        assert!(watcher.gatekeeper.registered_users.borrow()[&user_id]
            .appointments
            .contains_key(&uuid1));
        assert!(watcher.gatekeeper.registered_users.borrow()[&user2_id]
            .appointments
            .contains_key(&uuid2));

        watcher.block_connected(&chain.generate(None), chain.blocks.len() as u32);

        assert!(!watcher.appointments.borrow().contains_key(&uuid1));
        assert!(watcher.gatekeeper.registered_users.borrow()[&user_id]
            .appointments
            .contains_key(&uuid1));

        assert!(watcher.appointments.borrow().contains_key(&uuid2));
        assert!(watcher.gatekeeper.registered_users.borrow()[&user2_id]
            .appointments
            .contains_key(&uuid2));

        // Check triggers. Add a new appointment and trigger it with valid data.
        let dispute_tx = get_random_tx();
        let appointment = generate_dummy_appointment(Some(&dispute_tx.txid()));
        let sig = cryptography::sign(&appointment.inner.serialize(), &all_two_sk).unwrap();
        let uuid = UUID::new(&appointment.inner.locator, &user2_id);
        watcher
            .add_appointment(appointment.inner.clone(), sig)
            .unwrap();

        assert!(watcher.appointments.borrow().contains_key(&uuid));

        watcher.block_connected(
            &chain.generate(Some(vec![dispute_tx])),
            chain.blocks.len() as u32,
        );

        // Data should have been moved to the Responder and kept in the Gatekeeper, since it is still part of the system.
        assert!(!watcher.appointments.borrow().contains_key(&uuid));
        assert!(watcher.responder.trackers.borrow().contains_key(&uuid));
        assert!(watcher.gatekeeper.registered_users.borrow()[&user2_id]
            .appointments
            .contains_key(&uuid));

        // Checks invalid triggers. Add a new appointment and trigger it with invalid data.
        let dispute_tx = get_random_tx();
        let mut appointment = generate_dummy_appointment(Some(&dispute_tx.txid()));
        // Modify the encrypted blob so the data is invalid both non-decryptable blobs and blobs with invalid transactions will yield an invalid trigger
        appointment.inner.encrypted_blob = vec![1; 64];
        let sig = cryptography::sign(&appointment.inner.serialize(), &all_two_sk).unwrap();
        let uuid = UUID::new(&appointment.inner.locator, &user2_id);
        watcher
            .add_appointment(appointment.inner.clone(), sig)
            .unwrap();

        watcher.block_connected(
            &chain.generate(Some(vec![dispute_tx])),
            chain.blocks.len() as u32,
        );

        // Data has been wiped since it was invalid
        assert!(!watcher.appointments.borrow().contains_key(&uuid));
        assert!(!watcher.responder.trackers.borrow().contains_key(&uuid));
        assert!(!watcher.gatekeeper.registered_users.borrow()[&user2_id]
            .appointments
            .contains_key(&uuid));
    }
}
