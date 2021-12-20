//! Logic related to the Watcher, the components in charge of watching for breaches on chain.

use futures::executor::block_on;
use log;

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::iter::FromIterator;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

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

use crate::dbm::DBM;
use crate::extended_appointment::{AppointmentSummary, ExtendedAppointment, UUID};
use crate::gatekeeper::{Gatekeeper, MaxSlotsReached};
use crate::responder::{Responder, TransactionTracker};

/// Data structure used to cache locators computed from parsed blocks.
///
/// Holds up to `size` blocks with their corresponding computed [Locator]s.
struct LocatorCache {
    /// A [Locator]:[Transaction] map.
    cache: HashMap<Locator, Transaction>,
    /// Vector of block hashes corresponding to the cached blocks.
    blocks: Vec<BlockHash>,
    /// Map of [BlockHash]:[Vec<Locator>]. Used to remove data from the cache.
    tx_in_block: HashMap<BlockHash, Vec<Locator>>,
    /// Maximum size of the cache.
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

//TODO: Check if calls to the LocatorCache needs explicit Mutex of if Rust already prevents race conditions in this case.
// This is accessed both by block_connected (write) and add_appointment (read). The later is an API method.
impl LocatorCache {
    /// Creates a new [LocatorCache] instance.
    /// The cache is initialized using the provided vector of blocks.
    /// The size of the cache is defined as the size of `last_n_blocks`.
    ///
    /// # Panics
    ///
    /// Panics if any of the blocks in `last_n_blocks` is unchained. That is, if the given blocks
    /// are not linked in strict descending order.
    fn new(last_n_blocks: Vec<ValidatedBlock>) -> LocatorCache {
        let size = last_n_blocks.len();
        let mut cache = HashMap::new();
        let mut blocks = Vec::with_capacity(size);
        let mut tx_in_block = HashMap::new();

        for block in last_n_blocks.into_iter().rev() {
            blocks.last().map(|prev_block_hash| {
                if block.header.prev_blockhash != *prev_block_hash {
                    panic!("last_n_blocks contains unchained blocks");
                }
            });

            let mut locators = Vec::new();
            for tx in block.txdata.iter() {
                let locator = Locator::new(tx.txid());
                cache.insert(locator, tx.clone());
                locators.push(locator);
            }

            tx_in_block.insert(block.block_hash(), locators);
            blocks.push(block.header.block_hash());
        }

        LocatorCache {
            cache,
            blocks,
            tx_in_block,
            size,
        }
    }

    /// Gets a transaction from the cache if present. [None] otherwise.
    fn get_tx(&self, locator: Locator) -> Option<&Transaction> {
        self.cache.get(&locator)
    }

    /// Checks if the cache if full.
    fn is_full(&self) -> bool {
        self.blocks.len() > self.size
    }

    /// Updates the cache by adding data from a new block. Removes the oldest block if the cache is full afterwards.
    fn update(
        &mut self,
        block_header: BlockHeader,
        locator_tx_map: &HashMap<Locator, Transaction>,
    ) {
        self.blocks.push(block_header.block_hash());

        let mut locators = Vec::new();
        for (locator, tx) in locator_tx_map {
            self.cache.insert(*locator, tx.clone());
            locators.push(*locator);
        }

        self.tx_in_block.insert(block_header.block_hash(), locators);

        log::info!("New block added to cache: {}", block_header.block_hash());

        if self.is_full() {
            self.remove_oldest_block();
        }
    }

    #[allow(dead_code)]
    /// FIXME: Currently dead code. Fixes the cache by removing reorged blocks and adding the new valid ones.
    /// This should be called within Watcher::block_disconnected).
    async fn fix(&mut self, header: &BlockHeader) {
        for locator in self.tx_in_block[&header.block_hash()].iter() {
            self.cache.remove(locator);
        }
        self.tx_in_block.remove(&header.block_hash());

        //DISCUSS: Given blocks are disconnected in order by bitcoind we should always get them in order.
        // Log if that's not the case so we can revisit this and fix it.
        match self.blocks.pop() {
            Some(h) => {
                if h != header.block_hash() {
                    log::error!("Disconnected block does not match the oldest block stored in the LocatorCache ({} != {})", header.block_hash(), h)
                };
            }
            None => log::warn!("The cache is already empty"),
        }
    }

    /// Removes the oldest block from the cache.
    /// This removes data from `self.blocks`, `self.tx_in_block` and `self.cache`.
    fn remove_oldest_block(&mut self) {
        let oldest_hash = self.blocks.remove(0);
        for locator in self.tx_in_block.remove(&oldest_hash).unwrap() {
            self.cache.remove(&locator);
        }

        log::info!("Oldest block removed from cache: {}", oldest_hash);
    }
}

/// Structure holding data regarding a breach.
///
/// Breaches are computed after spotting a [Locator] on chain and
/// using the resulting dispute transaction id to decipher the encrypted blob of an ongoing [Appointment].
/// Breaches are passed to the [Responder] once created.
#[derive(Debug, Clone)]
pub struct Breach {
    /// Breach locator. Matches the [Appointment] locator.
    pub locator: Locator,
    /// Transaction that triggered the breach.
    pub dispute_tx: Transaction,
    /// Transaction that will be used as a response to the breach.
    pub penalty_tx: Transaction,
}

impl Breach {
    /// Creates a new [Breach] instance.
    pub fn new(locator: Locator, dispute_tx: Transaction, penalty_tx: Transaction) -> Self {
        Breach {
            locator,
            dispute_tx,
            penalty_tx,
        }
    }
}

/// Packs the reasons why trying to add an appointment may fail.
// TODO: It may be nice to create richer errors so the API can return richer rejection
#[derive(Debug)]
pub enum AddAppointmentFailure {
    AuthenticationFailure,
    NotEnoughSlots,
    SubscriptionExpired(u32),
    AlreadyTriggered,
}

/// Packs the reasons why trying to query an appointment may fail.
#[derive(Debug)]
pub enum GetAppointmentFailure {
    AuthenticationFailure,
    SubscriptionExpired(u32),
    NotFound,
}

/// Wraps the returning information regarding a queried appointment.
///
/// Either an [Appointment] or a [TransactionTracker] can be
/// returned depending on whether the appointment can be found in the [Watcher] or in the [Responder].
#[derive(Debug)]
pub enum AppointmentInfo {
    Appointment(Appointment),
    Tracker(TransactionTracker),
}

/// Component in charge of watching for triggers in the chain (aka channel breaches for lightning).
pub struct Watcher {
    /// A map holding a summary of every appointment ([ExtendedAppointment]) hold by the [Watcher], identified by a [UUID].
    appointments: Mutex<HashMap<UUID, AppointmentSummary>>,
    /// A map between [Locator]s (user identifiers for [Appointment]s) and [UUID]s (tower identifiers).
    locator_uuid_map: Mutex<HashMap<Locator, HashSet<UUID>>>,
    /// A cache of the [Locator]s computed for the transactions in the last few blocks.
    locator_cache: Mutex<LocatorCache>,
    /// A [Responder] instance. Data will be passed to it once triggered (if valid).
    responder: Arc<Responder>,
    /// A [Gatekeeper] instance. Data regarding users is requested to it.
    gatekeeper: Arc<Gatekeeper>,
    /// The last known block header.
    last_known_block_header: Mutex<BlockHeaderData>,
    /// The tower signing key. Used to sign messages going to users.
    signing_key: SecretKey,
    /// A [DBM] (database manager) instance. Used to persist appointment data into disk.
    dbm: Arc<Mutex<DBM>>,
}

impl Watcher {
    /// Creates a new [Watcher] instance.
    pub async fn new(
        gatekeeper: Arc<Gatekeeper>,
        responder: Arc<Responder>,
        last_n_blocks: Vec<ValidatedBlock>,
        last_known_block_header: ValidatedBlockHeader,
        signing_key: SecretKey,
        dbm: Arc<Mutex<DBM>>,
    ) -> Self {
        let appointments = Mutex::new(HashMap::new());
        let locator_uuid_map = Mutex::new(HashMap::new());
        let locator_cache = Mutex::new(LocatorCache::new(last_n_blocks));

        Watcher {
            appointments,
            locator_uuid_map,
            locator_cache,
            responder,
            gatekeeper,
            last_known_block_header: Mutex::new(*last_known_block_header.deref()),
            signing_key,
            dbm,
        }
    }

    /// Registers a new user within the [Watcher]. This request is passed to the [Gatekeeper], who is in
    /// charge of managing users.
    pub fn register(&self, user_id: UserId) -> Result<RegistrationReceipt, MaxSlotsReached> {
        let mut receipt = self.gatekeeper.add_update_user(user_id)?;
        receipt.sign(&self.signing_key);

        Ok(receipt)
    }

    /// Adds a new [Appointment] to the tower.
    ///
    /// Appointments are only added provided:
    /// - The user is registered into the system
    /// - The user subscription has not expired
    /// - The user has enough available slots to fit the appointment
    /// - The appointment hasn't been responded to yet (data cannot be found in the [Responder])
    ///
    /// If an appointment is accepted, an [AppointmentSummary] will be added to the the watching pool and
    /// monitored by the [Watcher]. An [ExtendedAppointment] (constructed from the [Appointment]) will be persisted on disk.
    /// In case the locator for the given appointment can be found in the cache (meaning the appointment has been
    /// triggered recently) the data will be passed to the [Responder] straightaway (modulo it being valid).
    pub async fn add_appointment(
        &self,
        appointment: Appointment,
        user_signature: String,
    ) -> Result<(AppointmentReceipt, u32, u32), AddAppointmentFailure> {
        let user_id = self
            .gatekeeper
            .authenticate_user(&appointment.serialize(), &user_signature)
            .map_err(|_| AddAppointmentFailure::AuthenticationFailure)?;

        let (has_subscription_expired, expiry) =
            self.gatekeeper.has_subscription_expired(user_id).unwrap();

        if has_subscription_expired {
            return Err(AddAppointmentFailure::SubscriptionExpired(expiry));
        }

        let extended_appointment = ExtendedAppointment::new(
            appointment,
            user_id,
            user_signature,
            self.last_known_block_header.lock().unwrap().height,
        );

        let uuid = UUID::new(extended_appointment.locator(), user_id);

        if self.responder.has_tracker(uuid) {
            log::info!("Tracker for {} already found in Responder", uuid);
            return Err(AddAppointmentFailure::AlreadyTriggered);
        }

        let available_slots = self
            .gatekeeper
            .add_update_appointment(user_id, uuid, &extended_appointment)
            .map_err(|_| AddAppointmentFailure::NotEnoughSlots)?;

        let locator = extended_appointment.locator();
        match self.locator_cache.lock().unwrap().get_tx(locator) {
            // Appointments that were triggered in blocks held in the cache
            Some(dispute_tx) => {
                log::info!("Trigger for locator {} found in cache", locator);
                match cryptography::decrypt(
                    &extended_appointment.encrypted_blob(),
                    &dispute_tx.txid(),
                ) {
                    Ok(penalty_tx) => {
                        // Data needs to be added the database straightaway since appointments are
                        // FKs to trackers. If handle breach fails, data will be deleted later.
                        self.dbm
                            .lock()
                            .unwrap()
                            .store_appointment(uuid, &extended_appointment)
                            .unwrap();

                        let breach = Breach::new(locator, dispute_tx.clone(), penalty_tx);
                        let receipt = self.responder.handle_breach(uuid, breach, user_id).await;

                        if receipt.delivered() {
                            log::info!("Appointment went straight to the Responder");
                        } else {
                            // DISCUSS: We could either free the slots or keep it occupied as if this was misbehavior.
                            // Keeping it for now.
                            log::warn!(
                                "Appointment bounced in the Responder. Reason: {:?}",
                                receipt.reason()
                            );

                            self.dbm.lock().unwrap().remove_appointment(uuid);
                        }
                    }

                    // DISCUSS: Check if this makes sense or if we should just drop the data altogether
                    // If data inside the encrypted blob is invalid, the appointment is accepted but the data is dropped.
                    // (same as with data that bounces in the Responder). This reduces the appointment slot count so it
                    // could be used to discourage user misbehavior.
                    Err(_) => log::info!("The appointment contained invalid data {}", locator),
                }
            }
            // Regular appointments that have not been triggered (or, at least, not recently)
            None => {
                self.appointments
                    .lock()
                    .unwrap()
                    .insert(uuid, extended_appointment.get_summary());
                let mut locator_uuid_map = self.locator_uuid_map.lock().unwrap();
                if locator_uuid_map.contains_key(&locator) {
                    // Either an update or an appointment from another user sharing the same locator
                    if locator_uuid_map.get_mut(&locator).unwrap().insert(uuid) {
                        log::debug!(
                            "Adding an additional appointment to locator {}: {}",
                            locator,
                            uuid
                        );
                        self.dbm
                            .lock()
                            .unwrap()
                            .store_appointment(uuid, &extended_appointment)
                            .unwrap();
                    } else {
                        log::debug!("Update received for {}, locator map not modified", uuid);
                        self.dbm
                            .lock()
                            .unwrap()
                            .update_appointment(uuid, &extended_appointment);
                    }
                } else {
                    // New appointment
                    locator_uuid_map.insert(locator, HashSet::from_iter(vec![uuid]));

                    self.dbm
                        .lock()
                        .unwrap()
                        .store_appointment(uuid, &extended_appointment)
                        .unwrap();
                }
            }
        }

        let mut receipt = AppointmentReceipt::new(
            extended_appointment.user_signature,
            extended_appointment.start_block,
        );
        receipt.sign(&self.signing_key);

        Ok((receipt, available_slots, expiry))
    }

    /// Retrieves an [Appointment] from the tower.
    ///
    /// Appointments can only be retrieved provided:
    /// - The user is registered into the system
    /// - The user subscription has not expired
    /// - The appointment belongs to the user
    /// - The appointment exists within the system (either in the [Watcher] or the [Responder])
    pub fn get_appointment(
        &self,
        locator: Locator,
        user_signature: &str,
    ) -> Result<AppointmentInfo, GetAppointmentFailure> {
        let message = format!("get appointment {}", locator);

        let user_id = self
            .gatekeeper
            .authenticate_user(message.as_bytes(), user_signature)
            .map_err(|_| GetAppointmentFailure::AuthenticationFailure)?;

        let (has_subscription_expired, expiry) =
            self.gatekeeper.has_subscription_expired(user_id).unwrap();

        if has_subscription_expired {
            return Err(GetAppointmentFailure::SubscriptionExpired(expiry));
        }

        let uuid = UUID::new(locator, user_id);

        if self.appointments.lock().unwrap().contains_key(&uuid) {
            Ok(AppointmentInfo::Appointment(
                self.dbm
                    .lock()
                    .unwrap()
                    .load_appointment(uuid)
                    .unwrap()
                    .inner,
            ))
        } else {
            self.responder
                .get_tracker(uuid)
                .map(|tracker| AppointmentInfo::Tracker(tracker))
                .ok_or({
                    log::info!("Cannot find {}", locator);
                    GetAppointmentFailure::NotFound
                })
        }
    }

    /// Gets a map of breaches provided a map between locators and transactions.
    ///
    /// The provided map if intersected with the map of all locators monitored by [Watcher] and the result
    /// is considered the list of all breaches. This is queried on a per-block basis with all the
    /// `(locator, transaction)` pairs computed from the transaction data.
    fn get_breaches(
        &self,
        locator_tx_map: HashMap<Locator, Transaction>,
    ) -> HashMap<Locator, Transaction> {
        let monitored_locators: HashSet<Locator> = self
            .locator_uuid_map
            .lock()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        let new_locators = locator_tx_map.keys().cloned().collect();
        let mut breaches = HashMap::new();

        for locator in monitored_locators.intersection(&new_locators) {
            let (k, v) = locator_tx_map.get_key_value(locator).unwrap();
            breaches.insert(*k, v.clone());
        }

        if breaches.is_empty() {
            log::info!("No breaches found")
        } else {
            log::debug!("List of breaches: {:?}", breaches.keys());
        }

        breaches
    }

    /// Filters a map of breaches between those that are valid and those that are not.
    ///
    /// Valid breaches are those resulting in a properly formatted [Transaction] once decrypted.
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

        let locator_uuid_map = self.locator_uuid_map.lock().unwrap();
        let dbm = self.dbm.lock().unwrap();
        for (locator, dispute_tx) in breaches.into_iter() {
            for uuid in locator_uuid_map.get(&locator).unwrap() {
                let appointment = dbm.load_appointment(*uuid).unwrap();
                match decrypted_blobs.get(appointment.encrypted_blob()) {
                    Some(penalty_tx) => {
                        valid_breaches.insert(
                            *uuid,
                            Breach::new(locator, dispute_tx.clone(), penalty_tx.clone()),
                        );
                    }
                    None => {
                        match cryptography::decrypt(
                            &appointment.encrypted_blob(),
                            &dispute_tx.txid(),
                        ) {
                            Ok(penalty_tx) => {
                                decrypted_blobs.insert(
                                    appointment.encrypted_blob().clone(),
                                    penalty_tx.clone(),
                                );
                                valid_breaches.insert(
                                    *uuid,
                                    Breach::new(locator, dispute_tx.clone(), penalty_tx),
                                );
                            }
                            Err(e) => {
                                invalid_breaches.insert(*uuid, e);
                            }
                        }
                    }
                }
            }
        }

        (valid_breaches, invalid_breaches)
    }

    // DISCUSS:: For outdated data this may be nicer if implemented with a callback from the GK given that:
    // - The GK is queried for the data to be deleted
    // - Appointment and tracker data can be deleted in cascade when a user is deleted
    // If done, the GK can notify the Watcher and Responder to delete data in memory and
    // take care of the database itself.

    // TODO: Document once modified given the above comment
    fn delete_appointments(&self, uuids: HashSet<UUID>, outdated: bool) {
        // FIXME: This is identical to Responder::delete_trackers. It can be implemented using generics.
        let mut appointments = self.appointments.lock().unwrap();
        let mut locator_uuid_map = self.locator_uuid_map.lock().unwrap();
        for uuid in uuids.iter() {
            if outdated {
                log::info!(
                    "End time reached without breach. Deleting appointment  {}",
                    uuid
                );
            } else {
                log::info!(
                    "Appointment cannot be completed, it contains invalid data. Deleting  {}",
                    uuid
                );
            }

            match appointments.remove(uuid) {
                Some(appointment) => {
                    let appointments = locator_uuid_map.get_mut(&appointment.locator).unwrap();

                    if appointments.len() == 1 {
                        locator_uuid_map.remove(&appointment.locator);

                        log::info!("No more appointments for locator: {}", appointment.locator);
                    } else {
                        appointments.remove(uuid);
                    }
                }
                None => {
                    // This should never happen. Logging just in case so we can fix it if so
                    log::error!("Appointment not found when cleaning: {}", uuid);
                }
            }
        }

        // Remove data from the database
        self.dbm.lock().unwrap().batch_remove_appointments(&uuids);
    }
}

/// Listen implementation by the [Watcher]. Handles monitoring and reorgs.
impl chain::Listen for Watcher {
    /// Handles the monitoring process by the [Watcher].
    ///
    /// Watching is performed in a per-block basis. Therefore, a breach is only considered (and detected) if seen
    /// in a block.
    ///
    /// Every time a new block is received a list of all potential locators is computed using the transaction data.
    /// Then, the potential locators are checked against the data being monitored by the [Watcher] and passed to the
    /// [Responder] if valid. Otherwise data is removed from the tower.
    ///
    /// This also takes care of updating the [LocatorCache] and removing outdated data from the [Watcher] when
    /// told by the [Gatekeeper].
    fn block_connected(&self, block: &Block, height: u32) {
        log::info!("New block received: {}", block.header.block_hash());

        let locator_tx_map = block
            .txdata
            .iter()
            .map(|tx| (Locator::new(tx.txid()), tx.clone()))
            .collect();

        self.locator_cache
            .lock()
            .unwrap()
            .update(block.header, &locator_tx_map);

        if !self.appointments.lock().unwrap().is_empty() {
            // Get a list of outdated appointments from the Gatekeeper. This appointments may be either in the Watcher
            // or in the Responder.
            let outdated_appointments = self.gatekeeper.get_outdated_appointments(height);
            self.delete_appointments(outdated_appointments, true);

            // Filter out those breaches that do not yield a valid transaction
            let (valid_breaches, invalid_breaches) =
                self.filter_breaches(self.get_breaches(locator_tx_map));

            let mut appointments_to_delete = HashSet::new();
            let mut appointments_to_delete_gatekeeper = HashMap::new();
            {
                let appointments = self.appointments.lock().unwrap();
                for uuid in invalid_breaches.into_keys() {
                    appointments_to_delete.insert(uuid);
                    appointments_to_delete_gatekeeper.insert(uuid, appointments[&uuid].user_id);
                }
            }

            // Send data to the Responder and remove it from the Watcher
            {
                let appointments = self.appointments.lock().unwrap();
                for (uuid, breach) in valid_breaches {
                    log::info!(
                        "Notifying Responder and deleting appointment (uuid: {})",
                        uuid
                    );

                    //DISCUSS: This cannot be async given block_connected is not.
                    // Is there any alternative? Remove async from here altogether?
                    block_on(self.responder.handle_breach(
                        uuid,
                        breach,
                        appointments[&uuid].user_id,
                    ));

                    appointments_to_delete.insert(uuid);
                }
            }

            // Delete data from the Watcher (invalid + triggered)
            self.delete_appointments(appointments_to_delete, false);

            // Delete data from the Gatekeeper
            self.gatekeeper
                .delete_appointments(&appointments_to_delete_gatekeeper);

            if self.appointments.lock().unwrap().is_empty() {
                log::info!("No more pending appointments");
            }
        }

        *self.last_known_block_header.lock().unwrap() = BlockHeaderData {
            header: block.header,
            height,
            chainwork: block.header.work(),
        };
        self.dbm
            .lock()
            .unwrap()
            .store_last_known_block_watcher(&block.header.block_hash());
    }

    #[allow(unused_variables)]
    /// FIXME: To be implemented.
    /// This will handle reorgs on the [Watcher].
    fn block_disconnected(&self, header: &BlockHeader, height: u32) {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::carrier::Carrier;
    use crate::dbm::{Error as DBError, DBM};
    use crate::rpc_errors;
    use crate::test_utils::{
        create_carrier, generate_dummy_appointment, generate_dummy_appointment_with_user,
        generate_uuid, get_random_breach_from_locator, get_random_tx, start_server,
        store_appointment_and_fks_to_db, BitcoindMock, Blockchain, MockOptions, MockedServerQuery,
        DURATION, EXPIRY_DELTA, SLOTS, START_HEIGHT,
    };
    use teos_common::cryptography::{get_random_bytes, get_random_keypair};

    use bitcoin::hash_types::Txid;
    use bitcoin::hashes::Hash;
    use bitcoin::network::constants::Network;
    use bitcoin::secp256k1::key::ONE_KEY;
    use bitcoin::secp256k1::{PublicKey, Secp256k1};
    use bitcoincore_rpc::{Auth, Client as BitcoindClient};
    use lightning::chain::Listen;
    use lightning_block_sync::poll::{ChainPoller, Poll};
    use std::sync::{Arc, Mutex};

    const TOWER_SK: SecretKey = ONE_KEY;

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

    fn create_responder(
        tip: ValidatedBlockHeader,
        gatekeeper: Arc<Gatekeeper>,
        dbm: Arc<Mutex<DBM>>,
        server_url: String,
    ) -> Responder {
        let bitcoin_cli = Arc::new(BitcoindClient::new(server_url, Auth::None).unwrap());
        let carrier = Carrier::new(bitcoin_cli);

        Responder::new(carrier, gatekeeper, dbm, tip)
    }

    async fn create_watcher(
        chain: &mut Blockchain,
        responder: Arc<Responder>,
        gatekeeper: Arc<Gatekeeper>,
        bitcoind_mock: BitcoindMock,
        dbm: Arc<Mutex<DBM>>,
    ) -> Watcher {
        let tip = chain.tip();
        let last_n_blocks = get_last_n_blocks(chain, 6).await;

        start_server(bitcoind_mock);
        Watcher::new(gatekeeper, responder, last_n_blocks, tip, TOWER_SK, dbm).await
    }

    fn assert_appointment_added(
        slots: u32,
        expected_slots: u32,
        expiry: u32,
        receipt: AppointmentReceipt,
        expected_user_signature: &str,
        tower_id: UserId,
    ) {
        assert_eq!(slots, expected_slots);
        assert_eq!(expiry, START_HEIGHT as u32 + DURATION);
        assert_eq!(receipt.start_block(), START_HEIGHT as u32);
        assert_eq!(receipt.user_signature(), expected_user_signature);
        let recovered_pk =
            cryptography::recover_pk(&receipt.serialize(), &receipt.signature().unwrap()).unwrap();
        assert_eq!(UserId(recovered_pk), tower_id);
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
        let bitcoind_mock = BitcoindMock::new(MockOptions::empty());
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, None);

        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let gk = Arc::new(Gatekeeper::new(
            chain.tip(),
            SLOTS,
            DURATION,
            EXPIRY_DELTA,
            dbm.clone(),
        ));
        let responder = create_responder(chain.tip(), gk.clone(), dbm.clone(), bitcoind_mock.url());
        let watcher = create_watcher(
            &mut chain,
            Arc::new(responder),
            gk.clone(),
            bitcoind_mock,
            dbm.clone(),
        )
        .await;
        let tower_pk = PublicKey::from_secret_key(&Secp256k1::new(), &TOWER_SK);

        let (_, user_pk) = get_random_keypair();
        let user_id = UserId(user_pk);
        let receipt = watcher.register(user_id).unwrap();

        assert_eq!(receipt.user_id(), user_id);
        assert_eq!(receipt.available_slots(), SLOTS);
        assert_eq!(
            receipt.subscription_expiry(),
            START_HEIGHT as u32 + DURATION
        );

        assert!(cryptography::verify(
            &receipt.serialize(),
            &receipt.signature().unwrap(),
            &tower_pk
        ));
    }

    #[tokio::test]
    async fn test_add_appointment() {
        let bitcoind_mock = BitcoindMock::new(MockOptions::empty());
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, None);
        let tip_txs = chain.blocks.last().unwrap().txdata.clone();

        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let gk = Arc::new(Gatekeeper::new(
            chain.tip(),
            SLOTS,
            DURATION,
            EXPIRY_DELTA,
            dbm.clone(),
        ));
        let responder = create_responder(chain.tip(), gk.clone(), dbm.clone(), bitcoind_mock.url());
        let watcher = create_watcher(
            &mut chain,
            Arc::new(responder),
            gk.clone(),
            bitcoind_mock,
            dbm.clone(),
        )
        .await;

        // add_appointment should add a given appointment to the Watcher given the following logic:
        //      - if the appointment does not exist for a given user, add the appointment
        //      - if the appointment already exists for a given user, update the data
        //      - if the appointment is already in the Responder, reject
        //      - if the trigger for the appointment is in the cache, trigger straightaway
        //      - DISCUSS: if the appointment is accepted but bounces in the Responder, do not reduce the subscription count
        // In any of the cases where the appointment should be added to the Watcher, the appointment will be rejected if:
        //      - the user does not have enough slots (either to add or update)
        //      - the subscription has expired

        let tower_id: UserId = UserId(PublicKey::from_secret_key(
            &Secp256k1::new(),
            &watcher.signing_key,
        ));
        let (user_sk, user_pk) = get_random_keypair();
        let user_id = UserId(user_pk);
        watcher.register(user_id).unwrap();
        let appointment = generate_dummy_appointment(None).inner;

        // Add the appointment for a new user (twice so we can check that updates work)
        for _ in 0..2 {
            let user_sig = cryptography::sign(&appointment.serialize(), &user_sk).unwrap();
            let (receipt, slots, expiry) = watcher
                .add_appointment(appointment.clone(), user_sig.clone())
                .await
                .unwrap();

            assert_appointment_added(slots, SLOTS - 1, expiry, receipt, &user_sig, tower_id);
        }

        // Add the same appointment but for another user
        let (user2_sk, user2_pk) = get_random_keypair();
        let user2_id = UserId(user2_pk);
        watcher.register(user2_id).unwrap();

        let user2_sig = cryptography::sign(&appointment.serialize(), &user2_sk).unwrap();
        let (receipt, slots, expiry) = watcher
            .add_appointment(appointment.clone(), user2_sig.clone())
            .await
            .unwrap();

        assert_appointment_added(slots, SLOTS - 1, expiry, receipt, &user2_sig, tower_id);

        // There should be now two appointments in the Watcher and the same locator should have two different uuids
        assert_eq!(watcher.appointments.lock().unwrap().len(), 2);
        assert_eq!(
            watcher.locator_uuid_map.lock().unwrap()[&appointment.locator].len(),
            2
        );

        // Check data was added to the database
        for uuid in watcher.appointments.lock().unwrap().keys() {
            assert!(matches!(
                dbm.lock().unwrap().load_appointment(*uuid),
                Ok(ExtendedAppointment { .. })
            ));
        }

        // If an appointment is already in the Responder, it should bounce
        let (uuid, triggered_appointment) = generate_dummy_appointment_with_user(user_id, None);
        let signature =
            cryptography::sign(&triggered_appointment.inner.serialize(), &user_sk).unwrap();
        watcher
            .add_appointment(triggered_appointment.inner.clone(), signature.clone())
            .await
            .unwrap();

        let breach = get_random_breach_from_locator(triggered_appointment.locator());
        watcher.responder.add_tracker(uuid, breach, user_id, 0);
        let receipt = watcher
            .add_appointment(triggered_appointment.inner, signature)
            .await;
        assert!(matches!(
            receipt,
            Err(AddAppointmentFailure::AlreadyTriggered)
        ));

        // If the trigger is already in the cache, the appointment will go straight to the Responder
        let dispute_tx = tip_txs.last().unwrap();
        let (uuid, appointment_in_cache) =
            generate_dummy_appointment_with_user(user_id, Some(&dispute_tx.txid()));
        let user_sig =
            cryptography::sign(&appointment_in_cache.inner.serialize(), &user_sk).unwrap();
        let (receipt, slots, expiry) = watcher
            .add_appointment(appointment_in_cache.inner.clone(), user_sig.clone())
            .await
            .unwrap();

        // The appointment should have been accepted, slots should have been decreased, and data should have been deleted from
        // the Watcher's memory. Moreover, a new tracker should be found in the Responder
        assert_appointment_added(slots, SLOTS - 3, expiry, receipt, &user_sig, tower_id);
        assert_eq!(watcher.appointments.lock().unwrap().len(), 3);
        assert!(!watcher
            .locator_uuid_map
            .lock()
            .unwrap()
            .contains_key(&appointment_in_cache.locator()));
        assert!(watcher.responder.has_tracker(uuid));

        // Check data was added to the database
        assert!(matches!(
            dbm.lock().unwrap().load_appointment(uuid),
            Ok(ExtendedAppointment { .. })
        ));
        assert!(matches!(
            dbm.lock().unwrap().load_tracker(uuid),
            Ok(TransactionTracker { .. })
        ));

        // If an appointment is rejected by the Responder, it is considered misbehavior and the slot count is kept
        // Wrong penalty
        let dispute_tx = &tip_txs[tip_txs.len() - 2];
        let (uuid, mut invalid_appointment) =
            generate_dummy_appointment_with_user(user_id, Some(&dispute_tx.txid()));
        invalid_appointment.inner.encrypted_blob.reverse();
        let user_sig =
            cryptography::sign(&invalid_appointment.inner.serialize(), &user_sk).unwrap();
        let (receipt, slots, expiry) = watcher
            .add_appointment(invalid_appointment.inner.clone(), user_sig.clone())
            .await
            .unwrap();

        assert_appointment_added(slots, SLOTS - 4, expiry, receipt, &user_sig, tower_id);
        assert_eq!(watcher.appointments.lock().unwrap().len(), 3);

        // Data should not be in the database
        assert!(matches!(
            dbm.lock().unwrap().load_appointment(uuid),
            Err(DBError::NotFound)
        ));
        assert!(matches!(
            dbm.lock().unwrap().load_tracker(uuid),
            Err(DBError::NotFound)
        ));

        // Transaction rejected
        // Update the Responder with a new Carrier
        *watcher.responder.get_carrier().lock().unwrap() = create_carrier(
            MockedServerQuery::Error(rpc_errors::RPC_VERIFY_ERROR as i64),
        );

        let dispute_tx = &tip_txs[tip_txs.len() - 2];
        let invalid_appointment = generate_dummy_appointment(Some(&dispute_tx.txid())).inner;
        let user_sig = cryptography::sign(&invalid_appointment.serialize(), &user_sk).unwrap();
        let (receipt, slots, expiry) = watcher
            .add_appointment(invalid_appointment.clone(), user_sig.clone())
            .await
            .unwrap();

        assert_appointment_added(slots, SLOTS - 4, expiry, receipt, &user_sig, tower_id);
        assert_eq!(watcher.appointments.lock().unwrap().len(), 3);

        // Data should not be in the database
        assert!(matches!(
            dbm.lock().unwrap().load_appointment(uuid),
            Err(DBError::NotFound)
        ));

        // FAIL cases (non-registered, subscription expired and not enough slots)

        // If the user is not registered, trying to add an appointment should fail. Since user_ids are
        // computed using ECRecovery, we can simulate a non-registered user by creating a "random" signature
        let user3_sig = String::from_utf8((0..65).collect()).unwrap();

        assert!(matches!(
            watcher
                .add_appointment(appointment.clone(), user3_sig.clone())
                .await,
            Err(AddAppointmentFailure::AuthenticationFailure)
        ));
        // Data should not be in the database
        assert!(matches!(
            dbm.lock().unwrap().load_appointment(uuid),
            Err(DBError::NotFound)
        ));

        // If the user has no enough slots, the appointment is rejected. We do not test all possible cases since updates are
        // already tested int he Gatekeeper. Testing that it is  rejected if the condition is met should suffice.
        watcher
            .gatekeeper
            .get_registered_users()
            .lock()
            .unwrap()
            .get_mut(&user_id)
            .unwrap()
            .available_slots = 0;

        let dispute_txid = Txid::from_slice(&get_random_bytes(32)).unwrap();
        let new_appointment = generate_dummy_appointment(Some(&dispute_txid)).inner;
        let new_app_sig = cryptography::sign(&new_appointment.serialize(), &user_sk).unwrap();

        assert!(matches!(
            watcher.add_appointment(new_appointment, new_app_sig).await,
            Err(AddAppointmentFailure::NotEnoughSlots)
        ));
        // Data should not be in the database
        assert!(matches!(
            dbm.lock().unwrap().load_appointment(uuid),
            Err(DBError::NotFound)
        ));

        // If the user subscription has expired, the appointment should be rejected.
        watcher
            .gatekeeper
            .get_registered_users()
            .lock()
            .unwrap()
            .get_mut(&user2_id)
            .unwrap()
            .subscription_expiry = START_HEIGHT as u32;

        assert!(matches!(
            watcher
                .add_appointment(appointment.clone(), user2_sig.clone())
                .await,
            Err(AddAppointmentFailure::SubscriptionExpired { .. })
        ));
        // Data should not be in the database
        assert!(matches!(
            dbm.lock().unwrap().load_appointment(uuid),
            Err(DBError::NotFound)
        ));
    }

    #[tokio::test]
    async fn test_get_appointment() {
        let bitcoind_mock = BitcoindMock::new(MockOptions::empty());
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, None);

        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let gk = Arc::new(Gatekeeper::new(
            chain.tip(),
            SLOTS,
            DURATION,
            EXPIRY_DELTA,
            dbm.clone(),
        ));
        let responder = create_responder(chain.tip(), gk.clone(), dbm.clone(), bitcoind_mock.url());
        let watcher = create_watcher(
            &mut chain,
            Arc::new(responder),
            gk.clone(),
            bitcoind_mock,
            dbm.clone(),
        )
        .await;

        let appointment = generate_dummy_appointment(None).inner;

        //  If the user cannot be properly identified, the request will fail. This can be simulated by providing a wrong signature
        let wrong_sig = String::from_utf8((0..65).collect()).unwrap();
        assert!(matches!(
            watcher.get_appointment(appointment.locator, &wrong_sig),
            Err(GetAppointmentFailure::AuthenticationFailure)
        ));

        // If the user does exist and there's an appointment with the given locator belonging to him, it will be returned
        let (user_sk, user_pk) = get_random_keypair();
        let user_id = UserId(user_pk);
        watcher.register(user_id).unwrap();
        watcher
            .add_appointment(
                appointment.clone(),
                cryptography::sign(&appointment.serialize(), &user_sk).unwrap(),
            )
            .await
            .unwrap();

        let message = format!("get appointment {}", appointment.locator);
        let signature = cryptography::sign(message.as_bytes(), &user_sk).unwrap();
        let info = watcher
            .get_appointment(appointment.locator, &signature)
            .unwrap();

        match info {
            AppointmentInfo::Appointment(a) => assert_eq!(a, appointment),
            AppointmentInfo::Tracker { .. } => assert!(false),
        }

        // If the appointment is in the Responder (in the form of a Tracker), data should be also returned

        // Remove the data from the Watcher memory first (data is kept in the db tho)
        let uuid = UUID::new(appointment.locator, user_id);
        watcher.appointments.lock().unwrap().remove(&uuid);
        watcher
            .locator_uuid_map
            .lock()
            .unwrap()
            .remove(&appointment.locator);

        // Add data to the Responder
        let breach = get_random_breach_from_locator(appointment.locator);
        let tracker = TransactionTracker::new(breach.clone(), user_id);

        watcher.responder.add_tracker(uuid, breach, user_id, 0);

        let tracker_message = format!("get appointment {}", tracker.locator);
        let tracker_signature = cryptography::sign(tracker_message.as_bytes(), &user_sk).unwrap();
        let info = watcher
            .get_appointment(tracker.locator, &tracker_signature)
            .unwrap();

        match info {
            AppointmentInfo::Appointment { .. } => assert!(false),
            AppointmentInfo::Tracker(t) => assert_eq!(t, tracker),
        }

        // If the user does exists but the requested locator does not belong to any of their associated appointments, NotFound
        // should be returned.
        let (user2_sk, user2_pk) = get_random_keypair();
        let user2_id = UserId(user2_pk);
        watcher.register(user2_id).unwrap();

        let signature2 = cryptography::sign(message.as_bytes(), &user2_sk).unwrap();
        assert!(matches!(
            watcher.get_appointment(appointment.locator, &signature2),
            Err(GetAppointmentFailure::NotFound { .. })
        ));

        // If the user subscription has expired, the request will fail
        watcher
            .gatekeeper
            .get_registered_users()
            .lock()
            .unwrap()
            .get_mut(&user_id)
            .unwrap()
            .subscription_expiry = START_HEIGHT as u32;

        assert!(matches!(
            watcher.get_appointment(appointment.locator, &signature),
            Err(GetAppointmentFailure::SubscriptionExpired { .. })
        ));
    }

    #[tokio::test]
    async fn test_get_breaches() {
        let bitcoind_mock = BitcoindMock::new(MockOptions::empty());
        let mut chain = Blockchain::default().with_height_and_txs(12, None);
        let txs = chain.blocks.last().unwrap().txdata.clone();

        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let gk = Arc::new(Gatekeeper::new(
            chain.tip(),
            SLOTS,
            DURATION,
            EXPIRY_DELTA,
            dbm.clone(),
        ));
        let responder = create_responder(chain.tip(), gk.clone(), dbm.clone(), bitcoind_mock.url());
        let watcher = create_watcher(
            &mut chain,
            Arc::new(responder),
            gk.clone(),
            bitcoind_mock,
            dbm.clone(),
        )
        .await;

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
                    .lock()
                    .unwrap()
                    .insert(*locator, HashSet::from_iter(vec![generate_uuid()]));
            }
        }

        // Check that breaches are correctly detected
        let breaches = watcher.get_breaches(locator_tx_map);
        let locator_uuid_map = watcher.locator_uuid_map.lock().unwrap();
        assert!(
            breaches.len() == locator_uuid_map.len()
                && breaches.keys().all(|k| locator_uuid_map.contains_key(k))
        );
    }

    #[tokio::test]
    async fn test_filter_breaches() {
        let bitcoind_mock = BitcoindMock::new(MockOptions::empty());
        let mut chain = Blockchain::default().with_height_and_txs(10, Some(12));
        let txs = chain.blocks.last().unwrap().txdata.clone();

        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let gk = Arc::new(Gatekeeper::new(
            chain.tip(),
            SLOTS,
            DURATION,
            EXPIRY_DELTA,
            dbm.clone(),
        ));
        let responder = create_responder(chain.tip(), gk.clone(), dbm.clone(), bitcoind_mock.url());
        let watcher = create_watcher(
            &mut chain,
            Arc::new(responder),
            gk.clone(),
            bitcoind_mock,
            dbm.clone(),
        )
        .await;

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

                let appointment = generate_dummy_appointment(dispute_txid);

                watcher
                    .appointments
                    .lock()
                    .unwrap()
                    .insert(uuid, appointment.get_summary());
                watcher
                    .locator_uuid_map
                    .lock()
                    .unwrap()
                    .insert(*locator, HashSet::from_iter(vec![uuid]));

                // Store data in the database (the user needs to be there as well since it is a FK for appointments)
                store_appointment_and_fks_to_db(&dbm.lock().unwrap(), uuid, &appointment);
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
    async fn test_delete_appointments() {
        // TODO: This is an adaptation of Responder::test_delete_trackers, merge together once the method
        // is implemented using generics.
        let bitcoind_mock = BitcoindMock::new(MockOptions::empty());
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, None);

        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let gk = Arc::new(Gatekeeper::new(
            chain.tip(),
            SLOTS,
            DURATION,
            EXPIRY_DELTA,
            dbm.clone(),
        ));
        let responder = create_responder(chain.tip(), gk.clone(), dbm.clone(), bitcoind_mock.url());
        let watcher = create_watcher(
            &mut chain,
            Arc::new(responder),
            gk.clone(),
            bitcoind_mock,
            dbm.clone(),
        )
        .await;

        // Delete appointments removes data from the appointments and locator_uuid_map
        // Add data to the map first
        let mut all_appointments = HashSet::new();
        let mut target_appointments = HashSet::new();
        let mut uuid_locator_map = HashMap::new();
        let mut locator_with_multiple_uuids = HashSet::new();

        for i in 0..10 {
            let uuid = generate_uuid();
            let appointment = generate_dummy_appointment(None);
            watcher
                .appointments
                .lock()
                .unwrap()
                .insert(uuid, appointment.clone().get_summary());
            watcher
                .locator_uuid_map
                .lock()
                .unwrap()
                .insert(appointment.locator(), HashSet::from_iter([uuid]));

            // Add data to the database to check data deletion
            store_appointment_and_fks_to_db(&dbm.lock().unwrap(), uuid, &appointment);

            // Make it so some of the locators have multiple associated uuids
            if i % 3 == 0 {
                // We don't need to store this properly since they will not be targeted
                let uuid2 = generate_uuid();
                watcher
                    .locator_uuid_map
                    .lock()
                    .unwrap()
                    .get_mut(&appointment.locator())
                    .unwrap()
                    .insert(uuid2);
                locator_with_multiple_uuids.insert(appointment.locator());
            }

            all_appointments.insert(uuid);
            uuid_locator_map.insert(uuid, appointment.locator());

            // Add some appointments to be deleted
            if i % 2 == 0 {
                target_appointments.insert(uuid);
            }
        }

        watcher.delete_appointments(target_appointments.clone(), false);

        // Only appointments in the target_appointments map should have been removed from
        // the Watcher's data structures.
        for uuid in all_appointments {
            if target_appointments.contains(&uuid) {
                assert!(!watcher.appointments.lock().unwrap().contains_key(&uuid));
                assert!(matches!(
                    dbm.lock().unwrap().load_appointment(uuid),
                    Err(DBError::NotFound)
                ));

                let locator = &uuid_locator_map[&uuid];
                // If the penalty had more than one associated uuid, only one has been deleted
                // (because that's how the test has been designed)
                if locator_with_multiple_uuids.contains(locator) {
                    assert_eq!(
                        watcher
                            .locator_uuid_map
                            .lock()
                            .unwrap()
                            .get(locator)
                            .unwrap()
                            .len(),
                        1
                    );
                } else {
                    // Otherwise the whole structure is removed, given it is now empty
                    assert!(!watcher
                        .locator_uuid_map
                        .lock()
                        .unwrap()
                        .contains_key(locator));
                }
            } else {
                assert!(watcher.appointments.lock().unwrap().contains_key(&uuid));
                assert!(watcher
                    .locator_uuid_map
                    .lock()
                    .unwrap()
                    .contains_key(&uuid_locator_map[&uuid]));
                assert!(matches!(
                    dbm.lock().unwrap().load_appointment(uuid),
                    Ok(ExtendedAppointment { .. })
                ));
            }
        }
    }

    #[tokio::test]
    async fn test_block_connected() {
        let bitcoind_mock = BitcoindMock::new(MockOptions::empty());
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, None);

        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let gk = Arc::new(Gatekeeper::new(
            chain.tip(),
            SLOTS,
            DURATION,
            EXPIRY_DELTA,
            dbm.clone(),
        ));
        let responder = create_responder(chain.tip(), gk.clone(), dbm.clone(), bitcoind_mock.url());
        let watcher = create_watcher(
            &mut chain,
            Arc::new(responder),
            gk.clone(),
            bitcoind_mock,
            dbm.clone(),
        )
        .await;

        // block_connected for the Watcher is used to keep track of what new transactions has been mined whose may be potential
        // channel breaches.

        // If the Watcher is not watching any appointment, block_connected will only be used to keep track of the last known block
        // by the Watcher.
        assert_eq!(
            watcher.last_known_block_header.lock().unwrap().header,
            chain.tip().header
        );
        watcher.block_connected(&chain.generate(None), chain.blocks.len() as u32);
        assert_eq!(
            watcher.last_known_block_header.lock().unwrap().header,
            chain.tip().header
        );
        // Check the data also matches the on in database
        assert_eq!(
            watcher
                .dbm
                .lock()
                .unwrap()
                .load_last_known_block_watcher()
                .unwrap(),
            chain.tip().header.block_hash()
        );

        // If there are appointments to watch, the Watcher will:
        //  - Check if any new transaction is a trigger
        //      - Check if a trigger is valid, if so pass the data to the Responder
        //  - Delete invalid appointments.
        //  - Delete appointments that have been outdated (i.e. have expired without a trigger)
        //  - Delete invalid appointments also from the Gatekeeper (not outdated tough, the GK will take care of those via it's own Listen)

        // Let's first check how data gets outdated (create two users, add an appointment to both and outdate only one)
        let (user_sk, user_pk) = get_random_keypair();
        let user_id = UserId(user_pk);
        let (user2_sk, user2_pk) = get_random_keypair();
        let user2_id = UserId(user2_pk);
        watcher.register(user_id).unwrap();
        watcher.register(user2_id).unwrap();

        let appointment = generate_dummy_appointment(None);
        let uuid1 = UUID::new(appointment.locator(), user_id);
        let uuid2 = UUID::new(appointment.locator(), user2_id);

        let user_sig = cryptography::sign(&appointment.inner.serialize(), &user_sk).unwrap();
        watcher
            .add_appointment(appointment.inner.clone(), user_sig)
            .await
            .unwrap();
        let user2_sig = cryptography::sign(&appointment.inner.serialize(), &user2_sk).unwrap();
        watcher
            .add_appointment(appointment.inner.clone(), user2_sig)
            .await
            .unwrap();

        watcher
            .gatekeeper
            .get_registered_users()
            .lock()
            .unwrap()
            .get_mut(&user_id)
            .unwrap()
            .subscription_expiry = (chain.blocks.len() as u32) - EXPIRY_DELTA + 1;

        // Both appointments can be found before mining a block, only the user's 2 can be found afterwards
        for uuid in vec![uuid1, uuid2] {
            assert!(watcher.appointments.lock().unwrap().contains_key(&uuid));
            assert!(
                watcher.locator_uuid_map.lock().unwrap()[&appointment.locator()].contains(&uuid)
            );
        }
        assert!(
            watcher.gatekeeper.get_registered_users().lock().unwrap()[&user_id]
                .appointments
                .contains_key(&uuid1)
        );
        assert!(
            watcher.gatekeeper.get_registered_users().lock().unwrap()[&user2_id]
                .appointments
                .contains_key(&uuid2)
        );

        watcher.block_connected(&chain.generate(None), chain.blocks.len() as u32);

        assert!(!watcher.appointments.lock().unwrap().contains_key(&uuid1));
        assert!(!watcher.locator_uuid_map.lock().unwrap()[&appointment.locator()].contains(&uuid1));
        assert!(
            watcher.gatekeeper.get_registered_users().lock().unwrap()[&user_id]
                .appointments
                .contains_key(&uuid1)
        );
        assert!(matches!(
            dbm.lock().unwrap().load_appointment(uuid1),
            Err(DBError::NotFound)
        ));

        assert!(watcher.appointments.lock().unwrap().contains_key(&uuid2));
        assert!(watcher.locator_uuid_map.lock().unwrap()[&appointment.locator()].contains(&uuid2));
        assert!(
            watcher.gatekeeper.get_registered_users().lock().unwrap()[&user2_id]
                .appointments
                .contains_key(&uuid2)
        );
        assert!(matches!(
            dbm.lock().unwrap().load_appointment(uuid2),
            Ok(ExtendedAppointment { .. })
        ));

        // Check triggers. Add a new appointment and trigger it with valid data.
        let dispute_tx = get_random_tx();
        let appointment = generate_dummy_appointment(Some(&dispute_tx.txid()));
        let sig = cryptography::sign(&appointment.inner.serialize(), &user2_sk).unwrap();
        let uuid = UUID::new(appointment.locator(), user2_id);
        watcher
            .add_appointment(appointment.inner.clone(), sig)
            .await
            .unwrap();

        assert!(watcher.appointments.lock().unwrap().contains_key(&uuid));

        watcher.block_connected(
            &chain.generate(Some(vec![dispute_tx])),
            chain.blocks.len() as u32,
        );

        // Data should have been moved to the Responder and kept in the Gatekeeper, since it is still part of the system.
        assert!(!watcher.appointments.lock().unwrap().contains_key(&uuid));
        assert!(watcher
            .responder
            .get_trackers()
            .lock()
            .unwrap()
            .contains_key(&uuid));
        assert!(
            watcher.gatekeeper.get_registered_users().lock().unwrap()[&user2_id]
                .appointments
                .contains_key(&uuid)
        );

        // Checks invalid triggers. Add a new appointment and trigger it with invalid data.
        let dispute_tx = get_random_tx();
        let mut appointment = generate_dummy_appointment(Some(&dispute_tx.txid()));
        // Modify the encrypted blob so the data is invalid.
        //Both non-decryptable blobs and blobs with invalid transactions will yield an invalid trigger
        appointment.inner.encrypted_blob.reverse();
        let sig = cryptography::sign(&appointment.inner.serialize(), &user2_sk).unwrap();
        let uuid = UUID::new(appointment.locator(), user2_id);
        watcher
            .add_appointment(appointment.inner.clone(), sig)
            .await
            .unwrap();

        watcher.block_connected(
            &chain.generate(Some(vec![dispute_tx])),
            chain.blocks.len() as u32,
        );

        // Data has been wiped since it was invalid
        assert!(!watcher.appointments.lock().unwrap().contains_key(&uuid));
        assert!(!watcher
            .responder
            .get_trackers()
            .lock()
            .unwrap()
            .contains_key(&uuid));
        assert!(
            !watcher.gatekeeper.get_registered_users().lock().unwrap()[&user2_id]
                .appointments
                .contains_key(&uuid)
        );
        assert!(matches!(
            dbm.lock().unwrap().load_appointment(uuid),
            Err(DBError::NotFound)
        ));
    }
}
