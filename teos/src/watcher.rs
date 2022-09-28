//! Logic related to the Watcher, the components in charge of watching for breaches on chain.

use log;

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use bitcoin::secp256k1::SecretKey;
use bitcoin::{BlockHeader, Transaction};
use lightning::chain;
use lightning_block_sync::poll::ValidatedBlock;

use teos_common::appointment::{Appointment, Locator};
use teos_common::cryptography;
use teos_common::receipts::{AppointmentReceipt, RegistrationReceipt};
use teos_common::{TowerId, UserId};

use crate::dbm::DBM;
use crate::extended_appointment::{AppointmentSummary, ExtendedAppointment, UUID};
use crate::gatekeeper::{Gatekeeper, MaxSlotsReached, UserInfo};
use crate::responder::{ConfirmationStatus, Responder, TransactionTracker};
use crate::tx_index::TxIndex;

/// Structure holding data regarding a breach.
///
/// Breaches are computed after spotting a [Locator] on chain and
/// using the resulting dispute transaction id to decipher the encrypted blob of an ongoing [Appointment].
/// Breaches are passed to the [Responder] once created.
#[derive(Debug, Clone)]
pub(crate) struct Breach {
    /// Transaction that triggered the breach.
    pub dispute_tx: Transaction,
    /// Transaction that will be used as a response to the breach.
    pub penalty_tx: Transaction,
}

impl Breach {
    /// Creates a new [Breach] instance.
    pub fn new(dispute_tx: Transaction, penalty_tx: Transaction) -> Self {
        Breach {
            dispute_tx,
            penalty_tx,
        }
    }
}

/// Packs the reasons why trying to add an appointment may fail.
// TODO: It may be nice to create richer errors so the API can return richer rejection
#[derive(Debug)]
pub(crate) enum AddAppointmentFailure {
    AuthenticationFailure,
    NotEnoughSlots,
    SubscriptionExpired(u32),
    AlreadyTriggered,
}

/// Packs the reasons why trying to query an appointment may fail.
#[derive(Debug)]
pub(crate) enum GetAppointmentFailure {
    AuthenticationFailure,
    SubscriptionExpired(u32),
    NotFound,
}

/// Packs the reasons why trying to query a subscription info may fail.
#[derive(Debug)]
pub(crate) enum GetSubscriptionInfoFailure {
    AuthenticationFailure,
    SubscriptionExpired(u32),
}

/// Wraps the returning information regarding a queried appointment.
///
/// Either an [Appointment] or a [TransactionTracker] can be
/// returned depending on whether the appointment can be found in the [Watcher] or in the [Responder].
#[derive(Debug)]
pub(crate) enum AppointmentInfo {
    Appointment(Appointment),
    Tracker(TransactionTracker),
}

/// Reason why the appointment is deleted. Used for logging purposes.
enum DeletionReason {
    Outdated,
    Invalid,
    Accepted,
}

/// Types of new appointments stored in the [Watcher].
#[derive(Debug, PartialEq, Eq)]
enum StoredAppointment {
    New,
    Update,
    Collision,
}

/// Types of new triggered appointments handled by the [Watcher].
#[derive(Debug, PartialEq, Eq)]
enum TriggeredAppointment {
    Accepted,
    Rejected,
    Invalid,
}

/// Component in charge of watching for triggers in the chain (aka channel breaches for lightning).
#[derive(Debug)]
pub struct Watcher {
    /// A map holding a summary of every appointment ([ExtendedAppointment]) hold by the [Watcher], identified by a [UUID].
    appointments: Mutex<HashMap<UUID, AppointmentSummary>>,
    /// A map between [Locator]s (user identifiers for [Appointment]s) and [UUID]s (tower identifiers).
    locator_uuid_map: Mutex<HashMap<Locator, HashSet<UUID>>>,
    /// A cache of the [Locator]s computed for the transactions in the last few blocks.
    locator_cache: Mutex<TxIndex<Locator, Transaction>>,
    /// A [Responder] instance. Data will be passed to it once triggered (if valid).
    responder: Arc<Responder>,
    /// A [Gatekeeper] instance. Data regarding users is requested to it.
    gatekeeper: Arc<Gatekeeper>,
    /// The last known block height.
    last_known_block_height: AtomicU32,
    /// The tower signing key. Used to sign messages going to users.
    signing_key: SecretKey,
    /// The tower identifier.
    pub tower_id: TowerId,
    /// A [DBM] (database manager) instance. Used to persist appointment data into disk.
    dbm: Arc<Mutex<DBM>>,
}

impl Watcher {
    /// Creates a new [Watcher] instance.
    pub fn new(
        gatekeeper: Arc<Gatekeeper>,
        responder: Arc<Responder>,
        last_n_blocks: &[ValidatedBlock],
        last_known_block_height: u32,
        signing_key: SecretKey,
        tower_id: TowerId,
        dbm: Arc<Mutex<DBM>>,
    ) -> Self {
        let mut appointments = HashMap::new();
        let mut locator_uuid_map: HashMap<Locator, HashSet<UUID>> = HashMap::new();
        for (uuid, appointment) in dbm.lock().unwrap().load_appointments(None) {
            appointments.insert(uuid, appointment.get_summary());

            if let Some(map) = locator_uuid_map.get_mut(&appointment.locator()) {
                map.insert(uuid);
            } else {
                locator_uuid_map.insert(appointment.locator(), HashSet::from_iter(vec![uuid]));
            }
        }

        Watcher {
            appointments: Mutex::new(appointments),
            locator_uuid_map: Mutex::new(locator_uuid_map),
            locator_cache: Mutex::new(TxIndex::new(last_n_blocks, last_known_block_height)),
            responder,
            gatekeeper,
            last_known_block_height: AtomicU32::new(last_known_block_height),
            signing_key,
            tower_id,
            dbm,
        }
    }

    /// Returns whether the [Watcher] has been created from scratch (fresh) or from backed-up data.
    pub fn is_fresh(&self) -> bool {
        self.appointments.lock().unwrap().is_empty()
    }

    /// Registers a new user within the [Watcher]. This request is passed to the [Gatekeeper], who is in
    /// charge of managing users.
    pub(crate) fn register(&self, user_id: UserId) -> Result<RegistrationReceipt, MaxSlotsReached> {
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
    pub(crate) fn add_appointment(
        &self,
        appointment: Appointment,
        user_signature: String,
    ) -> Result<(AppointmentReceipt, u32, u32), AddAppointmentFailure> {
        let user_id = self
            .gatekeeper
            .authenticate_user(&appointment.to_vec(), &user_signature)
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
            self.last_known_block_height.load(Ordering::Acquire),
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

        // FIXME: There's an edge case here if store_triggered_appointment is called and bitcoind is unreachable.
        // This will hang, the request will timeout but be accepted. However, the user will not be handed the receipt.
        // This could be fixed adding a thread to take care of storing while the main thread returns the receipt.
        // Not fixing this atm since working with threads that call self.method is surprisingly non-trivial.
        match self
            .locator_cache
            .lock()
            .unwrap()
            .get(&extended_appointment.locator())
        {
            // Appointments that were triggered in blocks held in the cache
            Some(dispute_tx) => {
                self.store_triggered_appointment(uuid, &extended_appointment, user_id, dispute_tx);
            }
            // Regular appointments that have not been triggered (or, at least, not recently)
            None => {
                self.store_appointment(uuid, &extended_appointment);
            }
        };

        let mut receipt = AppointmentReceipt::new(
            extended_appointment.user_signature,
            extended_appointment.start_block,
        );
        receipt.sign(&self.signing_key);

        Ok((receipt, available_slots, expiry))
    }

    /// Stores an appointment in the [Watcher] memory and into the database (or updates it if it already exists).
    ///
    /// Data is stored in `locator_uuid_map` and `appointments`.
    fn store_appointment(
        &self,
        uuid: UUID,
        appointment: &ExtendedAppointment,
    ) -> StoredAppointment {
        self.appointments
            .lock()
            .unwrap()
            .insert(uuid, appointment.get_summary());
        let mut locator_uuid_map = self.locator_uuid_map.lock().unwrap();
        if let Entry::Vacant(e) = locator_uuid_map.entry(appointment.locator()) {
            // New appointment
            e.insert(HashSet::from_iter(vec![uuid]));

            self.dbm
                .lock()
                .unwrap()
                .store_appointment(uuid, appointment)
                .unwrap();
            StoredAppointment::New
        } else {
            // Either an update or an appointment from another user sharing the same locator
            if locator_uuid_map
                .get_mut(&appointment.locator())
                .unwrap()
                .insert(uuid)
            {
                log::debug!(
                    "Adding an additional appointment to locator {}: {}",
                    appointment.locator(),
                    uuid
                );
                self.dbm
                    .lock()
                    .unwrap()
                    .store_appointment(uuid, appointment)
                    .unwrap();
                StoredAppointment::Collision
            } else {
                log::debug!("Update received for {}, locator map not modified", uuid);
                self.dbm
                    .lock()
                    .unwrap()
                    .update_appointment(uuid, appointment);
                StoredAppointment::Update
            }
        }
    }

    /// Stores and already triggered appointment in the database and hands it to the [Responder].
    ///
    /// If the appointment is rejected by the [Responder] (i.e. for being invalid), the data is wiped
    /// from the database but the slot is not freed.
    fn store_triggered_appointment(
        &self,
        uuid: UUID,
        appointment: &ExtendedAppointment,
        user_id: UserId,
        dispute_tx: &Transaction,
    ) -> TriggeredAppointment {
        log::info!(
            "Trigger for locator {} found in cache",
            appointment.locator()
        );
        match cryptography::decrypt(appointment.encrypted_blob(), &dispute_tx.txid()) {
            Ok(penalty_tx) => {
                // Data needs to be added the database straightaway since appointments are
                // FKs to trackers. If handle breach fails, data will be deleted later.
                self.dbm
                    .lock()
                    .unwrap()
                    .store_appointment(uuid, appointment)
                    .unwrap();

                if let ConfirmationStatus::Rejected(reason) = self.responder.handle_breach(
                    uuid,
                    Breach::new(dispute_tx.clone(), penalty_tx),
                    user_id,
                ) {
                    // DISCUSS: We could either free the slots or keep it occupied as if this was misbehavior.
                    // Keeping it for now.
                    log::warn!("Appointment bounced in the Responder. Reason: {:?}", reason);

                    self.dbm.lock().unwrap().remove_appointment(uuid);
                    TriggeredAppointment::Rejected
                } else {
                    log::info!("Appointment went straight to the Responder");
                    TriggeredAppointment::Accepted
                }
            }

            // DISCUSS: Check if this makes sense or if we should just drop the data altogether
            // If data inside the encrypted blob is invalid, the appointment is accepted but the data is dropped.
            // (same as with data that bounces in the Responder). This reduces the appointment slot count so it
            // could be used to discourage user misbehavior.
            Err(_) => {
                log::info!(
                    "The appointment contained invalid data {}",
                    appointment.locator()
                );
                TriggeredAppointment::Invalid
            }
        }
    }

    /// Retrieves an [Appointment] from the tower.
    ///
    /// Appointments can only be retrieved provided:
    /// - The user is registered into the system
    /// - The user subscription has not expired
    /// - The appointment belongs to the user
    /// - The appointment exists within the system (either in the [Watcher] or the [Responder])
    pub(crate) fn get_appointment(
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
                .map(AppointmentInfo::Tracker)
                .ok_or_else(|| {
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
                        valid_breaches
                            .insert(*uuid, Breach::new(dispute_tx.clone(), penalty_tx.clone()));
                    }
                    None => {
                        match cryptography::decrypt(
                            appointment.encrypted_blob(),
                            &dispute_tx.txid(),
                        ) {
                            Ok(penalty_tx) => {
                                decrypted_blobs.insert(
                                    appointment.encrypted_blob().clone(),
                                    penalty_tx.clone(),
                                );
                                valid_breaches
                                    .insert(*uuid, Breach::new(dispute_tx.clone(), penalty_tx));
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

    /// Deletes appointments from memory.
    ///
    /// The appointments are deleted from the appointments and locator_uuid_map maps.
    /// Logs a different message depending on whether the appointments have been outdated, invalid, or accepted.
    fn delete_appointments_from_memory(&self, uuids: &HashSet<UUID>, reason: DeletionReason) {
        let mut appointments = self.appointments.lock().unwrap();
        let mut locator_uuid_map = self.locator_uuid_map.lock().unwrap();

        for uuid in uuids {
            match reason {
                DeletionReason::Outdated => log::info!(
                    "End time reached by {} without breach. Deleting appointment",
                    uuid
                ),
                DeletionReason::Invalid => log::info!(
                    "{} cannot be completed, it contains invalid data. Deleting appointment",
                    uuid
                ),
                DeletionReason::Accepted => {
                    log::info!("{} accepted by the Responder. Deleting appointment", uuid)
                }
            };
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
    }

    /// Deletes appointments from memory and the database.
    fn delete_appointments(
        &self,
        uuids: &HashSet<UUID>,
        updated_users: &HashMap<UserId, UserInfo>,
        reason: DeletionReason,
    ) {
        if !uuids.is_empty() {
            self.delete_appointments_from_memory(uuids, reason);
            self.dbm
                .lock()
                .unwrap()
                .batch_remove_appointments(uuids, updated_users);
        }
    }

    /// Ges the number of users currently registered with the tower.
    pub(crate) fn get_registered_users_count(&self) -> usize {
        self.gatekeeper.get_registered_users_count()
    }

    /// Gets the total number of appointments stored in the [Watcher].
    pub(crate) fn get_appointments_count(&self) -> usize {
        self.appointments.lock().unwrap().len()
    }

    /// Gets the total number of trackers in the [Responder].
    pub(crate) fn get_trackers_count(&self) -> usize {
        self.responder.get_trackers_count()
    }

    /// Gets all the appointments stored in the [Watcher] (from the database).
    pub(crate) fn get_all_watcher_appointments(&self) -> HashMap<UUID, ExtendedAppointment> {
        self.dbm.lock().unwrap().load_appointments(None)
    }

    /// Gets all the appointments matching a specific locator from the [Watcher] (from the database).
    pub(crate) fn get_watcher_appointments_with_locator(
        &self,
        locator: Locator,
    ) -> HashMap<UUID, ExtendedAppointment> {
        self.dbm.lock().unwrap().load_appointments(Some(locator))
    }

    /// Gets all the trackers stored in the [Responder] (from the database).
    pub(crate) fn get_all_responder_trackers(&self) -> HashMap<UUID, TransactionTracker> {
        self.dbm.lock().unwrap().load_trackers(None)
    }

    /// Gets all the trackers matching s specific locator from the [Responder] (from the database).
    pub(crate) fn get_responder_trackers_with_locator(
        &self,
        locator: Locator,
    ) -> HashMap<UUID, TransactionTracker> {
        self.dbm.lock().unwrap().load_trackers(Some(locator))
    }

    /// Gets the list of all registered user ids.
    pub(crate) fn get_user_ids(&self) -> Vec<UserId> {
        self.gatekeeper.get_user_ids()
    }

    /// Gets the data held by the tower about a given user.
    pub(crate) fn get_user_info(&self, user_id: UserId) -> Option<UserInfo> {
        self.gatekeeper.get_user_info(user_id)
    }

    /// Gets information about a user's subscription.
    pub(crate) fn get_subscription_info(
        &self,
        signature: &str,
    ) -> Result<(UserInfo, Vec<Locator>), GetSubscriptionInfoFailure> {
        let message = "get subscription info".to_string();

        let user_id = self
            .gatekeeper
            .authenticate_user(message.as_bytes(), signature)
            .map_err(|_| GetSubscriptionInfoFailure::AuthenticationFailure)?;

        let (has_subscription_expired, expiry) =
            self.gatekeeper.has_subscription_expired(user_id).unwrap();

        if has_subscription_expired {
            return Err(GetSubscriptionInfoFailure::SubscriptionExpired(expiry));
        }

        let subscription_info = self.gatekeeper.get_user_info(user_id).unwrap();
        let mut locators = Vec::new();

        let appointments = self.appointments.lock().unwrap();
        let dbm = self.dbm.lock().unwrap();
        for uuid in subscription_info.appointments.keys() {
            match appointments.get(uuid) {
                Some(a) => locators.push(a.locator),
                None => {
                    if self.responder.has_tracker(*uuid) {
                        match dbm.load_locator(*uuid) {
                            Ok(locator) => locators.push(locator),
                            Err(_) => log::error!(
                                "Tracker found in Responder but not in DB (uuid = {})",
                                uuid
                            ),
                        }
                    } else {
                        log::error!("Appointment found in the Gatekeeper but not in the Watcher nor the Responder (uuid = {})", uuid)
                    }
                }
            }
        }

        Ok((subscription_info, locators))
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
    fn filtered_block_connected(
        &self,
        header: &BlockHeader,
        txdata: &chain::transaction::TransactionData,
        height: u32,
    ) {
        log::info!("New block received: {}", header.block_hash());

        let locator_tx_map = txdata
            .iter()
            .map(|(_, tx)| (Locator::new(tx.txid()), (*tx).clone()))
            .collect();

        self.locator_cache
            .lock()
            .unwrap()
            .update(*header, &locator_tx_map);

        if !self.appointments.lock().unwrap().is_empty() {
            // Start by removing outdated data so it is not taken into account from this point on
            self.delete_appointments_from_memory(
                &self.gatekeeper.get_outdated_appointments(height),
                DeletionReason::Outdated,
            );

            // Filter out those breaches that do not yield a valid transaction
            let (valid_breaches, invalid_breaches) =
                self.filter_breaches(self.get_breaches(locator_tx_map));

            // Send data to the Responder
            let mut appointments_to_delete = HashSet::from_iter(invalid_breaches.into_keys());
            let mut delivered_appointments = HashSet::new();
            for (uuid, breach) in valid_breaches {
                log::info!(
                    "Notifying Responder and deleting appointment (uuid: {})",
                    uuid
                );

                if let ConfirmationStatus::Rejected(_) = self.responder.handle_breach(
                    uuid,
                    breach,
                    self.appointments.lock().unwrap()[&uuid].user_id,
                ) {
                    appointments_to_delete.insert(uuid);
                } else {
                    delivered_appointments.insert(uuid);
                }
            }

            // Delete data
            let appointments_to_delete_gatekeeper = {
                let appointments = self.appointments.lock().unwrap();
                appointments_to_delete
                    .iter()
                    .map(|uuid| (*uuid, appointments[uuid].user_id))
                    .collect()
            };
            self.delete_appointments_from_memory(&delivered_appointments, DeletionReason::Accepted);
            self.delete_appointments(
                &appointments_to_delete,
                &self
                    .gatekeeper
                    .delete_appointments_from_memory(&appointments_to_delete_gatekeeper),
                DeletionReason::Invalid,
            );

            if self.appointments.lock().unwrap().is_empty() {
                log::info!("No more pending appointments");
            }
        }

        // Update last known block
        self.last_known_block_height
            .store(height, Ordering::Release);
    }

    /// Handle reorgs in the [Watcher].
    ///
    /// Fixes the [LocatorCache] by removing the disconnected data and updates the last_known_block_height.
    fn block_disconnected(&self, header: &BlockHeader, height: u32) {
        log::warn!("Block disconnected: {}", header.block_hash());
        self.locator_cache
            .lock()
            .unwrap()
            .remove_disconnected_block(&header.block_hash());
        self.last_known_block_height
            .store(height - 1, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::Deref;
    use std::sync::{Arc, Mutex};

    use crate::dbm::DBM;
    use crate::responder::ConfirmationStatus;
    use crate::rpc_errors;
    use crate::test_utils::{
        create_carrier, create_responder, create_watcher, generate_dummy_appointment,
        generate_dummy_appointment_with_user, generate_uuid, get_last_n_blocks, get_random_breach,
        get_random_tx, store_appointment_and_fks_to_db, BitcoindMock, BitcoindStopper, Blockchain,
        MockOptions, MockedServerQuery, AVAILABLE_SLOTS, DURATION, EXPIRY_DELTA, SLOTS,
        START_HEIGHT, SUBSCRIPTION_EXPIRY, SUBSCRIPTION_START,
    };
    use teos_common::cryptography::{get_random_bytes, get_random_keypair};
    use teos_common::dbm::Error as DBError;

    use bitcoin::hash_types::Txid;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{PublicKey, Secp256k1};
    use bitcoin::Block;
    use lightning::chain::Listen;

    impl PartialEq for Watcher {
        fn eq(&self, other: &Self) -> bool {
            *self.appointments.lock().unwrap() == *other.appointments.lock().unwrap()
                && *self.locator_uuid_map.lock().unwrap() == *other.locator_uuid_map.lock().unwrap()
                && self.last_known_block_height.load(Ordering::Relaxed)
                    == other.last_known_block_height.load(Ordering::Relaxed)
        }
    }
    impl Eq for Watcher {}

    impl Watcher {
        pub(crate) fn add_dummy_tracker_to_responder(
            &self,
            uuid: UUID,
            tracker: &TransactionTracker,
        ) {
            self.responder.add_dummy_tracker(uuid, tracker)
        }

        pub(crate) fn add_random_tracker_to_responder(&self, uuid: UUID) -> TransactionTracker {
            // The confirmation status can be whatever here. Using the most common.
            self.responder
                .add_random_tracker(uuid, ConfirmationStatus::ConfirmedIn(100))
        }
    }

    async fn init_watcher(chain: &mut Blockchain) -> (Watcher, BitcoindStopper) {
        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        init_watcher_with_db(chain, dbm).await
    }

    async fn init_watcher_with_db(
        chain: &mut Blockchain,
        dbm: Arc<Mutex<DBM>>,
    ) -> (Watcher, BitcoindStopper) {
        let bitcoind_mock = BitcoindMock::new(MockOptions::empty());

        let gk = Arc::new(Gatekeeper::new(
            chain.get_block_count(),
            SLOTS,
            DURATION,
            EXPIRY_DELTA,
            dbm.clone(),
        ));
        let responder = create_responder(chain.tip(), gk.clone(), dbm.clone(), bitcoind_mock.url());
        create_watcher(
            chain,
            Arc::new(responder),
            gk.clone(),
            bitcoind_mock,
            dbm.clone(),
        )
        .await
    }

    fn assert_appointment_added(
        slots: u32,
        expected_slots: u32,
        expiry: u32,
        receipt: AppointmentReceipt,
        expected_user_signature: &str,
        tower_id: TowerId,
    ) {
        assert_eq!(slots, expected_slots);
        assert_eq!(expiry, START_HEIGHT as u32 + DURATION);
        assert_eq!(receipt.start_block(), START_HEIGHT as u32);
        assert_eq!(receipt.user_signature(), expected_user_signature);
        let recovered_pk =
            cryptography::recover_pk(&receipt.to_vec(), &receipt.signature().unwrap()).unwrap();
        assert_eq!(TowerId(recovered_pk), tower_id);
    }

    #[tokio::test]
    async fn test_new() {
        // A fresh watcher has no associated data
        let mut chain = Blockchain::default().with_height(START_HEIGHT);
        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let (watcher, _s) = init_watcher_with_db(&mut chain, dbm.clone()).await;
        assert!(watcher.is_fresh());

        let (user_sk, user_pk) = get_random_keypair();
        let user_id = UserId(user_pk);
        watcher.register(user_id).unwrap();
        let appointment = generate_dummy_appointment(None).inner;

        // If we add some trackers to the system and create a new Responder reusing the same db
        // (as if simulating a bootstrap from existing data), the data should be properly loaded.
        for _ in 0..10 {
            let user_sig = cryptography::sign(&appointment.to_vec(), &user_sk).unwrap();
            watcher
                .add_appointment(appointment.clone(), user_sig.clone())
                .unwrap();
        }

        // Create a new Responder reusing the same DB and check that the data is loaded
        let (another_w, _as) = init_watcher_with_db(&mut chain, dbm).await;
        assert!(!another_w.is_fresh());
        assert_eq!(watcher, another_w);
    }

    #[tokio::test]
    async fn test_register() {
        // register calls Gatekeeper::add_update_user and signs the UserInfo returned by it.
        // Not testing the update / rejection logic, since that's already covered in the Gatekeeper, just that the data makes
        // sense and the signature verifies.
        let mut chain = Blockchain::default().with_height(START_HEIGHT);
        let (watcher, _s) = init_watcher(&mut chain).await;
        let tower_pk = watcher.tower_id.0;

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
            &receipt.to_vec(),
            &receipt.signature().unwrap(),
            &tower_pk
        ));
    }

    #[tokio::test]
    async fn test_add_appointment() {
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, 10);
        let tip_txs = chain.blocks.last().unwrap().txdata.clone();
        let (watcher, _s) = init_watcher(&mut chain).await;

        // add_appointment should add a given appointment to the Watcher given the following logic:
        //      - if the appointment does not exist for a given user, add the appointment
        //      - if the appointment already exists for a given user, update the data
        //      - if the appointment is already in the Responder, reject
        //      - if the trigger for the appointment is in the cache, trigger straightaway
        //      - DISCUSS: if the appointment is accepted but bounces in the Responder, do not reduce the subscription count
        // In any of the cases where the appointment should be added to the Watcher, the appointment will be rejected if:
        //      - the user does not have enough slots (either to add or update)
        //      - the subscription has expired

        let tower_id = TowerId(PublicKey::from_secret_key(
            &Secp256k1::new(),
            &watcher.signing_key,
        ));
        let (user_sk, user_pk) = get_random_keypair();
        let user_id = UserId(user_pk);
        watcher.register(user_id).unwrap();
        let appointment = generate_dummy_appointment(None).inner;

        // Add the appointment for a new user (twice so we can check that updates work)
        for _ in 0..2 {
            let user_sig = cryptography::sign(&appointment.to_vec(), &user_sk).unwrap();
            let (receipt, slots, expiry) = watcher
                .add_appointment(appointment.clone(), user_sig.clone())
                .unwrap();

            assert_appointment_added(slots, SLOTS - 1, expiry, receipt, &user_sig, tower_id);
        }

        // Add the same appointment but for another user
        let (user2_sk, user2_pk) = get_random_keypair();
        let user2_id = UserId(user2_pk);
        watcher.register(user2_id).unwrap();

        let user2_sig = cryptography::sign(&appointment.to_vec(), &user2_sk).unwrap();
        let (receipt, slots, expiry) = watcher
            .add_appointment(appointment.clone(), user2_sig.clone())
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
                watcher.dbm.lock().unwrap().load_appointment(*uuid),
                Ok(ExtendedAppointment { .. })
            ));
        }

        // If an appointment is already in the Responder, it should bounce
        let (uuid, triggered_appointment) = generate_dummy_appointment_with_user(user_id, None);
        let signature =
            cryptography::sign(&triggered_appointment.inner.to_vec(), &user_sk).unwrap();
        watcher
            .add_appointment(triggered_appointment.inner.clone(), signature.clone())
            .unwrap();

        let breach = get_random_breach();
        watcher.responder.add_tracker(
            uuid,
            breach,
            user_id,
            ConfirmationStatus::InMempoolSince(chain.get_block_count()),
        );
        let receipt = watcher.add_appointment(triggered_appointment.inner, signature);

        assert!(matches!(
            receipt,
            Err(AddAppointmentFailure::AlreadyTriggered)
        ));

        // If the trigger is already in the cache, the appointment will go straight to the Responder
        let dispute_tx = tip_txs.last().unwrap();
        let (uuid, appointment_in_cache) =
            generate_dummy_appointment_with_user(user_id, Some(&dispute_tx.txid()));
        let user_sig = cryptography::sign(&appointment_in_cache.inner.to_vec(), &user_sk).unwrap();
        let (receipt, slots, expiry) = watcher
            .add_appointment(appointment_in_cache.inner.clone(), user_sig.clone())
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
            watcher.dbm.lock().unwrap().load_appointment(uuid),
            Ok(ExtendedAppointment { .. })
        ));
        assert!(matches!(
            watcher.dbm.lock().unwrap().load_tracker(uuid),
            Ok(TransactionTracker { .. })
        ));

        // If an appointment is rejected by the Responder, it is considered misbehavior and the slot count is kept
        // Wrong penalty
        let dispute_tx = &tip_txs[tip_txs.len() - 2];
        let (uuid, mut invalid_appointment) =
            generate_dummy_appointment_with_user(user_id, Some(&dispute_tx.txid()));
        invalid_appointment.inner.encrypted_blob.reverse();
        let user_sig = cryptography::sign(&invalid_appointment.inner.to_vec(), &user_sk).unwrap();
        let (receipt, slots, expiry) = watcher
            .add_appointment(invalid_appointment.inner.clone(), user_sig.clone())
            .unwrap();

        assert_appointment_added(slots, SLOTS - 4, expiry, receipt, &user_sig, tower_id);
        assert_eq!(watcher.appointments.lock().unwrap().len(), 3);

        // Data should not be in the database
        assert!(matches!(
            watcher.dbm.lock().unwrap().load_appointment(uuid),
            Err(DBError::NotFound)
        ));
        assert!(matches!(
            watcher.dbm.lock().unwrap().load_tracker(uuid),
            Err(DBError::NotFound)
        ));

        // Transaction rejected
        // Update the Responder with a new Carrier
        let (carrier, _as) = create_carrier(
            MockedServerQuery::Error(rpc_errors::RPC_VERIFY_ERROR as i64),
            chain.tip().deref().height,
        );
        *watcher.responder.get_carrier().lock().unwrap() = carrier;

        let dispute_tx = &tip_txs[tip_txs.len() - 2];
        let invalid_appointment = generate_dummy_appointment(Some(&dispute_tx.txid())).inner;
        let user_sig = cryptography::sign(&invalid_appointment.to_vec(), &user_sk).unwrap();
        let (receipt, slots, expiry) = watcher
            .add_appointment(invalid_appointment, user_sig.clone())
            .unwrap();

        assert_appointment_added(slots, SLOTS - 4, expiry, receipt, &user_sig, tower_id);
        assert_eq!(watcher.appointments.lock().unwrap().len(), 3);

        // Data should not be in the database
        assert!(matches!(
            watcher.dbm.lock().unwrap().load_appointment(uuid),
            Err(DBError::NotFound)
        ));

        // FAIL cases (non-registered, subscription expired and not enough slots)

        // If the user is not registered, trying to add an appointment should fail. Since user_ids are
        // computed using ECRecovery, we can simulate a non-registered user by creating a "random" signature
        let user3_sig = String::from_utf8((0..65).collect()).unwrap();

        assert!(matches!(
            watcher.add_appointment(appointment.clone(), user3_sig),
            Err(AddAppointmentFailure::AuthenticationFailure)
        ));
        // Data should not be in the database
        assert!(matches!(
            watcher.dbm.lock().unwrap().load_appointment(uuid),
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
        let new_app_sig = cryptography::sign(&new_appointment.to_vec(), &user_sk).unwrap();

        assert!(matches!(
            watcher.add_appointment(new_appointment, new_app_sig),
            Err(AddAppointmentFailure::NotEnoughSlots)
        ));
        // Data should not be in the database
        assert!(matches!(
            watcher.dbm.lock().unwrap().load_appointment(uuid),
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
            watcher.add_appointment(appointment, user2_sig),
            Err(AddAppointmentFailure::SubscriptionExpired { .. })
        ));
        // Data should not be in the database
        assert!(matches!(
            watcher.dbm.lock().unwrap().load_appointment(uuid),
            Err(DBError::NotFound)
        ));
    }

    #[tokio::test]
    async fn test_store_appointment() {
        let mut chain = Blockchain::default().with_height(START_HEIGHT);
        let (watcher, _s) = init_watcher(&mut chain).await;

        // Register the user
        let (_, user_pk) = get_random_keypair();
        let user_id = UserId(user_pk);
        watcher.register(user_id).unwrap();

        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);

        // Storing a new appointment should return New
        assert_eq!(
            watcher.store_appointment(uuid, &appointment),
            StoredAppointment::New,
        );
        assert_eq!(
            *watcher.appointments.lock().unwrap(),
            HashMap::from_iter([(uuid, appointment.get_summary())])
        );
        assert_eq!(
            *watcher.locator_uuid_map.lock().unwrap(),
            HashMap::from_iter([(appointment.locator(), HashSet::from_iter([uuid]))])
        );

        // Adding an appointment with the same UUID should be seen as an updated
        // The appointment data here does not matter much, just the UUID and the locator since they are tied to each other.
        assert_eq!(
            watcher.store_appointment(uuid, &appointment),
            StoredAppointment::Update,
        );
        assert_eq!(
            *watcher.appointments.lock().unwrap(),
            HashMap::from_iter([(uuid, appointment.get_summary())])
        );
        assert_eq!(
            *watcher.locator_uuid_map.lock().unwrap(),
            HashMap::from_iter([(appointment.locator(), HashSet::from_iter([uuid]))])
        );

        // Adding the same appointment (same locator) with a different UUID should be seen as a collision.
        // This means that a different user is sending an appointment with the same locator.
        let new_uuid = generate_uuid();
        assert_eq!(
            watcher.store_appointment(new_uuid, &appointment),
            StoredAppointment::Collision,
        );
        assert_eq!(
            *watcher.appointments.lock().unwrap(),
            HashMap::from_iter([
                (uuid, appointment.get_summary()),
                (new_uuid, appointment.get_summary())
            ])
        );
        assert_eq!(
            *watcher.locator_uuid_map.lock().unwrap(),
            HashMap::from_iter([(appointment.locator(), HashSet::from_iter([uuid, new_uuid]))])
        );
    }

    #[tokio::test]
    async fn test_store_triggered_appointment() {
        let mut chain = Blockchain::default().with_height(START_HEIGHT);
        let (watcher, _s) = init_watcher(&mut chain).await;

        // Register the user
        let (_, user_pk) = get_random_keypair();
        let user_id = UserId(user_pk);
        watcher.register(user_id).unwrap();

        let dispute_tx = get_random_tx();
        let (uuid, appointment) =
            generate_dummy_appointment_with_user(user_id, Some(&dispute_tx.txid()));

        // Valid triggered appointments should be accepted by the Responder
        assert_eq!(
            watcher.store_triggered_appointment(uuid, &appointment, user_id, &dispute_tx),
            TriggeredAppointment::Accepted,
        );
        // In this case the appointment is kept in the Responder and, therefore, in the database
        assert!(watcher.responder.has_tracker(uuid));
        assert!(matches!(
            watcher.dbm.lock().unwrap().load_appointment(uuid),
            Ok(ExtendedAppointment { .. })
        ));

        // A properly formatted but invalid transaction should be rejected by the Responder
        // Update the Responder with a new Carrier that will reject the transaction
        let (carrier, _as) = create_carrier(
            MockedServerQuery::Error(rpc_errors::RPC_VERIFY_ERROR as i64),
            chain.tip().deref().height,
        );
        *watcher.responder.get_carrier().lock().unwrap() = carrier;
        let dispute_tx = get_random_tx();
        let (uuid, appointment) =
            generate_dummy_appointment_with_user(user_id, Some(&dispute_tx.txid()));
        assert_eq!(
            watcher.store_triggered_appointment(uuid, &appointment, user_id, &dispute_tx),
            TriggeredAppointment::Rejected,
        );
        // In this case the appointment is not kept in the Responder nor in the database
        assert!(!watcher.responder.has_tracker(uuid));
        assert!(matches!(
            watcher.dbm.lock().unwrap().load_appointment(uuid),
            Err { .. }
        ));

        // Invalid triggered appointments should not be passed to the Responder
        // Use a dispute_tx that does not match the appointment to replicate a decryption error
        // (the same applies to invalid formatted transactions)
        let uuid = generate_uuid();
        assert_eq!(
            watcher.store_triggered_appointment(uuid, &appointment, user_id, &get_random_tx()),
            TriggeredAppointment::Invalid,
        );
        // The appointment is not kept anywhere
        assert!(!watcher.responder.has_tracker(uuid));
        assert!(matches!(
            watcher.dbm.lock().unwrap().load_appointment(uuid),
            Err { .. }
        ));
    }

    #[tokio::test]
    async fn test_get_appointment() {
        let mut chain = Blockchain::default().with_height(START_HEIGHT);
        let (watcher, _s) = init_watcher(&mut chain).await;

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
                cryptography::sign(&appointment.to_vec(), &user_sk).unwrap(),
            )
            .unwrap();

        let message = format!("get appointment {}", appointment.locator);
        let signature = cryptography::sign(message.as_bytes(), &user_sk).unwrap();
        let info = watcher
            .get_appointment(appointment.locator, &signature)
            .unwrap();

        match info {
            AppointmentInfo::Appointment(a) => assert_eq!(a, appointment),
            AppointmentInfo::Tracker { .. } => {
                panic!("Should have received an appointment, not a tracker")
            }
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
        let breach = get_random_breach();
        let tracker = TransactionTracker::new(
            breach.clone(),
            user_id,
            ConfirmationStatus::InMempoolSince(chain.get_block_count()),
        );

        watcher.responder.add_tracker(
            uuid,
            breach,
            user_id,
            ConfirmationStatus::InMempoolSince(chain.get_block_count()),
        );

        let tracker_message = format!("get appointment {}", appointment.locator);
        let tracker_signature = cryptography::sign(tracker_message.as_bytes(), &user_sk).unwrap();
        let info = watcher
            .get_appointment(appointment.locator, &tracker_signature)
            .unwrap();

        match info {
            AppointmentInfo::Appointment { .. } => {
                panic!("Should have received an tracker, not an appointment")
            }
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
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, 10);
        let txs = chain.blocks.last().unwrap().txdata.clone();
        let (watcher, _s) = init_watcher(&mut chain).await;

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
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, 12);
        let txs = chain.blocks.last().unwrap().txdata.clone();
        let (watcher, _s) = init_watcher(&mut chain).await;

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
                store_appointment_and_fks_to_db(&watcher.dbm.lock().unwrap(), uuid, &appointment);
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
    async fn test_delete_appointments_from_memory() {
        let mut chain = Blockchain::default().with_height(START_HEIGHT);
        let (watcher, _s) = init_watcher(&mut chain).await;

        // Add some appointments both to memory and to the database
        let mut to_be_deleted = HashMap::new();

        for _ in 0..10 {
            let uuid = generate_uuid();
            let appointment = generate_dummy_appointment(None);
            watcher
                .appointments
                .lock()
                .unwrap()
                .insert(uuid, appointment.get_summary());
            watcher
                .locator_uuid_map
                .lock()
                .unwrap()
                .insert(appointment.locator(), HashSet::from_iter([uuid]));

            store_appointment_and_fks_to_db(&watcher.dbm.lock().unwrap(), uuid, &appointment);
            to_be_deleted.insert(uuid, appointment.locator());
        }

        // Delete and check data is not in memory (the reason does not matter for the test)
        watcher.delete_appointments_from_memory(
            &to_be_deleted.keys().cloned().collect(),
            DeletionReason::Outdated,
        );

        for (uuid, locator) in to_be_deleted {
            // Data is not in memory
            assert!(!watcher.appointments.lock().unwrap().contains_key(&uuid));
            assert!(!watcher
                .locator_uuid_map
                .lock()
                .unwrap()
                .contains_key(&locator));

            // But it can be found in the database
            assert!(matches!(
                watcher.dbm.lock().unwrap().load_appointment(uuid),
                Ok(ExtendedAppointment { .. })
            ));
        }
    }

    #[tokio::test]
    async fn test_delete_appointments() {
        // TODO: This is an adaptation of Responder::test_delete_trackers, merge together once the method
        // is implemented using generics.
        let mut chain = Blockchain::default().with_height(START_HEIGHT);
        let (watcher, _s) = init_watcher(&mut chain).await;

        // Delete appointments removes data from the appointments and locator_uuid_map
        // Add data to the map first
        let mut all_appointments = HashSet::new();
        let mut target_appointments = HashSet::new();
        let mut uuid_locator_map = HashMap::new();
        let mut locator_with_multiple_uuids = HashSet::new();
        let mut updated_users = HashMap::new();

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
            store_appointment_and_fks_to_db(&watcher.dbm.lock().unwrap(), uuid, &appointment);

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
                // Users will also be updated once the data is deleted.
                // We can made up the numbers here just to check they are updated.
                target_appointments.insert(uuid);
                updated_users.insert(
                    appointment.user_id,
                    UserInfo::new(
                        AVAILABLE_SLOTS + i,
                        SUBSCRIPTION_START + i,
                        SUBSCRIPTION_EXPIRY + i,
                    ),
                );
            }
        }

        // The deletion reason does not matter here, it only changes the logged message when deleting data
        watcher.delete_appointments(
            &target_appointments,
            &updated_users,
            DeletionReason::Accepted,
        );

        // Only appointments in the target_appointments map should have been removed from
        // the Watcher's data structures.
        for uuid in all_appointments {
            if target_appointments.contains(&uuid) {
                assert!(!watcher.appointments.lock().unwrap().contains_key(&uuid));
                assert!(matches!(
                    watcher.dbm.lock().unwrap().load_appointment(uuid),
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
                    watcher.dbm.lock().unwrap().load_appointment(uuid),
                    Ok(ExtendedAppointment { .. })
                ));
            }
        }

        // The users that needed to be updated in the database have been (just checking the slot count)
        for (id, info) in updated_users {
            assert_eq!(
                watcher
                    .dbm
                    .lock()
                    .unwrap()
                    .load_user(id)
                    .unwrap()
                    .available_slots,
                info.available_slots
            );
        }
    }

    #[tokio::test]
    async fn test_filtered_block_connected() {
        let mut chain = Blockchain::default().with_height(START_HEIGHT);
        let (watcher, _s) = init_watcher(&mut chain).await;

        // block_connected for the Watcher is used to keep track of what new transactions has been mined whose may be potential
        // channel breaches.

        // If the Watcher is not watching any appointment, block_connected will only be used to keep track of the last known block
        // by the Watcher.
        assert_eq!(
            watcher.last_known_block_height.load(Ordering::Relaxed),
            chain.get_block_count()
        );
        watcher.block_connected(&chain.generate(None), chain.get_block_count() as u32);
        assert_eq!(
            watcher.last_known_block_height.load(Ordering::Relaxed),
            chain.get_block_count()
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

        let user_sig = cryptography::sign(&appointment.inner.to_vec(), &user_sk).unwrap();
        watcher
            .add_appointment(appointment.inner.clone(), user_sig)
            .unwrap();
        let user2_sig = cryptography::sign(&appointment.inner.to_vec(), &user2_sk).unwrap();
        watcher
            .add_appointment(appointment.inner.clone(), user2_sig)
            .unwrap();

        watcher
            .gatekeeper
            .get_registered_users()
            .lock()
            .unwrap()
            .get_mut(&user_id)
            .unwrap()
            .subscription_expiry = chain.get_block_count() - EXPIRY_DELTA + 1;

        // Both appointments can be found before mining a block, only the user's 2 can be found afterwards
        for uuid in &[uuid1, uuid2] {
            assert!(watcher.appointments.lock().unwrap().contains_key(uuid));
            assert!(
                watcher.locator_uuid_map.lock().unwrap()[&appointment.locator()].contains(uuid)
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

        watcher.block_connected(&chain.generate(None), chain.get_block_count());

        assert!(!watcher.appointments.lock().unwrap().contains_key(&uuid1));
        assert!(!watcher.locator_uuid_map.lock().unwrap()[&appointment.locator()].contains(&uuid1));
        // Data is still in the Gatekeeper and in the database, since it'll be deleted in cascade by the
        // Gatekeeper on user's deletion (given the user was outdated in the test).
        assert!(
            watcher.gatekeeper.get_registered_users().lock().unwrap()[&user_id]
                .appointments
                .contains_key(&uuid1)
        );
        assert!(matches!(
            watcher.dbm.lock().unwrap().load_appointment(uuid1),
            Ok(ExtendedAppointment { .. })
        ));

        assert!(watcher.appointments.lock().unwrap().contains_key(&uuid2));
        assert!(watcher.locator_uuid_map.lock().unwrap()[&appointment.locator()].contains(&uuid2));
        assert!(
            watcher.gatekeeper.get_registered_users().lock().unwrap()[&user2_id]
                .appointments
                .contains_key(&uuid2)
        );
        assert!(matches!(
            watcher.dbm.lock().unwrap().load_appointment(uuid2),
            Ok(ExtendedAppointment { .. })
        ));

        // Check triggers. Add a new appointment and trigger it with valid data.
        let dispute_tx = get_random_tx();
        let appointment = generate_dummy_appointment(Some(&dispute_tx.txid()));
        let sig = cryptography::sign(&appointment.inner.to_vec(), &user2_sk).unwrap();
        let uuid = UUID::new(appointment.locator(), user2_id);
        watcher.add_appointment(appointment.inner, sig).unwrap();

        assert!(watcher.appointments.lock().unwrap().contains_key(&uuid));

        watcher.block_connected(
            &chain.generate(Some(vec![dispute_tx])),
            chain.get_block_count(),
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

        // Data should have been kept in the database
        assert!(matches!(
            watcher.dbm.lock().unwrap().load_appointment(uuid),
            Ok(ExtendedAppointment { .. })
        ));
        assert!(matches!(
            watcher.dbm.lock().unwrap().load_tracker(uuid),
            Ok(TransactionTracker { .. })
        ));

        // Check triggering with a valid formatted transaction but that is rejected by the Responder.
        let dispute_tx = get_random_tx();
        let appointment = generate_dummy_appointment(Some(&dispute_tx.txid()));
        let sig = cryptography::sign(&appointment.inner.to_vec(), &user2_sk).unwrap();
        let uuid = UUID::new(appointment.locator(), user2_id);
        watcher.add_appointment(appointment.inner, sig).unwrap();

        // Set the carrier response
        let (carrier, _as) = create_carrier(
            MockedServerQuery::Error(rpc_errors::RPC_VERIFY_ERROR as i64),
            chain.tip().deref().height,
        );
        *watcher.responder.get_carrier().lock().unwrap() = carrier;

        watcher.block_connected(
            &chain.generate(Some(vec![dispute_tx])),
            chain.get_block_count(),
        );

        // Data should not be in the Responder, in the Watcher nor in the Gatekeeper
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
        // Data should also have been deleted from the database
        assert!(matches!(
            watcher.dbm.lock().unwrap().load_appointment(uuid),
            Err(DBError::NotFound)
        ));
        assert!(matches!(
            watcher.dbm.lock().unwrap().load_tracker(uuid),
            Err(DBError::NotFound)
        ));

        // Checks invalid triggers. Add a new appointment and trigger it with invalid data.
        let dispute_tx = get_random_tx();
        let mut appointment = generate_dummy_appointment(Some(&dispute_tx.txid()));
        // Modify the encrypted blob so the data is invalid.
        //Both non-decryptable blobs and blobs with invalid transactions will yield an invalid trigger
        appointment.inner.encrypted_blob.reverse();
        let sig = cryptography::sign(&appointment.inner.to_vec(), &user2_sk).unwrap();
        let uuid = UUID::new(appointment.locator(), user2_id);
        watcher
            .add_appointment(appointment.inner.clone(), sig)
            .unwrap();

        watcher.block_connected(
            &chain.generate(Some(vec![dispute_tx])),
            chain.get_block_count(),
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
            watcher.dbm.lock().unwrap().load_appointment(uuid),
            Err(DBError::NotFound)
        ));
    }

    #[tokio::test]
    async fn test_block_disconnected() {
        let mut chain = Blockchain::default().with_height(START_HEIGHT);
        let start_height = START_HEIGHT as u32;
        let (watcher, _s) = init_watcher(&mut chain).await;

        // block_disconnected for the Watcher fixes the locator cache by removing the disconnected block
        // and updates the last_known_block_height to the previous block height
        let last_block_header = chain.tip().deref().header;
        assert!(watcher
            .locator_cache
            .lock()
            .unwrap()
            .blocks()
            .contains(&last_block_header.block_hash()));

        watcher.block_disconnected(&last_block_header, start_height);

        assert_eq!(
            watcher.last_known_block_height.load(Ordering::Relaxed),
            start_height - 1
        );
        assert!(!watcher
            .locator_cache
            .lock()
            .unwrap()
            .blocks()
            .contains(&last_block_header.block_hash()));
    }
}
