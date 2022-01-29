//! Logic related to the Responder, the components in charge of making sure breaches get properly punished.

use futures::executor::block_on;
use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

use bitcoin::util::psbt::serialize::Serialize;
use bitcoin::{BlockHeader, Transaction, Txid};
use lightning::chain::Listen;
use lightning_block_sync::poll::ValidatedBlockHeader;
use lightning_block_sync::BlockHeaderData;

use teos_common::appointment::Locator;
use teos_common::constants;
use teos_common::UserId;

use crate::carrier::{Carrier, DeliveryReceipt};
use crate::dbm::DBM;
use crate::extended_appointment::UUID;
use crate::gatekeeper::Gatekeeper;
use crate::protos as msgs;
use crate::watcher::Breach;

/// Number of missed confirmations to wait before rebroadcasting a transaction.
const CONFIRMATIONS_BEFORE_RETRY: u8 = 6;

/// Minimal data required in memory to keep track of transaction trackers.
pub struct TrackerSummary {
    /// Identifier of the user who arranged the appointment.
    user_id: UserId,
    /// Transaction id the [Responder] is keeping track of.
    penalty_txid: Txid,
}

/// Structure to keep track of triggered appointments.
///
/// It is analogous to [ExtendedAppointment](crate::extended_appointment::ExtendedAppointment) for the [`Watcher`](crate::watcher::Watcher).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionTracker {
    /// Matches the corresponding [ExtendedAppointment](crate::extended_appointment::ExtendedAppointment) locator.
    pub locator: Locator,
    /// Matches the corresponding [Breach] `dispute_tx` field.
    pub dispute_tx: Transaction,
    /// Matches the corresponding [Breach] penalty_tx field.
    pub penalty_tx: Transaction,
    /// [UserId] the original [ExtendedAppointment](crate::extended_appointment::ExtendedAppointment) belongs to.
    pub user_id: UserId,
}

impl TransactionTracker {
    /// Creates a new [TransactionTracker] instance.
    pub fn new(breach: Breach, user_id: UserId) -> Self {
        Self {
            locator: breach.locator,
            dispute_tx: breach.dispute_tx,
            penalty_tx: breach.penalty_tx,
            user_id,
        }
    }

    /// Computes the [TrackerSummary] of the [TransactionTracker].
    pub fn get_summary(&self) -> TrackerSummary {
        TrackerSummary {
            user_id: self.user_id,
            penalty_txid: self.penalty_tx.txid(),
        }
    }
}

impl Into<msgs::Tracker> for TransactionTracker {
    fn into(self) -> msgs::Tracker {
        msgs::Tracker {
            locator: self.locator.serialize(),
            dispute_txid: self.dispute_tx.txid().to_vec(),
            penalty_txid: self.penalty_tx.txid().to_vec(),
            penalty_rawtx: self.penalty_tx.serialize(),
        }
    }
}

/// Component in charge of keeping track of triggered appointments.
///
/// The [Responder] receives data from the [Watcher](crate::watcher::Watcher) in form of a [Breach].
/// From there, a [TransactionTracker] is created and the penalty transaction is sent to the network via the [Carrier].
/// The [Transaction] is then monitored to make sure it makes it to a block and it gets [irrevocably resolved](https://github.com/lightning/bolts/blob/master/05-onchain.md#general-nomenclature).
pub struct Responder {
    /// A map holding a summary of every tracker ([TransactionTracker]) hold by the [Responder], identified by [UUID].
    /// The identifiers match those used by the [Watcher](crate::watcher::Watcher).
    trackers: Mutex<HashMap<UUID, TrackerSummary>>,
    /// A map between [Txid]s and [UUID]s.
    tx_tracker_map: Mutex<HashMap<Txid, HashSet<UUID>>>,
    /// A collection of transactions yet to get a single confirmation.
    /// Only keeps track of penalty transactions being monitored by the [Responder].
    unconfirmed_txs: Mutex<HashSet<Txid>>,
    /// A collection of [Transaction]s that have missed some confirmation, along with the missed count.
    /// Only keeps track of penalty transactions being monitored by the [Responder].
    missed_confirmations: Mutex<HashMap<Txid, u8>>,
    /// A [Carrier] instance. Data is sent to the `bitcoind` through it.
    carrier: Mutex<Carrier>,
    /// A [Gatekeeper] instance. Data regarding users is requested to it.
    gatekeeper: Arc<Gatekeeper>,
    /// A [DBM] (database manager) instance. Used to persist tracker data into disk.
    dbm: Arc<Mutex<DBM>>,
    /// The last known block header.
    last_known_block_header: Mutex<BlockHeaderData>,
}

impl Responder {
    /// Creates a new [Responder] instance.
    pub fn new(
        carrier: Carrier,
        gatekeeper: Arc<Gatekeeper>,
        dbm: Arc<Mutex<DBM>>,
        last_known_block_header: ValidatedBlockHeader,
    ) -> Self {
        let trackers = Mutex::new(HashMap::new());
        let tx_tracker_map = Mutex::new(HashMap::new());
        let unconfirmed_txs = Mutex::new(HashSet::new());
        let missed_confirmations = Mutex::new(HashMap::new());

        Responder {
            carrier: Mutex::new(carrier),
            trackers,
            tx_tracker_map,
            unconfirmed_txs,
            missed_confirmations,
            dbm,
            gatekeeper,
            last_known_block_header: Mutex::new(*last_known_block_header.deref()),
        }
    }

    /// Gets the total number of trackers in the responder.
    pub fn get_trackers_count(&self) -> usize {
        self.trackers.lock().unwrap().len()
    }

    /// Data entry point for the [Responder]. Handles a [Breach] provided by the [Watcher](crate::watcher::Watcher).
    ///
    /// Breaches can either be added to the [Responder] in the form of a [TransactionTracker] if the [penalty transaction](Breach::penalty_tx)
    /// is accepted by the `bitcoind` or rejected otherwise.
    pub async fn handle_breach(
        &self,
        uuid: UUID,
        breach: Breach,
        user_id: UserId,
    ) -> DeliveryReceipt {
        let receipt = self
            .carrier
            .lock()
            .unwrap()
            .send_transaction(&breach.penalty_tx)
            .await;

        if receipt.delivered() {
            self.add_tracker(uuid, breach, user_id, receipt.confirmations().unwrap());
        }

        receipt
    }

    /// Adds a [TransactionTracker] to the [Responder] from a given [Breach].
    ///
    /// From this point on, transactions are accepted as valid. They may not end up being confirmed, but they
    /// have been checked syntactically by the [Watcher](crate::watcher::Watcher) and against consensus / network
    /// acceptance rules by the [Carrier].
    ///
    /// The [TransactionTracker] will be added to [self.unconfirmed_txs](Self::unconfirmed_txs) depending on the confirmation count (`confirmations`).
    /// Some transaction may already be confirmed by the time the tower tries to send them to the network. If that's the case,
    /// the [Responder] will simply continue tracking the job until its completion.
    pub(crate) fn add_tracker(
        &self,
        uuid: UUID,
        breach: Breach,
        user_id: UserId,
        confirmations: u32,
    ) {
        let penalty_txid = breach.penalty_tx.txid();
        let tracker = TransactionTracker::new(breach, user_id);

        self.trackers
            .lock()
            .unwrap()
            .insert(uuid, tracker.get_summary());

        let mut tx_tracker_map = self.tx_tracker_map.lock().unwrap();
        match tx_tracker_map.get_mut(&penalty_txid) {
            Some(map) => {
                map.insert(uuid);
            }
            None => {
                tx_tracker_map.insert(penalty_txid, HashSet::from_iter(vec![uuid]));
            }
        }

        let mut unconfirmed_txs = self.unconfirmed_txs.lock().unwrap();
        if !unconfirmed_txs.contains(&tracker.penalty_tx.txid()) && confirmations == 0 {
            unconfirmed_txs.insert(tracker.penalty_tx.txid());
        }

        self.dbm
            .lock()
            .unwrap()
            .store_tracker(uuid, &tracker)
            .unwrap();
        log::info!("New tracker added (uuid={}).", uuid);
    }

    /// Checks whether a given tracker can be found in the [Responder].
    pub fn has_tracker(&self, uuid: UUID) -> bool {
        // Has tracker should return true as long as the given tracker is hold by the Responder.
        // If the tracker is partially kept, the function will log and the return will be false.
        // This may point out that some partial data deletion is happening, which must be fixed.
        self.trackers
            .lock()
            .unwrap()
            .get(&uuid)
            .map_or(false, |tracker| {
                self.tx_tracker_map
                    .lock()
                    .unwrap()
                    .get(&tracker.penalty_txid)
                    .map_or(
                        {
                            log::debug!(
                            "Partially found Tracker. Some data may have not been properly deleted"
                        );
                            false
                        },
                        |_| true,
                    )
            })
    }

    /// Gets a tracker from the [Responder] if found. [None] otherwise.
    ///
    /// The [TransactionTracker] is queried to the [DBM].
    pub fn get_tracker(&self, uuid: UUID) -> Option<TransactionTracker> {
        if self.trackers.lock().unwrap().contains_key(&uuid) {
            self.dbm.lock().unwrap().load_tracker(uuid).ok()
        } else {
            None
        }
    }

    /// Checks if any of the unconfirmed tracked transaction has received a confirmation. If so, it is removed from [self.unconfirmed_txs](Self::unconfirmed_txs).
    /// Otherwise, its unconfirmed count is increased by one.
    fn check_confirmations(&self, txs: &Vec<Transaction>) {
        // A confirmation has been received
        let mut unconfirmed_txs = self.unconfirmed_txs.lock().unwrap();
        for tx in txs.iter() {
            if unconfirmed_txs.remove(&tx.txid()) {
                log::info!("Confirmation received for transaction: {}", tx.txid());
            }
        }

        // Increase the missing confirmation count for all those transactions pending confirmation that have not been confirmed this block
        let mut missed_confirmations = self.missed_confirmations.lock().unwrap();
        for txid in unconfirmed_txs.iter() {
            match missed_confirmations.get_mut(txid) {
                Some(x) => *x += 1,
                None => {
                    missed_confirmations.insert(*txid, 1);
                }
            }
            log::info!(
                "Transaction missed a confirmation: {} (missed conf count: {})",
                txid,
                missed_confirmations.get(txid).unwrap()
            );
        }
    }

    /// Gets a vector of transactions that need to be rebroadcast. A [Transaction] is flagged to be rebroadcast
    /// if its missed confirmation count has reached the threshold ([CONFIRMATIONS_BEFORE_RETRY]).
    ///
    /// Given the [Responder] only keeps around the minimal data to track transactions, the [TransactionTracker]s
    /// are queried to the [DBM].
    fn get_txs_to_rebroadcast(&self) -> Vec<Transaction> {
        let mut tx_to_rebroadcast = Vec::new();
        let mut tracker: TransactionTracker;

        let tx_tracker_map = self.tx_tracker_map.lock().unwrap();
        let dbm = self.dbm.lock().unwrap();
        for (txid, missed_conf) in self.missed_confirmations.lock().unwrap().iter() {
            if missed_conf >= &CONFIRMATIONS_BEFORE_RETRY {
                for uuid in tx_tracker_map.get(txid).unwrap() {
                    tracker = dbm.load_tracker(*uuid).unwrap();
                    tx_to_rebroadcast.push(tracker.penalty_tx)
                }
            }
        }

        tx_to_rebroadcast
    }

    /// Gets a collection of trackers that have been completed (and therefore can be removed from the [Responder]).
    ///
    /// The confirmation count is not kept by the [Responder]. Instead, data is queried to `bitcoind` via the [Carrier].
    async fn get_completed_trackers(&self) -> HashSet<UUID> {
        // DISCUSS: Not using a checked_txs cache for now, check whether it may be necessary
        let mut completed_trackers = HashSet::new();

        let trackers = self.trackers.lock().unwrap();
        let unconfirmed_txs = self.unconfirmed_txs.lock().unwrap();
        let carrier = self.carrier.lock().unwrap();
        for uuid in trackers.keys() {
            let penalty_txid = trackers[uuid].penalty_txid;
            if !unconfirmed_txs.contains(&penalty_txid) {
                carrier
                    .get_confirmations(&penalty_txid)
                    .await
                    .map(|confirmations| {
                        if confirmations > constants::IRREVOCABLY_RESOLVED {
                            completed_trackers.insert(*uuid);
                        }
                    });
            }
        }

        completed_trackers
    }

    /// Gets a collection of trackers that have been outdated. An outdated tracker is a [TransactionTracker]
    /// from a user who's subscription has been outdated (and therefore will be removed from the tower).
    fn get_outdated_trackers(&self, block_height: u32) -> HashSet<UUID> {
        let mut outdated_trackers = HashSet::new();
        let unconfirmed_txs = self.unconfirmed_txs.lock().unwrap();
        let trackers = self.trackers.lock().unwrap();
        for uuid in self
            .gatekeeper
            .get_outdated_appointments(block_height)
            .intersection(&trackers.keys().cloned().collect())
        {
            if unconfirmed_txs.contains(&trackers[&uuid].penalty_txid) {
                outdated_trackers.insert(*uuid);
            }
        }

        outdated_trackers
    }

    /// Rebroadcasts a list of penalty transactions that have missed too many confirmations.
    // FIXME: This is not of much use at the moment given fees can not be bumped. It may be
    // useful if nodes have wiped the transaction from the mempool for some reasons.
    async fn rebroadcast(&self) -> HashMap<Txid, DeliveryReceipt> {
        let mut receipts = HashMap::new();
        let mut carrier = self.carrier.lock().unwrap();

        for penalty_tx in self.get_txs_to_rebroadcast().into_iter() {
            *self
                .missed_confirmations
                .lock()
                .unwrap()
                .get_mut(&penalty_tx.txid())
                .unwrap() = 0;

            log::warn!(
                "Transaction has missed many confirmations. Rebroadcasting: {}",
                penalty_tx.txid()
            );

            let receipt = carrier.send_transaction(&penalty_tx).await;

            if !receipt.delivered() {
                // DISCUSS: Check is this can actually happen. Feels like it may if the original tx
                // is RBF and it has been already replaced by a higher fee variant.
                log::warn!(
                    "Transaction rebroadcast failed: {} (reason: {:?})",
                    penalty_tx.txid(),
                    receipt.reason()
                );
            }

            receipts.insert(penalty_tx.txid(), receipt);
        }

        receipts
    }

    // DISCUSS: Check comment regarding callbacks in watcher.rs

    /// Deletes trackers from memory and the database.
    ///
    /// Logs a different message depending on whether the trackers have been outdated or completed.
    /// Removes all data related to the appointment from the database in cascade.
    fn delete_trackers(&self, uuids: HashSet<UUID>, outdated: bool) {
        let mut trackers = self.trackers.lock().unwrap();
        let mut tx_tracker_map = self.tx_tracker_map.lock().unwrap();
        for uuid in uuids.iter() {
            if outdated {
                log::info!("Appointment couldn't be completed. Expiry reached but penalty didn't make it to the chain:  {}", uuid);
            } else {
                log::info!(
                    "Appointment completed. Penalty transaction was irrevocably confirmed:  {}",
                    uuid
                );
            }

            match trackers.remove(uuid) {
                Some(tracker) => {
                    let trackers = tx_tracker_map.get_mut(&tracker.penalty_txid).unwrap();

                    // The transaction will only be in the unconfirmed_txs map if the trackers are outdated
                    self.unconfirmed_txs
                        .lock()
                        .unwrap()
                        .remove(&tracker.penalty_txid);

                    if trackers.len() == 1 {
                        tx_tracker_map.remove(&tracker.penalty_txid);

                        log::info!(
                            "No more trackers for penalty transaction: {}",
                            tracker.penalty_txid
                        );
                    } else {
                        trackers.remove(uuid);
                    }
                }
                None => {
                    // This should never happen. Logging just in case so we can fix it if so
                    log::error!("Completed tracker not found when cleaning: {}", uuid);
                }
            }
        }

        // Remove both the appointment and tracker matching the given uuids
        self.dbm.lock().unwrap().batch_remove_appointments(&uuids);
    }
}

/// Listen implementation by the [Responder]. Handles monitoring and reorgs.
impl Listen for Responder {
    /// Handles the monitoring process by the [Responder].
    ///
    /// Watching is performed in a per-block basis. A [TransactionTracker] is tracked until:
    /// - It gets [irrevocably resolved](https://github.com/lightning/bolts/blob/master/05-onchain.md#general-nomenclature) or
    /// - The user subscription expires
    ///
    /// Every time a block is received the tracking conditions are checked against the monitored [TransactionTracker]s and
    /// data deletion is performed accordingly. Moreover, lack of confirmations is check for the tracked transactions and
    /// rebroadcasting is performed for those that have missed too many.
    fn block_connected(&self, block: &bitcoin::Block, height: u32) {
        log::info!("New block received: {}", block.header.block_hash());

        if self.trackers.lock().unwrap().len() > 0 {
            let completed_trackers = block_on(self.get_completed_trackers());
            let outdated_trackers = self.get_outdated_trackers(height);

            let trackers_to_delete_gk = completed_trackers
                .iter()
                .map(|uuid| (*uuid, self.trackers.lock().unwrap()[uuid].user_id))
                .collect();

            self.check_confirmations(&block.txdata);
            self.delete_trackers(completed_trackers, false);
            self.delete_trackers(outdated_trackers, true);

            // Remove completed trackers from the GK
            self.gatekeeper.delete_appointments(&trackers_to_delete_gk);

            // Rebroadcast those transactions that need to
            block_on(self.rebroadcast());

            // Remove all receipts created in this block
            self.carrier.lock().unwrap().clear_receipts();

            if self.trackers.lock().unwrap().is_empty() {
                log::info!("No more pending trackers");
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
            .store_last_known_block_responder(&block.header.block_hash());
    }

    /// FIXME: To be implemented
    /// This will handle reorgs on the [Responder].
    #[allow(unused_variables)]
    fn block_disconnected(&self, header: &BlockHeader, height: u32) {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::{Arc, Mutex};

    use crate::dbm::{Error as DBError, DBM};
    use crate::gatekeeper::UserInfo;
    use crate::rpc_errors;
    use crate::test_utils::{
        create_carrier, generate_dummy_appointment_with_user, generate_uuid, get_random_breach,
        get_random_breach_from_locator, get_random_tracker, get_random_tx, get_random_user_id,
        store_appointment_and_fks_to_db, Blockchain, MockedServerQuery, DURATION, EXPIRY_DELTA,
        SLOTS, START_HEIGHT,
    };

    impl Responder {
        pub fn get_trackers(&self) -> &Mutex<HashMap<UUID, TrackerSummary>> {
            &self.trackers
        }

        pub fn get_carrier(&self) -> &Mutex<Carrier> {
            &self.carrier
        }

        pub fn add_random_tracker(&self, uuid: UUID) {
            let user_id = get_random_user_id();
            let tracker = get_random_tracker(user_id);

            // Add data to memory
            self.trackers
                .lock()
                .unwrap()
                .insert(uuid, tracker.get_summary());
            self.tx_tracker_map
                .lock()
                .unwrap()
                .insert(tracker.penalty_tx.txid(), HashSet::from_iter([uuid]));

            // Add data to the db
            let (_, appointment) =
                generate_dummy_appointment_with_user(user_id, Some(&tracker.dispute_tx.txid()));
            store_appointment_and_fks_to_db(&self.dbm.lock().unwrap(), uuid, &appointment);
            self.dbm
                .lock()
                .unwrap()
                .store_tracker(uuid, &tracker)
                .unwrap();
        }
    }

    fn create_responder(
        chain: &mut Blockchain,
        gatekeeper: Arc<Gatekeeper>,
        dbm: Arc<Mutex<DBM>>,
        query: MockedServerQuery,
    ) -> Responder {
        let tip = chain.tip();
        let carrier = create_carrier(query);
        Responder::new(carrier, gatekeeper, dbm, tip)
    }

    fn init_responder(mocked_query: MockedServerQuery) -> (Responder, Blockchain) {
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, None);
        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let gk = Gatekeeper::new(chain.tip(), SLOTS, DURATION, EXPIRY_DELTA, dbm.clone());
        (
            create_responder(&mut chain, Arc::new(gk), dbm.clone(), mocked_query),
            chain,
        )
    }

    #[tokio::test]
    async fn test_handle_breach_delivered() {
        let (responder, _) = init_responder(MockedServerQuery::Regular);

        let user_id = get_random_user_id();
        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        store_appointment_and_fks_to_db(&responder.dbm.lock().unwrap(), uuid, &appointment);

        let breach = get_random_breach_from_locator(appointment.locator());
        let penalty_txid = breach.penalty_tx.txid();

        let r = responder.handle_breach(uuid, breach.clone(), user_id).await;

        assert!(r.delivered());
        assert!(responder.trackers.lock().unwrap().contains_key(&uuid));
        assert!(responder
            .tx_tracker_map
            .lock()
            .unwrap()
            .contains_key(&penalty_txid));
        assert!(responder
            .unconfirmed_txs
            .lock()
            .unwrap()
            .contains(&penalty_txid));
    }

    #[tokio::test]
    async fn test_handle_breach_not_delivered() {
        let (responder, _) = init_responder(MockedServerQuery::Error(
            rpc_errors::RPC_VERIFY_ERROR as i64,
        ));

        let user_id = get_random_user_id();
        let uuid = generate_uuid();
        let breach = get_random_breach();
        let penalty_txid = breach.penalty_tx.txid();

        let r = responder.handle_breach(uuid, breach.clone(), user_id).await;

        assert!(!r.delivered());
        assert!(!responder.trackers.lock().unwrap().contains_key(&uuid));
        assert!(!responder
            .tx_tracker_map
            .lock()
            .unwrap()
            .contains_key(&penalty_txid));
        assert!(!responder
            .unconfirmed_txs
            .lock()
            .unwrap()
            .contains(&penalty_txid));
    }

    #[test]
    fn test_add_tracker() {
        let (responder, _) = init_responder(MockedServerQuery::Regular);

        // Add the necessary FKs in the database
        let user_id = get_random_user_id();
        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        store_appointment_and_fks_to_db(&responder.dbm.lock().unwrap(), uuid, &appointment);

        let mut breach = get_random_breach_from_locator(appointment.locator());
        responder.add_tracker(uuid, breach.clone(), user_id, 0);

        // Check that the data has been added to trackers and tom the tx_tracker_map
        assert!(responder.trackers.lock().unwrap().contains_key(&uuid));
        assert!(responder
            .tx_tracker_map
            .lock()
            .unwrap()
            .contains_key(&breach.penalty_tx.txid()));
        // Since the penalty tx was added with no confirmations, check that it has been added to the unconfirmed_transactions map too
        assert!(responder
            .unconfirmed_txs
            .lock()
            .unwrap()
            .contains(&breach.penalty_tx.txid()));
        // Check that the data is also in the database
        assert_eq!(
            responder.dbm.lock().unwrap().load_tracker(uuid).unwrap(),
            TransactionTracker::new(breach, user_id)
        );

        // Adding a tracker with confirmations should result in the same but with the penalty not being added to the unconfirmed_transactions
        //map
        let uuid = generate_uuid();
        breach = get_random_breach_from_locator(appointment.locator());

        responder
            .dbm
            .lock()
            .unwrap()
            .store_appointment(uuid, &appointment)
            .unwrap();

        responder.add_tracker(uuid, breach.clone(), user_id, 1);

        assert!(responder.trackers.lock().unwrap().contains_key(&uuid));
        assert!(responder
            .tx_tracker_map
            .lock()
            .unwrap()
            .contains_key(&breach.penalty_tx.txid()));
        assert_eq!(
            responder.tx_tracker_map.lock().unwrap()[&breach.penalty_tx.txid()].len(),
            1
        );
        assert!(!responder
            .unconfirmed_txs
            .lock()
            .unwrap()
            .contains(&breach.penalty_tx.txid()));
        assert_eq!(
            responder.dbm.lock().unwrap().load_tracker(uuid).unwrap(),
            TransactionTracker::new(breach.clone(), user_id)
        );

        // Adding another breach with the same penalty transaction (but different uuid) adds an additional uuid to the map entry
        let uuid = generate_uuid();
        responder
            .dbm
            .lock()
            .unwrap()
            .store_appointment(uuid, &appointment)
            .unwrap();

        responder.add_tracker(uuid, breach.clone(), user_id, 1);

        assert!(responder.trackers.lock().unwrap().contains_key(&uuid));
        assert!(responder
            .tx_tracker_map
            .lock()
            .unwrap()
            .contains_key(&breach.penalty_tx.txid()));
        assert_eq!(
            responder.tx_tracker_map.lock().unwrap()[&breach.penalty_tx.txid()].len(),
            2
        );
        assert_eq!(
            responder.dbm.lock().unwrap().load_tracker(uuid).unwrap(),
            TransactionTracker::new(breach, user_id)
        );
    }

    #[test]
    fn test_has_tracker() {
        // Has tracker should return true as long as the given tracker is held by the Responder.
        // As long as the tracker is in Responder.trackers and Responder.tx_tracker_map, the return
        // must be true.
        let (responder, _) = init_responder(MockedServerQuery::Regular);

        // Add a new tracker
        let user_id = get_random_user_id();
        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        store_appointment_and_fks_to_db(&responder.dbm.lock().unwrap(), uuid, &appointment);

        let breach = get_random_breach_from_locator(appointment.locator());
        responder.add_tracker(uuid, breach.clone(), user_id, 0);

        assert!(responder.has_tracker(uuid));

        // Delete the tracker and check again
        responder.delete_trackers(HashSet::from_iter([uuid]), false);
        assert!(!responder.has_tracker(uuid));
    }

    #[test]
    fn test_get_tracker() {
        // Should return a tracker as long as it exists
        let (responder, _) = init_responder(MockedServerQuery::Regular);

        // Store the user and the appointment in the database so we can add the tracker later on (due to FK restrictions)
        let user_id = get_random_user_id();
        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        store_appointment_and_fks_to_db(&responder.dbm.lock().unwrap(), uuid, &appointment);

        // Data should not be there before adding it
        assert_eq!(responder.get_tracker(uuid), None);

        // Data should be there now
        let breach = get_random_breach_from_locator(appointment.locator());
        let tracker = TransactionTracker::new(breach.clone(), user_id);
        responder.add_tracker(uuid, breach, user_id, 0);
        assert_eq!(responder.get_tracker(uuid).unwrap(), tracker);

        // After deleting the data it should be gone
        responder.delete_trackers(HashSet::from_iter([uuid]), false);
        assert_eq!(responder.get_tracker(uuid), None);
    }

    #[test]
    fn test_check_confirmations() {
        let (responder, _) = init_responder(MockedServerQuery::Regular);

        // If a transaction is in the unconfirmed_transactions map it will be removed
        let mut txs = Vec::new();
        for _ in 0..10 {
            let tx = get_random_tx();
            txs.push(tx.clone());
            responder.unconfirmed_txs.lock().unwrap().insert(tx.txid());
        }

        responder.check_confirmations(&txs);

        for tx in txs.iter() {
            assert!(!responder
                .unconfirmed_txs
                .lock()
                .unwrap()
                .contains(&tx.txid()));
            assert!(!responder
                .missed_confirmations
                .lock()
                .unwrap()
                .contains_key(&tx.txid()));
        }
        // All the transactions remaining in the unconfirmed_transactions map are added a missed confirmation
        let mut unconfirmed_txs = Vec::new();
        for (i, tx) in txs.into_iter().enumerate() {
            if i % 2 == 0 {
                responder.unconfirmed_txs.lock().unwrap().insert(tx.txid());
                unconfirmed_txs.push(tx);
            }
        }

        for i in 1..10 {
            responder.check_confirmations(&Vec::new());
            for tx in unconfirmed_txs.iter() {
                assert!(responder
                    .unconfirmed_txs
                    .lock()
                    .unwrap()
                    .contains(&tx.txid()));
                assert_eq!(
                    responder
                        .missed_confirmations
                        .lock()
                        .unwrap()
                        .get(&tx.txid())
                        .unwrap(),
                    &i
                );
            }
        }
    }

    #[test]
    fn test_get_txs_to_rebroadcast() {
        let (responder, _) = init_responder(MockedServerQuery::Regular);

        let user_id = get_random_user_id();
        responder
            .dbm
            .lock()
            .unwrap()
            .store_user(user_id, &UserInfo::new(21, 42))
            .unwrap();

        // Transactions are flagged to be rebroadcast when they've missed CONFIRMATIONS_BEFORE_RETRY confirmations
        let mut txs = Vec::new();

        for i in 0..CONFIRMATIONS_BEFORE_RETRY + 2 {
            // Add the appointment to the db so FK rules are satisfied
            let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
            responder
                .dbm
                .lock()
                .unwrap()
                .store_appointment(uuid, &appointment)
                .unwrap();

            // Create a breach and add it, manually setting the missed confirmation count
            let breach = get_random_breach_from_locator(appointment.locator());
            txs.push(breach.penalty_tx.clone());

            responder.add_tracker(uuid, breach.clone(), user_id, 0);
            responder
                .missed_confirmations
                .lock()
                .unwrap()
                .insert(breach.penalty_tx.txid(), i);
        }

        let txs_to_rebroadcast: HashSet<Transaction> =
            HashSet::from_iter(responder.get_txs_to_rebroadcast());
        let target_txs: HashSet<Transaction> =
            HashSet::from_iter(txs[CONFIRMATIONS_BEFORE_RETRY as usize..].to_vec());

        assert_eq!(target_txs, txs_to_rebroadcast)
    }

    #[tokio::test]
    async fn test_get_completed_trackers() {
        let (responder, _) = init_responder(MockedServerQuery::Regular);

        let user_id = get_random_user_id();
        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        store_appointment_and_fks_to_db(&responder.dbm.lock().unwrap(), uuid, &appointment);

        // Let's add a tracker first
        let breach = get_random_breach_from_locator(appointment.locator());
        responder.add_tracker(uuid, breach.clone(), user_id, 1);

        // A tracker is completed when it has passed constants::IRREVOCABLY_RESOLVED confirmations
        // Not completed yet
        for i in 1..constants::IRREVOCABLY_RESOLVED + 2 {
            assert_eq!(responder.get_completed_trackers().await, HashSet::new());
            *responder.carrier.lock().unwrap() =
                create_carrier(MockedServerQuery::Confirmations(i));
        }

        // Just completed
        *responder.carrier.lock().unwrap() = create_carrier(MockedServerQuery::Confirmations(
            constants::IRREVOCABLY_RESOLVED + 1,
        ));
        assert_eq!(
            responder.get_completed_trackers().await,
            [uuid].iter().cloned().collect()
        );
    }

    #[test]
    fn test_get_outdated_trackers() {
        let (responder, _) = init_responder(MockedServerQuery::Regular);

        // Outdated trackers are those whose associated subscription is outdated and have not been confirmed yet (they don't have
        // a single confirmation).

        // Mock data into the GK
        let target_block_height = 100;
        let user_id = get_random_user_id();
        let uuids = (0..10)
            .into_iter()
            .map(|_| generate_uuid())
            .collect::<Vec<UUID>>();
        responder
            .gatekeeper
            .add_outdated_user(user_id, target_block_height, Some(uuids.clone()));

        // If data is not in the unconfirmed_transaction it won't be returned
        assert_eq!(
            responder.get_outdated_trackers(target_block_height),
            HashSet::new(),
        );

        // Otherwise the matching data should be returned

        // Mock the data to the Responder. Add data to trackers and half of them to the unconfirmed_transactions map
        let mut target_uuids = HashSet::new();
        for (i, uuid) in uuids.into_iter().enumerate() {
            let tracker = get_random_tracker(user_id);
            responder
                .trackers
                .lock()
                .unwrap()
                .insert(uuid, tracker.get_summary());

            if i % 2 == 0 {
                responder
                    .unconfirmed_txs
                    .lock()
                    .unwrap()
                    .insert(tracker.penalty_tx.txid());
                target_uuids.insert(uuid);
            }
        }

        // Check the expected data is there
        assert_eq!(
            responder.get_outdated_trackers(target_block_height),
            target_uuids
        );
    }

    #[tokio::test]
    async fn test_rebroadcast() {
        let (responder, _) = init_responder(MockedServerQuery::Regular);

        // Add user to the database
        let user_id = get_random_user_id();
        responder
            .dbm
            .lock()
            .unwrap()
            .store_user(user_id, &UserInfo::new(21, 42))
            .unwrap();

        // Transactions are rebroadcast once they hit CONFIRMATIONS_BEFORE_RETRY
        // Add some trackers and set their missed confirmation count
        let mut need_rebroadcast = Vec::new();
        let mut dont_need_rebroadcast = Vec::new();

        for i in 0..10 {
            // Generate appointment and also add it to the DB (FK checks)
            let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
            responder
                .dbm
                .lock()
                .unwrap()
                .store_appointment(uuid, &appointment)
                .unwrap();

            let breach = get_random_breach_from_locator(appointment.locator());
            let penalty_txid = breach.penalty_tx.txid();
            responder.add_tracker(uuid, breach, user_id, 0);

            if i % 2 == 0 {
                responder
                    .missed_confirmations
                    .lock()
                    .unwrap()
                    .insert(penalty_txid.clone(), CONFIRMATIONS_BEFORE_RETRY);
                need_rebroadcast.push(penalty_txid);
            } else {
                responder
                    .missed_confirmations
                    .lock()
                    .unwrap()
                    .insert(penalty_txid.clone(), CONFIRMATIONS_BEFORE_RETRY - 1);
                dont_need_rebroadcast.push(penalty_txid);
            }
        }

        for (txid, receipt) in responder.rebroadcast().await {
            assert_eq!(
                responder
                    .missed_confirmations
                    .lock()
                    .unwrap()
                    .get(&txid)
                    .unwrap()
                    .to_owned(),
                0
            );
            assert!(receipt.delivered());
        }

        for txid in dont_need_rebroadcast {
            assert_eq!(
                responder
                    .missed_confirmations
                    .lock()
                    .unwrap()
                    .get(&txid)
                    .unwrap()
                    .to_owned(),
                CONFIRMATIONS_BEFORE_RETRY - 1
            );
        }
    }

    #[test]
    fn test_delete_trackers() {
        let (responder, _) = init_responder(MockedServerQuery::Regular);

        // Add user to the database
        let user_id = get_random_user_id();
        responder
            .dbm
            .lock()
            .unwrap()
            .store_user(user_id, &UserInfo::new(21, 42))
            .unwrap();

        // Delete trackers removes data from the trackers, tx_tracker_map maps, the database (and unconfirmed_txs if the data is outdated)
        // The deletion of the later is better check in test_block_connected
        // Add data to the map first
        let mut all_trackers = HashSet::new();
        let mut target_trackers = HashSet::new();
        let mut uuid_txid_map = HashMap::new();
        let mut txs_with_multiple_uuids = HashSet::new();

        for i in 0..10 {
            // Generate appointment and also add it to the DB (FK checks)
            let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
            responder
                .dbm
                .lock()
                .unwrap()
                .store_appointment(uuid, &appointment)
                .unwrap();

            let breach = get_random_breach_from_locator(appointment.locator());
            responder.add_tracker(uuid, breach.clone(), user_id, 0);

            // Make it so some of the penalties have multiple associated trackers
            if i % 3 == 0 {
                let uuid2 = generate_uuid();
                responder
                    .tx_tracker_map
                    .lock()
                    .unwrap()
                    .get_mut(&breach.penalty_tx.txid())
                    .unwrap()
                    .insert(uuid2);
                txs_with_multiple_uuids.insert(breach.penalty_tx.txid());
            }

            all_trackers.insert(uuid);
            uuid_txid_map.insert(uuid, breach.penalty_tx.txid());

            // Add some trackers to be deleted
            if i % 2 == 0 {
                target_trackers.insert(uuid);
            }
        }

        responder.delete_trackers(target_trackers.clone(), false);

        // Only trackers in the target_trackers map should have been removed from
        // the Responder data structures.
        for uuid in all_trackers {
            if target_trackers.contains(&uuid) {
                assert!(!responder.trackers.lock().unwrap().contains_key(&uuid));
                assert!(matches!(
                    responder.dbm.lock().unwrap().load_tracker(uuid),
                    Err(DBError::NotFound)
                ));
                let penalty_txid = &uuid_txid_map[&uuid];
                // If the penalty had more than one associated uuid, only one has been deleted
                // (because that's how the test has been designed)
                if txs_with_multiple_uuids.contains(penalty_txid) {
                    assert_eq!(
                        responder
                            .tx_tracker_map
                            .lock()
                            .unwrap()
                            .get(penalty_txid)
                            .unwrap()
                            .len(),
                        1
                    );
                } else {
                    // Otherwise the whole structure is removed, given it is now empty
                    assert!(!responder
                        .tx_tracker_map
                        .lock()
                        .unwrap()
                        .contains_key(penalty_txid));
                }
            } else {
                assert!(responder.trackers.lock().unwrap().contains_key(&uuid));
                assert!(responder
                    .tx_tracker_map
                    .lock()
                    .unwrap()
                    .contains_key(&uuid_txid_map[&uuid]));
                assert!(matches!(
                    responder.dbm.lock().unwrap().load_tracker(uuid),
                    Ok(TransactionTracker { .. })
                ));
            }
        }
    }

    #[test]
    fn test_block_connected() {
        let (responder, mut chain) = init_responder(MockedServerQuery::Confirmations(
            constants::IRREVOCABLY_RESOLVED + 1,
        ));

        // block_connected is used to keep track of the confirmation received (or missed) by the trackers the Responder
        // is keeping track of.

        // If the Responder has no trackers, block_connected will only be used to track the last known block by the Responder.
        assert_eq!(
            responder.last_known_block_header.lock().unwrap().header,
            chain.tip().header
        );
        responder.block_connected(&chain.generate(None), chain.blocks.len() as u32);
        assert_eq!(
            responder.last_known_block_header.lock().unwrap().header,
            chain.tip().header
        );
        // Check the id is also stored in the database
        assert_eq!(
            responder
                .last_known_block_header
                .lock()
                .unwrap()
                .header
                .block_hash(),
            responder
                .dbm
                .lock()
                .unwrap()
                .load_last_known_block_responder()
                .unwrap()
        );

        // If there are any trackers, the Responder will:
        // - Check if there is any tracker that has been completed
        // - Check if there is any tracker that has been outdated
        // - Check if any tracker has been confirmed or add missing confirmations otherwise
        // - Rebroadcast all penalty transactions that need so
        // - Delete completed and outdated data (including data in the GK)
        // - Clear the Carrier issued_receipts cache

        // Let's start by doing the data setup for each test (i.e. adding all the necessary data to the Responder and GK)
        let mut users = Vec::new();
        for _ in 2..23 {
            let user_id = get_random_user_id();

            responder.gatekeeper.add_update_user(user_id).unwrap();
            users.push(user_id);
        }

        let mut completed_trackers = HashMap::new();

        // COMPLETED TRACKERS SETUP
        for i in 0..10 {
            // Adding two trackers to each user
            let user_id = users[i % 2];
            let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);

            responder
                .dbm
                .lock()
                .unwrap()
                .store_appointment(uuid, &appointment)
                .unwrap();

            let breach = get_random_breach_from_locator(appointment.locator());
            responder.add_tracker(
                uuid,
                breach.clone(),
                user_id,
                constants::IRREVOCABLY_RESOLVED + 1,
            );
            responder
                .gatekeeper
                .get_registered_users()
                .lock()
                .unwrap()
                .get_mut(&user_id)
                .unwrap()
                .appointments
                .insert(uuid, 1);

            completed_trackers.insert(uuid, (user_id, breach));
        }

        // OUTDATED TRACKER SETUP
        let mut penalties = Vec::new();
        let mut uuids = Vec::new();
        let target_block_height = (chain.blocks.len() + 1) as u32;
        for i in 11..21 {
            let pair = [generate_uuid(), generate_uuid()].to_vec();
            let user_id = users[i];

            for uuid in pair.iter() {
                let (_, appointment) = generate_dummy_appointment_with_user(user_id, None);
                responder
                    .dbm
                    .lock()
                    .unwrap()
                    .store_appointment(*uuid, &appointment)
                    .unwrap();

                let breach = get_random_breach_from_locator(appointment.locator());
                penalties.push(breach.penalty_tx.txid());
                responder.add_tracker(*uuid, breach, user_id, 0);
            }

            uuids.extend(pair.clone());
            responder
                .gatekeeper
                .add_outdated_user(user_id, target_block_height, Some(pair));
        }

        // CONFIRMATIONS SETUP
        let standalone_user_id = get_random_user_id();
        responder
            .gatekeeper
            .add_update_user(standalone_user_id)
            .unwrap();

        let mut transactions = Vec::new();
        let mut confirmed_txs = Vec::new();
        let mut confirmations: u32;
        for i in 0..10 {
            let (uuid, appointment) =
                generate_dummy_appointment_with_user(standalone_user_id, None);
            responder
                .dbm
                .lock()
                .unwrap()
                .store_appointment(uuid, &appointment)
                .unwrap();

            let breach = get_random_breach_from_locator(appointment.locator());
            transactions.push(breach.clone().penalty_tx.txid());

            if i % 2 == 0 {
                confirmations = 0;
            } else {
                confirmed_txs.push(breach.clone().penalty_tx.txid());
                confirmations = 1;
            };

            responder.add_tracker(uuid, breach, standalone_user_id, confirmations);
        }

        // REBROADCAST SETUP
        let (uuid, appointment) = generate_dummy_appointment_with_user(standalone_user_id, None);

        responder
            .dbm
            .lock()
            .unwrap()
            .store_appointment(uuid, &appointment)
            .unwrap();

        let breach_rebroadcast = get_random_breach_from_locator(appointment.locator());
        responder.add_tracker(uuid, breach_rebroadcast.clone(), standalone_user_id, 0);
        responder.missed_confirmations.lock().unwrap().insert(
            breach_rebroadcast.penalty_tx.txid(),
            CONFIRMATIONS_BEFORE_RETRY,
        );

        // CARRIER CACHE SETUP
        // Add some dummy data in the cache to check that it gets cleared
        responder
            .carrier
            .lock()
            .unwrap()
            .get_issued_receipts()
            .insert(
                get_random_tx().txid(),
                DeliveryReceipt::new(true, Some(0), None),
            );

        // Connecting a block should trigger all the state transitions
        responder.block_connected(&chain.generate(None), chain.blocks.len() as u32);

        // CARRIER CHECKS
        assert!(responder
            .carrier
            .lock()
            .unwrap()
            .get_issued_receipts()
            .is_empty());

        // COMPLETED TRACKERS CHECKS
        // Data should have been removed
        for (uuid, (user_id, breach)) in completed_trackers {
            assert!(!responder.trackers.lock().unwrap().contains_key(&uuid));
            assert!(!responder
                .tx_tracker_map
                .lock()
                .unwrap()
                .contains_key(&breach.penalty_tx.txid()));
            assert!(
                !responder.gatekeeper.get_registered_users().lock().unwrap()[&user_id]
                    .appointments
                    .contains_key(&uuid)
            );
        }

        // OUTDATED TRACKERS CHECKS
        // Data should have been removed
        for uuid in uuids {
            assert!(!responder.trackers.lock().unwrap().contains_key(&uuid));
        }
        for txid in penalties {
            assert!(!responder.tx_tracker_map.lock().unwrap().contains_key(&txid));
            assert!(!responder.unconfirmed_txs.lock().unwrap().contains(&txid));
        }

        // CONFIRMATIONS CHECKS
        // The transaction confirmation count / confirmation missed should have been updated
        for txid in transactions {
            if confirmed_txs.contains(&txid) {
                assert!(!responder.unconfirmed_txs.lock().unwrap().contains(&txid));
                assert!(!responder
                    .missed_confirmations
                    .lock()
                    .unwrap()
                    .contains_key(&txid));
            } else {
                assert!(responder.unconfirmed_txs.lock().unwrap().contains(&txid));
                assert_eq!(
                    responder
                        .missed_confirmations
                        .lock()
                        .unwrap()
                        .get(&txid)
                        .unwrap()
                        .to_owned(),
                    1
                );
            }
        }

        // REBROADCAST CHECKS
        // The penalty transaction in breach_rebroadcast should have been rebroadcast
        assert_eq!(
            responder.missed_confirmations.lock().unwrap()[&breach_rebroadcast.penalty_tx.txid()],
            0
        );
    }
}
