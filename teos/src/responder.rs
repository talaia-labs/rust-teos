//! Logic related to the Responder, the components in charge of making sure breaches get properly punished.

use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

use bitcoin::util::psbt::serialize::Serialize;
use bitcoin::{BlockHeader, Transaction, Txid};
use lightning::chain::Listen;
use lightning_block_sync::poll::ValidatedBlockHeader;
use lightning_block_sync::BlockHeaderData;

use teos_common::constants;
use teos_common::UserId;

use crate::carrier::{Carrier, DeliveryReceipt};
use crate::dbm::DBM;
use crate::extended_appointment::UUID;
use crate::gatekeeper::{Gatekeeper, UserInfo};
use crate::protos as msgs;
use crate::watcher::Breach;

/// Number of missed confirmations to wait before rebroadcasting a transaction.
const CONFIRMATIONS_BEFORE_RETRY: u8 = 6;

/// Minimal data required in memory to keep track of transaction trackers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrackerSummary {
    /// Identifier of the user who arranged the appointment.
    user_id: UserId,
    /// Transaction id the [Responder] is keeping track of.
    penalty_txid: Txid,
    /// The height where the penalty transaction was confirmed at.
    height: Option<u32>,
}

/// Structure to keep track of triggered appointments.
///
/// It is analogous to [ExtendedAppointment](crate::extended_appointment::ExtendedAppointment) for the [`Watcher`](crate::watcher::Watcher).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TransactionTracker {
    /// Matches the corresponding [Breach] `dispute_tx` field.
    pub dispute_tx: Transaction,
    /// Matches the corresponding [Breach] penalty_tx field.
    pub penalty_tx: Transaction,
    /// The height where the penalty transaction was confirmed at.
    pub height: Option<u32>,
    /// [UserId] the original [ExtendedAppointment](crate::extended_appointment::ExtendedAppointment) belongs to.
    pub user_id: UserId,
}

impl TransactionTracker {
    /// Creates a new [TransactionTracker] instance.
    pub fn new(breach: Breach, user_id: UserId, height: Option<u32>) -> Self {
        Self {
            dispute_tx: breach.dispute_tx,
            penalty_tx: breach.penalty_tx,
            height,
            user_id,
        }
    }

    /// Computes the [TrackerSummary] of the [TransactionTracker].
    pub fn get_summary(&self) -> TrackerSummary {
        TrackerSummary {
            user_id: self.user_id,
            penalty_txid: self.penalty_tx.txid(),
            height: self.height,
        }
    }
}

impl From<TransactionTracker> for msgs::Tracker {
    fn from(t: TransactionTracker) -> Self {
        msgs::Tracker {
            dispute_txid: t.dispute_tx.txid().to_vec(),
            penalty_txid: t.penalty_tx.txid().to_vec(),
            penalty_rawtx: t.penalty_tx.serialize(),
        }
    }
}

/// Component in charge of keeping track of triggered appointments.
///
/// The [Responder] receives data from the [Watcher](crate::watcher::Watcher) in form of a [Breach].
/// From there, a [TransactionTracker] is created and the penalty transaction is sent to the network via the [Carrier].
/// The [Transaction] is then monitored to make sure it makes it to a block and it gets [irrevocably resolved](https://github.com/lightning/bolts/blob/master/05-onchain.md#general-nomenclature).
#[derive(Debug)]
pub struct Responder {
    /// A map holding a summary of every tracker ([TransactionTracker]) hold by the [Responder], identified by [UUID].
    /// The identifiers match those used by the [Watcher](crate::watcher::Watcher).
    trackers: Mutex<HashMap<UUID, TrackerSummary>>,
    /// A map between [Txid]s and [UUID]s.
    tx_tracker_map: Mutex<HashMap<Txid, HashSet<UUID>>>,
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
        let mut trackers = HashMap::new();
        let mut tx_tracker_map: HashMap<Txid, HashSet<UUID>> = HashMap::new();

        for (uuid, tracker) in dbm.lock().unwrap().load_all_trackers() {
            trackers.insert(uuid, tracker.get_summary());

            if let Some(map) = tx_tracker_map.get_mut(&tracker.penalty_tx.txid()) {
                map.insert(uuid);
            } else {
                tx_tracker_map.insert(tracker.penalty_tx.txid(), HashSet::from_iter(vec![uuid]));
            }
        }

        Responder {
            carrier: Mutex::new(carrier),
            trackers: Mutex::new(trackers),
            tx_tracker_map: Mutex::new(tx_tracker_map),
            missed_confirmations: Mutex::new(HashMap::new()),
            dbm,
            gatekeeper,
            last_known_block_header: Mutex::new(*last_known_block_header.deref()),
        }
    }

    /// Returns whether the [Responder] has been created from scratch (fresh) or from backed-up data.
    pub fn is_fresh(&self) -> bool {
        self.trackers.lock().unwrap().is_empty()
    }

    /// Gets the total number of trackers in the responder.
    pub(crate) fn get_trackers_count(&self) -> usize {
        self.trackers.lock().unwrap().len()
    }

    /// Data entry point for the [Responder]. Handles a [Breach] provided by the [Watcher](crate::watcher::Watcher).
    ///
    /// Breaches can either be added to the [Responder] in the form of a [TransactionTracker] if the [penalty transaction](Breach::penalty_tx)
    /// is accepted by the `bitcoind` or rejected otherwise.
    pub(crate) fn handle_breach(
        &self,
        uuid: UUID,
        breach: Breach,
        user_id: UserId,
    ) -> DeliveryReceipt {
        let mut carrier = self.carrier.lock().unwrap();

        // Do not add already added trackers. This can only happen if handle_breach is called twice with the same data, which can only happen
        // if Watcher::block_connected is interrupted during execution and called back during bootstrap.
        if let Some(tracker) = self.trackers.lock().unwrap().get(&uuid) {
            return DeliveryReceipt::new(true, tracker.height, None);
        }

        let receipt = carrier.send_transaction(&breach.penalty_tx);
        if receipt.delivered() {
            self.add_tracker(uuid, breach, user_id, receipt.height());
        }
        receipt
    }

    /// Adds a [TransactionTracker] to the [Responder] from a given [Breach].
    ///
    /// From this point on, transactions are accepted as valid. They may not end up being confirmed, but they
    /// have been checked syntactically by the [Watcher](crate::watcher::Watcher) and against consensus / network
    /// acceptance rules by the [Carrier].
    ///
    /// Some transaction may already be confirmed by the time the tower tries to send them to the network. If that's the case,
    /// the [Responder] will simply continue tracking the job until its completion.
    pub(crate) fn add_tracker(
        &self,
        uuid: UUID,
        breach: Breach,
        user_id: UserId,
        tx_height: Option<u32>,
    ) {
        let tracker = TransactionTracker::new(breach, user_id, tx_height);

        self.trackers
            .lock()
            .unwrap()
            .insert(uuid, tracker.get_summary());

        let mut tx_tracker_map = self.tx_tracker_map.lock().unwrap();
        if let Some(map) = tx_tracker_map.get_mut(&tracker.penalty_tx.txid()) {
            map.insert(uuid);
        } else {
            tx_tracker_map.insert(tracker.penalty_tx.txid(), HashSet::from_iter(vec![uuid]));
        }

        self.dbm
            .lock()
            .unwrap()
            .store_tracker(uuid, &tracker)
            .unwrap();
        log::info!("New tracker added (uuid={}).", uuid);
    }

    /// Checks whether a given tracker can be found in the [Responder].
    pub(crate) fn has_tracker(&self, uuid: UUID) -> bool {
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
    pub(crate) fn get_tracker(&self, uuid: UUID) -> Option<TransactionTracker> {
        if self.trackers.lock().unwrap().contains_key(&uuid) {
            self.dbm.lock().unwrap().load_tracker(uuid).ok()
        } else {
            None
        }
    }

    /// Checks and updates the confirmation count for the [TransactionTracker]s.
    ///
    /// For unconfirmed transactions, it checks whether they have been confirmed or keep missing confirmations.
    /// For confirmed transactions, it keeps increasing the confirmation count until they are completed (confirmation count reaches [IRREVOCABLY_RESOLVED](constants::IRREVOCABLY_RESOLVED))
    /// Returns the set of completed trackers.
    fn check_confirmations(&self, txids: &[Txid], current_height: u32) -> HashSet<UUID> {
        let mut completed_trackers = HashSet::new();
        let mut missed_confirmations = self.missed_confirmations.lock().unwrap();

        for (uuid, tracker) in self.trackers.lock().unwrap().iter_mut() {
            if let Some(tx_height) = tracker.height {
                if current_height - tx_height == constants::IRREVOCABLY_RESOLVED {
                    // Tracker is deep enough in the chain, it can be deleted
                    completed_trackers.insert(*uuid);
                }
            } else if txids.contains(&tracker.penalty_txid) {
                // First confirmation was received
                tracker.height = Some(current_height);
                missed_confirmations.remove(&tracker.penalty_txid);
            } else {
                // Increase the missing confirmation count for all those transactions pending confirmation that have not been confirmed this block
                match missed_confirmations.get_mut(&tracker.penalty_txid) {
                    Some(x) => *x += 1,
                    None => {
                        missed_confirmations.insert(tracker.penalty_txid, 1);
                    }
                }
                log::info!(
                    "Transaction missed a confirmation: {} (missed conf count: {})",
                    tracker.penalty_txid,
                    missed_confirmations.get(&tracker.penalty_txid).unwrap()
                );
            }
        }

        completed_trackers
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

    /// Gets a collection of trackers that have been outdated. An outdated tracker is a [TransactionTracker]
    /// from a user who's subscription has been outdated (and therefore will be removed from the tower).
    fn get_outdated_trackers(&self, block_height: u32) -> HashSet<UUID> {
        let mut outdated_trackers = HashSet::new();
        let trackers = self.trackers.lock().unwrap();
        for uuid in self
            .gatekeeper
            .get_outdated_appointments(block_height)
            .intersection(&trackers.keys().cloned().collect())
        {
            if trackers[uuid].height.is_none() {
                outdated_trackers.insert(*uuid);
            }
        }

        outdated_trackers
    }

    /// Rebroadcasts a list of penalty transactions that have missed too many confirmations.
    // FIXME: This is not of much use at the moment given fees can not be bumped. It may be
    // useful if nodes have wiped the transaction from the mempool for some reasons.
    fn rebroadcast(&self) -> HashMap<Txid, DeliveryReceipt> {
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

            let receipt = carrier.send_transaction(&penalty_tx);

            if !receipt.delivered() {
                // This may if the original tx is RBF and it has been already replaced by a higher fee variant.
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

    /// Deletes trackers from memory.
    ///
    /// Logs a different message depending on whether the trackers have been outdated or completed.
    fn delete_trackers_from_memory(&self, uuids: &HashSet<UUID>, outdated: bool) {
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
    }

    /// Deletes trackers from memory and the database.
    ///
    /// Removes all data related to the appointment from the database in cascade.
    fn delete_trackers(
        &self,
        uuids: &HashSet<UUID>,
        updated_users: &HashMap<UserId, UserInfo>,
        outdated: bool,
    ) {
        self.delete_trackers_from_memory(uuids, outdated);
        self.dbm
            .lock()
            .unwrap()
            .batch_remove_appointments(uuids, updated_users);
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
            // Complete those appointments that are due at this height
            let completed_trackers = self.check_confirmations(
                &block
                    .txdata
                    .iter()
                    .map(|tx| tx.txid())
                    .collect::<Vec<Txid>>(),
                height,
            );
            let trackers_to_delete_gk = completed_trackers
                .iter()
                .map(|uuid| (*uuid, self.trackers.lock().unwrap()[uuid].user_id))
                .collect();
            self.delete_trackers(
                &completed_trackers,
                &self
                    .gatekeeper
                    .delete_appointments_from_memory(&trackers_to_delete_gk),
                false,
            );

            // Also delete trackers from outdated users (from memory only, the db deletion is handled by the Gatekeeper)
            self.delete_trackers_from_memory(&self.get_outdated_trackers(height), true);

            // Rebroadcast those transactions that need to
            self.rebroadcast();

            // Remove all receipts created in this block
            self.carrier.lock().unwrap().clear_receipts();

            if self.trackers.lock().unwrap().is_empty() {
                log::info!("No more pending trackers");
            }
        }

        // Update last known block
        *self.last_known_block_header.lock().unwrap() = BlockHeaderData {
            header: block.header,
            height,
            chainwork: block.header.work(),
        };
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
        get_random_tracker, get_random_tx, get_random_user_id, store_appointment_and_fks_to_db,
        Blockchain, MockedServerQuery, DURATION, EXPIRY_DELTA, SLOTS, START_HEIGHT,
    };

    impl PartialEq for Responder {
        fn eq(&self, other: &Self) -> bool {
            *self.trackers.lock().unwrap() == *other.trackers.lock().unwrap()
                && *self.tx_tracker_map.lock().unwrap() == *other.tx_tracker_map.lock().unwrap()
                && *self.last_known_block_header.lock().unwrap()
                    == *other.last_known_block_header.lock().unwrap()
        }
    }
    impl Eq for Responder {}

    impl Responder {
        pub(crate) fn get_trackers(&self) -> &Mutex<HashMap<UUID, TrackerSummary>> {
            &self.trackers
        }

        pub(crate) fn get_carrier(&self) -> &Mutex<Carrier> {
            &self.carrier
        }

        pub(crate) fn add_random_tracker(&self, uuid: UUID, height: Option<u32>) {
            let user_id = get_random_user_id();
            let tracker = get_random_tracker(user_id, height);

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
        chain: &Blockchain,
        gatekeeper: Arc<Gatekeeper>,
        dbm: Arc<Mutex<DBM>>,
        query: MockedServerQuery,
    ) -> Responder {
        let tip = chain.tip();
        let carrier = create_carrier(query);
        Responder::new(carrier, gatekeeper, dbm, tip)
    }

    fn init_responder_with_chain_and_dbm(
        mocked_query: MockedServerQuery,
        chain: &Blockchain,
        dbm: Arc<Mutex<DBM>>,
    ) -> Responder {
        let gk = Gatekeeper::new(chain.tip(), SLOTS, DURATION, EXPIRY_DELTA, dbm.clone());
        create_responder(chain, Arc::new(gk), dbm, mocked_query)
    }

    fn init_responder(mocked_query: MockedServerQuery) -> Responder {
        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let chain = Blockchain::default().with_height_and_txs(START_HEIGHT, 10);
        init_responder_with_chain_and_dbm(mocked_query, &chain, dbm)
    }

    #[test]
    fn test_new() {
        // A fresh responder has no associated data
        let chain = Blockchain::default().with_height(START_HEIGHT);
        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let responder =
            init_responder_with_chain_and_dbm(MockedServerQuery::Regular, &chain, dbm.clone());
        assert!(responder.is_fresh());

        // If we add some trackers to the system and create a new Responder reusing the same db
        // (as if simulating a bootstrap from existing data), the data should be properly loaded.
        for i in 0..10 {
            // Add the necessary FKs in the database
            let user_id = get_random_user_id();
            let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
            store_appointment_and_fks_to_db(&responder.dbm.lock().unwrap(), uuid, &appointment);

            let breach = get_random_breach();
            let height = if i % 2 == 0 { None } else { Some(i) };
            responder.add_tracker(uuid, breach.clone(), user_id, height);
        }

        // Create a new Responder reusing the same DB and check that the data is loaded
        let another_r = init_responder_with_chain_and_dbm(MockedServerQuery::Regular, &chain, dbm);
        assert!(!responder.is_fresh());
        assert_eq!(responder, another_r);
    }

    #[test]
    fn test_handle_breach_delivered() {
        let responder = init_responder(MockedServerQuery::Regular);

        let user_id = get_random_user_id();
        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        store_appointment_and_fks_to_db(&responder.dbm.lock().unwrap(), uuid, &appointment);

        let breach = get_random_breach();
        let penalty_txid = breach.penalty_tx.txid();

        let r = responder.handle_breach(uuid, breach, user_id);

        assert!(r.delivered());
        assert!(responder.trackers.lock().unwrap().contains_key(&uuid));
        assert!(responder.trackers.lock().unwrap()[&uuid].height.is_none());
        assert!(responder
            .tx_tracker_map
            .lock()
            .unwrap()
            .contains_key(&penalty_txid));

        // Breaches won't be overwritten once passed to the Responder. If the same UUID is
        // passed twice, the receipt corresponding to the first breach will be handed back.
        let another_breach = get_random_breach();
        let r = responder.handle_breach(uuid, another_breach.clone(), user_id);
        assert!(r.delivered());
        assert!(responder.trackers.lock().unwrap().contains_key(&uuid));
        assert!(responder.trackers.lock().unwrap()[&uuid].height.is_none());
        assert!(!responder
            .tx_tracker_map
            .lock()
            .unwrap()
            .contains_key(&another_breach.penalty_tx.txid()));
    }

    #[test]
    fn test_handle_breach_not_delivered() {
        let responder = init_responder(MockedServerQuery::Error(
            rpc_errors::RPC_VERIFY_ERROR as i64,
        ));

        let user_id = get_random_user_id();
        let uuid = generate_uuid();
        let breach = get_random_breach();
        let penalty_txid = breach.penalty_tx.txid();

        let r = responder.handle_breach(uuid, breach, user_id);

        assert!(!r.delivered());
        assert!(!responder.trackers.lock().unwrap().contains_key(&uuid));
        assert!(!responder
            .tx_tracker_map
            .lock()
            .unwrap()
            .contains_key(&penalty_txid));
    }

    #[test]
    fn test_add_tracker() {
        let responder = init_responder(MockedServerQuery::Regular);
        let start_height = START_HEIGHT as u32;

        // Add the necessary FKs in the database
        let user_id = get_random_user_id();
        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        store_appointment_and_fks_to_db(&responder.dbm.lock().unwrap(), uuid, &appointment);

        let mut breach = get_random_breach();
        responder.add_tracker(uuid, breach.clone(), user_id, None);

        // Check that the data has been added to trackers and to the tx_tracker_map
        assert_eq!(
            responder.trackers.lock().unwrap().get(&uuid),
            Some(&TrackerSummary {
                user_id,
                penalty_txid: breach.penalty_tx.txid(),
                height: None
            })
        );
        assert!(responder
            .tx_tracker_map
            .lock()
            .unwrap()
            .contains_key(&breach.penalty_tx.txid()));
        // Check that the data is also in the database
        assert_eq!(
            responder.dbm.lock().unwrap().load_tracker(uuid).unwrap(),
            TransactionTracker::new(breach, user_id, None)
        );

        // Adding a confirmed tracker should result in the same but with the height being set.
        let uuid = generate_uuid();
        breach = get_random_breach();

        responder
            .dbm
            .lock()
            .unwrap()
            .store_appointment(uuid, &appointment)
            .unwrap();

        responder.add_tracker(uuid, breach.clone(), user_id, Some(start_height));

        assert_eq!(
            responder.trackers.lock().unwrap().get(&uuid),
            Some(&TrackerSummary {
                user_id,
                penalty_txid: breach.penalty_tx.txid(),
                height: Some(start_height)
            })
        );
        assert!(responder
            .tx_tracker_map
            .lock()
            .unwrap()
            .contains_key(&breach.penalty_tx.txid()));
        assert_eq!(
            responder.tx_tracker_map.lock().unwrap()[&breach.penalty_tx.txid()].len(),
            1
        );
        assert_eq!(
            responder.dbm.lock().unwrap().load_tracker(uuid).unwrap(),
            TransactionTracker::new(breach.clone(), user_id, Some(start_height))
        );

        // Adding another breach with the same penalty transaction (but different uuid) adds an additional uuid to the map entry
        let uuid = generate_uuid();
        responder
            .dbm
            .lock()
            .unwrap()
            .store_appointment(uuid, &appointment)
            .unwrap();

        responder.add_tracker(uuid, breach.clone(), user_id, Some(start_height * 2));

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
            TransactionTracker::new(breach, user_id, Some(start_height * 2))
        );
    }

    #[test]
    fn test_has_tracker() {
        // Has tracker should return true as long as the given tracker is held by the Responder.
        // As long as the tracker is in Responder.trackers and Responder.tx_tracker_map, the return
        // must be true.
        let responder = init_responder(MockedServerQuery::Regular);

        // Add a new tracker
        let user_id = get_random_user_id();
        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        store_appointment_and_fks_to_db(&responder.dbm.lock().unwrap(), uuid, &appointment);

        let breach = get_random_breach();
        responder.add_tracker(uuid, breach, user_id, None);

        assert!(responder.has_tracker(uuid));

        // Delete the tracker and check again (updated users are irrelevant here)
        responder.delete_trackers(&HashSet::from_iter([uuid]), &HashMap::new(), false);
        assert!(!responder.has_tracker(uuid));
    }

    #[test]
    fn test_get_tracker() {
        // Should return a tracker as long as it exists
        let responder = init_responder(MockedServerQuery::Regular);

        // Store the user and the appointment in the database so we can add the tracker later on (due to FK restrictions)
        let user_id = get_random_user_id();
        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        store_appointment_and_fks_to_db(&responder.dbm.lock().unwrap(), uuid, &appointment);

        // Data should not be there before adding it
        assert_eq!(responder.get_tracker(uuid), None);

        // Data should be there now
        let breach = get_random_breach();
        responder.add_tracker(uuid, breach.clone(), user_id, None);
        assert_eq!(
            responder.get_tracker(uuid).unwrap(),
            TransactionTracker::new(breach, user_id, None)
        );

        // After deleting the data it should be gone (updated users are irrelevant here)
        responder.delete_trackers(&HashSet::from_iter([uuid]), &HashMap::new(), false);
        assert_eq!(responder.get_tracker(uuid), None);
    }

    #[test]
    fn test_check_confirmations_missed_confirmations() {
        let responder = init_responder(MockedServerQuery::Regular);
        // Unconfirmed transactions that miss a confirmation will be added to missed_confirmations (if not there) or their missed confirmation count till be increased
        let mut missed_confirmations = Vec::new();
        let mut first_missed = HashSet::new();

        for i in 0..10 {
            let user_id = get_random_user_id();
            let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
            let breach = get_random_breach();

            missed_confirmations.push(breach.penalty_tx.txid());
            if i % 2 == 0 {
                first_missed.insert(breach.penalty_tx.txid());
            } else {
                responder
                    .missed_confirmations
                    .lock()
                    .unwrap()
                    .insert(breach.penalty_tx.txid(), 1);
            }

            store_appointment_and_fks_to_db(&responder.dbm.lock().unwrap(), uuid, &appointment);
            responder.add_tracker(uuid, breach.clone(), user_id, None);
        }

        // The current height does not matter here since nothing is getting confirmed
        let completed_trackers = responder.check_confirmations(&Vec::new(), 0);
        assert!(completed_trackers.is_empty());

        for txid in missed_confirmations.iter() {
            if first_missed.contains(txid) {
                assert_eq!(responder.missed_confirmations.lock().unwrap()[txid], 1);
            } else {
                assert_eq!(responder.missed_confirmations.lock().unwrap()[txid], 2);
            }
        }
    }

    #[test]
    fn test_check_confirmations_first_confirmation() {
        let responder = init_responder(MockedServerQuery::Regular);
        // Unconfirmed transactions that get their first confirmation will have its confirmation count increased and will be
        // removed from the missed_confirmations map if found.
        let mut first_confirmation_uuids = HashSet::new();
        let mut first_confirmation = Vec::new();
        let start_height = START_HEIGHT as u32;

        for i in 0..10 {
            let user_id = get_random_user_id();
            let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
            let breach = get_random_breach();

            first_confirmation_uuids.insert(uuid);
            first_confirmation.push(breach.penalty_tx.txid());
            if i % 2 == 0 {
                responder
                    .missed_confirmations
                    .lock()
                    .unwrap()
                    .insert(breach.penalty_tx.txid(), 1);
            }

            store_appointment_and_fks_to_db(&responder.dbm.lock().unwrap(), uuid, &appointment);
            responder.add_tracker(uuid, breach.clone(), user_id, None);
        }

        let completed_trackers = responder.check_confirmations(&first_confirmation, start_height);
        assert!(completed_trackers.is_empty());

        for txid in first_confirmation.iter() {
            assert!(!responder
                .missed_confirmations
                .lock()
                .unwrap()
                .contains_key(txid))
        }
        for uuid in first_confirmation_uuids.iter() {
            assert_eq!(
                responder.trackers.lock().unwrap()[uuid].height,
                Some(start_height)
            );
        }
    }

    #[test]
    fn test_check_confirmations_already_confirmed() {
        let responder = init_responder(MockedServerQuery::Regular);
        // Already confirmed transactions that receive a confirmation will simply have their confirmation count increased;
        let mut already_confirmed = Vec::new();
        let start_height = START_HEIGHT as u32;

        for _ in 0..10 {
            let user_id = get_random_user_id();
            let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
            let breach = get_random_breach();

            already_confirmed.push(breach.penalty_tx.txid());

            store_appointment_and_fks_to_db(&responder.dbm.lock().unwrap(), uuid, &appointment);
            responder.add_tracker(uuid, breach.clone(), user_id, Some(start_height));
        }

        let completed_trackers =
            responder.check_confirmations(&already_confirmed, start_height + 1);
        assert!(completed_trackers.is_empty());

        for txid in already_confirmed.iter() {
            assert!(!responder
                .missed_confirmations
                .lock()
                .unwrap()
                .contains_key(txid))
        }
    }

    #[test]
    fn test_check_confirmations_completed() {
        let responder = init_responder(MockedServerQuery::Regular);
        // Already confirmed transactions that receive their last confirmation will count as completed
        let mut irrevocably_resolved_uuids = HashSet::new();
        let mut irrevocably_resolved = Vec::new();
        let start_height = START_HEIGHT as u32;

        for _ in 0..10 {
            let user_id = get_random_user_id();
            let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
            let breach = get_random_breach();

            irrevocably_resolved_uuids.insert(uuid);
            irrevocably_resolved.push(breach.penalty_tx.txid());

            store_appointment_and_fks_to_db(&responder.dbm.lock().unwrap(), uuid, &appointment);
            responder.add_tracker(uuid, breach.clone(), user_id, Some(start_height));
        }

        let completed_trackers = responder.check_confirmations(
            &irrevocably_resolved,
            start_height + constants::IRREVOCABLY_RESOLVED,
        );
        assert_eq!(completed_trackers, irrevocably_resolved_uuids);

        for txid in irrevocably_resolved.iter() {
            assert!(!responder
                .missed_confirmations
                .lock()
                .unwrap()
                .contains_key(txid))
        }
    }

    #[test]
    fn test_get_txs_to_rebroadcast() {
        let responder = init_responder(MockedServerQuery::Regular);

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
            let breach = get_random_breach();
            txs.push(breach.penalty_tx.clone());

            responder.add_tracker(uuid, breach.clone(), user_id, None);
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

    #[test]
    fn test_get_outdated_trackers() {
        let responder = init_responder(MockedServerQuery::Regular);

        // Outdated trackers are those whose associated subscription is outdated and have not been confirmed yet (they don't have
        // a single confirmation).

        // Mock data into the GK
        let target_block_height = START_HEIGHT as u32;
        let user_id = get_random_user_id();
        let uuids = (0..10)
            .into_iter()
            .map(|_| generate_uuid())
            .collect::<Vec<UUID>>();
        responder
            .gatekeeper
            .add_outdated_user(user_id, target_block_height, Some(uuids.clone()));

        // Mock the data to the Responder. Add data to trackers (half of them unconfirmed)
        let mut target_uuids = HashSet::new();
        for (i, uuid) in uuids.into_iter().enumerate() {
            let tracker = if i % 2 == 0 {
                target_uuids.insert(uuid);
                get_random_tracker(user_id, None)
            } else {
                get_random_tracker(user_id, Some(target_block_height))
            };

            responder
                .trackers
                .lock()
                .unwrap()
                .insert(uuid, tracker.get_summary());
        }

        // Check the expected data is there
        assert_eq!(
            responder.get_outdated_trackers(target_block_height),
            target_uuids
        );
    }

    #[test]
    fn test_rebroadcast() {
        let responder = init_responder(MockedServerQuery::Regular);

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

            let breach = get_random_breach();
            let penalty_txid = breach.penalty_tx.txid();
            responder.add_tracker(uuid, breach, user_id, None);

            if i % 2 == 0 {
                responder
                    .missed_confirmations
                    .lock()
                    .unwrap()
                    .insert(penalty_txid, CONFIRMATIONS_BEFORE_RETRY);
                need_rebroadcast.push(penalty_txid);
            } else {
                responder
                    .missed_confirmations
                    .lock()
                    .unwrap()
                    .insert(penalty_txid, CONFIRMATIONS_BEFORE_RETRY - 1);
                dont_need_rebroadcast.push(penalty_txid);
            }
        }

        for (txid, receipt) in responder.rebroadcast() {
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
    fn test_delete_trackers_from_memory() {
        let responder = init_responder(MockedServerQuery::Regular);

        // Add user to the database
        let user_id = get_random_user_id();
        responder
            .dbm
            .lock()
            .unwrap()
            .store_user(user_id, &UserInfo::new(21, 42))
            .unwrap();

        // Add some trackers both to memory and to the database
        let mut to_be_deleted = HashMap::new();

        for _ in 0..10 {
            let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
            responder
                .dbm
                .lock()
                .unwrap()
                .store_appointment(uuid, &appointment)
                .unwrap();

            let breach = get_random_breach();
            responder.add_tracker(uuid, breach.clone(), user_id, None);
            to_be_deleted.insert(uuid, breach.penalty_tx.txid());
        }

        // Delete and check data is not in memory (the reason does not matter for the test)
        responder.delete_trackers_from_memory(&to_be_deleted.keys().cloned().collect(), false);

        for (uuid, txid) in to_be_deleted {
            // Data is not in memory
            assert!(!responder.trackers.lock().unwrap().contains_key(&uuid));
            assert!(!responder.tx_tracker_map.lock().unwrap().contains_key(&txid));

            // But it can be found in the database
            assert!(matches!(
                responder.dbm.lock().unwrap().load_tracker(uuid),
                Ok(TransactionTracker { .. })
            ));
        }
    }
    #[test]
    fn test_delete_trackers() {
        let responder = init_responder(MockedServerQuery::Regular);

        // Add user to the database
        let user_id = get_random_user_id();
        responder
            .dbm
            .lock()
            .unwrap()
            .store_user(user_id, &UserInfo::new(21, 42))
            .unwrap();

        // Delete trackers removes data from the trackers, tx_tracker_map maps, the database. The deletion of the later is
        // better check in test_block_connected. Add data to the map first.
        let mut all_trackers = HashSet::new();
        let mut target_trackers = HashSet::new();
        let mut uuid_txid_map = HashMap::new();
        let mut txs_with_multiple_uuids = HashSet::new();
        let mut updated_users = HashMap::new();

        for i in 0..10 {
            // Generate appointment and also add it to the DB (FK checks)
            let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
            responder
                .dbm
                .lock()
                .unwrap()
                .store_appointment(uuid, &appointment)
                .unwrap();

            let breach = get_random_breach();
            responder.add_tracker(uuid, breach.clone(), user_id, None);

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
                // Users will also be updated once the data is deleted.
                // We can made up the numbers here just to check they are updated.
                target_trackers.insert(uuid);
                updated_users.insert(appointment.user_id, UserInfo::new(i, 42));
            }
        }

        responder.delete_trackers(&target_trackers, &updated_users, false);

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

        // The users that needed to be updated in the database have been (just checking the slot count)
        for (id, info) in updated_users {
            assert_eq!(
                responder
                    .dbm
                    .lock()
                    .unwrap()
                    .load_user(id)
                    .unwrap()
                    .available_slots,
                info.available_slots
            )
        }
    }

    #[test]
    fn test_block_connected() {
        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let start_height = START_HEIGHT * 2;
        let mut chain = Blockchain::default().with_height(start_height);
        let responder = init_responder_with_chain_and_dbm(MockedServerQuery::Regular, &chain, dbm);

        // block_connected is used to keep track of the confirmation received (or missed) by the trackers the Responder
        // is keeping track of.

        // If the Responder has no trackers, block_connected will only be used to track the last known block by the Responder.
        assert_eq!(
            responder.last_known_block_header.lock().unwrap().header,
            chain.tip().header
        );

        responder.block_connected(&chain.generate(None), chain.get_block_count() as u32);
        assert_eq!(
            responder.last_known_block_header.lock().unwrap().header,
            chain.tip().header
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

            // Trackers complete in the next block.
            let breach = get_random_breach();
            responder.add_tracker(
                uuid,
                breach.clone(),
                user_id,
                Some((chain.get_block_count() + 1) as u32 - constants::IRREVOCABLY_RESOLVED),
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

        let target_block_height = (chain.get_block_count() + 1) as u32;
        for user_id in users.iter().take(21).skip(11) {
            let pair = [generate_uuid(), generate_uuid()].to_vec();

            for uuid in pair.iter() {
                let (_, appointment) = generate_dummy_appointment_with_user(*user_id, None);
                responder
                    .dbm
                    .lock()
                    .unwrap()
                    .store_appointment(*uuid, &appointment)
                    .unwrap();

                let breach = get_random_breach();
                penalties.push(breach.penalty_tx.txid());
                responder.add_tracker(*uuid, breach, *user_id, None);
            }

            uuids.extend(pair.clone());
            responder
                .gatekeeper
                .add_outdated_user(*user_id, target_block_height, Some(pair));
        }

        // CONFIRMATIONS SETUP
        let standalone_user_id = get_random_user_id();
        responder
            .gatekeeper
            .add_update_user(standalone_user_id)
            .unwrap();

        let mut transactions = Vec::new();
        let mut just_confirmed_txs = Vec::new();
        for i in 0..10 {
            let (uuid, appointment) =
                generate_dummy_appointment_with_user(standalone_user_id, None);
            responder
                .dbm
                .lock()
                .unwrap()
                .store_appointment(uuid, &appointment)
                .unwrap();

            let breach = get_random_breach();
            transactions.push(breach.clone().penalty_tx.txid());

            if i % 2 == 0 {
                just_confirmed_txs.push(breach.clone().penalty_tx);
            }
            responder.add_tracker(uuid, breach, standalone_user_id, None);
        }

        // REBROADCAST SETUP
        let (uuid, appointment) = generate_dummy_appointment_with_user(standalone_user_id, None);

        responder
            .dbm
            .lock()
            .unwrap()
            .store_appointment(uuid, &appointment)
            .unwrap();

        let breach_rebroadcast = get_random_breach();
        responder.add_tracker(uuid, breach_rebroadcast.clone(), standalone_user_id, None);
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
                DeliveryReceipt::new(true, None, None),
            );

        // Connecting a block should trigger all the state transitions
        responder.block_connected(
            &chain.generate(Some(just_confirmed_txs.clone())),
            chain.get_block_count() as u32,
        );

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
        }

        // CONFIRMATIONS CHECKS
        // The transaction confirmation count / confirmation missed should have been updated
        let just_confirmed_txids: Vec<Txid> =
            just_confirmed_txs.iter().map(|tx| tx.txid()).collect();
        let tx_tracker_map = responder.tx_tracker_map.lock().unwrap();
        for txid in transactions {
            let uuids = tx_tracker_map.get(&txid).unwrap();
            if just_confirmed_txids.contains(&txid) {
                assert!(!responder
                    .missed_confirmations
                    .lock()
                    .unwrap()
                    .contains_key(&txid));
                for uuid in uuids.iter() {
                    assert_eq!(
                        responder.trackers.lock().unwrap()[uuid].height,
                        Some(chain.get_block_count() as u32)
                    );
                }
            } else {
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
                for uuid in uuids.iter() {
                    assert!(responder.trackers.lock().unwrap()[uuid].height.is_none());
                }
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
