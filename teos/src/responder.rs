//! Logic related to the Responder, the components in charge of making sure breaches get properly punished.

use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;
use std::sync::{Arc, Mutex};

use bitcoin::{consensus, BlockHash};
use bitcoin::{BlockHeader, Transaction, Txid};
use lightning::chain;
use lightning_block_sync::poll::ValidatedBlock;

use teos_common::constants;
use teos_common::protos as common_msgs;
use teos_common::UserId;

use crate::carrier::Carrier;
use crate::dbm::DBM;
use crate::extended_appointment::UUID;
use crate::gatekeeper::{Gatekeeper, UserInfo};
use crate::tx_index::TxIndex;
use crate::watcher::Breach;

/// Number of missed confirmations to wait before rebroadcasting a transaction.
const CONFIRMATIONS_BEFORE_RETRY: u8 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The confirmation status of a given penalty transaction.
pub enum ConfirmationStatus {
    ConfirmedIn(u32),
    InMempoolSince(u32),
    IrrevocablyResolved,
    Rejected(i32),
    ReorgedOut,
}

/// Reason why the tracker is deleted. Used for logging purposes.
enum DeletionReason {
    Outdated,
    Rejected,
    Completed,
}

impl ConfirmationStatus {
    /// Builds a [ConfirmationStatus] from data loaded from the database.
    /// Only trackers that are confirmed or accepted to mempool are stored.
    pub fn from_db_data(height: u32, confirmed: bool) -> Self {
        if confirmed {
            ConfirmationStatus::ConfirmedIn(height)
        } else {
            ConfirmationStatus::InMempoolSince(height)
        }
    }

    /// Converts a confirmation status into a tuple ready to be stored in the database.
    /// Only trackers that are confirmed or accepted to mempool are stored.
    pub fn to_db_data(&self) -> Option<(u32, bool)> {
        if let ConfirmationStatus::ConfirmedIn(h) = self {
            Some((*h, true))
        } else if let ConfirmationStatus::InMempoolSince(h) = self {
            Some((*h, false))
        } else {
            None
        }
    }

    /// Whether the transaction was accepted by the underlying node.
    pub fn accepted(&self) -> bool {
        matches!(
            self,
            ConfirmationStatus::ConfirmedIn(_) | &ConfirmationStatus::InMempoolSince(_)
        )
    }
}

/// Minimal data required in memory to keep track of transaction trackers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrackerSummary {
    /// Identifier of the user who arranged the appointment.
    user_id: UserId,
    /// Transaction id the [Responder] is keeping track of.
    penalty_txid: Txid,
    /// The confirmation status of a given tracker.
    status: ConfirmationStatus,
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
    /// The confirmation status of a given tracker. Reflects the penalty transaction status.
    pub status: ConfirmationStatus,
    /// [UserId] the original [ExtendedAppointment](crate::extended_appointment::ExtendedAppointment) belongs to.
    pub user_id: UserId,
}

impl TransactionTracker {
    /// Creates a new [TransactionTracker] instance.
    pub fn new(breach: Breach, user_id: UserId, status: ConfirmationStatus) -> Self {
        Self {
            dispute_tx: breach.dispute_tx,
            penalty_tx: breach.penalty_tx,
            status,
            user_id,
        }
    }

    /// Computes the [TrackerSummary] of the [TransactionTracker].
    pub fn get_summary(&self) -> TrackerSummary {
        TrackerSummary {
            user_id: self.user_id,
            penalty_txid: self.penalty_tx.txid(),
            status: self.status,
        }
    }
}

impl From<TransactionTracker> for common_msgs::Tracker {
    fn from(t: TransactionTracker) -> Self {
        common_msgs::Tracker {
            dispute_txid: t.dispute_tx.txid().to_vec(),
            penalty_txid: t.penalty_tx.txid().to_vec(),
            penalty_rawtx: consensus::serialize(&t.penalty_tx),
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
    /// A local, pruned, [TxIndex] used to avoid the need of `txindex=1`.
    tx_index: Mutex<TxIndex<Txid, BlockHash>>,
    /// A [Carrier] instance. Data is sent to the `bitcoind` through it.
    carrier: Mutex<Carrier>,
    /// A [Gatekeeper] instance. Data regarding users is requested to it.
    gatekeeper: Arc<Gatekeeper>,
    /// A [DBM] (database manager) instance. Used to persist tracker data into disk.
    dbm: Arc<Mutex<DBM>>,
}

impl Responder {
    /// Creates a new [Responder] instance.
    pub fn new(
        last_n_blocs: &[ValidatedBlock],
        last_known_block_height: u32,
        carrier: Carrier,
        gatekeeper: Arc<Gatekeeper>,
        dbm: Arc<Mutex<DBM>>,
    ) -> Self {
        let mut trackers = HashMap::new();
        let mut tx_tracker_map: HashMap<Txid, HashSet<UUID>> = HashMap::new();

        for (uuid, tracker) in dbm.lock().unwrap().load_trackers(None) {
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
            tx_index: Mutex::new(TxIndex::new(last_n_blocs, last_known_block_height)),
            dbm,
            gatekeeper,
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
    ) -> ConfirmationStatus {
        // Do not add already added trackers. This can only happen if handle_breach is called twice with the same data, which can only happen
        // if Watcher::block_connected is interrupted during execution and called back during bootstrap.
        if let Some(tracker) = self.trackers.lock().unwrap().get(&uuid) {
            return tracker.status;
        }

        let mut carrier = self.carrier.lock().unwrap();
        let tx_index = self.tx_index.lock().unwrap();

        // Check whether the transaction is in mempool or part of our internal txindex. Send it to our node otherwise.
        let status = if carrier.in_mempool(&breach.penalty_tx.txid()) {
            // If it's in mempool we assume it was just included
            ConfirmationStatus::InMempoolSince(carrier.block_height())
        } else if let Some(block_hash) = tx_index.get(&breach.penalty_tx.txid()) {
            ConfirmationStatus::ConfirmedIn(tx_index.get_height(block_hash).unwrap() as u32)
        } else {
            carrier.send_transaction(&breach.penalty_tx)
        };

        if status.accepted() {
            self.add_tracker(uuid, breach, user_id, status);
        }

        status
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
        status: ConfirmationStatus,
    ) {
        let tracker = TransactionTracker::new(breach, user_id, status);

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
        log::info!("New tracker added (uuid={uuid})");
    }

    /// Checks whether a given tracker can be found in the [Responder].
    pub(crate) fn has_tracker(&self, uuid: UUID) -> bool {
        // has_tracker should return true as long as the given tracker is hold by the Responder.
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
            self.dbm.lock().unwrap().load_tracker(uuid)
        } else {
            None
        }
    }

    /// Checks the confirmation count for the [TransactionTracker]s.
    ///
    /// For unconfirmed transactions, it checks whether they have been confirmed or keep missing confirmations.
    /// For confirmed transactions, nothing is done until they are completed (confirmation count reaches [IRREVOCABLY_RESOLVED](constants::IRREVOCABLY_RESOLVED))
    /// Returns the set of completed trackers.
    fn check_confirmations(&self, txids: &[Txid], current_height: u32) -> HashSet<UUID> {
        let mut completed_trackers = HashSet::new();

        for (uuid, tracker) in self.trackers.lock().unwrap().iter_mut() {
            if let ConfirmationStatus::ConfirmedIn(h) = tracker.status {
                let confirmations = current_height - h;
                if confirmations == constants::IRREVOCABLY_RESOLVED {
                    // Tracker is deep enough in the chain, it can be deleted
                    completed_trackers.insert(*uuid);
                } else {
                    log::info!("{uuid} received a confirmation (count={confirmations})");
                }
            } else if txids.contains(&tracker.penalty_txid) {
                // First confirmation was received
                tracker.status = ConfirmationStatus::ConfirmedIn(current_height);
            } else if let ConfirmationStatus::InMempoolSince(h) = tracker.status {
                // Log all transactions that have missed confirmations
                log::info!(
                    "Transaction missed a confirmation: {} (missed conf count: {})",
                    tracker.penalty_txid,
                    current_height - h
                );
            }
        }

        completed_trackers
    }

    /// Gets a map of transactions that need to be rebroadcast. A [Transaction] is flagged to be rebroadcast
    /// if its missed confirmation count has reached the threshold ([CONFIRMATIONS_BEFORE_RETRY]) or if they have been
    /// reorged out of the chain. If the transaction has been reorged out, the commitment transaction is also returned.
    ///
    /// Given the [Responder] only keeps around the minimal data to track transactions, the [TransactionTracker]s
    /// are queried to the [DBM].
    fn get_txs_to_rebroadcast(
        &self,
        height: u32,
    ) -> HashMap<UUID, (Transaction, Option<Transaction>)> {
        let dbm = self.dbm.lock().unwrap();
        let mut tx_to_rebroadcast = HashMap::new();
        let mut tracker: TransactionTracker;

        for (uuid, t) in self.trackers.lock().unwrap().iter() {
            if let ConfirmationStatus::InMempoolSince(h) = t.status {
                if (height - h) as u8 >= CONFIRMATIONS_BEFORE_RETRY {
                    tracker = dbm.load_tracker(*uuid).unwrap();
                    tx_to_rebroadcast.insert(*uuid, (tracker.penalty_tx, None));
                }
            } else if let ConfirmationStatus::ReorgedOut = t.status {
                tracker = dbm.load_tracker(*uuid).unwrap();
                tx_to_rebroadcast.insert(*uuid, (tracker.penalty_tx, Some(tracker.dispute_tx)));
            }
        }

        tx_to_rebroadcast
    }

    /// Gets a collection of trackers that have been outdated. An outdated tracker is a [TransactionTracker]
    /// from a user who's subscription has been outdated (and therefore will be removed from the tower).
    ///
    /// Trackers are only returned as long as they have not been confirmed, otherwise we'll keep watching for then anyway.
    fn get_outdated_trackers(&self, block_height: u32) -> HashSet<UUID> {
        let mut outdated_trackers = HashSet::new();
        let trackers = self.trackers.lock().unwrap();
        for uuid in self
            .gatekeeper
            .get_outdated_appointments(block_height)
            .intersection(&trackers.keys().cloned().collect())
        {
            if let ConfirmationStatus::InMempoolSince(_) = trackers[uuid].status {
                outdated_trackers.insert(*uuid);
            }
        }

        outdated_trackers
    }

    /// Rebroadcasts a list of penalty transactions that have missed too many confirmations (or that have been reorged out).
    ///
    /// This covers both the case where a transaction is not getting confirmations (most likely due to low fess, and needs to be bumped),
    /// and the case where the transaction has been reorged out of the chain. For the former, there's no much to be done at the moment (until anchors),
    /// for the latter, we need to rebroadcast the penalty (and potentially the commitment if that has also been reorged).
    ///
    /// Given how the confirmation status and reorgs work with a bitcoind backend, we will be rebroadcasting this during the first new connected block
    /// after a reorg, but bitcoind will already be at the new tip. If the transaction is accepted, we won't do anything else until passed the new tip,
    /// otherwise, we could potentially try to rebroadcast again while processing the upcoming reorged blocks (if the tx hits [CONFIRMATIONS_BEFORE_RETRY]).
    ///
    /// Returns a tuple with two maps, one containing the trackers that where successfully rebroadcast and another one containing the ones that were rejected.
    fn rebroadcast(
        &self,
        txs: HashMap<UUID, (Transaction, Option<Transaction>)>,
    ) -> (HashMap<UUID, ConfirmationStatus>, HashSet<UUID>) {
        let mut accepted = HashMap::new();
        let mut rejected = HashSet::new();

        let mut trackers = self.trackers.lock().unwrap();
        let mut carrier = self.carrier.lock().unwrap();
        let tx_index = self.tx_index.lock().unwrap();

        for (uuid, (penalty_tx, dispute_tx)) in txs.into_iter() {
            let status = if let Some(dispute_tx) = dispute_tx {
                // The tracker was reorged out, and the dispute may potentially not be in the chain (or mempool) anymore.
                if tx_index.contains_key(&dispute_tx.txid())
                    | carrier.in_mempool(&dispute_tx.txid())
                {
                    // Dispute tx is on chain (or mempool), so we only need to care about the penalty
                    carrier.send_transaction(&penalty_tx)
                } else {
                    // Dispute tx has also been reorged out, meaning that both transactions need to be broadcast.
                    // DISCUSS: For lightning transactions, if the dispute has been reorged the penalty cannot make it to the network.
                    // If we keep this general, the dispute can simply be a trigger and the penalty doesn't necessarily have to spend from it.
                    // We'll keel it lightning specific, at least for now.
                    let status = carrier.send_transaction(&dispute_tx);
                    if let ConfirmationStatus::Rejected(e) = status {
                        log::error!(
                        "Reorged dispute transaction rejected during rebroadcast: {} (reason: {e})",
                        dispute_tx.txid()
                    );
                        status
                    } else {
                        // The dispute was accepted, so we can rebroadcast the penalty.
                        carrier.send_transaction(&penalty_tx)
                    }
                }
            } else {
                // The tracker has simply reached CONFIRMATIONS_BEFORE_RETRY missed confirmations.
                log::warn!(
                    "Penalty transaction has missed many confirmations: {}",
                    penalty_tx.txid()
                );
                carrier.send_transaction(&penalty_tx)
            };

            if let ConfirmationStatus::Rejected(_) = status {
                rejected.insert(uuid);
            } else {
                // Update the tracker if it gets accepted. This will also update the height (since when we are counting the tracker
                // to have been in mempool), so it resets the wait period instead of trying to rebroadcast every block.
                // DISCUSS: We may want to find another approach in the future for the InMempoool transactions.
                trackers.get_mut(&uuid).unwrap().status = status;
                accepted.insert(uuid, status);
            }
        }

        (accepted, rejected)
    }

    // DISCUSS: Check comment regarding callbacks in watcher.rs

    /// Deletes trackers from memory.
    ///
    /// Logs a different message depending on whether the trackers have been outdated or completed.
    fn delete_trackers_from_memory(&self, uuids: &HashSet<UUID>, reason: DeletionReason) {
        let mut trackers = self.trackers.lock().unwrap();
        let mut tx_tracker_map = self.tx_tracker_map.lock().unwrap();
        for uuid in uuids.iter() {
            match reason {
                DeletionReason::Completed => log::info!("Appointment completed. Penalty transaction was irrevocably confirmed: {uuid}"),
                DeletionReason::Outdated => log::info!("Appointment couldn't be completed. Expiry reached but penalty didn't make it to the chain: {uuid}"),
                DeletionReason::Rejected => log::info!("Appointment couldn't be completed. Either the dispute or the penalty txs where rejected during rebroadcast: {uuid}"),
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
                    log::error!("Completed tracker not found when cleaning: {uuid}");
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
        reason: DeletionReason,
    ) {
        if !uuids.is_empty() {
            self.delete_trackers_from_memory(uuids, reason);
            self.dbm
                .lock()
                .unwrap()
                .batch_remove_appointments(uuids, updated_users);
        }
    }
}

/// Listen implementation by the [Responder]. Handles monitoring and reorgs.
impl chain::Listen for Responder {
    /// Handles the monitoring process by the [Responder].
    ///
    /// Watching is performed in a per-block basis. A [TransactionTracker] is tracked until:
    /// - It gets [irrevocably resolved](https://github.com/lightning/bolts/blob/master/05-onchain.md#general-nomenclature) or
    /// - The user subscription expires
    /// - The trackers becomes invalid (due to a reorg)
    ///
    /// Every time a block is received the tracking conditions are checked against the monitored [TransactionTracker]s and
    /// data deletion is performed accordingly. Moreover, lack of confirmations is check for the tracked transactions and
    /// rebroadcasting is performed for those that have missed too many.
    fn filtered_block_connected(
        &self,
        header: &BlockHeader,
        txdata: &chain::transaction::TransactionData,
        height: u32,
    ) {
        log::info!("New block received: {}", header.block_hash());
        self.carrier.lock().unwrap().update_height(height);

        let txs = txdata
            .iter()
            .map(|(_, tx)| (tx.txid(), header.block_hash()))
            .collect();
        self.tx_index.lock().unwrap().update(*header, &txs);

        if !self.trackers.lock().unwrap().is_empty() {
            // Complete those appointments that are due at this height
            let completed_trackers = self.check_confirmations(
                &txdata.iter().map(|(_, tx)| tx.txid()).collect::<Vec<_>>(),
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
                DeletionReason::Completed,
            );

            // Also delete trackers from outdated users (from memory only, the db deletion is handled by the Gatekeeper)
            self.delete_trackers_from_memory(
                &self.get_outdated_trackers(height),
                DeletionReason::Outdated,
            );

            // Rebroadcast those transactions that need to
            let (_, rejected_trackers) = self.rebroadcast(self.get_txs_to_rebroadcast(height));
            // Delete trackers rejected during rebroadcast
            let trackers_to_delete_gk = rejected_trackers
                .iter()
                .map(|uuid| (*uuid, self.trackers.lock().unwrap()[uuid].user_id))
                .collect();
            self.delete_trackers(
                &rejected_trackers,
                &self
                    .gatekeeper
                    .delete_appointments_from_memory(&trackers_to_delete_gk),
                DeletionReason::Rejected,
            );

            // Remove all receipts created in this block
            self.carrier.lock().unwrap().clear_receipts();

            if self.trackers.lock().unwrap().is_empty() {
                log::info!("No more pending trackers");
            }
        }
    }

    /// Handles reorgs in the [Responder].
    fn block_disconnected(&self, header: &BlockHeader, height: u32) {
        log::warn!("Block disconnected: {}", header.block_hash());
        self.carrier.lock().unwrap().update_height(height);
        self.tx_index
            .lock()
            .unwrap()
            .remove_disconnected_block(&header.block_hash());

        for tracker in self.trackers.lock().unwrap().values_mut() {
            // The transaction has been unconfirmed. Flag it as reorged out so we can rebroadcast it.
            if tracker.status == ConfirmationStatus::ConfirmedIn(height) {
                tracker.status = ConfirmationStatus::ReorgedOut;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lightning::chain::Listen;

    use std::sync::{Arc, Mutex};

    use crate::dbm::DBM;
    use crate::gatekeeper::UserInfo;
    use crate::rpc_errors;
    use crate::test_utils::{
        create_carrier, generate_dummy_appointment_with_user, generate_uuid, get_last_n_blocks,
        get_random_breach, get_random_tracker, get_random_tx, store_appointment_and_fks_to_db,
        BitcoindStopper, Blockchain, MockedServerQuery, AVAILABLE_SLOTS, DURATION, EXPIRY_DELTA,
        SLOTS, START_HEIGHT, SUBSCRIPTION_EXPIRY, SUBSCRIPTION_START,
    };

    use teos_common::constants::IRREVOCABLY_RESOLVED;
    use teos_common::test_utils::get_random_user_id;

    impl PartialEq for Responder {
        fn eq(&self, other: &Self) -> bool {
            *self.trackers.lock().unwrap() == *other.trackers.lock().unwrap()
                && *self.tx_tracker_map.lock().unwrap() == *other.tx_tracker_map.lock().unwrap()
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

        pub(crate) fn add_random_tracker(
            &self,
            uuid: UUID,
            status: ConfirmationStatus,
        ) -> TransactionTracker {
            let user_id = get_random_user_id();
            let tracker = get_random_tracker(user_id, status);
            self.add_dummy_tracker(uuid, &tracker);

            tracker
        }

        pub(crate) fn add_dummy_tracker(&self, uuid: UUID, tracker: &TransactionTracker) {
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
            let (_, appointment) = generate_dummy_appointment_with_user(
                tracker.user_id,
                Some(&tracker.dispute_tx.txid()),
            );
            store_appointment_and_fks_to_db(&self.dbm.lock().unwrap(), uuid, &appointment);
            self.dbm
                .lock()
                .unwrap()
                .store_tracker(uuid, tracker)
                .unwrap();
        }
    }

    async fn create_responder(
        chain: &mut Blockchain,
        gatekeeper: Arc<Gatekeeper>,
        dbm: Arc<Mutex<DBM>>,
        query: MockedServerQuery,
    ) -> (Responder, BitcoindStopper) {
        let height = if chain.tip().height < IRREVOCABLY_RESOLVED {
            chain.tip().height
        } else {
            IRREVOCABLY_RESOLVED
        };

        let last_n_blocks = get_last_n_blocks(chain, height as usize).await;

        let (carrier, bitcoind_stopper) = create_carrier(query, chain.tip().height);
        (
            Responder::new(&last_n_blocks, chain.tip().height, carrier, gatekeeper, dbm),
            bitcoind_stopper,
        )
    }

    async fn init_responder_with_chain_and_dbm(
        mocked_query: MockedServerQuery,
        chain: &mut Blockchain,
        dbm: Arc<Mutex<DBM>>,
    ) -> (Responder, BitcoindStopper) {
        let gk = Gatekeeper::new(
            chain.get_block_count(),
            SLOTS,
            DURATION,
            EXPIRY_DELTA,
            dbm.clone(),
        );
        create_responder(chain, Arc::new(gk), dbm, mocked_query).await
    }

    async fn init_responder(mocked_query: MockedServerQuery) -> (Responder, BitcoindStopper) {
        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, 10);
        init_responder_with_chain_and_dbm(mocked_query, &mut chain, dbm).await
    }

    #[test]
    fn test_confirmation_status_from_db_data() {
        // These are pretty simple tests. The db can only store trackers with a confirmation status
        // that's either ConfirmedIn or InMempoolSince (Rejected and Reorged are never passed to store).
        let h = 21;
        let statuses = [true, false];

        for status in statuses {
            if status {
                assert_eq!(
                    ConfirmationStatus::from_db_data(h, status),
                    ConfirmationStatus::ConfirmedIn(h)
                );
            } else {
                assert_eq!(
                    ConfirmationStatus::from_db_data(h, status),
                    ConfirmationStatus::InMempoolSince(h)
                );
            }
        }
    }

    #[test]
    fn test_confirmation_status_to_db_data() {
        // Analogous to the previous test, this will only construct ConfirmedIn and InMempolSince statuses.
        // The None case has to be threaten though.
        let h = 21;

        assert_eq!(
            ConfirmationStatus::ConfirmedIn(h).to_db_data(),
            Some((h, true))
        );
        assert_eq!(
            ConfirmationStatus::InMempoolSince(h).to_db_data(),
            Some((h, false))
        );
        assert_eq!(ConfirmationStatus::Rejected(0).to_db_data(), None);
        assert_eq!(ConfirmationStatus::ReorgedOut.to_db_data(), None);
    }

    #[tokio::test]
    async fn test_responder_new() {
        // A fresh responder has no associated data
        let mut chain = Blockchain::default().with_height(START_HEIGHT);
        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let (responder, _s) =
            init_responder_with_chain_and_dbm(MockedServerQuery::Regular, &mut chain, dbm.clone())
                .await;
        assert!(responder.is_fresh());

        // If we add some trackers to the system and create a new Responder reusing the same db
        // (as if simulating a bootstrap from existing data), the data should be properly loaded.
        for i in 0..10 {
            // Add the necessary FKs in the database
            let user_id = get_random_user_id();
            let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
            store_appointment_and_fks_to_db(&responder.dbm.lock().unwrap(), uuid, &appointment);

            let breach = get_random_breach();
            let s = if i % 2 == 0 {
                ConfirmationStatus::InMempoolSince(i)
            } else {
                ConfirmationStatus::ConfirmedIn(i)
            };
            responder.add_tracker(uuid, breach.clone(), user_id, s);
        }

        // Create a new Responder reusing the same DB and check that the data is loaded
        let (another_r, _) =
            init_responder_with_chain_and_dbm(MockedServerQuery::Regular, &mut chain, dbm).await;
        assert!(!responder.is_fresh());
        assert_eq!(responder, another_r);
    }

    #[tokio::test]
    async fn test_handle_breach_accepted() {
        let start_height = START_HEIGHT as u32;
        let (responder, _s) = init_responder(MockedServerQuery::Regular).await;

        let user_id = get_random_user_id();
        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        store_appointment_and_fks_to_db(&responder.dbm.lock().unwrap(), uuid, &appointment);

        let breach = get_random_breach();
        let penalty_txid = breach.penalty_tx.txid();

        assert_eq!(
            responder.handle_breach(uuid, breach, user_id),
            ConfirmationStatus::InMempoolSince(start_height)
        );
        assert!(responder.trackers.lock().unwrap().contains_key(&uuid));
        assert_eq!(
            responder.trackers.lock().unwrap()[&uuid].status,
            ConfirmationStatus::InMempoolSince(start_height)
        );
        assert!(responder
            .tx_tracker_map
            .lock()
            .unwrap()
            .contains_key(&penalty_txid));

        // Breaches won't be overwritten once passed to the Responder. If the same UUID is
        // passed twice, the receipt corresponding to the first breach will be handed back.
        let another_breach = get_random_breach();
        assert_eq!(
            responder.handle_breach(uuid, another_breach.clone(), user_id),
            ConfirmationStatus::InMempoolSince(start_height)
        );

        assert!(responder.trackers.lock().unwrap().contains_key(&uuid));
        assert_eq!(
            responder.trackers.lock().unwrap()[&uuid].status,
            ConfirmationStatus::InMempoolSince(start_height)
        );
        assert!(!responder
            .tx_tracker_map
            .lock()
            .unwrap()
            .contains_key(&another_breach.penalty_tx.txid()));
    }

    #[tokio::test]
    async fn test_handle_breach_accepted_in_mempool() {
        let start_height = START_HEIGHT as u32;
        let (responder, _s) = init_responder(MockedServerQuery::InMempoool).await;

        let user_id = get_random_user_id();
        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        store_appointment_and_fks_to_db(&responder.dbm.lock().unwrap(), uuid, &appointment);

        let breach = get_random_breach();
        let penalty_txid = breach.penalty_tx.txid();

        assert_eq!(
            responder.handle_breach(uuid, breach, user_id),
            ConfirmationStatus::InMempoolSince(start_height)
        );
        assert!(responder.trackers.lock().unwrap().contains_key(&uuid));
        assert_eq!(
            responder.trackers.lock().unwrap()[&uuid].status,
            ConfirmationStatus::InMempoolSince(start_height)
        );
        assert!(responder
            .tx_tracker_map
            .lock()
            .unwrap()
            .contains_key(&penalty_txid));
    }

    #[tokio::test]
    async fn test_handle_breach_accepted_in_txindex() {
        let (responder, _s) = init_responder(MockedServerQuery::Regular).await;

        let user_id = get_random_user_id();
        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        store_appointment_and_fks_to_db(&responder.dbm.lock().unwrap(), uuid, &appointment);

        let breach = get_random_breach();
        let penalty_txid = breach.penalty_tx.txid();

        // Add the tx to our txindex
        let target_block_hash = *responder.tx_index.lock().unwrap().blocks().get(2).unwrap();
        responder
            .tx_index
            .lock()
            .unwrap()
            .index_mut()
            .insert(penalty_txid, target_block_hash);
        let target_height = responder
            .tx_index
            .lock()
            .unwrap()
            .get_height(&target_block_hash)
            .unwrap() as u32;

        assert_eq!(
            responder.handle_breach(uuid, breach, user_id),
            ConfirmationStatus::ConfirmedIn(target_height)
        );
        assert!(responder.trackers.lock().unwrap().contains_key(&uuid));
        assert_eq!(
            responder.trackers.lock().unwrap()[&uuid].status,
            ConfirmationStatus::ConfirmedIn(target_height)
        );
        assert!(responder
            .tx_tracker_map
            .lock()
            .unwrap()
            .contains_key(&penalty_txid));
    }

    #[tokio::test]
    async fn test_handle_breach_rejected() {
        let (responder, _s) = init_responder(MockedServerQuery::Error(
            rpc_errors::RPC_VERIFY_ERROR as i64,
        ))
        .await;

        let user_id = get_random_user_id();
        let uuid = generate_uuid();
        let breach = get_random_breach();
        let penalty_txid = breach.penalty_tx.txid();

        assert_eq!(
            responder.handle_breach(uuid, breach, user_id),
            ConfirmationStatus::Rejected(rpc_errors::RPC_VERIFY_ERROR)
        );
        assert!(!responder.trackers.lock().unwrap().contains_key(&uuid));
        assert!(!responder
            .tx_tracker_map
            .lock()
            .unwrap()
            .contains_key(&penalty_txid));
    }

    #[tokio::test]
    async fn test_add_tracker() {
        let (responder, _s) = init_responder(MockedServerQuery::Regular).await;
        let start_height = START_HEIGHT as u32;

        // Add the necessary FKs in the database
        let user_id = get_random_user_id();
        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        store_appointment_and_fks_to_db(&responder.dbm.lock().unwrap(), uuid, &appointment);

        let mut breach = get_random_breach();
        responder.add_tracker(
            uuid,
            breach.clone(),
            user_id,
            ConfirmationStatus::InMempoolSince(start_height),
        );

        // Check that the data has been added to trackers and to the tx_tracker_map
        assert_eq!(
            responder.trackers.lock().unwrap().get(&uuid),
            Some(&TrackerSummary {
                user_id,
                penalty_txid: breach.penalty_tx.txid(),
                status: ConfirmationStatus::InMempoolSince(start_height)
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
            TransactionTracker::new(
                breach,
                user_id,
                ConfirmationStatus::InMempoolSince(start_height)
            )
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

        responder.add_tracker(
            uuid,
            breach.clone(),
            user_id,
            ConfirmationStatus::ConfirmedIn(start_height - 1),
        );

        assert_eq!(
            responder.trackers.lock().unwrap().get(&uuid),
            Some(&TrackerSummary {
                user_id,
                penalty_txid: breach.penalty_tx.txid(),
                status: ConfirmationStatus::ConfirmedIn(start_height - 1)
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
            TransactionTracker::new(
                breach.clone(),
                user_id,
                ConfirmationStatus::ConfirmedIn(start_height - 1)
            )
        );

        // Adding another breach with the same penalty transaction (but different uuid) adds an additional uuid to the map entry
        let uuid = generate_uuid();
        responder
            .dbm
            .lock()
            .unwrap()
            .store_appointment(uuid, &appointment)
            .unwrap();

        responder.add_tracker(
            uuid,
            breach.clone(),
            user_id,
            ConfirmationStatus::ConfirmedIn(start_height),
        );

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
            TransactionTracker::new(
                breach,
                user_id,
                ConfirmationStatus::ConfirmedIn(start_height)
            )
        );
    }

    #[tokio::test]
    async fn test_has_tracker() {
        // Has tracker should return true as long as the given tracker is held by the Responder.
        // As long as the tracker is in Responder.trackers and Responder.tx_tracker_map, the return
        // must be true.
        let (responder, _s) = init_responder(MockedServerQuery::Regular).await;

        // Add a new tracker
        let user_id = get_random_user_id();
        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        store_appointment_and_fks_to_db(&responder.dbm.lock().unwrap(), uuid, &appointment);

        let breach = get_random_breach();
        responder.add_tracker(
            uuid,
            breach,
            user_id,
            ConfirmationStatus::ConfirmedIn(START_HEIGHT as u32),
        );

        assert!(responder.has_tracker(uuid));

        // Delete the tracker and check again (updated users are irrelevant here)
        responder.delete_trackers(
            &HashSet::from_iter([uuid]),
            &HashMap::new(),
            DeletionReason::Completed,
        );
        assert!(!responder.has_tracker(uuid));
    }

    #[tokio::test]
    async fn test_get_tracker() {
        // Should return a tracker as long as it exists
        let start_height = START_HEIGHT as u32;
        let (responder, _s) = init_responder(MockedServerQuery::Regular).await;

        // Store the user and the appointment in the database so we can add the tracker later on (due to FK restrictions)
        let user_id = get_random_user_id();
        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        store_appointment_and_fks_to_db(&responder.dbm.lock().unwrap(), uuid, &appointment);

        // Data should not be there before adding it
        assert_eq!(responder.get_tracker(uuid), None);

        // Data should be there now
        let breach = get_random_breach();
        responder.add_tracker(
            uuid,
            breach.clone(),
            user_id,
            ConfirmationStatus::InMempoolSince(start_height),
        );
        assert_eq!(
            responder.get_tracker(uuid).unwrap(),
            TransactionTracker::new(
                breach,
                user_id,
                ConfirmationStatus::InMempoolSince(start_height)
            )
        );

        // After deleting the data it should be gone (updated users are irrelevant here)
        responder.delete_trackers(
            &HashSet::from_iter([uuid]),
            &HashMap::new(),
            DeletionReason::Outdated,
        );
        assert_eq!(responder.get_tracker(uuid), None);
    }

    #[tokio::test]
    async fn test_check_confirmations() {
        let (responder, _s) = init_responder(MockedServerQuery::Regular).await;
        let target_height = (START_HEIGHT * 2) as u32;

        // Unconfirmed transactions that miss a confirmation will be added to missed_confirmations (if not there) or their missed confirmation count till be increased
        let mut in_mempool = HashSet::new();
        let mut just_confirmed = HashSet::new();
        let mut confirmed = HashSet::new();
        let mut completed = HashSet::new();
        let mut txids = Vec::new();

        for i in 0..40 {
            let user_id = get_random_user_id();
            let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
            let breach = get_random_breach();

            store_appointment_and_fks_to_db(&responder.dbm.lock().unwrap(), uuid, &appointment);

            if i % 4 == 0 {
                responder.add_tracker(
                    uuid,
                    breach.clone(),
                    user_id,
                    ConfirmationStatus::InMempoolSince(21),
                );
                in_mempool.insert(uuid);
            } else if i % 4 == 1 {
                responder.add_tracker(
                    uuid,
                    breach.clone(),
                    user_id,
                    ConfirmationStatus::InMempoolSince(i),
                );
                just_confirmed.insert(uuid);
                txids.push(breach.penalty_tx.txid());
            } else if i % 4 == 2 {
                responder.add_tracker(
                    uuid,
                    breach.clone(),
                    user_id,
                    ConfirmationStatus::ConfirmedIn(42),
                );
                confirmed.insert(uuid);
            } else {
                responder.add_tracker(
                    uuid,
                    breach.clone(),
                    user_id,
                    ConfirmationStatus::ConfirmedIn(
                        target_height - constants::IRREVOCABLY_RESOLVED,
                    ),
                );
                completed.insert(uuid);
            }
        }

        // The trackers that were completed should be returned
        assert_eq!(
            completed,
            responder.check_confirmations(&txids, target_height)
        );

        // The ones in mempool should still be there (at the same height)
        for uuid in in_mempool {
            assert_eq!(
                responder
                    .trackers
                    .lock()
                    .unwrap()
                    .get(&uuid)
                    .unwrap()
                    .status,
                ConfirmationStatus::InMempoolSince(21)
            );
        }

        // The ones that just got confirmed should have been flagged so (at this height)
        for uuid in just_confirmed {
            assert_eq!(
                responder
                    .trackers
                    .lock()
                    .unwrap()
                    .get(&uuid)
                    .unwrap()
                    .status,
                ConfirmationStatus::ConfirmedIn(target_height)
            );
        }

        // The ones that were already confirmed but have not reached the end should remain the same
        for uuid in confirmed {
            assert_eq!(
                responder
                    .trackers
                    .lock()
                    .unwrap()
                    .get(&uuid)
                    .unwrap()
                    .status,
                ConfirmationStatus::ConfirmedIn(42)
            );
        }
    }

    #[tokio::test]
    async fn test_get_txs_to_rebroadcast() {
        let (responder, _s) = init_responder(MockedServerQuery::Regular).await;
        let current_height = 100;

        let user_id = get_random_user_id();
        responder
            .dbm
            .lock()
            .unwrap()
            .store_user(
                user_id,
                &UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY),
            )
            .unwrap();

        // Transactions are flagged to be rebroadcast when they've been in mempool for longer than CONFIRMATIONS_BEFORE_RETRY
        let mut txs = HashMap::new();

        for i in 0..CONFIRMATIONS_BEFORE_RETRY + 2 {
            // Add the appointment to the db so FK rules are satisfied
            let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
            responder
                .dbm
                .lock()
                .unwrap()
                .store_appointment(uuid, &appointment)
                .unwrap();

            // Create a breach and add it, setting all them as unconfirmed (at different heights)
            let breach = get_random_breach();

            responder.add_tracker(
                uuid,
                breach.clone(),
                user_id,
                ConfirmationStatus::InMempoolSince(current_height - i as u32),
            );

            if i >= CONFIRMATIONS_BEFORE_RETRY {
                txs.insert(uuid, (breach.penalty_tx.clone(), None));
            }
        }

        assert_eq!(responder.get_txs_to_rebroadcast(current_height), txs);
    }

    #[tokio::test]
    async fn test_get_txs_to_rebroadcast_reorged() {
        // For reorged transactions this works a bit different, the dispute transaction will also be returned here
        let (responder, _s) = init_responder(MockedServerQuery::Regular).await;
        let current_height = 100;

        let user_id = get_random_user_id();
        responder
            .dbm
            .lock()
            .unwrap()
            .store_user(
                user_id,
                &UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY),
            )
            .unwrap();

        // Transactions are flagged to be rebroadcast when they've been in mempool for longer than CONFIRMATIONS_BEFORE_RETRY
        let mut txs = HashMap::new();

        for i in 0..10 {
            // Add the appointment to the db so FK rules are satisfied
            let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
            responder
                .dbm
                .lock()
                .unwrap()
                .store_appointment(uuid, &appointment)
                .unwrap();

            // Create a breach and add it, setting half of them as reorged
            let breach = get_random_breach();
            responder.add_tracker(
                uuid,
                breach.clone(),
                user_id,
                ConfirmationStatus::ConfirmedIn(current_height),
            );

            // Since we are adding trackers using add_trackers we'll need to manually change the state of the transaction
            // (reorged transactions are not passed to add_tracker, they are detected after they are already there).
            // Not doing so will trigger an error in the dbm since reorged transactions are not stored in the db.
            if i % 2 == 0 {
                responder
                    .trackers
                    .lock()
                    .unwrap()
                    .get_mut(&uuid)
                    .unwrap()
                    .status = ConfirmationStatus::ReorgedOut;
                // Here the dispute is also included
                txs.insert(
                    uuid,
                    (breach.penalty_tx.clone(), Some(breach.dispute_tx.clone())),
                );
            }
        }

        // Since we have only added confirmed and reorged transactions, we should get back only the reorged ones.
        assert_eq!(responder.get_txs_to_rebroadcast(current_height), txs);
    }

    #[tokio::test]
    async fn test_get_outdated_trackers() {
        let (responder, _s) = init_responder(MockedServerQuery::Regular).await;

        // Outdated trackers are those whose associated subscription is outdated and have not been confirmed yet (they don't have
        // a single confirmation).

        // Mock data into the GK
        let target_block_height = START_HEIGHT as u32;
        let user_id = get_random_user_id();
        let uuids = (0..10).map(|_| generate_uuid()).collect::<Vec<UUID>>();
        responder
            .gatekeeper
            .add_outdated_user(user_id, target_block_height, Some(uuids.clone()));

        // Mock the data to the Responder. Add data to trackers (half of them unconfirmed)
        let mut target_uuids = HashSet::new();
        for (i, uuid) in uuids.into_iter().enumerate() {
            let tracker = if i % 2 == 0 {
                target_uuids.insert(uuid);
                get_random_tracker(
                    user_id,
                    ConfirmationStatus::InMempoolSince(target_block_height),
                )
            } else {
                get_random_tracker(
                    user_id,
                    ConfirmationStatus::ConfirmedIn(target_block_height),
                )
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

    #[tokio::test]
    async fn test_rebroadcast_accepted() {
        // This test positive rebroadcast cases, including reorgs. However, complex reorg logic is not tested here, it will need a
        // dedicated test (against bitcoind, not mocked).
        let (responder, _s) = init_responder(MockedServerQuery::Regular).await;
        let current_height = 100;

        // Add user to the database
        let user_id = get_random_user_id();
        responder
            .dbm
            .lock()
            .unwrap()
            .store_user(
                user_id,
                &UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY),
            )
            .unwrap();

        // Transactions are rebroadcast once they've been in mempool for CONFIRMATIONS_BEFORE_RETRY or they've been reorged out
        let mut need_rebroadcast = HashSet::new();

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

            let height = if i % 2 == 0 {
                current_height + 1 - CONFIRMATIONS_BEFORE_RETRY as u32
            } else {
                need_rebroadcast.insert(uuid);
                current_height - CONFIRMATIONS_BEFORE_RETRY as u32
            };

            responder.add_tracker(
                uuid,
                breach,
                user_id,
                ConfirmationStatus::InMempoolSince(height),
            );

            // Reorged txs need to be set manually
            if i % 2 == 1 {
                responder
                    .trackers
                    .lock()
                    .unwrap()
                    .get_mut(&uuid)
                    .unwrap()
                    .status = ConfirmationStatus::ReorgedOut;
            }
        }

        // Check all are accepted
        let (accepted, rejected) =
            responder.rebroadcast(responder.get_txs_to_rebroadcast(current_height));
        let accepted_uuids: HashSet<UUID> = accepted.keys().cloned().collect();
        assert_eq!(accepted_uuids, need_rebroadcast);
        assert!(rejected.is_empty());
    }

    #[tokio::test]
    async fn test_rebroadcast_rejected() {
        // This test negative rebroadcast cases, including reorgs. However, complex reorg logic is not tested here, it will need a
        // dedicated test (against bitcoind, not mocked).
        let (responder, _s) = init_responder(MockedServerQuery::Error(
            rpc_errors::RPC_VERIFY_ERROR as i64,
        ))
        .await;
        let current_height = 100;

        // Add user to the database
        let user_id = get_random_user_id();
        responder
            .dbm
            .lock()
            .unwrap()
            .store_user(
                user_id,
                &UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY),
            )
            .unwrap();

        // Transactions are rebroadcast once they've been in mempool for CONFIRMATIONS_BEFORE_RETRY or they've been reorged out
        let mut need_rebroadcast = HashSet::new();

        for i in 0..30 {
            // Generate appointment and also add it to the DB (FK checks)
            let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
            responder
                .dbm
                .lock()
                .unwrap()
                .store_appointment(uuid, &appointment)
                .unwrap();

            let breach = get_random_breach();

            let height = if i % 2 == 0 {
                current_height + 1 - CONFIRMATIONS_BEFORE_RETRY as u32
            } else {
                need_rebroadcast.insert(uuid);
                current_height - CONFIRMATIONS_BEFORE_RETRY as u32
            };

            responder.add_tracker(
                uuid,
                breach,
                user_id,
                ConfirmationStatus::InMempoolSince(height),
            );

            // Reorged txs need to be set manually
            if i % 2 == 1 {
                responder
                    .trackers
                    .lock()
                    .unwrap()
                    .get_mut(&uuid)
                    .unwrap()
                    .status = ConfirmationStatus::ReorgedOut;
            }
        }

        // Check all are rejected
        let (accepted, rejected) =
            responder.rebroadcast(responder.get_txs_to_rebroadcast(current_height));
        assert_eq!(rejected, need_rebroadcast);
        assert!(accepted.is_empty());
    }

    #[tokio::test]
    async fn test_delete_trackers_from_memory() {
        let (responder, _s) = init_responder(MockedServerQuery::Regular).await;

        // Add user to the database
        let user_id = get_random_user_id();
        responder
            .dbm
            .lock()
            .unwrap()
            .store_user(
                user_id,
                &UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY),
            )
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
            responder.add_tracker(
                uuid,
                breach.clone(),
                user_id,
                ConfirmationStatus::ConfirmedIn(21),
            );
            to_be_deleted.insert(uuid, breach.penalty_tx.txid());
        }

        // Delete and check data is not in memory (the reason does not matter for the test)
        responder.delete_trackers_from_memory(
            &to_be_deleted.keys().cloned().collect(),
            DeletionReason::Completed,
        );

        for (uuid, txid) in to_be_deleted {
            // Data is not in memory
            assert!(!responder.trackers.lock().unwrap().contains_key(&uuid));
            assert!(!responder.tx_tracker_map.lock().unwrap().contains_key(&txid));

            // But it can be found in the database
            assert!(responder.dbm.lock().unwrap().load_tracker(uuid).is_some());
        }
    }

    #[tokio::test]
    async fn test_delete_trackers() {
        let (responder, _s) = init_responder(MockedServerQuery::Regular).await;

        // Add user to the database
        let user_id = get_random_user_id();
        responder
            .dbm
            .lock()
            .unwrap()
            .store_user(
                user_id,
                &UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY),
            )
            .unwrap();

        // Delete trackers removes data from the trackers, tx_tracker_map maps, the database. The deletion of the later is
        // better check in test_filtered_block_connected. Add data to the map first.
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
            responder.add_tracker(
                uuid,
                breach.clone(),
                user_id,
                ConfirmationStatus::ConfirmedIn(42),
            );

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

        responder.delete_trackers(&target_trackers, &updated_users, DeletionReason::Rejected);

        // Only trackers in the target_trackers map should have been removed from
        // the Responder data structures.
        for uuid in all_trackers {
            if target_trackers.contains(&uuid) {
                assert!(!responder.trackers.lock().unwrap().contains_key(&uuid));
                assert!(responder.dbm.lock().unwrap().load_tracker(uuid).is_none());
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
                assert!(responder.dbm.lock().unwrap().load_tracker(uuid).is_some());
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

    #[tokio::test]
    async fn test_filtered_block_connected() {
        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let start_height = START_HEIGHT * 2;
        let mut chain = Blockchain::default().with_height(start_height);
        let (responder, _s) =
            init_responder_with_chain_and_dbm(MockedServerQuery::Regular, &mut chain, dbm).await;

        // block_connected is used to keep track of the confirmation received (or missed) by the trackers the Responder
        // is keeping track of.
        //
        // If there are any trackers, the Responder will:
        // - Check if there is any tracker that has been completed
        // - Check if there is any tracker that has been outdated
        // - Check if any tracker has been confirmed or add missing confirmations otherwise
        // - Rebroadcast all penalty transactions that need so
        // - Delete completed and outdated data (including data in the GK)
        // - Clear the Carrier issued_receipts cache

        // Let's start by doing the data setup for each test (i.e. adding all the necessary data to the Responder and GK)
        let target_block_height = chain.get_block_count() + 1;
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
                ConfirmationStatus::ConfirmedIn(
                    target_block_height - constants::IRREVOCABLY_RESOLVED,
                ),
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
                responder.add_tracker(
                    *uuid,
                    breach,
                    *user_id,
                    ConfirmationStatus::InMempoolSince(target_block_height - 1),
                );
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
            responder.add_tracker(
                uuid,
                breach,
                standalone_user_id,
                ConfirmationStatus::InMempoolSince(target_block_height - 1),
            );
        }

        // REBROADCAST SETUP
        let (uuid, appointment) = generate_dummy_appointment_with_user(standalone_user_id, None);

        responder
            .dbm
            .lock()
            .unwrap()
            .store_appointment(uuid, &appointment)
            .unwrap();

        let tracker_to_rebroadcast = uuid;
        responder.add_tracker(
            uuid,
            get_random_breach(),
            standalone_user_id,
            ConfirmationStatus::InMempoolSince(
                target_block_height - CONFIRMATIONS_BEFORE_RETRY as u32,
            ),
        );

        // CARRIER CACHE SETUP
        // Add some dummy data in the cache to check that it gets cleared
        responder
            .carrier
            .lock()
            .unwrap()
            .get_issued_receipts()
            .insert(get_random_tx().txid(), ConfirmationStatus::ConfirmedIn(21));

        // Connecting a block should trigger all the state transitions
        responder.block_connected(
            &chain.generate(Some(just_confirmed_txs.clone())),
            chain.get_block_count(),
        );

        // CARRIER CHECKS
        assert!(responder
            .carrier
            .lock()
            .unwrap()
            .get_issued_receipts()
            .is_empty());

        // Check that the carrier last_known_block_height has been updated
        assert_eq!(
            responder.carrier.lock().unwrap().get_height(),
            target_block_height
        );

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
        let tx_tracker_map = responder.tx_tracker_map.lock().unwrap();
        for txid in transactions {
            let uuids = tx_tracker_map.get(&txid).unwrap();
            if just_confirmed_txs
                .iter()
                .map(|tx| tx.txid())
                .any(|x| x == txid)
            {
                for uuid in uuids.iter() {
                    assert_eq!(
                        responder.trackers.lock().unwrap()[uuid].status,
                        ConfirmationStatus::ConfirmedIn(target_block_height)
                    );
                }
            } else {
                for uuid in uuids.iter() {
                    assert_eq!(
                        responder.trackers.lock().unwrap()[uuid].status,
                        ConfirmationStatus::InMempoolSince(target_block_height - 1)
                    );
                }
            }
        }

        // REBROADCAST CHECKS
        assert_eq!(
            responder
                .trackers
                .lock()
                .unwrap()
                .get(&tracker_to_rebroadcast)
                .unwrap()
                .status,
            ConfirmationStatus::InMempoolSince(target_block_height),
        );
    }

    #[tokio::test]
    async fn test_block_disconnected() {
        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, 10);
        let (responder, _s) =
            init_responder_with_chain_and_dbm(MockedServerQuery::Regular, &mut chain, dbm).await;

        // Add user to the database
        let user_id = get_random_user_id();
        responder
            .dbm
            .lock()
            .unwrap()
            .store_user(
                user_id,
                &UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY),
            )
            .unwrap();

        let mut reorged = Vec::new();

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

            responder.add_tracker(
                uuid,
                breach.clone(),
                user_id,
                ConfirmationStatus::ConfirmedIn(i),
            );
            reorged.push(uuid);
        }

        // Check that trackers are flagged as reorged if the height they were included at gets disconnected
        for i in (0..10).rev() {
            // The header doesn't really matter, just the height
            responder.block_disconnected(&chain.tip().header, i);
            // Check that the proper tracker gets reorged at the proper height
            assert_eq!(
                responder
                    .trackers
                    .lock()
                    .unwrap()
                    .get(reorged.get(i as usize).unwrap())
                    .unwrap()
                    .status,
                ConfirmationStatus::ReorgedOut
            );

            // Check that the carrier block_height has been updated
            assert_eq!(responder.carrier.lock().unwrap().get_height(), i);
        }

        // Check that all reorged trackers are still reorged
        for uuid in reorged {
            assert_eq!(
                responder
                    .trackers
                    .lock()
                    .unwrap()
                    .get(&uuid)
                    .unwrap()
                    .status,
                ConfirmationStatus::ReorgedOut
            );
        }
    }
}
