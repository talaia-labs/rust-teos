use futures::executor::block_on;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

use bitcoin::{BlockHeader, Transaction, Txid};
use lightning::chain::Listen;
use lightning_block_sync::poll::ValidatedBlockHeader;
use lightning_block_sync::BlockHeaderData;

use teos_common::appointment::Locator;
use teos_common::constants;
use teos_common::UserId;

use crate::carrier::{Carrier, Receipt};
use crate::dbm::DBM;
use crate::extended_appointment::UUID;
use crate::gatekeeper::Gatekeeper;
use crate::watcher::Breach;

const CONFIRMATIONS_BEFORE_RETRY: u8 = 6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionTracker {
    pub locator: Locator,
    pub dispute_tx: Transaction,
    pub penalty_tx: Transaction,
    pub user_id: UserId,
}

pub struct TrackerSummary {
    user_id: UserId,
    penalty_txid: Txid,
}

impl TransactionTracker {
    pub fn new(breach: Breach, user_id: UserId) -> Self {
        Self {
            locator: breach.locator,
            dispute_tx: breach.dispute_tx,
            penalty_tx: breach.penalty_tx.clone(),
            user_id,
        }
    }

    pub fn get_summary(&self) -> TrackerSummary {
        TrackerSummary {
            user_id: self.user_id,
            penalty_txid: self.penalty_tx.txid(),
        }
    }
}

pub struct Responder<'a> {
    pub(crate) trackers: RefCell<HashMap<UUID, TrackerSummary>>,
    tx_tracker_map: RefCell<HashMap<Txid, HashSet<UUID>>>,
    unconfirmed_txs: RefCell<HashSet<Txid>>,
    missed_confirmations: RefCell<HashMap<Txid, u8>>,
    pub(crate) carrier: RefCell<Carrier>,
    gatekeeper: &'a Gatekeeper,
    dbm: Arc<Mutex<DBM>>,
    last_known_block_header: RefCell<BlockHeaderData>,
}

impl<'a> Responder<'a> {
    pub fn new(
        carrier: Carrier,
        gatekeeper: &'a Gatekeeper,
        dbm: Arc<Mutex<DBM>>,
        last_known_block_header: ValidatedBlockHeader,
    ) -> Self {
        let trackers = RefCell::new(HashMap::new());
        let tx_tracker_map = RefCell::new(HashMap::new());
        let unconfirmed_txs = RefCell::new(HashSet::new());
        let missed_confirmations = RefCell::new(HashMap::new());

        Responder {
            carrier: RefCell::new(carrier),
            trackers,
            tx_tracker_map,
            unconfirmed_txs,
            missed_confirmations,
            dbm,
            gatekeeper,
            last_known_block_header: RefCell::new(last_known_block_header.deref().clone()),
        }
    }

    pub async fn handle_breach(&self, uuid: UUID, breach: Breach, user_id: UserId) -> Receipt {
        let receipt = self
            .carrier
            .borrow_mut()
            .send_transaction(&breach.penalty_tx)
            .await;

        if receipt.delivered() {
            self.add_tracker(uuid, breach, user_id, receipt.confirmations().unwrap());
        }

        receipt
    }

    pub(crate) fn add_tracker(
        &self,
        uuid: UUID,
        breach: Breach,
        user_id: UserId,
        confirmations: u32,
    ) {
        let penalty_txid = breach.penalty_tx.txid();
        let tracker = TransactionTracker::new(breach.clone(), user_id);

        self.trackers
            .borrow_mut()
            .insert(uuid, tracker.get_summary());

        let mut tx_tracker_map = self.tx_tracker_map.borrow_mut();
        match tx_tracker_map.get_mut(&penalty_txid) {
            Some(map) => {
                map.insert(uuid);
            }
            None => {
                tx_tracker_map.insert(penalty_txid, HashSet::from_iter(vec![uuid]));
            }
        }

        if !self
            .unconfirmed_txs
            .borrow()
            .contains(&breach.penalty_tx.txid())
            && confirmations == 0
        {
            self.unconfirmed_txs
                .borrow_mut()
                .insert(breach.penalty_tx.txid());
        }

        self.dbm
            .lock()
            .unwrap()
            .store_tracker(&uuid, &tracker)
            .unwrap();
        log::info!("New tracker added (uuid={}).", uuid);
    }

    pub fn has_tracker(&self, uuid: &UUID) -> bool {
        // Has tracker should return true as long as the given tracker is hold by the Responder.
        // If the tracker is partially kept, the function will log and the return will be false.
        // This may point out that some partial data deletion is happening, which must be fixed.
        self.trackers.borrow().get(uuid).map_or(false, |tracker| {
            match self.tx_tracker_map.borrow().get(&tracker.penalty_txid) {
                Some(_) => true,
                None => {
                    log::debug!(
                        "Partially found Tracker. Some data may have not been properly deleted"
                    );
                    false
                }
            }
        })
    }

    pub fn get_tracker(&self, uuid: &UUID) -> Option<TransactionTracker> {
        if self.trackers.borrow().contains_key(&uuid) {
            self.dbm.lock().unwrap().load_tracker(&uuid).ok()
        } else {
            None
        }
    }

    fn check_confirmations(&self, txs: &Vec<Transaction>) {
        // If a new confirmed transaction matches one we are watching, we remove it from the unconfirmed transaction vector
        let mut unconfirmed_txs = self.unconfirmed_txs.borrow_mut();
        for tx in txs.iter() {
            if unconfirmed_txs.remove(&tx.txid()) {
                log::info!("Confirmation received for transaction: {}", tx.txid());
            }
        }

        // Increase the missing confirmation count for all those transactions pending confirmation that have not been confirmed this block
        let mut missed_confirmations = self.missed_confirmations.borrow_mut();
        for txid in unconfirmed_txs.iter() {
            match missed_confirmations.get_mut(txid) {
                Some(x) => *x += 1,
                None => {
                    missed_confirmations.insert(txid.clone(), 1);
                }
            }
            log::info!(
                "Transaction missed a confirmation: {} (missed conf count: {})",
                txid,
                missed_confirmations.get(txid).unwrap()
            );
        }
    }

    fn get_txs_to_rebroadcast(&self) -> Vec<Transaction> {
        let mut tx_to_rebroadcast = Vec::new();
        let mut tracker: TransactionTracker;

        for (txid, missed_conf) in self.missed_confirmations.borrow().iter() {
            if missed_conf >= &CONFIRMATIONS_BEFORE_RETRY {
                for uuid in self.tx_tracker_map.borrow().get(txid).unwrap() {
                    tracker = self.dbm.lock().unwrap().load_tracker(uuid).unwrap();
                    tx_to_rebroadcast.push(tracker.penalty_tx)
                }
            }
        }

        tx_to_rebroadcast
    }

    async fn get_completed_trackers(&self) -> HashSet<UUID> {
        // DISCUSS: Not using a checked_txs cache for now, check whether it may be necessary
        let mut completed_trackers = HashSet::new();

        for uuid in self.trackers.borrow().keys() {
            let penalty_txid = self.trackers.borrow()[uuid].penalty_txid;
            if !self.unconfirmed_txs.borrow().contains(&penalty_txid) {
                self.carrier
                    .borrow()
                    .get_confirmations(&penalty_txid)
                    .await
                    .map(|confirmations| {
                        if confirmations > constants::IRREVOCABLY_RESOLVED {
                            completed_trackers.insert(uuid.clone());
                        }
                    });
            }
        }

        completed_trackers
    }

    fn get_outdated_trackers(&self, block_height: &u32) -> HashSet<UUID> {
        let mut outdated_trackers = HashSet::new();
        let trackers: HashSet<UUID> = self.trackers.borrow().keys().cloned().collect();

        for uuid in self
            .gatekeeper
            .get_outdated_appointments(&block_height)
            .intersection(&trackers)
        {
            if self
                .unconfirmed_txs
                .borrow()
                .contains(&self.trackers.borrow()[&uuid].penalty_txid)
            {
                outdated_trackers.insert(uuid.clone());
            }
        }

        outdated_trackers
    }

    async fn rebroadcast(&self) -> HashMap<Txid, Receipt> {
        let mut receipts = HashMap::new();

        for penalty_tx in self.get_txs_to_rebroadcast().into_iter() {
            *self
                .missed_confirmations
                .borrow_mut()
                .get_mut(&penalty_tx.txid())
                .unwrap() = 0;

            log::warn!(
                "Transaction has missed many confirmations. Rebroadcasting: {}",
                penalty_tx.txid()
            );

            let receipt = self
                .carrier
                .borrow_mut()
                .send_transaction(&penalty_tx)
                .await;

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
    fn delete_trackers(&self, trackers: HashSet<UUID>, outdated: bool) {
        for uuid in trackers.iter() {
            if outdated {
                log::info!("Appointment couldn't be completed. Expiry reached but penalty didn't make it to the chain:  {}", uuid);
            } else {
                log::info!(
                    "Appointment completed. Penalty transaction was irrevocably confirmed:  {}",
                    uuid
                );
            }

            match self.trackers.borrow_mut().remove(uuid) {
                Some(tracker) => {
                    let mut tracker_map = self.tx_tracker_map.borrow_mut();
                    let trackers = tracker_map.get_mut(&tracker.penalty_txid).unwrap();

                    // The transaction will only be in the unconfirmed_txs map if the trackers are outdated
                    self.unconfirmed_txs
                        .borrow_mut()
                        .remove(&tracker.penalty_txid);

                    if trackers.len() == 1 {
                        tracker_map.remove(&tracker.penalty_txid);

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
        self.dbm
            .lock()
            .unwrap()
            .batch_remove_appointments(&trackers);
    }
}

impl<'a> Listen for Responder<'a> {
    fn block_connected(&self, block: &bitcoin::Block, height: u32) {
        log::info!("New block received: {}", block.header.block_hash());

        if self.trackers.borrow().len() > 0 {
            let completed_trackers = block_on(self.get_completed_trackers());
            let outdated_trackers = self.get_outdated_trackers(&height);

            let mut trackers_to_delete_gk = HashMap::new();
            for uuid in completed_trackers.iter() {
                trackers_to_delete_gk.insert(uuid.clone(), self.trackers.borrow()[uuid].user_id);
            }

            self.check_confirmations(&block.txdata);
            self.delete_trackers(completed_trackers, false);
            self.delete_trackers(outdated_trackers, true);

            // Remove completed trackers from the GK
            self.gatekeeper.delete_appointments(&trackers_to_delete_gk);

            // Rebroadcast those transactions that need to
            block_on(self.rebroadcast());
        }

        *self.last_known_block_header.borrow_mut() = BlockHeaderData {
            header: block.header,
            height,
            chainwork: block.header.work(),
        };
        self.dbm
            .lock()
            .unwrap()
            .store_last_known_block_responder(&block.header.block_hash());
    }

    // FIXME: To be implemented
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

    fn create_responder<'a>(
        chain: &mut Blockchain,
        gatekeeper: &'a Gatekeeper,
        dbm: Arc<Mutex<DBM>>,
        query: MockedServerQuery,
    ) -> Responder<'a> {
        let tip = chain.tip();
        let carrier = create_carrier(query);
        Responder::new(carrier, &gatekeeper, dbm, tip)
    }

    #[tokio::test]
    async fn test_handle_breach_delivered() {
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, None);
        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let gk = Gatekeeper::new(chain.tip(), SLOTS, DURATION, EXPIRY_DELTA, dbm.clone());
        let responder = create_responder(&mut chain, &gk, dbm.clone(), MockedServerQuery::Regular);

        let user_id = get_random_user_id();
        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        store_appointment_and_fks_to_db(&dbm.lock().unwrap(), &uuid, &appointment);

        let breach = get_random_breach_from_locator(appointment.locator());
        let penalty_txid = breach.penalty_tx.txid();

        let r = responder.handle_breach(uuid, breach.clone(), user_id).await;

        assert!(r.delivered());
        assert!(responder.trackers.borrow().contains_key(&uuid));
        assert!(responder
            .tx_tracker_map
            .borrow()
            .contains_key(&penalty_txid));
        assert!(responder.unconfirmed_txs.borrow().contains(&penalty_txid));
    }

    #[tokio::test]
    async fn test_handle_breach_not_delivered() {
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, None);
        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let gk = Gatekeeper::new(chain.tip(), SLOTS, DURATION, EXPIRY_DELTA, dbm.clone());
        let responder = create_responder(
            &mut chain,
            &gk,
            dbm.clone(),
            MockedServerQuery::Error(rpc_errors::RPC_VERIFY_ERROR as i64),
        );

        let user_id = get_random_user_id();
        let uuid = generate_uuid();
        let breach = get_random_breach();
        let penalty_txid = breach.penalty_tx.txid();

        let r = responder.handle_breach(uuid, breach.clone(), user_id).await;

        assert!(!r.delivered());
        assert!(!responder.trackers.borrow().contains_key(&uuid));
        assert!(!responder
            .tx_tracker_map
            .borrow()
            .contains_key(&penalty_txid));
        assert!(!responder.unconfirmed_txs.borrow().contains(&penalty_txid));
    }

    #[test]
    fn test_add_tracker() {
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, None);
        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let gk = Gatekeeper::new(chain.tip(), SLOTS, DURATION, EXPIRY_DELTA, dbm.clone());
        let responder = create_responder(&mut chain, &gk, dbm.clone(), MockedServerQuery::Regular);

        // Add the necessary FKs in the database
        let user_id = get_random_user_id();
        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        store_appointment_and_fks_to_db(&dbm.lock().unwrap(), &uuid, &appointment);

        let mut breach = get_random_breach_from_locator(appointment.locator());
        responder.add_tracker(uuid, breach.clone(), user_id, 0);

        // Check that the data has been added to trackers and tom the tx_tracker_map
        assert!(responder.trackers.borrow().contains_key(&uuid));
        assert!(responder
            .tx_tracker_map
            .borrow()
            .contains_key(&breach.penalty_tx.txid()));
        // Since the penalty tx was added with no confirmations, check that it has been added to the unconfirmed_transactions map too
        assert!(responder
            .unconfirmed_txs
            .borrow()
            .contains(&breach.penalty_tx.txid()));
        // Check that the data is also in the database
        assert_eq!(
            dbm.lock().unwrap().load_tracker(&uuid).unwrap(),
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
            .store_appointment(&uuid, &appointment)
            .unwrap();

        responder.add_tracker(uuid, breach.clone(), user_id, 1);

        assert!(responder.trackers.borrow().contains_key(&uuid));
        assert!(responder
            .tx_tracker_map
            .borrow()
            .contains_key(&breach.penalty_tx.txid()));
        assert_eq!(
            responder.tx_tracker_map.borrow()[&breach.penalty_tx.txid()].len(),
            1
        );
        assert!(!responder
            .unconfirmed_txs
            .borrow()
            .contains(&breach.penalty_tx.txid()));
        assert_eq!(
            dbm.lock().unwrap().load_tracker(&uuid).unwrap(),
            TransactionTracker::new(breach.clone(), user_id)
        );

        // Adding another breach with the same penalty transaction (but different uuid) adds an additional uuid to the map entry
        let uuid = generate_uuid();
        responder
            .dbm
            .lock()
            .unwrap()
            .store_appointment(&uuid, &appointment)
            .unwrap();

        responder.add_tracker(uuid, breach.clone(), user_id, 1);

        assert!(responder.trackers.borrow().contains_key(&uuid));
        assert!(responder
            .tx_tracker_map
            .borrow()
            .contains_key(&breach.penalty_tx.txid()));
        assert_eq!(
            responder.tx_tracker_map.borrow()[&breach.penalty_tx.txid()].len(),
            2
        );
        assert_eq!(
            dbm.lock().unwrap().load_tracker(&uuid).unwrap(),
            TransactionTracker::new(breach, user_id)
        );
    }

    #[test]
    fn test_has_tracker() {
        // Has tracker should return true as long as the given tracker is held by the Responder.
        // As long as the tracker is in Responder.trackers and Responder.tx_tracker_map, the return
        // must be true.

        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, None);
        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let gk = Gatekeeper::new(chain.tip(), SLOTS, DURATION, EXPIRY_DELTA, dbm.clone());
        let responder = create_responder(&mut chain, &gk, dbm.clone(), MockedServerQuery::Regular);

        // Add a new tracker
        let user_id = get_random_user_id();
        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        store_appointment_and_fks_to_db(&dbm.lock().unwrap(), &uuid, &appointment);

        let breach = get_random_breach_from_locator(appointment.locator());
        responder.add_tracker(uuid, breach.clone(), user_id, 0);

        assert!(responder.has_tracker(&uuid));

        // Delete the tracker and check again
        responder.delete_trackers(HashSet::from_iter([uuid]), false);
        assert!(!responder.has_tracker(&uuid));
    }

    #[test]
    fn test_get_tracker() {
        // Should return a tracker as long as it exists
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, None);
        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let gk = Gatekeeper::new(chain.tip(), SLOTS, DURATION, EXPIRY_DELTA, dbm.clone());
        let responder = create_responder(&mut chain, &gk, dbm.clone(), MockedServerQuery::Regular);

        // Store the user and the appointment in the database so we can add the tracker later on (due to FK restrictions)
        let user_id = get_random_user_id();
        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        store_appointment_and_fks_to_db(&dbm.lock().unwrap(), &uuid, &appointment);

        // Data should not be there before adding it
        assert_eq!(responder.get_tracker(&uuid), None);

        // Data should be there now
        let breach = get_random_breach_from_locator(appointment.locator());
        let tracker = TransactionTracker::new(breach.clone(), user_id);
        responder.add_tracker(uuid, breach, user_id, 0);
        assert_eq!(responder.get_tracker(&uuid).unwrap(), tracker);

        // After deleting the data it should be gone
        responder.delete_trackers(HashSet::from_iter([uuid]), false);
        assert_eq!(responder.get_tracker(&uuid), None);
    }

    #[test]
    fn test_check_confirmations() {
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, None);
        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let gk = Gatekeeper::new(chain.tip(), SLOTS, DURATION, EXPIRY_DELTA, dbm.clone());
        let responder = create_responder(&mut chain, &gk, dbm.clone(), MockedServerQuery::Regular);

        // If a transaction is in the unconfirmed_transactions map it will be removed
        let mut txs = Vec::new();
        for _ in 0..10 {
            let tx = get_random_tx();
            txs.push(tx.clone());
            responder.unconfirmed_txs.borrow_mut().insert(tx.txid());
        }

        responder.check_confirmations(&txs);

        for tx in txs.iter() {
            assert!(!responder.unconfirmed_txs.borrow().contains(&tx.txid()));
            assert!(!responder
                .missed_confirmations
                .borrow()
                .contains_key(&tx.txid()));
        }
        // All the transactions remaining in the unconfirmed_transactions map are added a missed confirmation
        let mut unconfirmed_txs = Vec::new();
        for (i, tx) in txs.into_iter().enumerate() {
            if i % 2 == 0 {
                responder.unconfirmed_txs.borrow_mut().insert(tx.txid());
                unconfirmed_txs.push(tx);
            }
        }

        for i in 1..10 {
            responder.check_confirmations(&Vec::new());
            for tx in unconfirmed_txs.iter() {
                assert!(responder.unconfirmed_txs.borrow().contains(&tx.txid()));
                assert_eq!(
                    responder
                        .missed_confirmations
                        .borrow()
                        .get(&tx.txid())
                        .unwrap(),
                    &i
                );
            }
        }
    }

    #[test]
    fn test_get_txs_to_rebroadcast() {
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, None);
        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let gk = Gatekeeper::new(chain.tip(), SLOTS, DURATION, EXPIRY_DELTA, dbm.clone());
        let responder = create_responder(&mut chain, &gk, dbm.clone(), MockedServerQuery::Regular);

        let user_id = get_random_user_id();
        responder
            .dbm
            .lock()
            .unwrap()
            .store_user(&user_id, &UserInfo::new(21, 42))
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
                .store_appointment(&uuid, &appointment)
                .unwrap();

            // Create a breach and add it, manually setting the missed confirmation count
            let breach = get_random_breach_from_locator(appointment.locator());
            txs.push(breach.penalty_tx.clone());

            responder.add_tracker(uuid, breach.clone(), user_id, 0);
            responder
                .missed_confirmations
                .borrow_mut()
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
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, None);
        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let gk = Gatekeeper::new(chain.tip(), SLOTS, DURATION, EXPIRY_DELTA, dbm.clone());
        let mut responder = create_responder(
            &mut chain,
            &gk,
            dbm.clone(),
            MockedServerQuery::Confirmations(1),
        );

        let user_id = get_random_user_id();
        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        store_appointment_and_fks_to_db(&dbm.lock().unwrap(), &uuid, &appointment);

        // Let's add a tracker first
        let breach = get_random_breach_from_locator(appointment.locator());
        responder.add_tracker(uuid, breach.clone(), user_id, 1);

        // A tracker is completed when it has passed constants::IRREVOCABLY_RESOLVED confirmations
        // Not completed yet
        for i in 1..constants::IRREVOCABLY_RESOLVED + 2 {
            assert_eq!(responder.get_completed_trackers().await, HashSet::new());
            *responder.carrier.get_mut() = create_carrier(MockedServerQuery::Confirmations(i));
        }

        // Just completed
        *responder.carrier.get_mut() = create_carrier(MockedServerQuery::Confirmations(
            constants::IRREVOCABLY_RESOLVED + 1,
        ));
        assert_eq!(
            responder.get_completed_trackers().await,
            [uuid].iter().cloned().collect()
        );
    }

    #[test]
    fn test_get_outdated_trackers() {
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, None);
        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let gk = Gatekeeper::new(chain.tip(), SLOTS, DURATION, EXPIRY_DELTA, dbm.clone());
        let responder = create_responder(&mut chain, &gk, dbm.clone(), MockedServerQuery::Regular);

        // Outdated trackers are those whose associated subscription is outdated and have not been confirmed yet (they don't have
        // a single confirmation).
        let target_block_height = 100;
        let user_id = get_random_user_id();

        // Mock data into the GK
        let mut uuids = Vec::new();
        for _ in 0..10 {
            uuids.push(generate_uuid());
        }
        let outdated_users: HashMap<UserId, Vec<UUID>> =
            [(user_id, uuids.clone())].iter().cloned().collect();
        gk.outdated_users_cache
            .borrow_mut()
            .insert(target_block_height, outdated_users);

        // If data is not in the unconfirmed_transaction it won't be returned
        assert_eq!(
            responder.get_outdated_trackers(&target_block_height),
            HashSet::new(),
        );

        // Otherwise the matching data should be returned

        // Mock the data to the Responder. Add data to trackers and half of them to the unconfirmed_transactions map
        let mut target_uuids = HashSet::new();
        for (i, uuid) in uuids.into_iter().enumerate() {
            let tracker = get_random_tracker(user_id);
            responder
                .trackers
                .borrow_mut()
                .insert(uuid, tracker.get_summary());

            if i % 2 == 0 {
                responder
                    .unconfirmed_txs
                    .borrow_mut()
                    .insert(tracker.penalty_tx.txid());
                target_uuids.insert(uuid);
            }
        }

        // Check the expected data is there
        assert_eq!(
            responder.get_outdated_trackers(&target_block_height),
            target_uuids
        );
    }

    #[tokio::test]
    async fn test_rebroadcast() {
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, None);
        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let gk = Gatekeeper::new(chain.tip(), SLOTS, DURATION, EXPIRY_DELTA, dbm.clone());
        let responder = create_responder(&mut chain, &gk, dbm.clone(), MockedServerQuery::Regular);
        let user_id = get_random_user_id();

        // Add user to the database
        responder
            .dbm
            .lock()
            .unwrap()
            .store_user(&user_id, &UserInfo::new(21, 42))
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
                .store_appointment(&uuid, &appointment)
                .unwrap();

            let breach = get_random_breach_from_locator(appointment.locator());
            let penalty_txid = breach.penalty_tx.txid();
            responder.add_tracker(uuid, breach, user_id, 0);

            if i % 2 == 0 {
                responder
                    .missed_confirmations
                    .borrow_mut()
                    .insert(penalty_txid.clone(), CONFIRMATIONS_BEFORE_RETRY);
                need_rebroadcast.push(penalty_txid);
            } else {
                responder
                    .missed_confirmations
                    .borrow_mut()
                    .insert(penalty_txid.clone(), CONFIRMATIONS_BEFORE_RETRY - 1);
                dont_need_rebroadcast.push(penalty_txid);
            }
        }

        for (txid, receipt) in responder.rebroadcast().await {
            assert_eq!(
                responder
                    .missed_confirmations
                    .borrow()
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
                    .borrow()
                    .get(&txid)
                    .unwrap()
                    .to_owned(),
                CONFIRMATIONS_BEFORE_RETRY - 1
            );
        }
    }

    #[test]
    fn test_delete_trackers() {
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, None);
        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let gk = Gatekeeper::new(chain.tip(), SLOTS, DURATION, EXPIRY_DELTA, dbm.clone());
        let responder = create_responder(&mut chain, &gk, dbm.clone(), MockedServerQuery::Regular);
        let user_id = get_random_user_id();

        // Add user to the database
        responder
            .dbm
            .lock()
            .unwrap()
            .store_user(&user_id, &UserInfo::new(21, 42))
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
                .store_appointment(&uuid, &appointment)
                .unwrap();

            let breach = get_random_breach_from_locator(appointment.locator());
            responder.add_tracker(uuid, breach.clone(), user_id, 0);

            // Make it so some of the penalties have multiple associated trackers
            if i % 3 == 0 {
                let uuid2 = generate_uuid();
                responder
                    .tx_tracker_map
                    .borrow_mut()
                    .get_mut(&breach.penalty_tx.txid())
                    .unwrap()
                    .insert(uuid2);
                txs_with_multiple_uuids.insert(breach.penalty_tx.txid());
            }

            all_trackers.insert(uuid.clone());
            uuid_txid_map.insert(uuid.clone(), breach.penalty_tx.txid());

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
                assert!(!responder.trackers.borrow().contains_key(&uuid));
                assert!(matches!(
                    dbm.lock().unwrap().load_tracker(&uuid),
                    Err(DBError::NotFound)
                ));
                let penalty_txid = &uuid_txid_map[&uuid];
                // If the penalty had more than one associated uuid, only one has been deleted
                // (because that's how the test has been designed)
                if txs_with_multiple_uuids.contains(penalty_txid) {
                    assert_eq!(
                        responder
                            .tx_tracker_map
                            .borrow()
                            .get(penalty_txid)
                            .unwrap()
                            .len(),
                        1
                    );
                } else {
                    // Otherwise the whole structure is removed, given it is now empty
                    assert!(!responder.tx_tracker_map.borrow().contains_key(penalty_txid));
                }
            } else {
                assert!(responder.trackers.borrow().contains_key(&uuid));
                assert!(responder
                    .tx_tracker_map
                    .borrow()
                    .contains_key(&uuid_txid_map[&uuid]));
                assert!(matches!(
                    dbm.lock().unwrap().load_tracker(&uuid),
                    Ok(TransactionTracker { .. })
                ));
            }
        }
    }

    #[test]
    fn test_block_connected() {
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, None);
        let dbm = Arc::new(Mutex::new(DBM::in_memory().unwrap()));
        let gk = Gatekeeper::new(chain.tip(), SLOTS, DURATION, EXPIRY_DELTA, dbm.clone());
        let responder = create_responder(
            &mut chain,
            &gk,
            dbm.clone(),
            MockedServerQuery::Confirmations(constants::IRREVOCABLY_RESOLVED + 1),
        );

        // block_connected is used to keep track of the confirmation received (or missed) by the trackers the Responder
        // is keeping track of.

        // If the Responder has no trackers, block_connected will only be used to track the last known block by the Responder.
        assert_eq!(
            responder.last_known_block_header.borrow().header,
            chain.tip().header
        );
        responder.block_connected(&chain.generate(None), chain.blocks.len() as u32);
        assert_eq!(
            responder.last_known_block_header.borrow().header,
            chain.tip().header
        );
        // Check the id is also stored in the database
        assert_eq!(
            responder
                .last_known_block_header
                .borrow()
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

        // Let's start by doing the data setup for each test (i.e. adding all the necessary data to the Responder and GK)
        let mut users = Vec::new();
        for _ in 2..23 {
            let user_id = get_random_user_id();

            gk.add_update_user(&user_id).unwrap();
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
                .store_appointment(&uuid, &appointment)
                .unwrap();

            let breach = get_random_breach_from_locator(appointment.locator());
            responder.add_tracker(
                uuid,
                breach.clone(),
                user_id,
                constants::IRREVOCABLY_RESOLVED + 1,
            );
            gk.registered_users
                .borrow_mut()
                .get_mut(&user_id)
                .unwrap()
                .appointments
                .insert(uuid, 1);

            completed_trackers.insert(uuid, (user_id, breach));
        }

        // OUTDATED TRACKER SETUP
        let mut penalties = Vec::new();
        let mut uuids = Vec::new();
        let mut outdated_users = HashMap::new();
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
                    .store_appointment(&uuid, &appointment)
                    .unwrap();

                let breach = get_random_breach_from_locator(appointment.locator());
                penalties.push(breach.penalty_tx.txid());
                responder.add_tracker(uuid.clone(), breach, user_id, 0);
            }

            outdated_users.insert(user_id, pair.clone());
            uuids.extend(pair);
        }

        gk.outdated_users_cache
            .borrow_mut()
            .insert(target_block_height, outdated_users);

        // CONFIRMATIONS SETUP
        let standalone_user_id = get_random_user_id();
        gk.add_update_user(&standalone_user_id).unwrap();

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
                .store_appointment(&uuid, &appointment)
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
            .store_appointment(&uuid, &appointment)
            .unwrap();

        let breach_rebroadcast = get_random_breach_from_locator(appointment.locator());
        responder.add_tracker(uuid, breach_rebroadcast.clone(), standalone_user_id, 0);
        responder.missed_confirmations.borrow_mut().insert(
            breach_rebroadcast.penalty_tx.txid(),
            CONFIRMATIONS_BEFORE_RETRY,
        );

        // Connecting a block should trigger all the state transitions
        responder.block_connected(&chain.generate(None), chain.blocks.len() as u32);

        // COMPLETED TRACKERS CHECKS
        // Data should have been removed
        for (uuid, (user_id, breach)) in completed_trackers {
            assert!(!responder.trackers.borrow().contains_key(&uuid));
            assert!(!responder
                .tx_tracker_map
                .borrow()
                .contains_key(&breach.penalty_tx.txid()));
            assert!(!gk.registered_users.borrow()[&user_id]
                .appointments
                .contains_key(&uuid));
        }

        // OUTDATED TRACKERS CHECKS
        // Data should have been removed
        for uuid in uuids {
            assert!(!responder.trackers.borrow().contains_key(&uuid));
        }
        for txid in penalties {
            assert!(!responder.tx_tracker_map.borrow().contains_key(&txid));
            assert!(!responder.unconfirmed_txs.borrow().contains(&txid));
        }

        // CONFIRMATIONS CHECKS
        // The transaction confirmation count / confirmation missed should have been updated
        for txid in transactions {
            if confirmed_txs.contains(&txid) {
                assert!(!responder.unconfirmed_txs.borrow().contains(&txid));
                assert!(!responder.missed_confirmations.borrow().contains_key(&txid));
            } else {
                assert!(responder.unconfirmed_txs.borrow().contains(&txid));
                assert_eq!(
                    responder
                        .missed_confirmations
                        .borrow()
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
            responder.missed_confirmations.borrow()[&breach_rebroadcast.penalty_tx.txid()],
            0
        );
    }
}
