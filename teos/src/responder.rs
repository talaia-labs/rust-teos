use futures::executor::block_on;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;
use std::ops::Deref;

use bitcoin::{BlockHeader, Transaction, Txid};
use lightning::chain::Listen;
use lightning_block_sync::poll::ValidatedBlockHeader;
use lightning_block_sync::BlockHeaderData;

use teos_common::appointment::Locator;
use teos_common::constants;
use teos_common::UserId;

use crate::carrier::{Carrier, Receipt};
use crate::extended_appointment::UUID;
use crate::gatekeeper::Gatekeeper;
use crate::watcher::Breach;

const CONFIRMATIONS_BEFORE_RETRY: u8 = 6;
const MIN_CONFIRMATIONS: u8 = 6;

pub struct TransactionTracker {
    locator: Locator,
    dispute_tx: Transaction,
    penalty_tx: Transaction,
    user_id: UserId,
}

pub struct Responder<'a> {
    pub(crate) trackers: RefCell<HashMap<UUID, TransactionTracker>>,
    tx_tracker_map: RefCell<HashMap<Txid, HashSet<UUID>>>,
    unconfirmed_txs: RefCell<HashSet<Transaction>>,
    missed_confirmations: RefCell<HashMap<Txid, u8>>,
    carrier: RefCell<Carrier>,
    gatekeeper: &'a Gatekeeper,
    last_known_block_header: RefCell<BlockHeaderData>,
}

impl<'a> Responder<'a> {
    pub fn new(
        carrier: Carrier,
        gatekeeper: &'a Gatekeeper,
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
            gatekeeper,
            last_known_block_header: RefCell::new(last_known_block_header.deref().clone()),
        }
    }

    pub async fn handle_breach(
        &self,
        uuid: UUID,
        breach: Breach,
        user_id: UserId,
        block_header: BlockHeader,
    ) -> Receipt {
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

    fn add_tracker(&self, uuid: UUID, breach: Breach, user_id: UserId, confirmations: u32) {
        let penalty_txid = breach.penalty_tx.txid();
        let tracker = TransactionTracker {
            locator: breach.locator,
            dispute_tx: breach.dispute_tx,
            penalty_tx: breach.penalty_tx.clone(),
            user_id,
        };

        self.trackers.borrow_mut().insert(uuid, tracker);

        let mut tx_tracker_map = self.tx_tracker_map.borrow_mut();
        match tx_tracker_map.get_mut(&penalty_txid) {
            Some(map) => {
                map.insert(uuid);
            }
            None => {
                tx_tracker_map.insert(penalty_txid, HashSet::from_iter(vec![uuid]));
            }
        }

        if !self.unconfirmed_txs.borrow().contains(&breach.penalty_tx) && confirmations == 0 {
            self.unconfirmed_txs
                .borrow_mut()
                .insert(breach.penalty_tx.clone());
        }

        log::info!("New tracker added (uuid={}).", uuid);
    }

    fn check_confirmations(&self, txs: &Vec<Transaction>) {
        // If a new confirmed transaction matches one we are watching, we remove it from the unconfirmed transaction vector
        let mut unconfirmed_txs = self.unconfirmed_txs.borrow_mut();
        for tx in txs.iter() {
            if unconfirmed_txs.contains(tx) {
                unconfirmed_txs.remove(tx);
                log::info!("Confirmation received for transaction: {}", tx.txid());
            }
        }

        // Increase the missing confirmation count for all those transactions pending confirmation that have not been confirmed this block
        let mut missed_confirmations = self.missed_confirmations.borrow_mut();
        for tx in unconfirmed_txs.iter() {
            match missed_confirmations.get_mut(&tx.txid()) {
                Some(x) => *x += 1,

                None => {
                    missed_confirmations.insert(tx.txid(), 1);
                }
            }
            log::info!(
                "Transaction missed a confirmation: {} (missed conf count: {})",
                tx.txid(),
                missed_confirmations.get(&tx.txid()).unwrap()
            );
        }
    }

    fn get_txs_to_rebroadcast(&self) -> Vec<Txid> {
        let mut tx_to_rebroadcast = Vec::new();

        for (txid, missed_conf) in self.missed_confirmations.borrow().iter() {
            if missed_conf >= &CONFIRMATIONS_BEFORE_RETRY {
                tx_to_rebroadcast.push(txid.clone())
            }
        }

        tx_to_rebroadcast
    }

    async fn get_completed_trackers(&self) -> Vec<UUID> {
        // DISCUSS: Not using a checked_txs cache for now, check whether it may be necessary
        let mut completed_trackers = Vec::new();

        for uuid in self.trackers.borrow().keys() {
            let penalty_tx = self.trackers.borrow()[uuid].penalty_tx.clone();
            if self.unconfirmed_txs.borrow().contains(&penalty_tx) {
                self.carrier
                    .borrow()
                    .get_confirmations(&penalty_tx.txid())
                    .await
                    .map(|confirmations| {
                        if confirmations > constants::IRREVOCABLY_RESOLVED {
                            completed_trackers.push(uuid.clone())
                        }
                    });
            }
        }

        completed_trackers
    }

    fn get_outdated_trackers(&self, block_height: &u32) -> Vec<UUID> {
        let mut outdated_trackers = Vec::new();

        for uuid in self.gatekeeper.get_outdated_appointments(&block_height) {
            if self
                .unconfirmed_txs
                .borrow()
                .contains(&self.trackers.borrow()[&uuid].penalty_tx)
            {
                outdated_trackers.push(uuid);
            }
        }

        outdated_trackers
    }

    async fn rebroadcast(&self) {
        let mut receipts = HashMap::new();

        for txid in self.get_txs_to_rebroadcast().iter() {
            *self
                .missed_confirmations
                .borrow_mut()
                .get_mut(txid)
                .unwrap() = 0;

            for uuid in self.tx_tracker_map.borrow().get(txid).unwrap() {
                log::warn!(
                    "Transaction has missed many confirmations. Rebroadcasting: {}",
                    txid
                );
                let receipt = self
                    .carrier
                    .borrow_mut()
                    .send_transaction(&self.trackers.borrow()[&uuid].penalty_tx)
                    .await;

                if !receipt.delivered() {
                    // DISCUSS: Check is this can actually happen. Feels like it may if the original tx
                    // is RBF and it has been already replaced by a higher fee variant.
                    log::warn!(
                        "Transaction rebroadcast failed: {} (reason: {:?})",
                        txid,
                        receipt.reason()
                    )
                }

                receipts.insert(txid, receipt);
            }
        }
    }

    fn delete_trackers(&self, trackers: Vec<UUID>, outdated: bool) {
        // FIXME: Delete data, this should be handled by the Cleaner when implemented
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
                    tracker_map
                        .get_mut(&tracker.penalty_tx.txid())
                        .unwrap()
                        .remove(uuid);

                    if tracker_map[&tracker.penalty_tx.txid()].is_empty() {
                        log::info!(
                            "No more trackers for penalty transaction: {}",
                            tracker.penalty_tx.txid()
                        );
                    }
                }
                None => {
                    // This should never happen. Logging just in case so we can fix it if so
                    log::error!("Completed tracker not found when cleaning: {}", uuid);
                }
            }
        }
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
            self.rebroadcast();
        }
    }

    fn block_disconnected(&self, header: &BlockHeader, height: u32) {
        todo!()
    }
}
