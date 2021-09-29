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

#[derive(Debug, Clone)]
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
            if unconfirmed_txs.remove(tx) {
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

    async fn get_completed_trackers(&self) -> HashSet<UUID> {
        // DISCUSS: Not using a checked_txs cache for now, check whether it may be necessary
        let mut completed_trackers = HashSet::new();

        for uuid in self.trackers.borrow().keys() {
            let penalty_tx = self.trackers.borrow()[uuid].penalty_tx.clone();
            if !self.unconfirmed_txs.borrow().contains(&penalty_tx) {
                self.carrier
                    .borrow()
                    .get_confirmations(&penalty_tx.txid())
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
                .contains(&self.trackers.borrow()[&uuid].penalty_tx)
            {
                outdated_trackers.insert(uuid.clone());
            }
        }

        outdated_trackers
    }

    async fn rebroadcast(&self) -> HashMap<Txid, Receipt> {
        let mut receipts = HashMap::new();

        for txid in self.get_txs_to_rebroadcast().into_iter() {
            *self
                .missed_confirmations
                .borrow_mut()
                .get_mut(&txid)
                .unwrap() = 0;

            for uuid in self.tx_tracker_map.borrow().get(&txid).unwrap() {
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
                    );
                }

                receipts.insert(txid, receipt);
            }
        }

        receipts
    }

    fn delete_trackers(&self, trackers: HashSet<UUID>, outdated: bool) {
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
                    let trackers = tracker_map.get_mut(&tracker.penalty_tx.txid()).unwrap();

                    // The transaction will only be in the unconfirmed_txs map if the trackers are outdated
                    self.unconfirmed_txs
                        .borrow_mut()
                        .remove(&tracker.penalty_tx);

                    if trackers.len() == 1 {
                        tracker_map.remove(&tracker.penalty_tx.txid());

                        log::info!(
                            "No more trackers for penalty transaction: {}",
                            tracker.penalty_tx.txid()
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
    }

    fn block_disconnected(&self, header: &BlockHeader, height: u32) {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use crate::rpc_errors;
    use crate::test_utils::{
        generate_uuid, get_random_tx, Blockchain, DURATION, EXPIRY_DELTA, RPC_NONCE, SLOTS,
        START_HEIGHT, TXID_HEX,
    };

    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use bitcoincore_rpc::jsonrpc::error::RpcError;
    use bitcoincore_rpc::{Auth, Client as BitcoindClient};
    use httpmock::prelude::*;

    enum MockedServerQuery {
        Tx,
        Confirmations(u32),
        Error,
        None,
    }

    fn create_mocked_server(query: MockedServerQuery) -> MockServer {
        let server = MockServer::start();

        let response_body = match query {
            MockedServerQuery::Tx =>
                serde_json::json!({ "id": RPC_NONCE, "result": TXID_HEX }).to_string(),
            MockedServerQuery::Confirmations(x) => {
                serde_json::json!({ "id": RPC_NONCE, "result": {"confirmations": x, "hex": "", "txid": TXID_HEX,
                "hash": TXID_HEX, "size": 0, "vsize": 0, "version": 1, "locktime": 0, "vin": [], "vout": [] }})
                    .to_string()
            }
            MockedServerQuery::Error => {
                let error = RpcError {
                    code: rpc_errors::RPC_VERIFY_ERROR,
                    message: String::from(""),
                    data: None,
                };

                serde_json::json!({ "id": RPC_NONCE, "error": error }).to_string()
            }
            MockedServerQuery::None => serde_json::json!({ "id": RPC_NONCE}).to_string(),
        };

        server.mock(|when, then| {
            when.method(POST);
            then.status(200)
                .header("content-type", "application/json")
                .body(response_body);
        });

        server
    }

    fn create_carrier(query: MockedServerQuery) -> Carrier {
        let server = create_mocked_server(query);
        let bitcoin_cli = Arc::new(BitcoindClient::new(server.base_url(), Auth::None).unwrap());
        Carrier::new(bitcoin_cli)
    }

    fn create_responder<'a>(
        chain: &mut Blockchain,
        gatekeeper: &'a Gatekeeper,
        query: MockedServerQuery,
    ) -> Responder<'a> {
        let tip = chain.tip();
        let carrier = create_carrier(query);
        Responder::new(carrier, &gatekeeper, tip)
    }

    fn get_random_breach() -> Breach {
        let dispute_tx = get_random_tx();
        let penalty_tx = get_random_tx();
        let locator = Locator::new(dispute_tx.txid());

        Breach::new(locator, dispute_tx, penalty_tx)
    }

    fn get_random_tracker(user_id: UserId) -> TransactionTracker {
        let breach = get_random_breach();
        TransactionTracker {
            locator: breach.locator,
            penalty_tx: breach.penalty_tx,
            dispute_tx: breach.dispute_tx,
            user_id,
        }
    }

    #[tokio::test]
    async fn test_handle_breach_delivered() {
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, None);
        let gk = Gatekeeper::new(chain.tip(), SLOTS, DURATION, EXPIRY_DELTA);
        let responder = create_responder(&mut chain, &gk, MockedServerQuery::Tx);

        let user_sk = SecretKey::from_slice(&[2; 32]).unwrap();
        let user_id = UserId(PublicKey::from_secret_key(&Secp256k1::new(), &user_sk));
        let uuid = generate_uuid();
        let breach = get_random_breach();
        let penalty_txid = breach.penalty_tx.txid();

        let r = responder.handle_breach(uuid, breach.clone(), user_id).await;

        assert!(r.delivered());
        assert!(responder.trackers.borrow().contains_key(&uuid));
        assert!(responder
            .tx_tracker_map
            .borrow()
            .contains_key(&penalty_txid));
        assert!(responder
            .unconfirmed_txs
            .borrow()
            .contains(&breach.penalty_tx));
    }

    #[tokio::test]
    async fn test_handle_breach_not_delivered() {
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, None);
        let gk = Gatekeeper::new(chain.tip(), SLOTS, DURATION, EXPIRY_DELTA);
        let responder = create_responder(&mut chain, &gk, MockedServerQuery::Error);

        let user_sk = SecretKey::from_slice(&[2; 32]).unwrap();
        let user_id = UserId(PublicKey::from_secret_key(&Secp256k1::new(), &user_sk));
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
        assert!(!responder
            .unconfirmed_txs
            .borrow()
            .contains(&breach.penalty_tx));
    }

    #[test]
    fn test_add_tracker() {
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, None);
        let gk = Gatekeeper::new(chain.tip(), SLOTS, DURATION, EXPIRY_DELTA);
        let responder = create_responder(&mut chain, &gk, MockedServerQuery::None);

        let user_sk = SecretKey::from_slice(&[2; 32]).unwrap();
        let user_id = UserId(PublicKey::from_secret_key(&Secp256k1::new(), &user_sk));
        let mut uuid = generate_uuid();
        let mut breach = get_random_breach();

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
            .contains(&breach.penalty_tx));

        // Adding a tracker with confirmations should result in the same but with the penalty not being added to the unconfirmed_transactions
        //map
        uuid = generate_uuid();
        breach = get_random_breach();

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
            .contains(&breach.penalty_tx));

        // Adding another breach with the same penalty transaction (but different uuid) adds an additional uuid to the map entry
        uuid = generate_uuid();
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
    }

    #[test]
    fn test_check_confirmations() {
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, None);
        let gk = Gatekeeper::new(chain.tip(), SLOTS, DURATION, EXPIRY_DELTA);
        let responder = create_responder(&mut chain, &gk, MockedServerQuery::None);

        // If a transaction is in the unconfirmed_transactions map it will be removed
        let mut txs = Vec::new();
        for _ in 0..10 {
            let tx = get_random_tx();
            txs.push(tx.clone());
            responder.unconfirmed_txs.borrow_mut().insert(tx);
        }

        responder.check_confirmations(&txs);

        for tx in txs.iter() {
            assert!(!responder.unconfirmed_txs.borrow().contains(tx));
            assert!(!responder
                .missed_confirmations
                .borrow()
                .contains_key(&tx.txid()));
        }
        // All the transactions remaining in the unconfirmed_transactions map are added a missed confirmation
        let mut unconfirmed_txs = Vec::new();
        for (i, tx) in txs.into_iter().enumerate() {
            if i % 2 == 0 {
                responder.unconfirmed_txs.borrow_mut().insert(tx.clone());
                unconfirmed_txs.push(tx);
            }
        }

        for i in 1..10 {
            responder.check_confirmations(&Vec::new());
            for tx in unconfirmed_txs.iter() {
                assert!(responder.unconfirmed_txs.borrow().contains(tx));
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
        let gk = Gatekeeper::new(chain.tip(), SLOTS, DURATION, EXPIRY_DELTA);
        let responder = create_responder(&mut chain, &gk, MockedServerQuery::Tx);

        // Transactions are flagged to be rebroadcast when they've missed CONFIRMATIONS_BEFORE_RETRY confirmations
        let mut txs = Vec::new();
        let mut tx: Transaction;

        for i in 0..CONFIRMATIONS_BEFORE_RETRY + 2 {
            tx = get_random_tx();
            txs.push(tx.txid());
            responder
                .missed_confirmations
                .borrow_mut()
                .insert(tx.txid(), i);
            responder.unconfirmed_txs.borrow_mut().insert(tx);
        }

        assert_eq!(
            responder.get_txs_to_rebroadcast().sort(),
            txs[CONFIRMATIONS_BEFORE_RETRY as usize..].to_vec().sort()
        )
    }

    #[tokio::test]
    async fn test_get_completed_trackers() {
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, None);
        let gk = Gatekeeper::new(chain.tip(), SLOTS, DURATION, EXPIRY_DELTA);
        let mut responder = create_responder(&mut chain, &gk, MockedServerQuery::Confirmations(1));

        // Let's add a tracker first
        let user_sk = SecretKey::from_slice(&[2; 32]).unwrap();
        let user_id = UserId(PublicKey::from_secret_key(&Secp256k1::new(), &user_sk));
        let uuid = generate_uuid();
        let breach = get_random_breach();
        responder.add_tracker(uuid, breach.clone(), user_id, 1);

        // A tracker is completed when it has passed constants::IRREVOCABLY_RESOLVED confirmations
        // Not completed yet
        // FIXME: Creating this many servers makes test fail
        //for i in 1..constants::IRREVOCABLY_RESOLVED + 2 {
        for i in constants::IRREVOCABLY_RESOLVED - 7..constants::IRREVOCABLY_RESOLVED + 2 {
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
        let gk = Gatekeeper::new(chain.tip(), SLOTS, DURATION, EXPIRY_DELTA);
        let responder = create_responder(&mut chain, &gk, MockedServerQuery::None);

        // Outdated trackers are those whose associated subscription is outdated and have not been confirmed yet (they don't have
        // a single confirmation).
        let target_block_height = 100;
        let user_sk = SecretKey::from_slice(&[2; 32]).unwrap();
        let user_id = UserId(PublicKey::from_secret_key(&Secp256k1::new(), &user_sk));

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
            let penalty_tx = tracker.penalty_tx.clone();
            responder.trackers.borrow_mut().insert(uuid, tracker);

            if i % 2 == 0 {
                responder.unconfirmed_txs.borrow_mut().insert(penalty_tx);
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
        let gk = Gatekeeper::new(chain.tip(), SLOTS, DURATION, EXPIRY_DELTA);
        let responder = create_responder(&mut chain, &gk, MockedServerQuery::Tx);

        let user_sk = SecretKey::from_slice(&[2; 32]).unwrap();
        let user_id = UserId(PublicKey::from_secret_key(&Secp256k1::new(), &user_sk));

        // Transactions are rebroadcast once they hit CONFIRMATIONS_BEFORE_RETRY
        // Add some trackers and set their missed confirmation count
        let mut need_rebroadcast = Vec::new();
        let mut dont_need_rebroadcast = Vec::new();

        for i in 0..10 {
            let uuid = generate_uuid();
            let breach = get_random_breach();
            let penalty_txid = breach.penalty_tx.txid();

            responder.add_tracker(uuid, breach, user_id, 0);

            // FIXME: We can only test this with a single transaction at the moment since the mockserver
            // cannot return the proper nonce for requests (https://github.com/alexliesenfeld/httpmock/issues/49)
            // It works with a single request since we can hardcode it the nonce to the init value.
            //if i % 2 == 0 {
            if i == 0 {
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
        let gk = Gatekeeper::new(chain.tip(), SLOTS, DURATION, EXPIRY_DELTA);
        let responder = create_responder(&mut chain, &gk, MockedServerQuery::None);

        let user_sk = SecretKey::from_slice(&[2; 32]).unwrap();
        let user_id = UserId(PublicKey::from_secret_key(&Secp256k1::new(), &user_sk));

        // Delete trackers removes data from the trackers, tx_tracker_map maps (and unconfirmed_txs if the data is outdated)
        // The deletion of the later is better check in test_block_connected
        // Add data to the map first
        let mut all_trackers = HashSet::new();
        let mut target_trackers = HashSet::new();
        let mut uuid_txid_map = HashMap::new();
        let mut txs_with_multiple_uuids = HashSet::new();

        for i in 0..10 {
            let uuid = generate_uuid();
            let breach = get_random_breach();
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
            }
        }
    }

    #[test]
    fn test_block_connected() {
        let mut chain = Blockchain::default().with_height_and_txs(START_HEIGHT, None);
        let gk = Gatekeeper::new(chain.tip(), SLOTS, DURATION, EXPIRY_DELTA);
        let mut responder = create_responder(
            &mut chain,
            &gk,
            MockedServerQuery::Confirmations(constants::IRREVOCABLY_RESOLVED + 1),
        );

        // block_connected is used to keep track of the confirmation received (or missed) by the trackers the Responder
        // is keeping track of.

        // If the Responder has no trackers, block_connected will only be used to track the last known block by  the Responder.
        assert_eq!(
            responder.last_known_block_header.borrow().header,
            chain.tip().header
        );
        responder.block_connected(&chain.generate(None), chain.blocks.len() as u32);
        assert_eq!(
            responder.last_known_block_header.borrow().header,
            chain.tip().header
        );

        // If there are any trackers, the Responder will:
        // - Check if there is any tracker that has been completed
        // - Check if there is any tracker that has been outdated
        // - Check if any tracker has been confirmed or add missing confirmations otherwise
        // - Rebroadcast all penalty transactions that need so
        // - Delete completed and outdated data (including data in the GK)

        // Let's start by adding data to the Responder and the Gatekeeper
        let user_sk = SecretKey::from_slice(&[2; 32]).unwrap();
        let user_id = UserId(PublicKey::from_secret_key(&Secp256k1::new(), &user_sk));

        // FIXME: We can only test this with a single transaction at the time due to
        // https://github.com/alexliesenfeld/httpmock/issues/49
        // We'll tests things one at a time for now
        let mut uuid = generate_uuid();
        let mut breach = get_random_breach();
        gk.add_update_user(&user_id).unwrap();

        // COMPLETED TRACKER
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

        // Connecting a block should remove the tracker from the Responder and the GK
        responder.block_connected(&chain.generate(None), chain.blocks.len() as u32);
        assert!(!responder.trackers.borrow().contains_key(&uuid));
        assert!(!responder
            .tx_tracker_map
            .borrow()
            .contains_key(&breach.penalty_tx.txid()));
        assert!(!gk.registered_users.borrow()[&user_id]
            .appointments
            .contains_key(&uuid));

        // FIXME: Workaround to reset the http server so the nonces match
        *responder.carrier.get_mut() = create_carrier(MockedServerQuery::Confirmations(
            constants::IRREVOCABLY_RESOLVED + 1,
        ));

        // OUTDATED TRACKER
        let outdated_users: HashMap<UserId, Vec<UUID>> =
            [(user_id, [uuid].to_vec())].iter().cloned().collect();
        let target_block_height = (chain.blocks.len() + 1) as u32;

        gk.outdated_users_cache
            .borrow_mut()
            .insert(target_block_height, outdated_users);
        responder.add_tracker(uuid, breach.clone(), user_id, 0);

        // Connecting a block should remove the data from the Responder
        responder.block_connected(&chain.generate(None), chain.blocks.len() as u32);
        assert!(!responder.trackers.borrow().contains_key(&uuid));
        assert!(!responder
            .tx_tracker_map
            .borrow()
            .contains_key(&breach.penalty_tx.txid()));
        assert!(!responder
            .unconfirmed_txs
            .borrow()
            .contains(&breach.penalty_tx));

        // CONFIRMATIONS
        let mut transactions = Vec::new();
        let mut confirmed_txs = Vec::new();
        let mut confirmations: u32;
        for i in 0..10 {
            breach = get_random_breach();
            uuid = generate_uuid();
            transactions.push(breach.clone().penalty_tx);

            if i % 2 == 0 {
                confirmations = 0;
            } else {
                confirmed_txs.push(breach.clone().penalty_tx);
                confirmations = 1;
            };

            responder.add_tracker(uuid, breach, user_id, confirmations);
        }

        responder.block_connected(&chain.generate(None), chain.blocks.len() as u32);

        for tx in transactions {
            if confirmed_txs.contains(&tx) {
                assert!(!responder.unconfirmed_txs.borrow().contains(&tx));
                assert!(!responder
                    .missed_confirmations
                    .borrow()
                    .contains_key(&tx.txid()));
            } else {
                assert!(responder.unconfirmed_txs.borrow().contains(&tx));
                assert_eq!(
                    responder
                        .missed_confirmations
                        .borrow()
                        .get(&tx.txid())
                        .unwrap()
                        .to_owned(),
                    1
                );
            }
        }

        // FIXME: Workaround to reset the http server so the nonces match
        *responder.carrier.get_mut() = create_carrier(MockedServerQuery::Confirmations(
            constants::IRREVOCABLY_RESOLVED + 1,
        ));

        // REBROADCAST
        breach = get_random_breach();
        uuid = generate_uuid();
        responder.add_tracker(uuid, breach.clone(), user_id, 0);
        responder
            .missed_confirmations
            .borrow_mut()
            .insert(breach.penalty_tx.txid(), CONFIRMATIONS_BEFORE_RETRY);

        responder.block_connected(&chain.generate(None), chain.blocks.len() as u32);
        assert_eq!(
            responder.missed_confirmations.borrow()[&breach.penalty_tx.txid()],
            0
        );
    }
}
