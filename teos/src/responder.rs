use std::cell::RefCell;
use std::collections::HashMap;
use std::ops::Deref;

use bitcoin::util::psbt::serialize::Serialize;
use bitcoin::{BlockHeader, Transaction, Txid};
use lightning::chain::Listen;
use lightning_block_sync::poll::ValidatedBlockHeader;
use lightning_block_sync::BlockHeaderData;

use serde::Deserialize;
use teos_common::appointment::Locator;
use teos_common::UserId;

use crate::carrier::Carrier;
use crate::extended_appointment::UUID;
use crate::gatekeeper::Gatekeeper;
use crate::watcher::Breach;

pub struct TransactionTracker {
    locator: Locator,
    dispute_tx: Transaction,
    penalty_tx: Transaction,
    user_id: UserId,
}

pub struct Responder<'a> {
    pub(crate) trackers: RefCell<HashMap<UUID, TransactionTracker>>,
    tx_tracker_map: RefCell<HashMap<Txid, UUID>>,
    unconfirmed_txs: RefCell<Vec<Transaction>>,
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
        let unconfirmed_txs = RefCell::new(Vec::new());
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

    // TODO: Just adding dummy functionality so we can check that data came trough. Needs refactor.
    pub async fn handle_breach(
        &self,
        uuid: UUID,
        breach: Breach,
        user_id: UserId,
        block_header: BlockHeader,
    ) {
        // FIXME: Temporary hack until bitcoincore_rpc bumps it's version to match ldk's
        let penalty_tx =
            bitcoincore_rpc::bitcoin::consensus::deserialize(&breach.penalty_tx.serialize())
                .unwrap();

        let receipt = self
            .carrier
            .borrow_mut()
            .send_transaction(&penalty_tx)
            .await;

        let tracker = TransactionTracker {
            locator: breach.locator,
            dispute_tx: breach.dispute_tx,
            penalty_tx: breach.penalty_tx,
            user_id,
        };

        self.trackers.borrow_mut().insert(uuid, tracker);
    }
}

impl<'a> Listen for Responder<'a> {
    fn block_connected(&self, block: &bitcoin::Block, height: u32) {
        todo!()
    }

    fn block_disconnected(&self, header: &BlockHeader, height: u32) {
        todo!()
    }
}
