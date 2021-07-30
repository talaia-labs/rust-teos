use std::cell::RefCell;
use std::collections::HashMap;
use std::ops::Deref;
use std::rc::Rc;

use bitcoin::{BlockHeader, Transaction, Txid};
use lightning_block_sync::poll::ValidatedBlockHeader;
use lightning_block_sync::BlockHeaderData;

use teos_common::appointment::Locator;
use teos_common::UserId;

use crate::extended_appointment::UUID;
use crate::gatekeeper::Gatekeeper;
use crate::watcher::Breach;

pub struct TransactionTracker {
    locator: Locator,
    dispute_tx: Transaction,
    penalty_tx: Transaction,
    user_id: UserId,
}

pub struct Responder {
    trackers: RefCell<HashMap<UUID, TransactionTracker>>,
    tx_tracker_map: RefCell<HashMap<Txid, UUID>>,
    unconfirmed_txs: RefCell<Vec<Transaction>>,
    missed_confirmations: RefCell<HashMap<Txid, u8>>,
    gatekeeper: Rc<RefCell<Gatekeeper>>,
    last_known_block_header: RefCell<BlockHeaderData>,
}

impl Responder {
    pub fn new(
        gatekeeper: Rc<RefCell<Gatekeeper>>,
        last_known_block_header: ValidatedBlockHeader,
    ) -> Self {
        let trackers = RefCell::new(HashMap::new());
        let tx_tracker_map = RefCell::new(HashMap::new());
        let unconfirmed_txs = RefCell::new(Vec::new());
        let missed_confirmations = RefCell::new(HashMap::new());

        Responder {
            trackers,
            tx_tracker_map,
            unconfirmed_txs,
            missed_confirmations,
            gatekeeper,
            last_known_block_header: RefCell::new(last_known_block_header.deref().clone()),
        }
    }

    pub fn handle_breach(
        &self,
        uuid: UUID,
        breach: Breach,
        user_id: UserId,
        block_header: BlockHeader,
    ) {
    }
}
