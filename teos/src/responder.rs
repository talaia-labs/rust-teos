use std::cell::RefCell;
use std::collections::HashMap;
use std::ops::DerefMut;
use std::rc::Rc;
use tokio::sync::broadcast::Receiver;

use bitcoin::{Transaction, Txid};
use lightning_block_sync::poll::ChainPoller;
use lightning_block_sync::poll::ValidatedBlockHeader;
use lightning_block_sync::BlockSource;

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

pub struct Responder<B: DerefMut<Target = T> + Sized, T: BlockSource> {
    trackers: HashMap<UUID, TransactionTracker>,
    tx_tracker_map: HashMap<Txid, UUID>,
    unconfirmed_txs: Vec<Transaction>,
    missed_confirmations: HashMap<Txid, u8>,
    block_queue: Receiver<ValidatedBlockHeader>,
    poller: Rc<RefCell<ChainPoller<B, T>>>,
    gatekeeper: Rc<RefCell<Gatekeeper>>,
    last_known_block_header: ValidatedBlockHeader,
}

impl<B, T> Responder<B, T>
where
    B: DerefMut<Target = T> + Sized + Send + Sync,
    T: BlockSource,
{
    pub fn new(
        block_queue: Receiver<ValidatedBlockHeader>,
        poller: Rc<RefCell<ChainPoller<B, T>>>,
        gatekeeper: Rc<RefCell<Gatekeeper>>,
        last_known_block_header: ValidatedBlockHeader,
    ) -> Self {
        let trackers = HashMap::new();
        let tx_tracker_map = HashMap::new();
        let unconfirmed_txs = Vec::new();
        let missed_confirmations = HashMap::new();

        Responder {
            trackers,
            tx_tracker_map,
            unconfirmed_txs,
            missed_confirmations,
            block_queue,
            poller,
            gatekeeper,
            last_known_block_header,
        }
    }

    pub fn handle_breach(
        &self,
        uuid: UUID,
        breach: Breach,
        user_id: UserId,
        block_header: ValidatedBlockHeader,
    ) {
    }
}
