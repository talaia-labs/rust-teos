use crate::dbm::DBM;

use std::marker::{Send, Sync};
use std::sync::{Arc, Mutex};

use bitcoin::{Block, BlockHeader};
use lightning::chain;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

#[tonic::async_trait]
pub trait AsyncListen: Send + Sync {
    async fn block_connected(&self, block: &Block, height: u32);
    async fn block_disconnected(&self, header: &BlockHeader, height: u32);
}

#[tonic::async_trait]
impl<T: AsyncListen> AsyncListen for Arc<T> {
    async fn block_connected(&self, block: &Block, height: u32) {
        (**self).block_connected(block, height).await;
    }

    async fn block_disconnected(&self, header: &BlockHeader, height: u32) {
        (**self).block_disconnected(header, height).await;
    }
}

#[tonic::async_trait]
impl<F: AsyncListen, S: AsyncListen> AsyncListen for (F, S) {
    async fn block_connected(&self, block: &Block, height: u32) {
        self.0.block_connected(block, height).await;
        self.1.block_connected(block, height).await;
    }

    async fn block_disconnected(&self, header: &BlockHeader, height: u32) {
        self.0.block_disconnected(header, height).await;
        self.1.block_disconnected(header, height).await;
    }
}

#[derive(Debug)]
enum BlockListenerAction {
    BlockConnected(Block, u32),
    BlockDisconnected(BlockHeader, u32),
}

pub struct AsyncBlockListener<L> {
    listener: L,
    dbm: Arc<Mutex<DBM>>,
    rx: UnboundedReceiver<BlockListenerAction>,
}

impl<L> AsyncBlockListener<L>
where
    L: AsyncListen + 'static,
{
    pub fn new(listener: L, dbm: Arc<Mutex<DBM>>) -> SyncBlockListener {
        let (tx, rx) = unbounded_channel();
        let actor = AsyncBlockListener { listener, dbm, rx };
        actor.run_actor_in_bg();
        SyncBlockListener { tx }
    }

    fn run_actor_in_bg(mut self: Self) {
        tokio::spawn(async move {
            while let Some(action) = self.rx.recv().await {
                match action {
                    BlockListenerAction::BlockConnected(block, height) => {
                        self.listener.block_connected(&block, height).await;
                        // We can update the last known block after all the listeners have received it.
                        self.dbm
                            .lock()
                            .unwrap()
                            .store_last_known_block(&block.block_hash())
                            .unwrap();
                    }
                    BlockListenerAction::BlockDisconnected(header, height) => {
                        self.listener.block_disconnected(&header, height).await;
                    }
                }
            }
        });
    }
}

#[derive(Debug)]
pub struct SyncBlockListener {
    tx: UnboundedSender<BlockListenerAction>,
}

impl chain::Listen for SyncBlockListener {
    fn block_connected(&self, block: &Block, height: u32) {
        self.tx
            .send(BlockListenerAction::BlockConnected(block.clone(), height))
            .unwrap();
    }

    fn block_disconnected(&self, header: &BlockHeader, height: u32) {
        self.tx
            .send(BlockListenerAction::BlockDisconnected(*header, height))
            .unwrap();
    }

    fn filtered_block_connected(
        &self,
        header: &BlockHeader,
        txdata: &chain::transaction::TransactionData,
        height: u32,
    ) {
        let block = Block {
            header: header.clone(),
            txdata: txdata.iter().map(|&(_, tx)| tx.clone()).collect(),
        };
        self.tx
            .send(BlockListenerAction::BlockConnected(block, height))
            .unwrap();
    }
}
