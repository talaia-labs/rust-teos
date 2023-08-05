//! Contains the [AsyncListen] trait that's analogous to the [chain::Listen] from LDK but runs
//! inside an asynchronous context.

use crate::dbm::DBM;

use std::marker::{Send, Sync};
use std::sync::Arc;

use bitcoin::{Block, BlockHeader};
use lightning::chain;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

/// A trait similar to LDK's [chain::Listen] but runs asynchronously.
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

/// A helper struct that wraps a listener that implements [AsyncListen] and feeds it connected and disconnected
/// blocks received from [UnboundedReceiver] in the background.
pub struct AsyncBlockListener<L: AsyncListen> {
    listener: L,
    dbm: Arc<DBM>,
    rx: UnboundedReceiver<BlockListenerAction>,
}

impl<L: AsyncListen + 'static> AsyncBlockListener<L> {
    /// Takes a `listener` that implements [AsyncListen] and returns a listener that implements [chain::Listen].
    ///
    /// These two listeners are connected. That is, blocks connected-to/disconnected-from the [chain::Listen]
    /// listener are forwarded to the [AsyncListen] listener.
    ///
    /// The [AsyncListen] listener will be actively listening for actions in a background tokio task.
    pub fn wrap_listener(listener: L, dbm: Arc<DBM>) -> SyncBlockListener {
        let (tx, rx) = unbounded_channel();
        let actor = AsyncBlockListener { listener, dbm, rx };
        actor.run_actor_in_bg();
        SyncBlockListener { tx }
    }

    /// Spawns a forever living task that listens for [BlockListenerAction] and feeds them to the
    /// listener in an asynchronous context.
    fn run_actor_in_bg(mut self) {
        tokio::spawn(async move {
            while let Some(action) = self.rx.recv().await {
                match action {
                    BlockListenerAction::BlockConnected(block, height) => {
                        self.listener.block_connected(&block, height).await;
                        // We can update the last known block after all the listeners have received it.
                        self.dbm
                            .store_last_known_block(&block.block_hash())
                            .await
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

/// A block listener that implements the sync [chain::Listen] trait. All it does is forward the blocks received
/// another (async) block listener through an [UnboundedSender].
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
            header: *header,
            txdata: txdata.iter().map(|&(_, tx)| tx.clone()).collect(),
        };
        self.tx
            .send(BlockListenerAction::BlockConnected(block, height))
            .unwrap();
    }
}
