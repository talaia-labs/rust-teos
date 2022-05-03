//! Logic related to the Carrier, the component in charge or sending/requesting transaction data from/to `bitcoind`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::{Notify};

use crate::responder::ConfirmationStatus;
use crate::{errors, rpc_errors};

use bitcoin::{BlockHash, Transaction, Txid};
use bitcoincore_rpc::{
    jsonrpc::error::Error::Rpc as RpcError, jsonrpc::error::Error::Transport as TransportError,
    Client as BitcoindClient, Error::JsonRpc as JsonRpcError, RpcApi,
};

/// Component in charge of the interaction with Bitcoind by sending / querying transactions via RPC.
#[derive(Debug)]
pub struct Carrier {
    /// The underlying bitcoin client used by the [Carrier].
    bitcoin_cli: Arc<Mutex<BitcoindClient>>,
    /// A flag that indicates wether bitcoind is reachable or not.
    bitcoind_reachable: Arc<(Mutex<bool>, Notify)>,
    /// A map of receipts already issued by the [Carrier].
    /// Used to prevent potentially re-sending the same transaction over and over.
    issued_receipts: Arc<Mutex<HashMap<Txid, ConfirmationStatus>>>,
    /// The last known block header.
    block_height: Arc<Mutex<u32>>,
}

impl Carrier {
    /// Creates a new [Carrier] instance.
    pub fn new(
        bitcoin_cli: BitcoindClient,
        bitcoind_reachable: Arc<(Mutex<bool>, Notify)>,
        last_known_block_height: u32,
    ) -> Self {
        Carrier {
            bitcoin_cli: Arc::new(Mutex::new(bitcoin_cli)),
            bitcoind_reachable,
            issued_receipts: Arc::new(Mutex::new(HashMap::new())),
            block_height: Arc::new(Mutex::new(last_known_block_height)),
        }
    }

    /// Clears the receipts cached by the [Carrier]. Should be called periodically to prevent it from
    /// growing unbounded.
    pub(crate) fn clear_receipts(&self) {
        let mut issued_receipts = self.issued_receipts.lock().unwrap();
        if !issued_receipts.is_empty() {
            issued_receipts.clear();
        }
    }

    /// Updates the last known block height by the [Carrier].
    pub(crate) fn update_height(&self, height: u32) {
        *self.block_height.lock().unwrap() = height;
    }

    /// Helper function to check carrier's status of bitcoind connection
    fn is_bitcoind_reachable(&self) -> bool {
        let (lock, _) = &*self.bitcoind_reachable;
        *lock.lock().unwrap()
    }

    /// Hangs the process until bitcoind is reachable. If bitcoind is already reachable it just passes trough.
    async fn hang_until_bitcoind_reachable(&self) {
        let notifier = &self.bitcoind_reachable.1;
        while !self.is_bitcoind_reachable() {
            notifier.notified().await;
        }
    }

    /// Flags bitcoind as unreachable.
    fn flag_bitcoind_unreachable(&self) {
        let (lock, _) = &*self.bitcoind_reachable;
        *lock.lock().unwrap() = false;
    }

    /// Sends a [Transaction] to the Bitcoin network.
    ///
    /// Returns a [ConfirmationStatus] indicating whether the transaction was accepted by the node or not.
    pub(crate) async fn send_transaction(&self, tx: &Transaction) -> ConfirmationStatus {
        let mut continue_looping = true;
        let mut receipt: Option<ConfirmationStatus> = None;
        while continue_looping {
            // We only need to loop once unless we have a bitcoind connectivity
            // issue
            continue_looping = false;

            // Wait until bitcoind is reachable
            self.hang_until_bitcoind_reachable().await;
        
            if let Some(receipt) = self.issued_receipts
                .lock()
                .unwrap()
                .get(&tx.txid())
            {
                log::info!("Transaction already sent: {}", tx.txid());
                return *receipt;
            }

            log::info!("Pushing transaction to the network: {}", tx.txid());
            let send_raw_tx_option = self.bitcoin_cli
                .lock()
                .unwrap()
                .send_raw_transaction(tx);
            match send_raw_tx_option {
                Ok(_) => {
                    // Here the transaction could, potentially, have been in mempool before the current height.
                    // This shouldn't really matter though.
                    log::info!("Transaction successfully delivered: {}", tx.txid());
                    receipt = Some(ConfirmationStatus::InMempoolSince(
                        *self.block_height.lock().unwrap()
                    ));
                }
                Err(JsonRpcError(RpcError(rpcerr))) => match rpcerr.code {
                    // Since we're pushing a raw transaction to the network we can face several rejections
                    rpc_errors::RPC_VERIFY_REJECTED => {
                        log::error!("Transaction couldn't be broadcast. {:?}", rpcerr);
                        receipt = Some(ConfirmationStatus::Rejected(rpc_errors::RPC_VERIFY_REJECTED));
                    }
                    rpc_errors::RPC_VERIFY_ERROR => {
                        log::error!("Transaction couldn't be broadcast. {:?}", rpcerr);
                        receipt = Some(ConfirmationStatus::Rejected(rpc_errors::RPC_VERIFY_ERROR));
                    }
                    rpc_errors::RPC_VERIFY_ALREADY_IN_CHAIN => {
                        log::info!(
                            "Transaction is already in the blockchain: {}. Getting confirmation count",
                            tx.txid()
                        );

                        receipt = Some(ConfirmationStatus::ConfirmedIn(
                            self.get_tx_height(&tx.txid())
                                .await
                                .unwrap()
                            )
                        )
                    }
                    rpc_errors::RPC_DESERIALIZATION_ERROR => {
                        // Adding this here just for completeness. We should never end up here. The Carrier only sends txs handed by the Responder,
                        // who receives them from the Watcher, who checks that the tx can be properly deserialized.
                        log::info!("Transaction cannot be deserialized: {}", tx.txid());
                        receipt = Some(ConfirmationStatus::Rejected(rpc_errors::RPC_DESERIALIZATION_ERROR));
                    }
                    _ => {
                        // If something else happens (unlikely but possible) log it so we can treat it in future releases.
                        log::error!(
                            "Unexpected rpc error when calling sendrawtransaction: {:?}",
                            rpcerr
                        );
                        receipt = Some(ConfirmationStatus::Rejected(errors::UNKNOWN_JSON_RPC_EXCEPTION));
                    }
                },
                Err(JsonRpcError(TransportError(_))) => {
                    // Connection refused, bitcoind is down.
                    log::error!("Connection lost with bitcoind, retrying request when possible");
                    self.flag_bitcoind_unreachable();
                    continue_looping = true;
                }
                Err(e) => {
                    // TODO: This may need finer catching.
                    log::error!("Unexpected error when calling sendrawtransaction: {:?}", e);
                    receipt = Some(ConfirmationStatus::Rejected(errors::UNKNOWN_JSON_RPC_EXCEPTION));
                }
            };
        }

        self.issued_receipts
            .lock()
            .unwrap()
            .insert(tx.txid(), receipt.unwrap());

        receipt.unwrap()
    }

    /// Gets the block height at where a given [Transaction] was confirmed at (if any).
    async fn get_tx_height(&self, txid: &Txid) -> Option<u32> {
        if let Some(block_hash) = self.get_block_hash_for_tx(txid).await {
            self.get_block_height(&block_hash).await
        } else {
            None
        }
    }

    /// Queries the height of a given [Block](bitcoin::Block). Returns it if the block can be found. Returns [None] otherwise.
    async fn get_block_height(&self, block_hash: &BlockHash) -> Option<u32> {
        self.hang_until_bitcoind_reachable().await;
        
        let mut continue_looping = true;
        let mut block_height: Option<u32> = None;
        while continue_looping {
            // We only need to loop once unless we have a bitcoind connectivity
            // issue
            continue_looping = false;

            match self.bitcoin_cli
                .lock()
                .unwrap()
                .get_block_header_info(block_hash) 
            {
                Ok(header_data) => {
                    block_height = Some(header_data.height as u32)
                },
                Err(JsonRpcError(RpcError(rpcerr))) => match rpcerr.code {
                    rpc_errors::RPC_INVALID_ADDRESS_OR_KEY => {
                        log::info!("Block not found: {}", block_hash);
                    }
                    e => {
                        log::error!("Unexpected error code when calling getblockheader: {}", e);
                    }
                },
                Err(JsonRpcError(TransportError(_))) => {
                    // Connection refused, bitcoind is down.
                    log::error!("Connection lost with bitcoind, retrying request when possible");
                    self.flag_bitcoind_unreachable();
                    continue_looping = true;
                }
                // TODO: This may need finer catching.
                Err(e) => {
                    log::error!("Unexpected JSONRPCError when calling getblockheader: {}", e);
                }
            }
        }

        block_height
    }

    /// Gets the block hash where a given [Transaction] was confirmed at (if any).
    pub(crate) async fn get_block_hash_for_tx(&self, txid: &Txid) -> Option<BlockHash> {
        self.hang_until_bitcoind_reachable().await;

        let mut continue_looping = true;
        let mut block_hash: Option<BlockHash> = None;
        while continue_looping {
            // We only need to loop once unless we have a bitcoind connectivity
            // issue
            continue_looping = false;
            match self.bitcoin_cli
                .lock()
                .unwrap()
                .get_raw_transaction_info(txid, None) 
            {
                Ok(tx_data) => {
                    block_hash = tx_data.blockhash
                },
                Err(JsonRpcError(RpcError(rpcerr))) => match rpcerr.code {
                    rpc_errors::RPC_INVALID_ADDRESS_OR_KEY => {
                        log::info!("Transaction not found in mempool nor blockchain: {}", txid);
                    }
                    e => {
                        log::error!(
                            "Unexpected error code when calling getrawtransaction: {}",
                            e
                        );
                    }
                },
                Err(JsonRpcError(TransportError(_))) => {
                    // Connection refused, bitcoind is down.
                    log::error!("Connection lost with bitcoind, retrying request when possible");
                    self.flag_bitcoind_unreachable();
                    continue_looping = true;
                }
                // TODO: This may need finer catching.
                Err(e) => {
                    log::error!(
                        "Unexpected JSONRPCError when calling getrawtransaction: {}",
                        e
                    );
                }
            }
        }

        block_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_utils::{
        get_random_tx, start_server, BitcoindMock, MockOptions, START_HEIGHT, TX_HEX,
    };

    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::hex::FromHex;
    use bitcoincore_rpc::Auth;

    impl Carrier {
        // Helper function to access issued_receipts in tests
        pub(crate) fn get_issued_receipts(&self) 
            -> std::sync::MutexGuard<'_, HashMap<Txid, ConfirmationStatus>> 
        {
            self.issued_receipts.lock().unwrap()
        }

        // Helper function to access height in tests
        pub(crate) fn get_height(&self) -> u32 {
            *self.block_height.lock().unwrap()
        }

        // Helper function to access bitcoind_reachable in tests
        pub(crate) fn get_bitcoind_reachable(&self) -> Arc<(Mutex<bool>, Notify)> {
            self.bitcoind_reachable.clone()
        }

        // Helper function to update the bitcoin client in tests
        pub(crate) fn update_bitcoind_cli(&self, bitcoin_cli: BitcoindClient) {
            *self.bitcoin_cli.lock().unwrap() = bitcoin_cli;
        }
    }

    #[test]
    fn test_clear_receipts() {
        let bitcoind_mock = BitcoindMock::new(MockOptions::empty());
        let bitcoind_reachable = Arc::new((Mutex::new(true), Notify::new()));
        let bitcoin_cli = BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap();
        let start_height = START_HEIGHT as u32;
        start_server(bitcoind_mock);

        let carrier = Carrier::new(bitcoin_cli, bitcoind_reachable, start_height);
        {
            // Lets add some dummy data into the cache
            let mut issued_receipts = carrier.issued_receipts.lock().unwrap();
            for i in 0..10 {
                issued_receipts.insert(
                    get_random_tx().txid(),
                    ConfirmationStatus::ConfirmedIn(start_height - i),
                );
            }
        }

        // Check it empties on request
        assert!(!carrier
            .issued_receipts
            .lock()
            .unwrap()
            .is_empty());
        carrier.clear_receipts();
        assert!(carrier
            .issued_receipts
            .lock()
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn test_send_transaction_ok() {
        let bitcoind_mock = BitcoindMock::new(MockOptions::empty());
        let bitcoind_reachable = Arc::new((Mutex::new(true), Notify::new()));
        let bitcoin_cli = BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap();
        let start_height = START_HEIGHT as u32;
        start_server(bitcoind_mock);

        let carrier = Carrier::new(bitcoin_cli, bitcoind_reachable, start_height);
        let tx = deserialize::<Transaction>(&Vec::from_hex(TX_HEX).unwrap()).unwrap();
        let r = carrier.send_transaction(&tx).await;

        assert_eq!(r, ConfirmationStatus::InMempoolSince(start_height));

        // Check the receipt is on the cache
        assert_eq!(carrier
            .issued_receipts
            .lock()
            .unwrap()
            .get(&tx.txid())
            .unwrap(), 
            &r);
    }

    #[tokio::test]
    async fn test_send_transaction_verify_rejected() {
        let bitcoind_mock = BitcoindMock::new(MockOptions::with_error(
            rpc_errors::RPC_VERIFY_REJECTED as i64,
        ));
        let bitcoind_reachable = Arc::new((Mutex::new(true), Notify::new()));
        let bitcoin_cli = BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap();
        let start_height = START_HEIGHT as u32;
        start_server(bitcoind_mock);

        let carrier = Carrier::new(bitcoin_cli, bitcoind_reachable, start_height);
        let tx = deserialize::<Transaction>(&Vec::from_hex(TX_HEX).unwrap()).unwrap();
        let r = carrier.send_transaction(&tx).await;

        assert_eq!(
            r,
            ConfirmationStatus::Rejected(rpc_errors::RPC_VERIFY_REJECTED)
        );

        // Check the receipt is on the cache
        assert_eq!(carrier
            .issued_receipts
            .lock()
            .unwrap()
            .get(&tx.txid())
            .unwrap(), 
            &r);
    }

    #[tokio::test]
    async fn test_send_transaction_verify_error() {
        let bitcoind_mock =
            BitcoindMock::new(MockOptions::with_error(rpc_errors::RPC_VERIFY_ERROR as i64));
        let bitcoind_reachable = Arc::new((Mutex::new(true), Notify::new()));
        let bitcoin_cli = BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap();
        let start_height = START_HEIGHT as u32;
        start_server(bitcoind_mock);

        let carrier = Carrier::new(bitcoin_cli, bitcoind_reachable, start_height);
        let tx = deserialize::<Transaction>(&Vec::from_hex(TX_HEX).unwrap()).unwrap();
        let r = carrier.send_transaction(&tx).await;

        assert_eq!(
            r,
            ConfirmationStatus::Rejected(rpc_errors::RPC_VERIFY_ERROR)
        );

        // Check the receipt is on the cache
        assert_eq!(carrier
            .issued_receipts
            .lock()
            .unwrap()
            .get(&tx.txid())
            .unwrap(), 
            &r);
    }

    #[tokio::test]
    async fn test_send_transaction_verify_already_in_chain() {
        let bitcoind_mock = BitcoindMock::new(MockOptions::new(
            rpc_errors::RPC_VERIFY_ALREADY_IN_CHAIN as i64,
            BlockHash::default(),
            START_HEIGHT,
        ));
        let bitcoind_reachable = Arc::new((Mutex::new(true), Notify::new()));
        let bitcoin_cli = BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap();
        let start_height = START_HEIGHT as u32;
        start_server(bitcoind_mock);

        let carrier = Carrier::new(bitcoin_cli, bitcoind_reachable, start_height);
        let tx = deserialize::<Transaction>(&Vec::from_hex(TX_HEX).unwrap()).unwrap();
        let r = carrier.send_transaction(&tx).await;

        assert_eq!(r, ConfirmationStatus::ConfirmedIn(start_height));

        // Check the receipt is on the cache
        assert_eq!(carrier
            .issued_receipts
            .lock()
            .unwrap()
            .get(&tx.txid())
            .unwrap(), 
            &r);
    }

    #[tokio::test]
    async fn test_send_transaction_unexpected_error() {
        let bitcoind_mock =
            BitcoindMock::new(MockOptions::with_error(rpc_errors::RPC_MISC_ERROR as i64));
        let bitcoind_reachable = Arc::new((Mutex::new(true), Notify::new()));
        let bitcoin_cli = BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap();
        let start_height = START_HEIGHT as u32;
        start_server(bitcoind_mock);

        let carrier = Carrier::new(bitcoin_cli, bitcoind_reachable, start_height);
        let tx = deserialize::<Transaction>(&Vec::from_hex(TX_HEX).unwrap()).unwrap();
        let r = carrier.send_transaction(&tx).await;

        assert_eq!(
            r,
            ConfirmationStatus::Rejected(errors::UNKNOWN_JSON_RPC_EXCEPTION)
        );

        // Check the receipt is on the cache
        assert_eq!(carrier
            .issued_receipts
            .lock()
            .unwrap()
            .get(&tx.txid())
            .unwrap(),
            &r);
    }

    #[tokio::test]
    async fn test_send_transaction_connection_error() {
        // Try to connect to an offline bitcoind.
        let bitcoind_mock = BitcoindMock::new(MockOptions::empty());
        let bitcoind_reachable = Arc::new((Mutex::new(false), Notify::new()));
        let bitcoin_cli = BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap();
        let start_height = START_HEIGHT as u32;
        let carrier = Carrier::new(bitcoin_cli, bitcoind_reachable.clone(), start_height);

        let tx = deserialize::<Transaction>(&Vec::from_hex(TX_HEX).unwrap()).unwrap();
        let delay = std::time::Duration::new(3, 0);

        let bitcoind_reachable_clone = bitcoind_reachable.clone();
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let (reachable, notifier) = &*bitcoind_reachable_clone;
            *reachable.lock().unwrap() = true;
            notifier.notify_waiters();
        });

        let before = std::time::Instant::now();
        carrier.send_transaction(&tx).await;

        // Check the request has hanged for ~delay and bitcoind is now
        // reachable (even though this test would not complete if 
        // bitcoind_reachable != true)
        assert_eq!(
            (std::time::Instant::now() - before).as_secs(),
            delay.as_secs()
        );
        assert!(*bitcoind_reachable.0.lock().unwrap());
    }

    #[tokio::test]
    async fn test_get_tx_height_ok() {
        let target_height = 21;
        let bitcoind_mock =
            BitcoindMock::new(MockOptions::with_block(BlockHash::default(), target_height));
        let bitcoind_reachable = Arc::new((Mutex::new(true), Notify::new()));
        let bitcoin_cli = BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap();
        let start_height = START_HEIGHT as u32;
        start_server(bitcoind_mock);

        let carrier = Carrier::new(bitcoin_cli, bitcoind_reachable, start_height);
        let tx = deserialize::<Transaction>(&Vec::from_hex(TX_HEX).unwrap()).unwrap();
        assert_eq!(
            carrier.get_tx_height(&tx.txid()).await,
            Some(target_height as u32)
        );
    }

    #[tokio::test]
    async fn test_get_tx_height_not_found() {
        // Hee we are not testing the case where the block hash is unknown (which will also return None). This is because we only
        // learn block hashes from bitcoind, and once a block is known, it cannot disappear (ir can be disconnected, but not banish).
        let bitcoind_mock = BitcoindMock::new(MockOptions::empty());
        let bitcoind_reachable = Arc::new((Mutex::new(true), Notify::new()));
        let bitcoin_cli = BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap();
        let start_height = START_HEIGHT as u32;
        start_server(bitcoind_mock);

        let carrier = Carrier::new(bitcoin_cli, bitcoind_reachable, start_height);
        let tx = deserialize::<Transaction>(&Vec::from_hex(TX_HEX).unwrap()).unwrap();
        assert_eq!(carrier.get_tx_height(&tx.txid()).await, None);
    }

    #[tokio::test]
    async fn test_get_block_height_ok() {
        let target_height = 21;
        let block_hash = BlockHash::default();
        let bitcoind_mock = BitcoindMock::new(MockOptions::with_block(block_hash, target_height));
        let bitcoind_reachable = Arc::new((Mutex::new(true), Notify::new()));
        let bitcoin_cli = BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap();
        let start_height = START_HEIGHT as u32;
        start_server(bitcoind_mock);

        let carrier = Carrier::new(bitcoin_cli, bitcoind_reachable, start_height);
        assert_eq!(
            carrier.get_block_height(&block_hash).await,
            Some(target_height as u32)
        );
    }

    #[tokio::test]
    async fn test_get_block_height_not_found() {
        let bitcoind_mock = BitcoindMock::new(MockOptions::empty());
        let bitcoind_reachable = Arc::new((Mutex::new(true), Notify::new()));
        let bitcoin_cli = BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap();
        let start_height = START_HEIGHT as u32;
        start_server(bitcoind_mock);

        let carrier = Carrier::new(bitcoin_cli, bitcoind_reachable, start_height);
        assert_eq!(carrier.get_block_height(&BlockHash::default()).await, None);
    }

    #[tokio::test]
    async fn test_get_block_hash_for_tx_ok() {
        let block_hash = BlockHash::default();
        let bitcoind_mock = BitcoindMock::new(MockOptions::with_block(block_hash, 21));
        let bitcoind_reachable = Arc::new((Mutex::new(true), Notify::new()));
        let bitcoin_cli = BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap();
        let start_height = START_HEIGHT as u32;
        start_server(bitcoind_mock);

        let tx = deserialize::<Transaction>(&Vec::from_hex(TX_HEX).unwrap()).unwrap();
        let carrier = Carrier::new(bitcoin_cli, bitcoind_reachable, start_height);
        assert_eq!(carrier.get_block_hash_for_tx(&tx.txid()).await, Some(block_hash));
    }

    #[tokio::test]
    async fn test_get_block_hash_for_tx_not_found() {
        let bitcoind_mock = BitcoindMock::new(MockOptions::empty());
        let bitcoind_reachable = Arc::new((Mutex::new(true), Notify::new()));
        let bitcoin_cli = BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap();
        let start_height = START_HEIGHT as u32;
        start_server(bitcoind_mock);

        let tx = deserialize::<Transaction>(&Vec::from_hex(TX_HEX).unwrap()).unwrap();
        let carrier = Carrier::new(bitcoin_cli, bitcoind_reachable, start_height);
        assert_eq!(carrier.get_block_hash_for_tx(&tx.txid()).await, None);
    }
}
