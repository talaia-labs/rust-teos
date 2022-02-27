//! Logic related to the Carrier, the component in charge or sending/requesting transaction data from/to `bitcoind`.

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};

use crate::errors;
use crate::rpc_errors;

use bitcoin::{BlockHash, Transaction, Txid};
use bitcoincore_rpc::{
    jsonrpc::error::Error::Rpc as RpcError, jsonrpc::error::Error::Transport as TransportError,
    Client as BitcoindClient, Error::JsonRpc as JsonRpcError, RpcApi,
};

/// Contains data regarding an attempt of broadcasting a transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeliveryReceipt {
    /// Whether the [Transaction] has been accepted by the network.
    delivered: bool,
    /// The height where the [Transaction] got confirmed. It may be [Some(x)] if the transaction was already broadcasted by someone else.
    height: Option<u32>,
    /// Rejection reason. Only present if the [Transaction] is rejected.
    reason: Option<i32>,
}

impl DeliveryReceipt {
    /// Creates a new [DeliveryReceipt] instance.
    pub fn new(delivered: bool, height: Option<u32>, reason: Option<i32>) -> Self {
        DeliveryReceipt {
            delivered,
            height,
            reason,
        }
    }

    /// Getter for [self.delivered](Self::delivered).
    pub fn delivered(&self) -> bool {
        self.delivered
    }

    /// Getter for [self.height](Self::height).
    pub fn height(&self) -> Option<u32> {
        self.height
    }

    /// Getter for [self.reason](Self::reason).
    pub fn reason(&self) -> &Option<i32> {
        &self.reason
    }
}

/// Component in charge of the interaction with Bitcoind by sending / querying transactions via RPC.
#[derive(Debug)]
pub struct Carrier {
    /// The underlying bitcoin client used by the [Carrier].
    bitcoin_cli: Arc<BitcoindClient>,
    /// A flag that indicates wether bitcoind is reachable or not.
    bitcoind_reachable: Arc<(Mutex<bool>, Condvar)>,
    /// A map of receipts already issued by the [Carrier].
    /// Used to prevent potentially re-sending the same transaction over and over.
    issued_receipts: HashMap<Txid, DeliveryReceipt>,
}

impl Carrier {
    /// Creates a new [Carrier] instance.
    pub fn new(
        bitcoin_cli: Arc<BitcoindClient>,
        bitcoind_reachable: Arc<(Mutex<bool>, Condvar)>,
    ) -> Self {
        Carrier {
            bitcoin_cli,
            bitcoind_reachable,
            issued_receipts: HashMap::new(),
        }
    }

    /// Clears the receipts cached by the [Carrier]. Should be called periodically to prevent it from
    /// growing unbounded.
    pub(crate) fn clear_receipts(&mut self) {
        if !self.issued_receipts.is_empty() {
            self.issued_receipts = HashMap::new()
        }
    }

    /// Hangs the process until bitcoind is reachable. If bitcoind is already reachable it just passes trough.
    fn hang_until_bitcoind_reachable(&self) {
        let (lock, notifier) = &*self.bitcoind_reachable;
        let mut reachable = lock.lock().unwrap();
        while !*reachable {
            reachable = notifier.wait(reachable).unwrap();
        }
    }

    /// Flags bitcoind as unreachable.
    fn flag_bitcoind_unreachable(&self) {
        let (lock, _) = &*self.bitcoind_reachable;
        let mut reachable = lock.lock().unwrap();
        *reachable = false;
    }

    /// Sends a [Transaction] to the Bitcoin network.
    ///
    /// Returns a [DeliveryReceipt] indicating whether the transaction could be delivered or not.
    pub(crate) fn send_transaction(&mut self, tx: &Transaction) -> DeliveryReceipt {
        self.hang_until_bitcoind_reachable();

        if let Some(receipt) = self.issued_receipts.get(&tx.txid()) {
            log::info!("Transaction already sent: {}", tx.txid());
            return receipt.clone();
        }

        log::info!("Pushing transaction to the network: {}", tx.txid());
        let receipt: DeliveryReceipt;

        match self.bitcoin_cli.send_raw_transaction(tx) {
            Ok(_) => {
                log::info!("Transaction successfully delivered: {}", tx.txid());
                receipt = DeliveryReceipt::new(true, None, None);
            }
            Err(JsonRpcError(RpcError(rpcerr))) => match rpcerr.code {
                // Since we're pushing a raw transaction to the network we can face several rejections
                rpc_errors::RPC_VERIFY_REJECTED => {
                    log::error!("Transaction couldn't be broadcast. {:?}", rpcerr);
                    receipt =
                        DeliveryReceipt::new(false, None, Some(rpc_errors::RPC_VERIFY_REJECTED))
                }
                rpc_errors::RPC_VERIFY_ERROR => {
                    log::error!("Transaction couldn't be broadcast. {:?}", rpcerr);
                    receipt = DeliveryReceipt::new(false, None, Some(rpc_errors::RPC_VERIFY_ERROR))
                }
                rpc_errors::RPC_VERIFY_ALREADY_IN_CHAIN => {
                    log::info!(
                        "Transaction is already in the blockchain: {}. Getting confirmation count",
                        tx.txid()
                    );

                    receipt = DeliveryReceipt::new(true, self.get_tx_height(&tx.txid()), None)
                }
                rpc_errors::RPC_DESERIALIZATION_ERROR => {
                    // Adding this here just for completeness. We should never end up here. The Carrier only sends txs handed by the Responder,
                    // who receives them from the Watcher, who checks that the tx can be properly deserialized.
                    log::info!("Transaction cannot be deserialized: {}", tx.txid());
                    receipt = DeliveryReceipt::new(
                        false,
                        None,
                        Some(rpc_errors::RPC_DESERIALIZATION_ERROR),
                    )
                }
                _ => {
                    // If something else happens (unlikely but possible) log it so we can treat it in future releases
                    log::error!(
                        "Unexpected rpc error when calling sendrawtransaction: {:?}",
                        rpcerr
                    );
                    receipt =
                        DeliveryReceipt::new(false, None, Some(errors::UNKNOWN_JSON_RPC_EXCEPTION))
                }
            },
            Err(JsonRpcError(TransportError(_))) => {
                // Connection refused, bitcoind is down
                log::error!("Connection lost with bitcoind, retrying request when possible");
                self.flag_bitcoind_unreachable();
                receipt = self.send_transaction(tx);
            }
            Err(e) => {
                // TODO: This may need finer catching.
                log::error!("Unexpected error when calling sendrawtransaction: {:?}", e);
                receipt = DeliveryReceipt::new(false, None, None)
            }
        }

        self.issued_receipts.insert(tx.txid(), receipt.clone());
        receipt
    }

    /// Gets the block height at where a given [Transaction] was confirmed at (if any).
    fn get_tx_height(&self, txid: &Txid) -> Option<u32> {
        if let Some(block_hash) = self.get_block_hash(txid) {
            self.get_block_height(&block_hash)
        } else {
            None
        }
    }

    /// Queries the height of a given [Block](bitcoin::Block). Returns it if the block can be found. Returns [None] otherwise.
    fn get_block_height(&self, block_hash: &BlockHash) -> Option<u32> {
        self.hang_until_bitcoind_reachable();

        match self.bitcoin_cli.get_block_header_info(block_hash) {
            Ok(header_data) => Some(header_data.height as u32),
            Err(JsonRpcError(RpcError(rpcerr))) => match rpcerr.code {
                rpc_errors::RPC_INVALID_ADDRESS_OR_KEY => {
                    log::info!("Block not found: {}", block_hash);
                    None
                }
                e => {
                    log::error!("Unexpected error code when calling getblockheader: {}", e);
                    None
                }
            },
            Err(JsonRpcError(TransportError(_))) => {
                // Connection refused, bitcoind is down
                log::error!("Connection lost with bitcoind, retrying request when possible");
                self.flag_bitcoind_unreachable();
                self.get_block_height(block_hash)
            }
            // TODO: This may need finer catching.
            Err(e) => {
                log::error!("Unexpected JSONRPCError when calling getblockheader: {}", e);
                None
            }
        }
    }

    /// Gets the block hash where a given [Transaction] was confirmed at (if any).
    fn get_block_hash(&self, txid: &Txid) -> Option<BlockHash> {
        self.hang_until_bitcoind_reachable();

        match self.bitcoin_cli.get_raw_transaction_info(txid, None) {
            Ok(tx_data) => tx_data.blockhash,
            Err(JsonRpcError(RpcError(rpcerr))) => match rpcerr.code {
                rpc_errors::RPC_INVALID_ADDRESS_OR_KEY => {
                    log::info!("Transaction not found in mempool nor blockchain: {}", txid);
                    None
                }
                e => {
                    log::error!(
                        "Unexpected error code when calling getrawtransaction: {}",
                        e
                    );
                    None
                }
            },
            Err(JsonRpcError(TransportError(_))) => {
                // Connection refused, bitcoind is down
                log::error!("Connection lost with bitcoind, retrying request when possible");
                self.flag_bitcoind_unreachable();
                self.get_block_hash(txid)
            }
            // TODO: This may need finer catching.
            Err(e) => {
                log::error!(
                    "Unexpected JSONRPCError when calling getrawtransaction: {}",
                    e
                );
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    use crate::test_utils::{
        get_random_tx, start_server, BitcoindMock, MockOptions, START_HEIGHT, TX_HEX,
    };

    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::hex::FromHex;
    use bitcoincore_rpc::Auth;

    impl Carrier {
        // Helper function to access issued_receipts in tests
        pub(crate) fn get_issued_receipts(&mut self) -> &mut HashMap<Txid, DeliveryReceipt> {
            &mut self.issued_receipts
        }
    }

    #[test]
    fn test_clear_receipts() {
        let bitcoind_mock = BitcoindMock::new(MockOptions::empty());
        let bitcoind_reachable = Arc::new((Mutex::new(true), Condvar::new()));
        let bitcoin_cli = Arc::new(BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap());
        start_server(bitcoind_mock);

        let mut carrier = Carrier::new(bitcoin_cli, bitcoind_reachable);

        // Lets add some dummy data into the cache
        for _ in 0..10 {
            carrier.issued_receipts.insert(
                get_random_tx().txid(),
                DeliveryReceipt::new(true, None, None),
            );
        }

        // Check it empties on request
        assert!(!carrier.issued_receipts.is_empty());
        carrier.clear_receipts();
        assert!(carrier.issued_receipts.is_empty());
    }

    #[test]
    fn test_send_transaction_ok() {
        let bitcoind_mock = BitcoindMock::new(MockOptions::empty());
        let bitcoind_reachable = Arc::new((Mutex::new(true), Condvar::new()));
        let bitcoin_cli = Arc::new(BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap());
        start_server(bitcoind_mock);

        let mut carrier = Carrier::new(bitcoin_cli, bitcoind_reachable);
        let tx = deserialize::<Transaction>(&Vec::from_hex(TX_HEX).unwrap()).unwrap();
        let r = carrier.send_transaction(&tx);

        assert!(r.delivered);
        assert!(r.height.is_none());
        assert!(r.reason.is_none());

        // Check the receipt is on the cache
        assert_eq!(carrier.issued_receipts.get(&tx.txid()).unwrap(), &r);
    }

    #[test]
    fn test_send_transaction_verify_rejected() {
        let bitcoind_mock = BitcoindMock::new(MockOptions::with_error(
            rpc_errors::RPC_VERIFY_REJECTED as i64,
        ));
        let bitcoind_reachable = Arc::new((Mutex::new(true), Condvar::new()));
        let bitcoin_cli = Arc::new(BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap());
        start_server(bitcoind_mock);

        let mut carrier = Carrier::new(bitcoin_cli, bitcoind_reachable);
        let tx = deserialize::<Transaction>(&Vec::from_hex(TX_HEX).unwrap()).unwrap();
        let r = carrier.send_transaction(&tx);

        assert!(!r.delivered);
        assert!(r.height.is_none());
        assert_eq!(r.reason, Some(rpc_errors::RPC_VERIFY_REJECTED));

        // Check the receipt is on the cache
        assert_eq!(carrier.issued_receipts.get(&tx.txid()).unwrap(), &r);
    }

    #[test]
    fn test_send_transaction_verify_error() {
        let bitcoind_mock =
            BitcoindMock::new(MockOptions::with_error(rpc_errors::RPC_VERIFY_ERROR as i64));
        let bitcoind_reachable = Arc::new((Mutex::new(true), Condvar::new()));
        let bitcoin_cli = Arc::new(BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap());
        start_server(bitcoind_mock);

        let mut carrier = Carrier::new(bitcoin_cli, bitcoind_reachable);
        let tx = deserialize::<Transaction>(&Vec::from_hex(TX_HEX).unwrap()).unwrap();
        let r = carrier.send_transaction(&tx);

        assert!(!r.delivered);
        assert!(r.height.is_none());
        assert_eq!(r.reason, Some(rpc_errors::RPC_VERIFY_ERROR));

        // Check the receipt is on the cache
        assert_eq!(carrier.issued_receipts.get(&tx.txid()).unwrap(), &r);
    }

    #[test]
    fn test_send_transaction_verify_already_in_chain() {
        let bitcoind_mock = BitcoindMock::new(MockOptions::new(
            rpc_errors::RPC_VERIFY_ALREADY_IN_CHAIN as i64,
            BlockHash::default(),
            START_HEIGHT,
        ));
        let bitcoind_reachable = Arc::new((Mutex::new(true), Condvar::new()));
        let bitcoin_cli = Arc::new(BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap());
        start_server(bitcoind_mock);

        let mut carrier = Carrier::new(bitcoin_cli, bitcoind_reachable);
        let tx = deserialize::<Transaction>(&Vec::from_hex(TX_HEX).unwrap()).unwrap();
        let r = carrier.send_transaction(&tx);

        assert!(r.delivered);
        assert_eq!(r.height, Some(START_HEIGHT as u32));
        assert_eq!(r.reason, None);

        // Check the receipt is on the cache
        assert_eq!(carrier.issued_receipts.get(&tx.txid()).unwrap(), &r);
    }

    #[test]
    fn test_send_transaction_unexpected_error() {
        let bitcoind_mock =
            BitcoindMock::new(MockOptions::with_error(rpc_errors::RPC_MISC_ERROR as i64));
        let bitcoind_reachable = Arc::new((Mutex::new(true), Condvar::new()));
        let bitcoin_cli = Arc::new(BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap());
        start_server(bitcoind_mock);

        let mut carrier = Carrier::new(bitcoin_cli, bitcoind_reachable);
        let tx = deserialize::<Transaction>(&Vec::from_hex(TX_HEX).unwrap()).unwrap();
        let r = carrier.send_transaction(&tx);

        assert!(!r.delivered);
        assert!(r.height.is_none());
        assert_eq!(r.reason, Some(errors::UNKNOWN_JSON_RPC_EXCEPTION));

        // Check the receipt is on the cache
        assert_eq!(carrier.issued_receipts.get(&tx.txid()).unwrap(), &r);
    }

    #[test]
    fn test_send_transaction_connection_error() {
        // Try to connect to an offline bitcoind.
        let bitcoind_mock = BitcoindMock::new(MockOptions::empty());
        let bitcoind_reachable = Arc::new((Mutex::new(false), Condvar::new()));
        let bitcoin_cli = Arc::new(BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap());
        let mut carrier = Carrier::new(bitcoin_cli, bitcoind_reachable.clone());

        let tx = deserialize::<Transaction>(&Vec::from_hex(TX_HEX).unwrap()).unwrap();
        let delay = std::time::Duration::new(3, 0);

        thread::spawn(move || {
            thread::sleep(delay);
            let (reachable, notifier) = &*bitcoind_reachable;
            *reachable.lock().unwrap() = true;
            notifier.notify_all();
        });

        let before = std::time::Instant::now();
        carrier.send_transaction(&tx);

        // Check the request has hanged for ~delay
        assert_eq!(
            (std::time::Instant::now() - before).as_secs(),
            delay.as_secs()
        );
    }
}
