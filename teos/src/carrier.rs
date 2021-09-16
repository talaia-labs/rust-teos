use std::collections::HashMap;
use std::sync::Arc;

use crate::errors;
use crate::rpc_errors;

use bitcoincore_rpc::bitcoin::{Transaction, Txid};
use bitcoincore_rpc::{
    jsonrpc::error::Error::Rpc as RpcError, Client as BitcoindClient,
    Error::JsonRpc as JsonRpcError, RpcApi,
};

#[derive(Clone, Debug)]
pub struct Receipt {
    delivered: bool,
    confirmations: Option<u32>,
    reason: Option<i32>,
}

impl Receipt {
    fn new(delivered: bool, confirmations: Option<u32>, reason: Option<i32>) -> Self {
        Receipt {
            delivered,
            confirmations,
            reason,
        }
    }
}

pub struct Carrier {
    bitcoin_cli: Arc<BitcoindClient>,
    issued_receipts: HashMap<Txid, Receipt>,
}

impl Carrier {
    pub fn new(bitcoin_cli: Arc<BitcoindClient>) -> Self {
        Carrier {
            bitcoin_cli,
            issued_receipts: HashMap::new(),
        }
    }

    pub async fn send_transaction(&mut self, tx: &Transaction) -> Receipt {
        log::info!("Pushing transaction to the network: {}", tx.txid());
        let receipt: Receipt;

        match self.bitcoin_cli.send_raw_transaction(tx) {
            Ok(_) => {
                log::info!("Transaction successfully delivered: {}", tx.txid());
                receipt = Receipt::new(true, Some(0), None);
            }
            Err(JsonRpcError(RpcError(rpcerr))) => match rpcerr.code {
                // Since we're pushing a raw transaction to the network we can face several rejections
                rpc_errors::RPC_VERIFY_REJECTED => {
                    log::error!("Transaction couldn't be broadcast.  {:?}", rpcerr);
                    receipt = Receipt::new(false, Some(0), Some(rpc_errors::RPC_VERIFY_REJECTED))
                }
                rpc_errors::RPC_VERIFY_ERROR => {
                    log::error!("Transaction couldn't be broadcast.  {:?}", rpcerr);
                    receipt = Receipt::new(false, Some(0), Some(rpc_errors::RPC_VERIFY_ERROR))
                }
                rpc_errors::RPC_VERIFY_ALREADY_IN_CHAIN => {
                    log::info!(
                        "Transaction is already in the blockchain: {}. Getting confirmation count",
                        tx.txid()
                    );

                    // TODO: Get confirmation count from bitcoind. Currently `get_transaction` builds a transaction but it has no confirmation
                    // field. Another method may be needed for this.
                    // FIXME: Update the confirmation count here
                    receipt = Receipt::new(true, Some(0), None)
                }
                rpc_errors::RPC_DESERIALIZATION_ERROR => {
                    // Adding this here just for completeness. We should never end up here. The Carrier only sends txs handed by the Responder,
                    // who receives them from the Watcher, who checks that the tx can be properly deserialized.
                    log::info!("Transaction cannot be deserialized: {}", tx.txid());
                    receipt = Receipt::new(false, None, Some(rpc_errors::RPC_DESERIALIZATION_ERROR))
                }
                _ => {
                    // If something else happens (unlikely but possible) log it so we can treat it in future releases
                    log::error!(
                        "Unexpected rpc error when calling sendrawtransaction: {:?}",
                        rpcerr
                    );
                    receipt = Receipt::new(false, None, Some(errors::UNKNOWN_JSON_RPC_EXCEPTION))
                }
            },
            Err(e) => {
                {
                    // FIXME: Only logging for now. This needs finer catching. e.g. Connection errors need to be handled here
                    log::error!("Unexpected error when calling sendrawtransaction: {:?}", e);
                    receipt = Receipt::new(false, None, None)
                }
            }
        }

        self.issued_receipts.insert(tx.txid(), receipt.clone());
        receipt
    }

    pub async fn get_transaction(&self, txid: &Txid) -> Option<Transaction> {
        match self.bitcoin_cli.get_raw_transaction(txid, None) {
            Ok(tx) => Some(tx),
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
            // TODO: This needs finer catching. e.g. Connection errors need to be handled here
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

// FIXME: This needs fixing. Tests make sense but the response has to contain the seed sent by the request, otherwise the rpc client rejects the response.
// Already contacted the httpmock devs regarding this to see if there is any solution.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{TXID_HEX, TX_HEX};
    use bitcoincore_rpc::bitcoin::consensus::{deserialize, serialize};
    use bitcoincore_rpc::bitcoin::hashes::hex::FromHex;
    use bitcoincore_rpc::Auth;
    use httpmock::prelude::*;
    use serde_json;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_send_transaction_ok() {
        let server = MockServer::start();
        let txid_mock = server.mock(|when, then| {
            when.method(POST);
            then.status(200)
                .header("content-type", "application/json")
                .body(serde_json::json!({ "id": TXID_HEX }).to_string());
        });

        let bitcoin_cli = Arc::new(BitcoindClient::new(server.base_url(), Auth::None).unwrap());
        let mut carrier = Carrier::new(bitcoin_cli);
        let tx: Transaction = deserialize(&Vec::from_hex(TX_HEX).unwrap()).unwrap();
        let r = carrier.send_transaction(&tx).await;

        txid_mock.assert();
        assert!(r.delivered);
        assert_eq!(r.confirmations, Some(0));
        assert_eq!(r.reason, None);
    }

    #[tokio::test]
    async fn test_send_transaction_verify_rejected() {
        let server = MockServer::start();
        let txid_mock = server.mock(|when, then| {
            when.method(POST);
            then.status(200)
                .header("content-type", "application/json")
                .body(serde_json::json!({ "error": rpc_errors::RPC_VERIFY_REJECTED }).to_string());
        });

        let bitcoin_cli = Arc::new(BitcoindClient::new(server.base_url(), Auth::None).unwrap());
        let mut carrier = Carrier::new(bitcoin_cli);
        let tx: Transaction = deserialize(&Vec::from_hex(TX_HEX).unwrap()).unwrap();
        let r = carrier.send_transaction(&tx).await;

        txid_mock.assert();
        assert!(!r.delivered);
        assert_eq!(r.confirmations, None);
        assert_eq!(r.reason, Some(rpc_errors::RPC_VERIFY_REJECTED));
    }

    #[tokio::test]
    async fn test_send_transaction_verify_error() {
        let server = MockServer::start();
        let txid_mock = server.mock(|when, then| {
            when.method(POST);
            then.status(200)
                .header("content-type", "application/json")
                .body(serde_json::json!({ "error": rpc_errors::RPC_VERIFY_ERROR }).to_string());
        });

        let bitcoin_cli = Arc::new(BitcoindClient::new(server.base_url(), Auth::None).unwrap());
        let mut carrier = Carrier::new(bitcoin_cli);
        let tx: Transaction = deserialize(&Vec::from_hex(TX_HEX).unwrap()).unwrap();
        let r = carrier.send_transaction(&tx).await;

        txid_mock.assert();
        assert!(!r.delivered);
        assert_eq!(r.confirmations, None);
        assert_eq!(r.reason, Some(rpc_errors::RPC_VERIFY_ERROR));
    }

    #[tokio::test]
    async fn test_send_transaction_verify_already_in_chain() {
        let server = MockServer::start();
        let txid_mock = server.mock(|when, then| {
            when.method(POST);
            then.status(200)
                .header("content-type", "application/json")
                .body(
                    serde_json::json!({ "error": rpc_errors::RPC_VERIFY_ALREADY_IN_CHAIN })
                        .to_string(),
                );
        });

        let bitcoin_cli = Arc::new(BitcoindClient::new(server.base_url(), Auth::None).unwrap());
        let mut carrier = Carrier::new(bitcoin_cli);
        let tx: Transaction = deserialize(&Vec::from_hex(TX_HEX).unwrap()).unwrap();
        let r = carrier.send_transaction(&tx).await;

        txid_mock.assert();
        assert!(r.delivered);
        // FIXME: This is temporary. Confirmations need to be properly set.
        assert_eq!(r.confirmations, Some(0));
        assert_eq!(r.reason, None);
    }

    #[tokio::test]
    async fn test_send_transaction_unexpected_error() {
        let server = MockServer::start();

        // Reply with an unexpected rpc error (any of the non accounted for should do)
        let txid_mock = server.mock(|when, then| {
            when.method(POST);
            then.status(200)
                .header("content-type", "application/json")
                .body(serde_json::json!({ "error": rpc_errors::RPC_MISC_ERROR }).to_string());
        });

        let bitcoin_cli = Arc::new(BitcoindClient::new(server.base_url(), Auth::None).unwrap());
        let mut carrier = Carrier::new(bitcoin_cli);
        let tx: Transaction = deserialize(&Vec::from_hex(TX_HEX).unwrap()).unwrap();
        let r = carrier.send_transaction(&tx).await;

        txid_mock.assert();
        assert!(!r.delivered);
        assert_eq!(r.confirmations, None);
        assert_eq!(r.reason, Some(errors::UNKNOWN_JSON_RPC_EXCEPTION));
    }

    #[tokio::test]
    async fn test_send_transaction_connection_error() {
        MockServer::start();

        // Try to connect to an nonexisting server.
        let bitcoin_cli =
            Arc::new(BitcoindClient::new("http://localhost:1234".to_string(), Auth::None).unwrap());
        let mut carrier = Carrier::new(bitcoin_cli);
        let tx: Transaction = deserialize(&Vec::from_hex(TX_HEX).unwrap()).unwrap();
        let r = carrier.send_transaction(&tx).await;

        assert!(!r.delivered);
        assert_eq!(r.confirmations, None);
        assert_eq!(r.reason, None);
    }

    #[tokio::test]
    async fn get_transaction_ok() {
        let server = MockServer::start();
        let txid_mock = server.mock(|when, then| {
            when.method(POST);
            then.status(200)
                .header("content-type", "application/json")
                .body(serde_json::json!({ "result": TX_HEX }).to_string());
        });

        let bitcoin_cli = Arc::new(BitcoindClient::new(server.base_url(), Auth::None).unwrap());
        let carrier = Carrier::new(bitcoin_cli);
        let txid = Txid::from_hex(TXID_HEX).unwrap();
        let r = carrier.get_transaction(&txid).await;

        txid_mock.assert();
        assert_eq!(serialize(&r.unwrap()), Vec::from_hex(TX_HEX).unwrap());
    }

    #[tokio::test]
    async fn get_transaction_not_found() {
        let server = MockServer::start();
        let txid_mock = server.mock(|when, then| {
            when.method(POST);
            then.status(200)
                .header("content-type", "application/json")
                .body(
                    serde_json::json!({ "error": rpc_errors::RPC_INVALID_ADDRESS_OR_KEY })
                        .to_string(),
                );
        });

        let bitcoin_cli = Arc::new(BitcoindClient::new(server.base_url(), Auth::None).unwrap());
        let carrier = Carrier::new(bitcoin_cli);
        let txid = Txid::from_hex(TXID_HEX).unwrap();
        let r = carrier.get_transaction(&txid).await;

        txid_mock.assert();
        assert_eq!(r, None);
    }

    #[tokio::test]
    async fn get_transaction_connection_error() {
        MockServer::start();

        // Try to connect to an nonexisting server.
        let bitcoin_cli =
            Arc::new(BitcoindClient::new("http://localhost:1234".to_string(), Auth::None).unwrap());
        let carrier = Carrier::new(bitcoin_cli);
        let txid = Txid::from_hex(TXID_HEX).unwrap();
        let r = carrier.get_transaction(&txid).await;

        assert_eq!(r, None);
    }
}
