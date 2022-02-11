//! Logic related to the BitcoindClient, an simple bitcoind client implementation.

// This is an adaptation of a bitcoind client with the minimal functionality required by the tower
// The original piece of software can be found at https://github.com/lightningdevkit/ldk-sample/blob/main/src/bitcoind_client.rs

/* This file is licensed under either of
 *  Apache License, Version 2.0, (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0) or
 *  MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)
 * at your option.
*/

use futures::executor::block_on;
use std::sync::Arc;
use tokio::sync::Mutex;

use bitcoin::base64;
use bitcoin::hash_types::{BlockHash, Txid};
use bitcoin::hashes::hex::ToHex;
use bitcoin::{Block, Transaction};
use lightning::util::ser::Writeable;
use lightning_block_sync::http::HttpEndpoint;
use lightning_block_sync::rpc::RpcClient;
use lightning_block_sync::{AsyncBlockSourceResult, BlockHeaderData, BlockSource};

/// A simple implementation of a bitcoind client (`bitcoin-cli`) with the minimal functionality required by the tower.
pub struct BitcoindClient<'a> {
    /// The underlying RPC client.
    bitcoind_rpc_client: Arc<Mutex<RpcClient>>,
    /// The hostname to connect to.
    host: &'a str,
    /// The port to connect to.
    port: u16,
    /// The RPC user `bitcoind` is configured with.
    rpc_user: &'a str,
    /// The RPC password for the given user.
    rpc_password: &'a str,
}

impl BlockSource for &BitcoindClient<'_> {
    /// Gets a block header given its hash.
    fn get_header<'a>(
        &'a mut self,
        header_hash: &'a BlockHash,
        height_hint: Option<u32>,
    ) -> AsyncBlockSourceResult<'a, BlockHeaderData> {
        Box::pin(async move {
            let mut rpc = self.bitcoind_rpc_client.lock().await;
            rpc.get_header(header_hash, height_hint).await
        })
    }

    /// Gets a block given its hash.
    fn get_block<'a>(
        &'a mut self,
        header_hash: &'a BlockHash,
    ) -> AsyncBlockSourceResult<'a, Block> {
        Box::pin(async move {
            let mut rpc = self.bitcoind_rpc_client.lock().await;
            rpc.get_block(header_hash).await
        })
    }

    /// Get the best block known by our node.
    fn get_best_block<'a>(&'a mut self) -> AsyncBlockSourceResult<(BlockHash, Option<u32>)> {
        Box::pin(async move {
            let mut rpc = self.bitcoind_rpc_client.lock().await;
            rpc.get_best_block().await
        })
    }
}

impl<'a> BitcoindClient<'a> {
    /// Creates a new [BitcoindClient] instance.
    pub async fn new(
        host: &'a str,
        port: u16,
        rpc_user: &'a str,
        rpc_password: &'a str,
    ) -> std::io::Result<BitcoindClient<'a>> {
        let http_endpoint = HttpEndpoint::for_host(host.to_owned()).with_port(port);
        let rpc_credentials = base64::encode(&format!("{}:{}", rpc_user, rpc_password));
        let bitcoind_rpc_client = RpcClient::new(&rpc_credentials, http_endpoint)?;

        let client = Self {
            bitcoind_rpc_client: Arc::new(Mutex::new(bitcoind_rpc_client)),
            host,
            port,
            rpc_user,
            rpc_password,
        };

        // Test that bitcoind is reachable
        match block_on(client.get_best_block_hash_and_height()) {
            Ok(_) => Ok(client),
            Err(e) => Err(e),
        }
    }

    /// Gets a fresh RPC client.
    pub fn get_new_rpc_client(&self) -> std::io::Result<RpcClient> {
        let http_endpoint = HttpEndpoint::for_host(self.host.to_owned()).with_port(self.port);
        let rpc_credentials = base64::encode(&format!("{}:{}", self.rpc_user, self.rpc_password));
        RpcClient::new(&rpc_credentials, http_endpoint)
    }

    /// Gets the hash of the chain tip and its height.
    pub async fn get_best_block_hash_and_height(
        &self,
    ) -> Result<(BlockHash, Option<u32>), std::io::Error> {
        let mut rpc = self.bitcoind_rpc_client.lock().await;
        rpc.call_method::<(BlockHash, Option<u32>)>("getblockchaininfo", &vec![])
            .await
    }

    /// Sends a transaction to the network.
    pub async fn send_raw_transaction(&self, raw_tx: &Transaction) -> Result<Txid, std::io::Error> {
        let mut rpc = self.bitcoind_rpc_client.lock().await;

        let raw_tx_json = serde_json::json!(raw_tx.encode().to_hex());
        rpc.call_method::<Txid>("sendrawtransaction", &[raw_tx_json])
            .await
    }

    /// Gets a transaction given its id.
    pub async fn get_raw_transaction(&self, txid: &Txid) -> Result<Transaction, std::io::Error> {
        let mut rpc = self.bitcoind_rpc_client.lock().await;

        let txid_hex = serde_json::json!(txid.encode().to_hex());
        rpc.call_method::<Transaction>("getrawtransaction", &[txid_hex])
            .await
    }
}
