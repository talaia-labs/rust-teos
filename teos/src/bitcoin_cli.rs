// This is an adaptation of a bitcoind client with the minimal functionality required by the tower
// The original piece of software can be found at https://github.com/lightningdevkit/ldk-sample/blob/main/src/bitcoind_client.rs

/* This file is licensed under either of
 *  Apache License, Version 2.0, (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0) or
 *  MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)
 * at your option.
*/

use base64;
use futures::executor::block_on;
use std::sync::Arc;
use tokio::sync::Mutex;

use bitcoin::hash_types::{BlockHash, Txid};
use bitcoin::hashes::hex::ToHex;
use bitcoin::{Block, Transaction};
use lightning::util::ser::Writeable;
use lightning_block_sync::http::HttpEndpoint;
use lightning_block_sync::rpc::RpcClient;
use lightning_block_sync::{AsyncBlockSourceResult, BlockHeaderData, BlockSource};

pub struct BitcoindClient {
    bitcoind_rpc_client: Arc<Mutex<RpcClient>>,
    host: String,
    port: u16,
    rpc_user: String,
    rpc_password: String,
}

impl BlockSource for &BitcoindClient {
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

    fn get_block<'a>(
        &'a mut self,
        header_hash: &'a BlockHash,
    ) -> AsyncBlockSourceResult<'a, Block> {
        Box::pin(async move {
            let mut rpc = self.bitcoind_rpc_client.lock().await;
            rpc.get_block(header_hash).await
        })
    }

    fn get_best_block<'a>(&'a mut self) -> AsyncBlockSourceResult<(BlockHash, Option<u32>)> {
        Box::pin(async move {
            let mut rpc = self.bitcoind_rpc_client.lock().await;
            rpc.get_best_block().await
        })
    }
}

impl BitcoindClient {
    pub async fn new(
        host: String,
        port: u16,
        rpc_user: String,
        rpc_password: String,
    ) -> std::io::Result<Self> {
        let http_endpoint = HttpEndpoint::for_host(host.clone()).with_port(port);
        let rpc_credentials =
            base64::encode(format!("{}:{}", rpc_user.clone(), rpc_password.clone()));
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

    pub fn get_new_rpc_client(&self) -> std::io::Result<RpcClient> {
        let http_endpoint = HttpEndpoint::for_host(self.host.clone()).with_port(self.port);
        let rpc_credentials = base64::encode(format!(
            "{}:{}",
            self.rpc_user.clone(),
            self.rpc_password.clone()
        ));
        RpcClient::new(&rpc_credentials, http_endpoint)
    }

    pub async fn get_best_block_hash_and_height(
        &self,
    ) -> Result<(BlockHash, Option<u32>), std::io::Error> {
        let mut rpc = self.bitcoind_rpc_client.lock().await;
        rpc.call_method::<(BlockHash, Option<u32>)>("getblockchaininfo", &vec![])
            .await
    }

    pub async fn send_raw_transaction(&self, raw_tx: &Transaction) -> Result<Txid, std::io::Error> {
        let mut rpc = self.bitcoind_rpc_client.lock().await;

        let raw_tx_json = serde_json::json!(raw_tx.encode().to_hex());
        rpc.call_method::<Txid>("sendrawtransaction", &[raw_tx_json])
            .await
    }

    pub async fn get_raw_transaction(&self, txid: &Txid) -> Result<Transaction, std::io::Error> {
        let mut rpc = self.bitcoind_rpc_client.lock().await;

        let txid_hex = serde_json::json!(txid.encode().to_hex());
        rpc.call_method::<Transaction>("getrawtransaction", &[txid_hex])
            .await
    }
}
