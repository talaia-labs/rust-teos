// Part of this file is an adaptation of test_utils from rust-lightning's lightning_block_sync crate.
// The original piece of software can be found at https://github.com/rust-bitcoin/rust-lightning/blob/main/lightning-block-sync/src/test_utils.rs

/* This file is licensed under either of
 *  Apache License, Version 2.0, (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0) or
 *  MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)
 * at your option.
*/

use rand::Rng;
use std::convert::TryInto;
use std::sync::Arc;
use std::thread;

use jsonrpc_http_server::jsonrpc_core::error::ErrorCode as JsonRpcErrorCode;
use jsonrpc_http_server::jsonrpc_core::{Error as JsonRpcError, IoHandler, Params, Value};
use jsonrpc_http_server::{Server, ServerBuilder};

use bitcoincore_rpc::{Auth, Client as BitcoindClient};

use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::blockdata::script::{Builder, Script};
use bitcoin::blockdata::transaction::{OutPoint, Transaction, TxIn, TxOut};
use bitcoin::hash_types::BlockHash;
use bitcoin::hash_types::Txid;
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::Hash;
use bitcoin::network::constants::Network;
use bitcoin::util::hash::bitcoin_merkle_root;
use bitcoin::util::psbt::serialize::Deserialize;
use bitcoin::util::uint::Uint256;
use lightning_block_sync::poll::{Validate, ValidatedBlockHeader};
use lightning_block_sync::{
    AsyncBlockSourceResult, BlockHeaderData, BlockSource, BlockSourceError, UnboundedCache,
};

use teos_common::appointment::{Appointment, Locator};
use teos_common::cryptography::{encrypt, get_random_bytes, get_random_keypair};
use teos_common::UserId;

use crate::carrier::Carrier;
use crate::dbm::DBM;
use crate::extended_appointment::{ExtendedAppointment, UUID};
use crate::gatekeeper::UserInfo;
use crate::responder::TransactionTracker;
use crate::watcher::Breach;

pub static TX_HEX: &str =  "010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff54038e830a1b4d696e656420627920416e74506f6f6c373432c2005b005e7a0ae3fabe6d6d7841cd582ead8ea5dd8e3de1173cae6fcd2a53c7362ebb7fb6f815604fe07cbe0200000000000000ac0e060005f90000ffffffff04d9476026000000001976a91411dbe48cc6b617f9c6adaf4d9ed5f625b1c7cb5988ac0000000000000000266a24aa21a9ed7248c6efddd8d99bfddd7f499f0b915bffa8253003cc934df1ff14a81301e2340000000000000000266a24b9e11b6d7054937e13f39529d6ad7e685e9dd4efa426f247d5f5a5bed58cdddb2d0fa60100000000000000002b6a2952534b424c4f434b3a054a68aa5368740e8b3e3c67bce45619c2cfd07d4d4f0936a5612d2d0034fa0a0120000000000000000000000000000000000000000000000000000000000000000000000000";
pub static TXID_HEX: &str = "338bda693c4a26e0d41a01f7f2887aaf48bf0bdf93e6415c9110b29349349d3e";

pub const SLOTS: u32 = 21;
pub const DURATION: u32 = 500;
pub const EXPIRY_DELTA: u32 = 42;
pub const START_HEIGHT: usize = 100;

#[derive(Clone, Default, Debug)]
pub(crate) struct Blockchain {
    pub blocks: Vec<Block>,
    without_blocks: Option<std::ops::RangeFrom<usize>>,
    without_headers: bool,
    malformed_headers: bool,
}

impl Blockchain {
    pub fn default() -> Self {
        Blockchain::with_network(Network::Bitcoin)
    }

    pub fn with_network(network: Network) -> Self {
        let blocks = vec![genesis_block(network)];
        Self {
            blocks,
            ..Default::default()
        }
    }

    pub fn with_height(mut self, height: usize) -> Self {
        self.blocks.reserve_exact(height);
        let bits = BlockHeader::compact_target_from_u256(&Uint256::from_be_bytes([0xff; 32]));
        for i in 1..=height {
            let prev_block = &self.blocks[i - 1];
            let prev_blockhash = prev_block.block_hash();
            let time = prev_block.header.time + height as u32;
            self.blocks.push(Block {
                header: BlockHeader {
                    version: 0,
                    prev_blockhash,
                    merkle_root: Default::default(),
                    time,
                    bits,
                    nonce: 0,
                },
                txdata: vec![],
            });
        }
        self
    }

    pub fn with_height_and_txs(mut self, height: usize, tx_count: Option<u8>) -> Self {
        let tx_count = match tx_count {
            Some(x) => x,
            None => 10,
        };

        for _ in 1..=height {
            let mut txs = Vec::new();
            for _ in 0..tx_count {
                txs.push(get_random_tx());
            }

            self.generate_with_txs(txs);
        }

        self
    }

    pub fn without_blocks(self, range: std::ops::RangeFrom<usize>) -> Self {
        Self {
            without_blocks: Some(range),
            ..self
        }
    }

    pub fn without_headers(self) -> Self {
        Self {
            without_headers: true,
            ..self
        }
    }

    pub fn malformed_headers(self) -> Self {
        Self {
            malformed_headers: true,
            ..self
        }
    }

    pub fn fork_at_height(&self, height: usize) -> Self {
        assert!(height + 1 < self.blocks.len());
        let mut blocks = self.blocks.clone();
        let mut prev_blockhash = blocks[height].block_hash();
        for block in blocks.iter_mut().skip(height + 1) {
            block.header.prev_blockhash = prev_blockhash;
            block.header.nonce += 1;
            prev_blockhash = block.block_hash();
        }
        Self {
            blocks,
            without_blocks: None,
            ..*self
        }
    }

    pub fn at_height(&self, height: usize) -> ValidatedBlockHeader {
        let block_header = self.at_height_unvalidated(height);
        let block_hash = self.blocks[height].block_hash();
        block_header.validate(block_hash).unwrap()
    }

    fn at_height_unvalidated(&self, height: usize) -> BlockHeaderData {
        assert!(!self.blocks.is_empty());
        assert!(height < self.blocks.len());
        BlockHeaderData {
            chainwork: self.blocks[0].header.work() + Uint256::from_u64(height as u64).unwrap(),
            height: height as u32,
            header: self.blocks[height].header.clone(),
        }
    }

    pub fn tip(&self) -> ValidatedBlockHeader {
        assert!(!self.blocks.is_empty());
        self.at_height(self.blocks.len() - 1)
    }

    pub fn disconnect_tip(&mut self) -> Option<Block> {
        self.blocks.pop()
    }

    pub fn generate_with_txs(&mut self, txs: Vec<Transaction>) {
        let bits = BlockHeader::compact_target_from_u256(&Uint256::from_be_bytes([0xff; 32]));
        let prev_block = &self.blocks.last().unwrap();
        let prev_blockhash = prev_block.block_hash();
        let time = prev_block.header.time + 1 as u32;
        let hashes = txs.iter().map(|obj| obj.txid().as_hash());

        self.blocks.push(Block {
            header: BlockHeader {
                version: 0,
                prev_blockhash,
                merkle_root: bitcoin_merkle_root(hashes).into(),
                time,
                bits,
                nonce: 0,
            },
            txdata: txs,
        });
    }

    pub fn header_cache(&self, heights: std::ops::RangeInclusive<usize>) -> UnboundedCache {
        let mut cache = UnboundedCache::new();
        for i in heights {
            let value = self.at_height(i);
            let key = value.header.block_hash();
            assert!(cache.insert(key, value).is_none());
        }
        cache
    }

    pub async fn get_block_count(&self) -> usize {
        self.blocks.len()
    }

    pub fn generate(&mut self, txs: Option<Vec<Transaction>>) -> Block {
        let bits = BlockHeader::compact_target_from_u256(&Uint256::from_be_bytes([0xff; 32]));

        let prev_block = self.blocks.last().unwrap();
        let prev_blockhash = prev_block.block_hash();
        let time = prev_block.header.time + (self.blocks.len() + 1) as u32;
        let txdata = match txs {
            Some(t) => t,
            None => vec![],
        };
        let block = Block {
            header: BlockHeader {
                version: 0,
                prev_blockhash,
                merkle_root: Default::default(),
                time,
                bits,
                nonce: 0,
            },
            txdata,
        };

        self.blocks.push(block.clone());

        block
    }
}

impl BlockSource for Blockchain {
    fn get_header<'a>(
        &'a mut self,
        header_hash: &'a BlockHash,
        _height_hint: Option<u32>,
    ) -> AsyncBlockSourceResult<'a, BlockHeaderData> {
        Box::pin(async move {
            if self.without_headers {
                return Err(BlockSourceError::persistent("header not found"));
            }

            for (height, block) in self.blocks.iter().enumerate() {
                if block.header.block_hash() == *header_hash {
                    let mut header_data = self.at_height_unvalidated(height);
                    if self.malformed_headers {
                        header_data.header.time += 1;
                    }

                    return Ok(header_data);
                }
            }
            Err(BlockSourceError::transient("header not found"))
        })
    }

    fn get_block<'a>(
        &'a mut self,
        header_hash: &'a BlockHash,
    ) -> AsyncBlockSourceResult<'a, Block> {
        Box::pin(async move {
            for (height, block) in self.blocks.iter().enumerate() {
                if block.header.block_hash() == *header_hash {
                    if let Some(without_blocks) = &self.without_blocks {
                        if without_blocks.contains(&height) {
                            return Err(BlockSourceError::persistent("block not found"));
                        }
                    }

                    return Ok(block.clone());
                }
            }
            Err(BlockSourceError::transient("block not found"))
        })
    }

    fn get_best_block<'a>(&'a mut self) -> AsyncBlockSourceResult<'a, (BlockHash, Option<u32>)> {
        Box::pin(async move {
            match self.blocks.last() {
                None => Err(BlockSourceError::transient("empty chain")),
                Some(block) => {
                    let height = (self.blocks.len() - 1) as u32;
                    Ok((block.block_hash(), Some(height)))
                }
            }
        })
    }
}

pub(crate) fn generate_uuid() -> UUID {
    let mut rng = rand::thread_rng();

    UUID(rng.gen())
}

pub(crate) fn get_random_user_id() -> UserId {
    let (_, pk) = get_random_keypair();

    UserId(pk)
}

pub(crate) fn get_random_tx() -> Transaction {
    let mut rng = rand::thread_rng();
    let prev_txid_bytes = get_random_bytes(32);

    Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint::new(
                Txid::from_slice(&prev_txid_bytes).unwrap(),
                rng.gen_range(0..200),
            ),
            script_sig: Script::new(),
            witness: Vec::new(),
            sequence: 0,
        }],
        output: vec![TxOut {
            script_pubkey: Builder::new().push_int(1).into_script(),
            value: rng.gen_range(0..21000000000),
        }],
    }
}

pub(crate) fn generate_dummy_appointment(dispute_txid: Option<&Txid>) -> ExtendedAppointment {
    let dispute_txid = match dispute_txid {
        Some(l) => l.clone(),
        None => {
            let prev_txid_bytes = get_random_bytes(32);
            Txid::from_slice(&prev_txid_bytes).unwrap()
        }
    };

    let tx_bytes = Vec::from_hex(TX_HEX).unwrap();
    let penalty_tx = Transaction::deserialize(&tx_bytes).unwrap();

    let mut locator: [u8; 16] = get_random_bytes(16).try_into().unwrap();
    locator.copy_from_slice(&dispute_txid[..16]);

    let encrypted_blob = encrypt(&penalty_tx, &dispute_txid).unwrap();
    let appointment = Appointment::new(locator, encrypted_blob, 21);
    let user_id = get_random_user_id();
    let user_signature = String::new();
    let start_block = 42;

    ExtendedAppointment::new(appointment, user_id, user_signature, start_block)
}

pub(crate) fn generate_dummy_appointment_with_user(
    user_id: UserId,
    dispute_txid: Option<&Txid>,
) -> (UUID, ExtendedAppointment) {
    let mut app = generate_dummy_appointment(dispute_txid);
    app.user_id = user_id;

    (UUID::new(&app.locator(), &user_id), app)
}

pub fn get_random_breach() -> Breach {
    let dispute_tx = get_random_tx();
    let penalty_tx = get_random_tx();
    let locator = Locator::new(dispute_tx.txid());

    Breach::new(locator, dispute_tx, penalty_tx)
}

pub fn get_random_breach_from_locator(locator: Locator) -> Breach {
    let mut breach = get_random_breach();
    breach.locator = locator;
    breach
}

pub fn get_random_tracker(user_id: UserId) -> TransactionTracker {
    let breach = get_random_breach();
    TransactionTracker::new(breach, user_id)
}

pub fn store_appointment_and_fks_to_db(dbm: &DBM, uuid: &UUID, appointment: &ExtendedAppointment) {
    dbm.store_user(&appointment.user_id, &UserInfo::new(21, 42))
        .unwrap();
    dbm.store_appointment(&uuid, &appointment).unwrap();
}

pub enum MockedServerQuery {
    Regular,
    Confirmations(u32),
    Error(i64),
}

pub fn create_carrier(query: MockedServerQuery) -> Carrier {
    let bitcoind_mock = match query {
        MockedServerQuery::Regular => BitcoindMock::new(MockOptions::empty()),
        MockedServerQuery::Confirmations(x) => {
            BitcoindMock::new(MockOptions::with_confirmations(x))
        }
        MockedServerQuery::Error(x) => BitcoindMock::new(MockOptions::with_error(x)),
    };
    let bitcoin_cli = Arc::new(BitcoindClient::new(bitcoind_mock.url(), Auth::None).unwrap());
    start_server(bitcoind_mock);

    Carrier::new(bitcoin_cli)
}

pub struct BitcoindMock {
    pub url: String,
    pub server: Server,
}

pub struct MockOptions {
    error_code: Option<i64>,
    confirmations: Option<u32>,
}

impl MockOptions {
    pub fn new(error_code: Option<i64>, confirmations: Option<u32>) -> Self {
        Self {
            error_code,
            confirmations,
        }
    }

    pub fn empty() -> Self {
        Self {
            error_code: None,
            confirmations: None,
        }
    }

    pub fn with_error(error_code: i64) -> Self {
        Self {
            error_code: Some(error_code),
            confirmations: None,
        }
    }

    pub fn with_confirmations(confirmations: u32) -> Self {
        Self {
            error_code: None,
            confirmations: Some(confirmations),
        }
    }
}

impl BitcoindMock {
    pub fn new(options: MockOptions) -> Self {
        let mut io = IoHandler::default();

        match options.error_code {
            Some(x) => {
                io.add_sync_method("error", move |_params: Params| {
                    Err(JsonRpcError::new(JsonRpcErrorCode::ServerError(x)))
                });
                io.add_alias("sendrawtransaction", "error");

                // So we can test a sendrawtransaction error b/c the tx is already on the mempool
                // and query the confirmation count
                match options.confirmations {
                    Some(c) => {
                        BitcoindMock::add_getrawtransaction(&mut io, c);
                    }
                    None => io.add_alias("getrawtransaction", "error"),
                }
            }
            None => {
                BitcoindMock::add_sendrawtransaction(&mut io);
                BitcoindMock::add_getrawtransaction(&mut io, options.confirmations.unwrap_or(0));
            }
        }

        let server = ServerBuilder::new(io)
            .threads(3)
            .start_http(&"127.0.0.1:0".parse().unwrap())
            .unwrap();

        Self {
            url: format!("http://{}", server.address()),
            server,
        }
    }

    fn add_sendrawtransaction(io: &mut IoHandler) {
        io.add_method("sendrawtransaction", |_params: Params| async {
            Ok(Value::String(TXID_HEX.to_owned()))
        });
    }

    fn add_getrawtransaction(io: &mut IoHandler, confirmations: u32) {
        io.add_sync_method("getrawtransaction", move |_params: Params|  {
            match _params {
                Params::Array(x) => match x[1] {
                    Value::Bool(x) => {
                        if x {
                            Ok(serde_json::json!({"confirmations": confirmations, "hex": TX_HEX, "txid": TXID_HEX,
                            "hash": TXID_HEX, "size": 0, "vsize": 0, "version": 1, "locktime": 0, "vin": [], "vout": [] }))
                        } else {
                            Ok(Value::String(TX_HEX.to_owned()))
                        }
                    }
                    _ => panic!("Boolean param not found"),
                },
                _ => panic!("No params found"),
            }
        })
    }

    pub fn url(&self) -> String {
        self.url.clone()
    }
}

pub fn start_server(bitcoind: BitcoindMock) {
    thread::spawn(move || {
        bitcoind.server.wait();
    });
}
