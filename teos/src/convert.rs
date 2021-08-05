// This is an adaptation of the conversions between JsonResponse returned by bitcoind via the bitcoind client to inner types.
// The original piece of software can be found at https://github.com/lightningdevkit/ldk-sample/blob/main/src/convert.rs

/* This file is licensed under either of
 *  Apache License, Version 2.0, (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0) or
 *  MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)
 * at your option.
*/

use std::convert::TryInto;

use bitcoin::consensus::encode;
use bitcoin::hashes::hex::FromHex;
use bitcoin::BlockHash;
use lightning_block_sync::http::JsonResponse;

pub struct BlockchainInfo {
    pub latest_height: usize,
    pub latest_blockhash: BlockHash,
    pub chain: String,
}

impl TryInto<BlockchainInfo> for JsonResponse {
    type Error = std::io::Error;
    fn try_into(self) -> std::io::Result<BlockchainInfo> {
        Ok(BlockchainInfo {
            latest_height: self.0["blocks"].as_u64().unwrap() as usize,
            latest_blockhash: BlockHash::from_hex(self.0["bestblockhash"].as_str().unwrap())
                .unwrap(),
            chain: self.0["chain"].as_str().unwrap().to_string(),
        })
    }
}
#[derive(Debug, PartialEq, Eq)]
pub struct TxidHex(pub String);

impl TryInto<TxidHex> for JsonResponse {
    type Error = std::io::Error;
    fn try_into(self) -> std::io::Result<TxidHex> {
        match self.0.as_str() {
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "expected JSON string",
            )),
            Some(hex_data) => match Vec::<u8>::from_hex(hex_data) {
                Err(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid hex data",
                )),
                Ok(txid_data) => match encode::deserialize(&txid_data) {
                    Err(_) => Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid txid",
                    )),
                    Ok(txid) => Ok(TxidHex(txid)),
                },
            },
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn into_txidhex_from_json_response_with_unexpected_type() {
        let response = JsonResponse(serde_json::json!({ "result": "foo" }));
        match TryInto::<TxidHex>::try_into(response) {
            Err(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
                assert_eq!(e.get_ref().unwrap().to_string(), "expected JSON string");
            }
            Ok(_) => panic!("Expected error"),
        }
    }

    #[test]
    fn into_txidhex_from_json_response_with_invalid_hex_data() {
        let response = JsonResponse(serde_json::json!("foobar"));
        match TryInto::<TxidHex>::try_into(response) {
            Err(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
                assert_eq!(e.get_ref().unwrap().to_string(), "invalid hex data");
            }
            Ok(_) => panic!("Expected error"),
        }
    }

    #[test]
    fn into_txidhex_from_json_response_with_invalid_txid_data() {
        let response = JsonResponse(serde_json::json!("abcd"));
        match TryInto::<TxidHex>::try_into(response) {
            Err(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
                assert_eq!(e.get_ref().unwrap().to_string(), "invalid txid");
            }
            Ok(_) => panic!("Expected error"),
        }
    }

    #[test]
    fn into_txidhex_from_json_response_with_valid_txid_data() {
        let txid_inner = hex::encode([2; 32]);
        let response = JsonResponse(serde_json::json!(encode::serialize_hex(&txid_inner)));
        match TryInto::<TxidHex>::try_into(response) {
            Err(e) => panic!("Unexpected error: {:?}", e),
            Ok(txid) => assert_eq!(txid, TxidHex(txid_inner)),
        }
    }
}
