//! The Eye of Satoshi - Lightning watchtower.
//!
//! Functionality shared between users and towers.

pub mod protos {
    tonic::include_proto!("common.teos.v2");
}

pub mod appointment;
pub mod constants;
pub mod cryptography;
pub mod dbm;
pub mod errors;
pub mod receipts;
pub mod ser;
pub mod test_utils;

use std::fmt;
use std::{convert::TryFrom, str::FromStr};

use serde::{Deserialize, Serialize};

use bitcoin::secp256k1::{Error, PublicKey};

pub const USER_ID_LEN: usize = 33;
pub use UserId as TowerId;

/// User identifier. A wrapper around a [PublicKey].
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct UserId(pub PublicKey);

impl UserId {
    /// Encodes the user id in its byte representation.
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.serialize().to_vec()
    }

    /// Builds a user id from its byte representation.
    pub fn from_slice(data: &[u8]) -> Result<Self, Error> {
        Ok(UserId(PublicKey::from_slice(data)?))
    }
}

impl std::str::FromStr for UserId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PublicKey::from_str(s)
            .map_err(|_| {
                "Provided public key does not match expected format (33-byte hex string)".into()
            })
            .map(Self)
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<serde_json::Value> for UserId {
    type Error = String;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        match value {
            serde_json::Value::String(s) => UserId::from_str(&s),
            serde_json::Value::Array(mut a) => {
                let param_count = a.len();
                if param_count == 1 {
                    UserId::try_from(a.pop().unwrap())
                } else {
                    Err(format!(
                        "Unexpected json format. Expected a single parameter. Received: {}",
                        param_count
                    ))
                }
            }
            _ => Err(format!(
                "Unexpected request format. Expected: user_id/tower_id. Received: '{}'",
                value
            )),
        }
    }
}
