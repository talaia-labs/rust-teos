//! The Eye of Satoshi - Lightning watchtower.
//!
//! Functionality shared between users and towers.

// FIXME: This is a temporary fix. See https://github.com/tokio-rs/prost/issues/661
#[allow(clippy::derive_partial_eq_without_eq)]
pub mod protos {
    tonic::include_proto!("common.teos.v2");
}

pub mod appointment;
pub mod constants;
pub mod cryptography;
pub mod errors;
pub mod net;
pub mod receipts;
pub mod ser;
pub mod test_utils;

use std::fmt;
use std::{convert::TryFrom, str::FromStr};

use serde::{Deserialize, Serialize};
use serde_json::json;

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
                        "Unexpected json format. Expected a single parameter. Received: {param_count}"
                    ))
                }
            }
            serde_json::Value::Object(mut m) => {
                let param_count = m.len();
                if param_count > 1 {
                    Err(format!(
                        "Unexpected json format. Expected a single parameter. Received: {param_count}"
                    ))
                } else {
                    UserId::try_from(json!(m
                        .remove("user_id")
                        .or_else(|| m.remove("tower_id"))
                        .ok_or("user_id or tower_id not found")?))
                }
            }
            _ => Err(format!(
                "Unexpected request format. Expected: user_id/tower_id. Received: '{value}'"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;

    use crate::test_utils::get_random_user_id;

    #[test]
    fn try_from_json_string() {
        let user_id = get_random_user_id();
        assert_eq!(UserId::try_from(json!(user_id.to_string())), Ok(user_id));
    }

    #[test]
    fn try_from_json_wrong_string() {
        let user_id = "not_a_user_id";
        assert!(matches!(
            UserId::try_from(json!(user_id.to_string())),
            Err(..)
        ));
    }

    #[test]
    fn try_from_json_array() {
        let user_id = get_random_user_id();
        assert_eq!(UserId::try_from(json!([user_id.to_string()])), Ok(user_id));
    }

    #[test]
    fn try_from_json_array_empty() {
        assert!(matches!(UserId::try_from(json!([])), Err(..)));
    }

    #[test]
    fn try_from_json_array_too_many_elements() {
        let user_id = get_random_user_id();
        assert!(matches!(
            UserId::try_from(json!([user_id.to_string(), user_id.to_string()])),
            Err(..)
        ));
    }

    #[test]
    fn try_from_json_dict() {
        let user_id = get_random_user_id();
        assert_eq!(
            UserId::try_from(json!(HashMap::from([("tower_id", user_id.to_string())]))),
            Ok(user_id)
        );
        assert_eq!(
            UserId::try_from(json!(HashMap::from([("user_id", user_id.to_string())]))),
            Ok(user_id)
        );
    }

    #[test]
    fn try_from_json_empty_dict() {
        assert!(matches!(
            UserId::try_from(json!(HashMap::<String, serde_json::Value>::new())),
            Err(..)
        ));
    }

    #[test]
    fn try_from_json_wrong_dict() {
        let user_id = get_random_user_id();
        assert!(matches!(
            UserId::try_from(json!(HashMap::from([("random_key", user_id.to_string())]))),
            Err(..)
        ));
    }

    #[test]
    fn try_from_json_dict_too_many_keys() {
        let user_id = get_random_user_id();

        assert!(matches!(
            UserId::try_from(json!(HashMap::from([
                ("tower_id", user_id.to_string()),
                ("user_id", user_id.to_string())
            ]))),
            Err(..)
        ));
    }
}
