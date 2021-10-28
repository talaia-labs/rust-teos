pub mod appointment;
pub mod constants;
pub mod cryptography;
pub mod receipts;

use std::fmt;

use bitcoin::secp256k1::{Error, PublicKey};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct UserId(pub PublicKey);

impl UserId {
    pub fn serialize(&self) -> Vec<u8> {
        self.0.serialize().to_vec()
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, Error> {
        Ok(UserId(PublicKey::from_slice(data)?))
    }
}

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
