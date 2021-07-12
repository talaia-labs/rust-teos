use bitcoin::secp256k1::PublicKey;

pub mod appointment;
pub mod constants;
pub mod cryptography;
pub mod receipts;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct UserId(pub PublicKey);

impl UserId {
    pub fn serialize(&self) -> [u8; 33] {
        self.0.serialize()
    }
}
