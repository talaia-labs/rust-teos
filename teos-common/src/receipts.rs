use bitcoin::secp256k1::SecretKey;

use crate::{cryptography, UserId};

#[derive(Debug)]
pub struct RegistrationReceipt {
    user_id: UserId,
    available_slots: u32,
    subscription_expiry: u32,
    signature: Option<String>,
}

impl RegistrationReceipt {
    pub fn new(user_id: UserId, available_slots: u32, subscription_expiry: u32) -> Self {
        RegistrationReceipt {
            user_id,
            available_slots,
            subscription_expiry,
            signature: None,
        }
    }

    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    pub fn available_slots(&self) -> u32 {
        self.available_slots
    }

    pub fn subscription_expiry(&self) -> u32 {
        self.subscription_expiry
    }

    pub fn signature(&self) -> Option<String> {
        self.signature.clone()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut ser = Vec::new();
        ser.extend_from_slice(&self.user_id.serialize());
        ser.extend_from_slice(&self.available_slots.to_be_bytes());
        ser.extend_from_slice(&self.subscription_expiry.to_be_bytes());

        ser
    }

    pub fn sign(&mut self, sk: &SecretKey) {
        // TODO: Check if there's any case where this can actually fail. Don't unwrap if so.
        self.signature = Some(cryptography::sign(&self.serialize(), sk).unwrap());
    }
}
#[derive(Debug)]
pub struct AppointmentReceipt {
    user_signature: String,
    start_block: u32,
    signature: Option<String>,
}

impl AppointmentReceipt {
    pub fn new(user_signature: String, start_block: u32) -> Self {
        AppointmentReceipt {
            user_signature,
            start_block,
            signature: None,
        }
    }

    pub fn user_signature(&self) -> String {
        self.user_signature.clone()
    }

    pub fn start_block(&self) -> u32 {
        self.start_block
    }

    pub fn signature(&self) -> Option<String> {
        self.signature.clone()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut ser = Vec::new();
        ser.extend_from_slice(&self.user_signature.as_bytes());
        ser.extend_from_slice(&self.start_block.to_be_bytes());

        ser
    }

    pub fn sign(&mut self, sk: &SecretKey) {
        // TODO: Check if there's any case where this can actually fail. Don't unwrap if so.
        self.signature = Some(cryptography::sign(&self.serialize(), sk).unwrap());
    }
}
