//! Receipts issued  by towers and handed to users as commitment proof.

use serde::Serialize;

use bitcoin::secp256k1::SecretKey;

use crate::{cryptography, UserId};

/// Proof that a user has registered with a tower. This serves two purposes:
///
/// - First, the user is able to prove that the tower agreed on providing a service. If a tower refuses to accept appointments
///   from a user (claiming the subscription has expired) but the expiry time has still not passed and the tower cannot
///   provide the relevant appointments signed by the user, it means it is cheating.
/// - Second, it serves as proof, alongside an appointment receipt, that an appointment was not fulfilled. A registration receipt
///   specifies a subscription period (`subscription_start` - `subscription_expiry`) and the appointment a `start_block` so inclusion
///   can be proved.
///
/// TODO: / DISCUSS: In order to minimize the amount of receipts the user has to store, the tower could batch subscription receipts
/// as long as the user info is still known. That is, if a user has a subscription with range (S, E) and the user renews the subscription
/// before the tower wipes their data, then the tower can create a new receipt with (S, E') for E' > E instead of a second receipt (E, E').
// Notice this only applies as long as there is no gap between the two subscriptions.
#[derive(Serialize, Debug, Eq, PartialEq, Clone)]
pub struct RegistrationReceipt {
    user_id: UserId,
    available_slots: u32,
    subscription_start: u32,
    subscription_expiry: u32,
    #[serde(rename = "subscription_signature")]
    signature: Option<String>,
}

impl RegistrationReceipt {
    pub fn new(
        user_id: UserId,
        available_slots: u32,
        subscription_start: u32,
        subscription_expiry: u32,
    ) -> Self {
        RegistrationReceipt {
            user_id,
            available_slots,
            subscription_start,
            subscription_expiry,
            signature: None,
        }
    }

    pub fn with_signature(
        user_id: UserId,
        available_slots: u32,
        subscription_start: u32,
        subscription_expiry: u32,
        signature: String,
    ) -> Self {
        RegistrationReceipt {
            user_id,
            available_slots,
            subscription_start,
            subscription_expiry,
            signature: Some(signature),
        }
    }

    pub fn user_id(&self) -> UserId {
        self.user_id
    }

    pub fn available_slots(&self) -> u32 {
        self.available_slots
    }

    pub fn subscription_start(&self) -> u32 {
        self.subscription_start
    }

    pub fn subscription_expiry(&self) -> u32 {
        self.subscription_expiry
    }

    pub fn signature(&self) -> Option<String> {
        self.signature.clone()
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut ser = Vec::new();
        ser.extend_from_slice(&self.user_id.to_vec());
        ser.extend_from_slice(&self.available_slots.to_be_bytes());
        ser.extend_from_slice(&self.subscription_start.to_be_bytes());
        ser.extend_from_slice(&self.subscription_expiry.to_be_bytes());

        ser
    }

    pub fn sign(&mut self, sk: &SecretKey) {
        self.signature = Some(cryptography::sign(&self.to_vec(), sk));
    }

    pub fn verify(&self, id: &UserId) -> bool {
        if let Some(signature) = self.signature() {
            cryptography::verify(&self.to_vec(), &signature, &id.0)
        } else {
            false
        }
    }
}

/// Proof that a certain state was backed up with the tower.
///
/// Appointment receipts can be used alongside a registration receipt that covers it, and on chain data (a breach not being reacted with a penalty), to prove a tower has not reacted to a channel breach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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

    pub fn with_signature(user_signature: String, start_block: u32, signature: String) -> Self {
        AppointmentReceipt {
            user_signature,
            start_block,
            signature: Some(signature),
        }
    }

    pub fn user_signature(&self) -> &str {
        &self.user_signature
    }

    pub fn start_block(&self) -> u32 {
        self.start_block
    }

    pub fn signature(&self) -> Option<String> {
        self.signature.clone()
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut ser = Vec::new();
        ser.extend_from_slice(self.user_signature.as_bytes());
        ser.extend_from_slice(&self.start_block.to_be_bytes());

        ser
    }

    pub fn sign(&mut self, sk: &SecretKey) {
        self.signature = Some(cryptography::sign(&self.to_vec(), sk));
    }

    pub fn verify(&self, id: &UserId) -> bool {
        if let Some(signature) = self.signature() {
            cryptography::verify(&self.to_vec(), &signature, &id.0)
        } else {
            false
        }
    }
}
