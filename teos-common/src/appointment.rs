use hex;
use std::{convert::TryInto, fmt};

use bitcoin::Txid;

#[derive(Debug, Eq, PartialEq, Copy, Clone, Hash)]
pub struct Locator([u8; 16]);

impl Locator {
    pub fn new(txid: Txid) -> Self {
        Locator(txid[..16].try_into().unwrap())
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn deserialize(data: Vec<u8>) -> Result<Self, ()> {
        if data.len() == 16 {
            data[..16].try_into().map(|x| Self(x)).map_err(|_| ())
        } else {
            // TODO: Maybe add a more expressive error?
            Err(())
        }
    }
}

impl std::fmt::Display for Locator {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.serialize()))
    }
}

/// Contains data regarding an appointment between a client and the Watchtower. An appointment is requested for every new channel update.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Appointment {
    pub locator: Locator,
    pub encrypted_blob: Vec<u8>,
    pub to_self_delay: u32,
}

/// Represents all the possible states of an appointment in the system, or in a response to a client request.
pub enum AppointmentStatus {
    NotFound,
    BeingWatched,
    DisputeResponded,
}

impl Appointment {
    pub fn new(locator: [u8; 16], encrypted_blob: Vec<u8>, to_self_delay: u32) -> Self {
        Appointment {
            locator: Locator(locator),
            encrypted_blob,
            to_self_delay,
        }
    }

    /// Serializes an appointment to be signed.
    /// The serialization follows the same ordering as the fields in the appointment:
    ///
    /// locator | encrypted_blob | to_self_delay
    ///
    /// All values are big endian.
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = self.locator.serialize();
        result.extend(&self.encrypted_blob);
        result.extend(self.to_self_delay.to_be_bytes().to_vec());
        result
    }
}
