use std::fmt;

use bitcoin::hashes::{ripemd160, Hash};

use teos_common::appointment::{Appointment, Locator};
use teos_common::UserId;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct UUID(pub [u8; 20]);

impl UUID {
    pub fn new(locator: &Locator, user_id: &UserId) -> Self {
        let mut uuid_data = locator.serialize();
        uuid_data.extend(&user_id.0.serialize());
        UUID(ripemd160::Hash::hash(&uuid_data).into_inner())
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl std::fmt::Display for UUID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct ExtendedAppointment {
    pub inner: Appointment,
    pub user_id: UserId,
    pub user_signature: String,
    pub start_block: u32,
}

pub struct AppointmentSummary {
    pub locator: Locator,
    pub user_id: UserId,
}

impl ExtendedAppointment {
    pub fn new(
        inner: Appointment,
        user_id: UserId,
        user_signature: String,
        start_block: u32,
    ) -> Self {
        ExtendedAppointment {
            inner,
            user_id,
            user_signature,
            start_block,
        }
    }

    pub fn locator(&self) -> Locator {
        self.inner.locator
    }

    pub fn encrypted_blob(&self) -> &Vec<u8> {
        &self.inner.encrypted_blob
    }

    pub fn to_self_delay(&self) -> u32 {
        self.inner.to_self_delay
    }

    pub fn get_summary(&self) -> AppointmentSummary {
        AppointmentSummary {
            locator: self.locator(),
            user_id: self.user_id,
        }
    }
}

pub fn compute_appointment_slots(blob_size: usize, blob_max_size: usize) -> u32 {
    (blob_size as f32 / blob_max_size as f32).ceil() as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryInto;

    use crate::test_utils::get_random_user_id;
    use teos_common::appointment::Appointment;
    use teos_common::cryptography::get_random_bytes;

    #[test]
    fn test_get_summary() {
        let locator = get_random_bytes(16).try_into().unwrap();
        let user_id = get_random_user_id();
        let signature = String::new();

        let a = Appointment::new(locator, get_random_bytes(32), 42);
        let e = ExtendedAppointment::new(a, user_id, signature, 21);

        let s = e.get_summary();

        assert_eq!(e.locator(), s.locator);
        assert_eq!(e.user_id, s.user_id);
    }
}
