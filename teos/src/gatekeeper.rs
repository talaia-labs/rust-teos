use bitcoin::secp256k1::PublicKey;
use std::collections::HashMap;
use teos_common::cryptography;
use tokio::sync::broadcast::Receiver;

use serde::{Deserialize, Serialize};
use serde_json::{Error as JSONError, Value};
use uuid::Uuid;

use lightning_block_sync::poll::ValidatedBlockHeader;

use crate::{block_processor::BlockProcessor, extended_appointment::ExtendedAppointment};
use teos_common::constants::ENCRYPTED_BLOB_MAX_SIZE_HEX;

#[derive(Clone, Eq, PartialEq, Hash)]
pub struct UserId(PublicKey);

#[derive(Serialize, Deserialize)]
pub struct UserInfo {
    available_slots: u32,
    subscription_expiry: u64,
    appointments: HashMap<Uuid, u32>,
}

impl UserInfo {
    pub fn new(available_slots: u32, subscription_expiry: u64) -> Self {
        UserInfo {
            available_slots,
            subscription_expiry,
            appointments: HashMap::new(),
        }
    }
    pub fn from_json(data: &str) -> Result<Self, JSONError> {
        serde_json::from_str::<UserInfo>(data)
    }

    pub fn to_json(self) -> Value {
        serde_json::to_value(&self).unwrap()
    }
}

pub struct AuthenticationFailure<'a>(&'a str);
pub struct NotEnoughSlots;

pub struct Gatekeeper {
    subscription_slots: u32,
    subscription_duration: u64,
    expiry_delta: u32,
    block_queue: Receiver<ValidatedBlockHeader>,
    block_processor: BlockProcessor,
    registered_users: HashMap<UserId, UserInfo>,
    outdated_users_cache: HashMap<UserId, UserInfo>,
}

impl Gatekeeper {
    pub fn authenticate_user(
        &self,
        message: &[u8],
        signature: &str,
    ) -> Result<UserId, AuthenticationFailure> {
        match cryptography::recover_pk(message, signature) {
            Ok(rpk) => {
                // FIXME:: This may need mutex.
                let user_id = UserId(rpk);
                if self.registered_users.contains_key(&user_id) {
                    Ok(user_id)
                } else {
                    Err(AuthenticationFailure("User not found."))
                }
            }
            Err(_) => Err(AuthenticationFailure("Wrong message or signature.")),
        }
    }
    pub async fn add_update_user(&mut self, user_id: &UserId) -> &UserInfo {
        let block_count = self.block_processor.get_block_count().await;

        //FIXME: This may need mutex
        if self.registered_users.contains_key(user_id) {
            // FIXME: For now new calls to register add subscription_slots to the current count and reset the expiry time

            if self.registered_users[user_id].available_slots + self.subscription_slots >= u32::MAX
            {
                println!("Maximum slots reached for the subscription");
            } else {
                self.registered_users
                    .get_mut(user_id)
                    .unwrap()
                    .available_slots += self.subscription_slots;
                self.registered_users
                    .get_mut(user_id)
                    .unwrap()
                    .subscription_expiry = block_count + self.subscription_duration;
            }
        } else {
            self.registered_users.insert(
                user_id.clone(),
                UserInfo::new(
                    self.subscription_slots,
                    block_count + self.subscription_duration,
                ),
            );
        }

        self.registered_users.get(user_id).unwrap()
    }

    pub fn add_update_appointments(
        &mut self,
        user_id: UserId,
        uuid: Uuid,
        appointment: ExtendedAppointment,
    ) -> Result<u32, NotEnoughSlots> {
        //FIXME: This may need muted

        // For updates, the difference between the existing appointment size and the update is computed.
        let used_slots = match self.registered_users[&user_id].appointments.get(&uuid) {
            Some(x) => x.clone(),
            None => 0,
        };
        let required_slots = (appointment.inner.encrypted_blob.len() as f32
            / ENCRYPTED_BLOB_MAX_SIZE_HEX as f32)
            .ceil() as u32;

        if required_slots - used_slots <= self.registered_users[&user_id].available_slots {
            // Filling / freeing slots depending on whether this is an update or not, and if it is bigger or smaller
            // than the old appointment
            let mut user = self.registered_users.get_mut(&user_id).unwrap();
            // FIXME: TEST THIS
            *user.appointments.get_mut(&uuid).unwrap() = required_slots;
            user.available_slots -= required_slots - used_slots;

            Ok(user.available_slots)
        } else {
            Err(NotEnoughSlots)
        }
    }

    pub async fn has_subscription_expired(
        &self,
        user_id: &UserId,
    ) -> Result<(bool, u64), AuthenticationFailure<'_>> {
        if self.registered_users.contains_key(&user_id) {
            let expiry = self.registered_users[&user_id].subscription_expiry;
            Ok((
                self.block_processor.get_block_count().await >= expiry,
                expiry,
            ))
        } else {
            Err(AuthenticationFailure("User not found."))
        }
    }
}
