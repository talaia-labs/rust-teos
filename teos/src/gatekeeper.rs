use bitcoin::secp256k1::PublicKey;
use lightning_block_sync::poll::{ChainPoller, ValidatedBlockHeader};
use lightning_block_sync::BlockSource;
use std::cell::RefCell;
use std::collections::HashMap;
use std::ops::DerefMut;
use std::rc::Rc;
use teos_common::cryptography;
use tokio::sync::broadcast::Receiver;

use serde::{Deserialize, Serialize};
use serde_json::{Error as JSONError, Value};
use uuid::Uuid;

use crate::extended_appointment::ExtendedAppointment;
use teos_common::constants::ENCRYPTED_BLOB_MAX_SIZE_HEX;

#[derive(Clone, Eq, PartialEq, Hash)]
pub struct UserId(PublicKey);

#[derive(Serialize, Deserialize)]
pub struct UserInfo {
    available_slots: u32,
    subscription_expiry: u32,
    appointments: HashMap<Uuid, u32>,
}

impl UserInfo {
    pub fn new(available_slots: u32, subscription_expiry: u32) -> Self {
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

#[derive(Debug, PartialEq)]
pub struct AuthenticationFailure<'a>(&'a str);

#[derive(Debug, PartialEq)]
pub struct NotEnoughSlots;

pub struct Gatekeeper<B: DerefMut<Target = T> + Sized, T: BlockSource> {
    poller: Rc<RefCell<ChainPoller<B, T>>>,
    last_known_block_header: ValidatedBlockHeader,
    block_queue: Receiver<ValidatedBlockHeader>,
    subscription_slots: u32,
    subscription_duration: u32,
    expiry_delta: u32,
    registered_users: HashMap<UserId, UserInfo>,
    outdated_users_cache: HashMap<UserId, UserInfo>,
}

impl<B, T> Gatekeeper<B, T>
where
    B: DerefMut<Target = T> + Sized + Send + Sync,
    T: BlockSource,
{
    pub fn new(
        poller: Rc<RefCell<ChainPoller<B, T>>>,
        last_known_block_header: ValidatedBlockHeader,
        block_queue: Receiver<ValidatedBlockHeader>,
        subscription_slots: u32,
        subscription_duration: u32,
        expiry_delta: u32,
    ) -> Self {
        Gatekeeper {
            poller: poller.clone(),
            last_known_block_header,
            block_queue,
            subscription_slots,
            subscription_duration,
            expiry_delta,
            registered_users: HashMap::new(),
            outdated_users_cache: HashMap::new(),
        }
    }

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
    pub fn add_update_user(&mut self, user_id: &UserId) -> &UserInfo {
        let block_count = self.last_known_block_header.height;

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

    pub fn has_subscription_expired(
        &self,
        user_id: &UserId,
    ) -> Result<(bool, u32), AuthenticationFailure<'_>> {
        if self.registered_users.contains_key(&user_id) {
            let expiry = self.registered_users[&user_id].subscription_expiry;
            Ok((self.last_known_block_header.height >= expiry, expiry))
        } else {
            Err(AuthenticationFailure("User not found."))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::Blockchain;
    use bitcoin::network::constants::Network;
    use bitcoin::secp256k1::key::ONE_KEY;
    use bitcoin::secp256k1::Secp256k1;
    use tokio::sync::broadcast;

    #[test]
    fn test_has_subscription_expired() {
        let slots = 21;
        let duration = 500;
        let expiry_delta = 42;
        let start_height = 100;

        let mut chain = Blockchain::default().with_height(start_height);
        let tip = chain.tip();
        let poller = Rc::new(RefCell::new(ChainPoller::new(&mut chain, Network::Bitcoin)));
        let (_, rx) = broadcast::channel(100);

        let mut gatekeeper = Gatekeeper::new(poller, tip, rx, slots, duration, expiry_delta);
        let user_id = UserId(PublicKey::from_secret_key(&Secp256k1::new(), &ONE_KEY));

        // If the user is not registered, querying for a subscription expiry check should return an error
        matches!(
            gatekeeper.has_subscription_expired(&user_id),
            Err(AuthenticationFailure { .. })
        );

        // If the user is registered and the subscription is active we should get (false, expiry)
        gatekeeper.add_update_user(&user_id);
        assert_eq!(
            gatekeeper.has_subscription_expired(&user_id),
            Ok((false, duration + start_height as u32))
        );

        // If the subscription has expired, we should get (true, expiry). Let's modify the user entry
        let expiry = start_height as u32;
        gatekeeper
            .registered_users
            .get_mut(&user_id)
            .unwrap()
            .subscription_expiry = expiry;
        assert_eq!(
            gatekeeper.has_subscription_expired(&user_id),
            Ok((true, expiry))
        );
    }
}
