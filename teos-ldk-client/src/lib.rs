use std::collections::HashMap;

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

use teos_common::{TowerId, UserId};

use crate::retrier::RetrierStatus;
use crate::{MisbehaviorProof, SubscriptionError, TowerInfo, TowerStatus, TowerSummary};

struct TeosCleint {
    key_pair: (PublicKey, SecretKey),
    storage: Storage,
    max_retry_count: u32,
    retry_relay: u32,
    // TODO:
    // KV storage
    // in memory towers info
    towers: HashMap<TowerId, TowerSummary>
}

impl TeosCleint {
    pub fn new(secret_key: SecretKey, storage: Storage) -> Self {
        TeosCleint {
            key_pair: (PublicKey::from_secret_key(&Secp256k1::new(), &secret_key), secret_key),
            storage,
            max_retry_count: 3,
            retry_relay: 3,
            towers: HashMap::new(),
        }
    }

    pub fn set_max_retry_count(&mut self, max_retry_count: u32) {
        self.max_retry_count = max_retry_count;
    }

    pub fn set_retry_relay(&mut self, retry_relay: u32) {
        self.retry_relay = retry_relay;
    }

    pub fn build(&self) -> Result<(), ()> {
        // validate things here
        Ok(())
    }

    /// registers the user id (compressed public key) with a given tower.
    // pub fn register_tower <tower_id>

    /// gets all the locally stored data about a given tower.
    // pub fn get_tower_info <tower_id>

    /// tries to send pending appointment to a (previously) unreachable tower.
    // pub fn retry_tower <tower_id>

    /// deletes all data associated with a given tower.
    // pub fn abandon_tower <tower_id>

    /// Polls the tower to check if it is online.
    // pub fn ping_tower <tower_id>

    /// lists all registered towers.
    // pub fn list_towers

    /// queries a given tower about an appointment.
    // pub fn get_appointment <tower_id> <locator>

    /// gets the subscription information by querying the tower.
    // pub fn get_subscription_info <tower_id>

    /// pulls a given appointment receipt from the local database.
    // pub fn get_appointment_receipt <tower_id> <locator>

    /// pulls the latest registration receipt from the local database.
    // pub fn get_registration_receipt <tower_id>

    /// sends appointments to the registered towers for every new commitment transaction.
    // pub fn on_commitment_revocation <tx>

}

