use std::collections::{HashMap, HashSet};

use lightning::util::persist::KVStore;
use lightning::io::Error;
use bitcoin::secp256k1::SecretKey;
use serde::Serialize;
use teos_common::{TowerId, UserId};
use teos_common::receipts::{AppointmentReceipt, RegistrationReceipt};
use teos_common::appointment::{Appointment, Locator};

use serde::Deserialize;
use crate::{AppointmentStatus, MisbehaviorProof, TowerInfo, TowerStatus, TowerSummary};

#[derive(Serialize, Deserialize)]
pub(crate) struct Storage<T: KVStore> {
    store: T,
    sk: String,
}

impl<T: KVStore> Storage<T> {
    pub(crate) fn new(store: T, sk: String) -> Self {
        Storage {
            store,
            sk
        }
    }

    /// Stores a tower record into the database alongside the corresponding registration receipt.
    ///
    /// This function MUST be guarded against inserting duplicate (tower_id, subscription_expiry) pairs.
    /// This is currently done in WTClient::add_update_tower.
    pub fn store_tower_record(&mut self, tower_id: TowerId, net_addr: &str, receipt: &RegistrationReceipt) -> Result<(), Error> {
        // primary namespace: "watchtower"
        // secondary namespance: "tower_record"
        // key: <tower_id>
        // value: ?
        todo!();
    }

    /// Loads a tower record from the database.
    ///
    /// Tower records are composed from the tower information and the appointment data. The latter is split in:
    /// accepted appointments (represented by appointment receipts), pending appointments and invalid appointments.
    /// In the case that the tower has misbehaved, then a misbehaving proof is also attached to the record.
    pub fn load_tower_record(&self, tower_id: TowerId) -> Option<TowerInfo> {
        // primary namespace: "watchtower"
        // secondary namespance: "tower_record"
        // key: <tower_id>
        todo!();
    }

    /// Removes a tower record from the database.
    ///
    /// This triggers a cascade deletion of all related data, such as appointments, appointment receipts, etc. As long as there is a single
    /// reference to them.
    pub fn remove_tower_record(&self, tower_id: TowerId) -> Result<(), Error> {
        // primary namespace: "watchtower"
        // secondary namespance: "tower_record"
        // key: <tower_id>
        // value: ?
        todo!();
    }

    /// Loads all tower records from the database.
    pub fn load_towers(&self) -> HashMap<TowerId, TowerSummary> {
        // primary namespace: "watchtower"
        // secondary namespance: "tower_record"
        todo!();
    }

    /// Loads the latest registration receipt for a given tower.
    ///
    /// Latests is determined by the one with the `subscription_expiry` further into the future.
    pub fn load_registration_receipt(&self, tower_id: TowerId, user_id: UserId) -> Option<RegistrationReceipt> {
        // primary namespace: "watchtower"
        // secondary namespance: "registration_receipt"
        // key: <tower_id>
        todo!();
    }


    /// Stores an appointments receipt into the database representing an appointment accepted by a given tower.
    pub fn store_appointment_receipt(&mut self, tower_id: TowerId, locator: Locator, available_slots: u32, receipt: &AppointmentReceipt) -> Result<(), Error> {
        // primary namespace: "watchtower"
        // secondary namespance: "appointment_receipt"
        // key: <tower_id> + <locator>
        // value: ?
        todo!();
    }

    /// Loads a given appointment receipt of a given tower from the database.
    pub fn load_appointment_receipt(&self, tower_id: TowerId, locator: Locator) -> Option<AppointmentReceipt> {
        // primary namespace: "watchtower"
        // secondary namespance: "appointment_receipt"
        // key: <tower_id> + <locator>
        todo!();
    }

    /// Loads the appointment receipts associated to a given tower.
    ///
    /// TODO: Currently this is only loading a summary of the receipt, if we need to really load all the information
    /// for any reason this method may need to be renamed.
    pub fn load_appointment_receipts(&self, tower_id: TowerId) -> HashMap<Locator, String> {
        // primary namespace: "watchtower"
        // secondary namespance: "appointment_receipt"
        // filter by tower_id
        todo!();
    }

    /// Loads a collection of locators from the database entry associated to a given tower.
    ///
    /// The loaded locators can be loaded either from appointment_receipts, pending_appointments or invalid_appointments
    ///  depending on `status`.
    pub fn load_appointment_locators(&self, tower_id: TowerId, status: AppointmentStatus) -> HashSet<Locator> {
        // primary namespace: "watchtower"
        // secondary namespance: "{status}_appointment_receipt"
        todo!();
    }

    /// Loads an appointment from the database.
    pub fn load_appointment(&self, locator: Locator) -> Option<Appointment> {
        // primary namespace: "watchtower"
        // secondary namespance: "appointment_receipt"
        // key: <locator>
        todo!();
    }

    /// Stores an appointment into the database.
    ///
    /// Appointments are only stored as a whole when they are pending or invalid.
    /// Accepted appointments are simplified in the form of an appointment receipt.
    fn store_appointment(&self, appointment: &Appointment) -> Result<usize, Error> {
        // primary namespace: "watchtower"
        // secondary namespance: "appointment_receipt"
        // key: ?
        // value: ?
        todo!();
    }

    /// Stores a pending appointment into the database.
    ///
    /// A pending appointment is an appointment that was sent to a tower when it was unreachable.
    /// This data is stored so it can be resent once the tower comes back online.
    /// Internally calls [Self::store_appointment].
    pub fn store_pending_appointment(&self, tower_id: TowerId, appointment: &Appointment) -> Result<(), Error> {
        // primary namespace: "watchtower"
        // secondary namespance: "pending_appointment_receipt"
        // key: 
        // value: ?
        todo!();
    }

    /// Removes a pending appointment from the database.
    ///
    /// If the pending appointment is the only instance of the appointment, the appointment will also be deleted form the appointments table.
    pub fn delete_pending_appointment(&self, tower_id: TowerId, locator: Locator) -> Result<(), Error> {
        // primary namespace: "watchtower"
        // secondary namespance: "pending_appointment_receipt"
        // key: ?
        // value: ?
        todo!();
    }

    /// Stores an invalid appointment into the database.
    ///
    /// An invalid appointment is an appointment that was rejected by the tower.
    /// Storing this data may allow us to see what was the issue and send the data later on.
    /// Internally calls [Self::store_appointment].
    pub fn store_invalid_appointment(&mut self, tower_id: TowerId, appointment: &Appointment) -> Result<(), Error> {
        // primary namespace: "watchtower"
        // secondary namespance: "invalid_appointment_receipt"
        // key: ?
        // value: ?
        todo!();
    }

    /// Loads non finalized appointments from the database for a given tower based on a status flag.
    ///
    /// This is meant to be used only for pending and invalid appointments, if the method is called for
    /// accepted appointment, an empty collection will be returned.
    pub fn load_appointments(&self, tower_id: TowerId, status: AppointmentStatus) -> Vec<Appointment> {
        // primary namespace: "watchtower"
        // secondary namespance: "{status}_appointment_receipt"
        // key: ?
        // value: ?
        todo!();
    }

    /// Stores a misbehaving proof into the database.
    ///
    /// A misbehaving proof is proof that the tower has signed an appointment using a key different
    /// than the one advertised to the user when they registered.
    pub fn store_misbehaving_proof(&self, tower_id: TowerId, proof: &MisbehaviorProof) -> Result<(), Error> {
        // primary namespace: "watchtower"
        // secondary namespance: "misbehaving_proof"
        // key: ?
        // value: ?
        todo!();
    }

    /// Loads the misbehaving proof for a given tower from the database (if found).
    fn load_misbehaving_proof(&self, tower_id: TowerId) -> Option<MisbehaviorProof> {
        // primary namespace: "watchtower"
        // secondary namespance: "misbehaving_proof"
        // key: ?
        todo!();
    }

    /// Checks whether a misbehaving proof exists for a given tower.
    fn exists_misbehaving_proof(&self, tower_id: TowerId) -> bool {
        // primary namespace: "watchtower"
        // secondary namespance: "misbehaving_proof"
        // key: ?
        todo!();
    }
}
