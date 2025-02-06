use std::collections::{HashMap, HashSet};

use lightning::util::persist::KVStore;
use lightning::io::Error;
use bitcoin::secp256k1::SecretKey;
use teos_common::{TowerId, UserId};
use teos_common::receipts::{AppointmentReceipt, RegistrationReceipt};
use teos_common::appointment::{Appointment, Locator};

use crate::{AppointmentStatus, MisbehaviorProof, TowerInfo, TowerStatus, TowerSummary};

// Primary namespace for all watchtower-related data
const PRIMARY_NAMESPACE: &str = "watchtower";

// Secondary namespaces for different data types
const NS_TOWER_RECORDS: &str = "tower_records";
const NS_APPOINTMENTS: &str = "appointments";
const NS_REGISTRATION_RECEIPTS: &str = "registration_receipts";
const NS_APPOINTMENT_RECEIPTS: &str = "appointment_receipts";
const NS_PENDING_APPOINTMENTS: &str = "pending_appointments";
const NS_INVALID_APPOINTMENTS: &str = "invalid_appointments";
const NS_MISBEHAVIOR_PROOFS: &str = "misbehavior_proofs";

pub(crate) struct Storage<T: KVStore> {
    store: T,
    sk: String,
}

// Implement methods to convert TowerInfo to vec<u8> and vice versa

impl<T: KVStore> Storage<T> {
    pub(crate) fn new(store: T, sk: String) -> Result<Self, Error> {
        Ok(Storage {
            store,
            sk
        })
    }

    /// Creates a composite key from multiple components
    fn make_key(components: &[&str]) -> String {
        components.join(":")
    }

    /// Gets the appropriate namespace based on appointment status
    fn get_appointment_namespace(status: AppointmentStatus) -> &'static str {
        match status {
            AppointmentStatus::Accepted => NS_APPOINTMENT_RECEIPTS,
            AppointmentStatus::Pending => NS_PENDING_APPOINTMENTS,
            AppointmentStatus::Invalid => NS_INVALID_APPOINTMENTS,
        }
    }

    /// Stores a tower record into the database alongside the corresponding registration receipt.
    ///
    /// This function MUST be guarded against inserting duplicate (tower_id, subscription_expiry) pairs.
    /// This is currently done in WTClient::add_update_tower.
    pub fn store_tower_record(&mut self, tower_id: TowerId, net_addr: &str, receipt: &RegistrationReceipt) -> Result<(), Error> {
        let key = Self::make_key(&[&tower_id.to_string()]);

        let value = TowerInfo::new(
            net_addr.to_string(),
            receipt.available_slots(),
            receipt.subscription_start(),
            receipt.subscription_expiry(),
            HashMap::new(),
            Vec::new(),
            Vec::new(),
        ).to_vec().unwrap();

        // TODO: encrypt

        self.store.write(PRIMARY_NAMESPACE, NS_TOWER_RECORDS, &key, &value)
    }

    /// Loads a tower record from the database.
    ///
    /// Tower records are composed from the tower information and the appointment data. The latter is split in:
    /// accepted appointments (represented by appointment receipts), pending appointments and invalid appointments.
    /// In the case that the tower has misbehaved, then a misbehaving proof is also attached to the record.
    pub fn load_tower_record(&self, tower_id: TowerId) -> Option<TowerInfo> {
        let key = Self::make_key(&[&tower_id.to_string()]);
        let value = match self.store.read(PRIMARY_NAMESPACE, NS_TOWER_RECORDS, &key) {
            Ok(v) => v,
            Err(_) => return None,
        };

        // TODO: decrypt

        let mut tower_info = TowerInfo::from_slice(&value).unwrap();
        tower_info.appointments = self.load_appointment_receipts(tower_id);
        tower_info.pending_appointments = self.load_appointments(tower_id, AppointmentStatus::Pending);
        tower_info.invalid_appointments = self.load_appointments(tower_id, AppointmentStatus::Invalid);

        Some(tower_info)
    }

    /// Removes a tower record from the database.
    ///
    /// This triggers a cascade deletion of all related data, such as appointments, appointment receipts, etc. As long as there is a single
    /// reference to them.
    pub fn remove_tower_record(&self, tower_id: TowerId) -> Result<(), Error> {
        let key = Self::make_key(&[&tower_id.to_string()]);
        // primary namespace: "watchtower"
        // secondary namespance: "tower_record"
        // key: <tower_id>
        // value: ?
        self.store.remove(PRIMARY_NAMESPACE, NS_TOWER_RECORDS, &key, true)
    }

    /// Loads all tower records from the database.
    pub fn load_towers(&self) -> HashMap<TowerId, TowerSummary> {
        todo!()
    }

    /// Loads the latest registration receipt for a given tower.
    ///
    /// Latests is determined by the one with the `subscription_expiry` further into the future.
    pub fn load_registration_receipt(&self, tower_id: TowerId, user_id: UserId) -> Option<RegistrationReceipt> {
        let key = Self::make_key(&[&tower_id.to_string()]);

        self.store.read(PRIMARY_NAMESPACE, NS_REGISTRATION_RECEIPTS, &key)
    }


    /// Stores an appointments receipt into the database representing an appointment accepted by a given tower.
    pub fn store_appointment_receipt(&mut self, tower_id: TowerId, locator: Locator, available_slots: u32, receipt: &AppointmentReceipt) -> Result<(), Error> {
        let key = Self::make_key(&[&tower_id.to_string(), &locator.to_string()]);
        // primary namespace: "watchtower"
        // secondary namespance: "appointment_receipt"
        // key: <tower_id> + <locator>
        // value: ?
        self.store.write(PRIMARY_NAMESPACE, NS_APPOINTMENT_RECEIPTS, &key, &value)
    }

    /// Loads a given appointment receipt of a given tower from the database.
    pub fn load_appointment_receipt(&self, tower_id: TowerId, locator: Locator) -> Option<AppointmentReceipt> {
        let key = Self::make_key(&[&tower_id.to_string(), &locator.to_string()]);
        // primary namespace: "watchtower"
        // secondary namespance: "appointment_receipt"
        self.store.read(PRIMARY_NAMESPACE, NS_APPOINTMENT_RECEIPTS, &key)
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
        let key = Self::make_key(&[&appointment.locator.to_string()]);
        // primary namespace: "watchtower"
        // secondary namespance: "appointment"
        // key:
        // value: appointment.encrypted_blob()
        todo!();
    }

    /// Stores a pending appointment into the database.
    ///
    /// A pending appointment is an appointment that was sent to a tower when it was unreachable.
    /// This data is stored so it can be resent once the tower comes back online.
    /// Internally calls [Self::store_appointment].
    pub fn store_pending_appointment(&self, tower_id: TowerId, appointment: &Appointment) -> Result<(), Error> {
        let key = Self::make_key(&[&tower_id.to_string(), &appointment.locator.to_string()]);
        // primary namespace: "watchtower"
        // secondary namespance: "pending_appointment"
        // key: 
        // value: ?
        todo!();
    }

    /// Removes a pending appointment from the database.
    ///
    /// If the pending appointment is the only instance of the appointment, the appointment will also be deleted form the appointments table.
    pub fn delete_pending_appointment(&self, tower_id: TowerId, locator: Locator) -> Result<(), Error> {
        let key = Self::make_key(&[&tower_id.to_string(), &locator.to_string()]);
        // primary namespace: "watchtower"
        // secondary namespance: "pending_appointment"
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
        let key = Self::make_key(&[&tower_id.to_string(), &appointment.locator.to_string()]);
        // primary namespace: "watchtower"
        // secondary namespance: "invalid_appointment"
        // key: ?
        // value: ?
        todo!();
    }

    /// Loads non finalized appointments from the database for a given tower based on a status flag.
    ///
    /// This is meant to be used only for pending and invalid appointments, if the method is called for
    /// accepted appointment, an empty collection will be returned.
    pub fn load_appointments(&self, tower_id: TowerId, status: AppointmentStatus) -> Vec<Appointment> {
        let key = Self::make_key(&[&tower_id.to_string()]);
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
        let key = Self::make_key(&[&tower_id.to_string()]);
        // primary namespace: "watchtower"
        // secondary namespance: "misbehaving_proof"
        // key: ?
        // value: ?
        todo!();
    }

    /// Loads the misbehaving proof for a given tower from the database (if found).
    fn load_misbehaving_proof(&self, tower_id: TowerId) -> Option<MisbehaviorProof> {
        let key = Self::make_key(&[&tower_id.to_string()]);
        // primary namespace: "watchtower"
        // secondary namespance: "misbehaving_proof"
        // key: ?
        todo!();
    }

    /// Checks whether a misbehaving proof exists for a given tower.
    fn exists_misbehaving_proof(&self, tower_id: TowerId) -> bool {
        let key = Self::make_key(&[&tower_id.to_string()]);
        // primary namespace: "watchtower"
        // secondary namespance: "misbehaving_proof"
        // key: ?
        todo!();
    }
}
