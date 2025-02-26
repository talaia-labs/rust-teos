use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::TowerStatus;

use crate::storage::persister::{Persister, PersisterError};
use lightning::io::Error as DBError;

use lightning::util::persist::KVStore;
use teos_common::appointment::{Appointment, Locator};
use teos_common::receipts::{AppointmentReceipt, RegistrationReceipt};
use teos_common::{TowerId, UserId};

use crate::storage::encryptor::Encryptor;
use crate::storage::namespace::{get_appointment_namespace, KeySpace, NameSpace};

impl From<DBError> for PersisterError {
    fn from(error: DBError) -> Self {
        PersisterError::Other(error.to_string())
    }
}

use crate::{AppointmentStatus, MisbehaviorProof, TowerInfo, TowerSummary};
// XXX: this is taken from LDK and should be imported after it is made public there
pub type DynStore = dyn KVStore + Sync + Send;

pub struct KVStorage {
    store: Arc<DynStore>,
    encryptor: Box<Encryptor>,
}

impl KVStorage {
    pub fn new(store: Arc<DynStore>, sk: Vec<u8>) -> Result<Self, PersisterError> {
        Ok(KVStorage {
            store,
            encryptor: Box::new(Encryptor::new(&sk[..])),
        })
    }

    fn store_item<T: serde::Serialize>(
        &mut self,
        key_space: KeySpace,
        value: &T,
        encrypted: bool,
    ) -> Result<(), PersisterError> {
        let value = bincode::serialize(value).unwrap();
        let value = if encrypted {
            self.encryptor.encrypt(&value).unwrap()
        } else {
            value
        };

        self.store
            .write(
                key_space.namespace().primary(),
                key_space.namespace().secondary(),
                key_space.key(),
                &value,
            )
            .map_err(|e| PersisterError::StoreError(e.to_string()))
    }

    fn load_item<T: serde::de::DeserializeOwned>(
        &self,
        key_space: &KeySpace,
        encrypted: bool,
    ) -> Option<T> {
        match self.store.read(
            key_space.namespace().primary(),
            key_space.namespace().secondary(),
            key_space.key(),
        ) {
            Ok(value) => {
                let value = if encrypted {
                    self.encryptor.decrypt(&value).unwrap()
                } else {
                    value
                };

                Some(bincode::deserialize(&value).unwrap())
            }
            Err(_) => None,
        }
    }

    fn list_keys(&self, name_space: NameSpace) -> Vec<String> {
        self.store
            .list(name_space.primary(), name_space.secondary())
            .unwrap()
    }

    fn remove_item(&self, key_space: KeySpace) -> Result<(), PersisterError> {
        self.store
            .remove(
                key_space.namespace().primary(),
                key_space.namespace().secondary(),
                key_space.key(),
                false,
            )
            .map_err(|_| PersisterError::StoreError(format!("removing: {}", key_space.key())))
    }

    fn store_appointment(&mut self, appointment: &Appointment) -> Result<(), PersisterError> {
        self.store_item(
            KeySpace::appointment(appointment.locator),
            appointment,
            true,
        )
    }

    fn load_misbehaving_proof(&self, tower_id: TowerId) -> Option<MisbehaviorProof> {
        self.load_item(&KeySpace::misbehaving_proof(tower_id), true)
    }

    fn remove_pending_appointments(&self, tower_id: TowerId) -> Result<(), PersisterError> {
        let pending_keys = self
            .list_keys(NameSpace::pending_appointments())
            .iter()
            .filter(|l| l.starts_with(&tower_id.to_string()))
            .map(|key| {
                let parts: Vec<&str> = key.split(':').collect();
                let locator = Locator::from_slice(&hex::decode(parts[1]).unwrap()).unwrap();
                KeySpace::pending_appointment(tower_id, locator)
            })
            .collect::<Vec<_>>();
        for key_space in pending_keys {
            self.remove_item(key_space)?;
        }

        Ok(())
    }

    fn remove_invalid_appointments(&self, tower_id: TowerId) -> Result<(), PersisterError> {
        let invalid_keys = self
            .list_keys(NameSpace::invalid_appointments())
            .iter()
            .filter(|l| l.starts_with(&tower_id.to_string()))
            .map(|key| {
                let parts: Vec<&str> = key.split(':').collect();
                let locator = Locator::from_slice(&hex::decode(parts[1]).unwrap()).unwrap();
                KeySpace::invalid_appointment(tower_id, locator)
            })
            .collect::<Vec<_>>();
        for key_space in invalid_keys {
            self.remove_item(key_space)?;
        }

        Ok(())
    }

    fn remove_registration_receipts(&self, tower_id: TowerId) -> Result<(), PersisterError> {
        let registration_keys = self
            .list_keys(NameSpace::registration_receipts(tower_id))
            .iter()
            .map(|key| {
                let expiry = key.parse::<u32>().unwrap();
                KeySpace::registration_receipt(tower_id, expiry)
            })
            .collect::<Vec<_>>();
        for key_space in registration_keys {
            self.remove_item(key_space)?;
        }

        Ok(())
    }

    fn remove_appointment_receipts(&self, tower_id: TowerId) -> Result<(), PersisterError> {
        let receipt_keys = self
            .list_keys(NameSpace::appointment_receipts())
            .iter()
            .filter(|l| l.starts_with(&tower_id.to_string()))
            .map(|key| {
                let parts: Vec<&str> = key.split(':').collect();
                let locator = Locator::from_slice(&hex::decode(parts[1]).unwrap()).unwrap();
                KeySpace::appointment_receipt(tower_id, locator)
            })
            .collect::<Vec<_>>();
        for key_space in receipt_keys {
            self.remove_item(key_space)?;
        }

        Ok(())
    }

    fn remove_misbehaving_proofs(&self, tower_id: TowerId) -> Result<(), PersisterError> {
        if self.load_misbehaving_proof(tower_id).is_some() {
            self.remove_item(KeySpace::misbehaving_proof(tower_id))?;
        }

        Ok(())
    }
}

impl Persister for KVStorage {
    /// Stores a tower record into the database alongside the corresponding registration receipt.
    ///
    /// This function MUST be guarded against inserting duplicate (tower_id, subscription_expiry) pairs.
    /// This is currently done in WTClient::add_update_tower.
    fn store_tower_record(
        &mut self,
        tower_id: TowerId,
        net_addr: &str,
        receipt: &RegistrationReceipt,
    ) -> Result<(), PersisterError> {
        // Create tower info
        let tower_info = TowerInfo::new(
            net_addr.to_string(),
            receipt.available_slots(),
            receipt.subscription_start(),
            receipt.subscription_expiry(),
            HashMap::new(),
            Vec::new(),
            Vec::new(),
        );

        // Store the tower record
        self.store_item(KeySpace::tower(tower_id), &tower_info, true)?;

        // Store the registration receipt
        self.store_item(
            KeySpace::registration_receipt(tower_id, receipt.subscription_expiry()),
            receipt,
            true,
        )?;

        // Store the available slots
        self.store_item(
            KeySpace::available_slots(tower_id),
            &receipt.available_slots(),
            true,
        )
    }

    /// Loads a tower record from the database.
    ///
    /// Tower records are composed from the tower information and the appointment data. The latter is split in:
    /// accepted appointments (represented by appointment receipts), pending appointments and invalid appointments.
    /// In the case that the tower has misbehaved, then a misbehaving proof is also attached to the record.
    fn load_tower_record(&self, tower_id: TowerId) -> Option<TowerInfo> {
        // Load base tower info
        let mut tower_info: TowerInfo = self.load_item(&KeySpace::tower(tower_id), true)?;

        // Load all appointments data
        tower_info.appointments = self.load_appointment_receipts(tower_id);
        tower_info.pending_appointments =
            self.load_appointments(tower_id, AppointmentStatus::Pending);
        tower_info.invalid_appointments =
            self.load_appointments(tower_id, AppointmentStatus::Invalid);

        // Load and update subscription info from latest registration receipt
        let latest_expiry = self
            .list_keys(NameSpace::registration_receipts(tower_id))
            .iter()
            .filter_map(|s_e| s_e.parse::<u32>().ok())
            .max()?;

        let registration_receipt: RegistrationReceipt = self.load_item(
            &KeySpace::registration_receipt(tower_id, latest_expiry),
            true,
        )?;

        tower_info.subscription_start = registration_receipt.subscription_start();
        tower_info.subscription_expiry = registration_receipt.subscription_expiry();

        // Update tower status based on misbehavior and pending appointments
        if let Some(proof) = self.load_misbehaving_proof(tower_id) {
            tower_info.status = TowerStatus::Misbehaving;
            tower_info.set_misbehaving_proof(proof);
        } else if !tower_info.pending_appointments.is_empty() {
            tower_info.status = TowerStatus::TemporaryUnreachable;
        }

        // Load available slots
        tower_info.available_slots = self.load_item(&KeySpace::available_slots(tower_id), true)?;

        Some(tower_info)
    }

    /// Removes a tower record from the database.
    ///
    /// This triggers a cascade deletion of all related data, such as appointments, appointment receipts, etc. As long as there is a single
    /// reference to them.
    fn remove_tower_record(&self, tower_id: TowerId) -> Result<(), PersisterError> {
        self.remove_pending_appointments(tower_id)?;

        self.remove_invalid_appointments(tower_id)?;

        self.remove_registration_receipts(tower_id)?;

        self.remove_appointment_receipts(tower_id)?;

        self.remove_misbehaving_proofs(tower_id)?;

        self.remove_item(KeySpace::tower(tower_id))
    }

    /// Loads all tower records from the database.
    ///
    /// Returns a key value pair with the tower id as key and the tower summary as value.
    fn load_towers(&self) -> HashMap<TowerId, TowerSummary> {
        self.list_keys(NameSpace::tower_records())
            .iter()
            .filter_map(|key| {
                let tower_id = key.parse().unwrap();
                self.load_tower_record(tower_id)
                    .map(|info| (tower_id, TowerSummary::from(info)))
            })
            .collect()
    }

    /// Loads the latest registration receipt for a given tower.
    ///
    /// Latests is determined by the one with the `subscription_expiry` further into the future.
    fn load_registration_receipt(
        &self,
        tower_id: TowerId,
        user_id: UserId,
    ) -> Option<RegistrationReceipt> {
        // Find the latest subscription expiry
        let latest_expiry = self
            .list_keys(NameSpace::registration_receipts(tower_id))
            .iter()
            .map(|s_e| s_e.parse::<u32>().unwrap())
            .max()?;

        // Load the registration receipt using KeySpace
        let receipt: RegistrationReceipt = self.load_item(
            &KeySpace::registration_receipt(tower_id, latest_expiry),
            true,
        )?;

        // Create new receipt with the provided user_id
        Some(RegistrationReceipt::with_signature(
            user_id,
            receipt.available_slots(),
            receipt.subscription_start(),
            receipt.subscription_expiry(),
            receipt.signature().unwrap(),
        ))
    }

    /// Stores an appointments receipt into the database representing an appointment accepted by a given tower.
    fn store_appointment_receipt(
        &mut self,
        tower_id: TowerId,
        locator: Locator,
        available_slots: u32,
        receipt: &AppointmentReceipt,
    ) -> Result<(), PersisterError> {
        // Store appointment receipt
        self.store_item(
            KeySpace::appointment_receipt(tower_id, locator),
            receipt,
            true,
        )?;

        // Update the tower's available slots
        self.store_item(KeySpace::available_slots(tower_id), &available_slots, true)?;

        // Load and update tower info
        let tower: TowerInfo = self.load_item(&KeySpace::tower(tower_id), true).unwrap();

        let tower_info = TowerInfo::new(
            tower.net_addr,
            available_slots,
            tower.subscription_start,
            tower.subscription_expiry,
            HashMap::new(),
            Vec::new(),
            Vec::new(),
        );

        // Store updated tower info
        self.store_item(KeySpace::tower(tower_id), &tower_info, true)?;

        Ok(())
    }

    /// Loads a given appointment receipt of a given tower from the database.
    fn load_appointment_receipt(
        &self,
        tower_id: TowerId,
        locator: Locator,
    ) -> Option<AppointmentReceipt> {
        self.load_item(&KeySpace::appointment_receipt(tower_id, locator), true)
    }

    /// Loads the appointment receipts associated to a given tower.
    ///
    /// TODO: Currently this is only loading a summary of the receipt, if we need to really load all the information
    /// for any reason this method may need to be renamed.
    fn load_appointment_receipts(&self, tower_id: TowerId) -> HashMap<Locator, String> {
        self.list_keys(NameSpace::appointment_receipts())
            .iter()
            .filter(|key| key.starts_with(&tower_id.to_string()))
            .filter_map(|key| {
                // Extract locator from key
                let locator_hex = key.split(':').nth(1)?;
                let locator = Locator::from_slice(&hex::decode(locator_hex).ok()?).ok()?;

                // Load and get signature from receipt
                self.load_appointment_receipt(tower_id, locator)
                    .and_then(|receipt| receipt.signature())
                    .map(|signature| (locator, signature))
            })
            .collect()
    }

    /// Loads a collection of locators from the database entry associated to a given tower.
    ///
    /// The loaded locators can be loaded either from appointment_receipts, pending_appointments or invalid_appointments
    ///  depending on `status`.
    fn load_appointment_locators(
        &self,
        tower_id: TowerId,
        status: AppointmentStatus,
    ) -> HashSet<Locator> {
        self.list_keys(get_appointment_namespace(status))
            .iter()
            .filter(|key| key.starts_with(&tower_id.to_string()))
            .filter_map(|key| {
                key.split(':')
                    .nth(1)
                    .and_then(|hex_str| hex::decode(hex_str).ok())
                    .and_then(|bytes| Locator::from_slice(&bytes).ok())
            })
            .collect()
    }

    /// Loads an appointment from the database.
    fn load_appointment(&self, locator: Locator) -> Option<Appointment> {
        self.load_item(&KeySpace::appointment(locator), true)
    }

    /// Stores a pending appointment into the database.
    ///
    /// A pending appointment is an appointment that was sent to a tower when it was unreachable.
    /// This data is stored so it can be resent once the tower comes back online.
    /// Internally calls [Self::store_appointment].
    fn store_pending_appointment(
        &mut self,
        tower_id: TowerId,
        appointment: &Appointment,
    ) -> Result<(), PersisterError> {
        // Check if pending appointment already exists
        let key_space = KeySpace::pending_appointment(tower_id, appointment.locator);
        if self.load_item::<Appointment>(&key_space, true).is_some() {
            return Err(PersisterError::Other(format!(
                "{}:{}",
                tower_id, appointment.locator
            )));
        }

        let key_space = KeySpace::pending_appointment(tower_id, appointment.locator);
        // Store the pending appointment
        self.store_item(key_space, appointment, true)?;

        // Store the appointment itself
        self.store_appointment(appointment)?;

        Ok(())
    }

    /// Removes a pending appointment from the database.
    ///
    /// If the pending appointment is the only instance of the appointment, the appointment will also be deleted form the appointments table.
    fn delete_pending_appointment(
        &mut self,
        tower_id: TowerId,
        locator: Locator,
    ) -> Result<(), PersisterError> {
        // Count total references to this appointment
        let total_references = {
            // Count invalid appointments
            let invalid_count = self
                .list_keys(NameSpace::invalid_appointments())
                .iter()
                .filter(|l| l.ends_with(&locator.to_string()))
                .count();

            // Count pending appointments
            let pending_count = self
                .list_keys(NameSpace::pending_appointments())
                .iter()
                .filter(|l| l.ends_with(&locator.to_string()))
                .count();

            invalid_count + pending_count
        };

        // If this is the last reference, remove the appointment itself
        if total_references == 1 {
            self.remove_item(KeySpace::appointment(locator))?;
        }

        // Remove the pending appointment reference
        self.remove_item(KeySpace::pending_appointment(tower_id, locator))
    }

    /// Stores an invalid appointment into the database.
    ///
    /// An invalid appointment is an appointment that was rejected by the tower.
    /// Storing this data may allow us to see what was the issue and send the data later on.
    /// Internally calls [Self::store_appointment].
    fn store_invalid_appointment(
        &mut self,
        tower_id: TowerId,
        appointment: &Appointment,
    ) -> Result<(), PersisterError> {
        let key_space = KeySpace::invalid_appointment(tower_id, appointment.locator);

        // Check if invalid appointment already exists using load_item
        if self.load_item::<Appointment>(&key_space, true).is_some() {
            return Err(PersisterError::Other(format!(
                "{}:{}",
                tower_id, appointment.locator
            )));
        }

        // Store the invalid appointment
        self.store_item(key_space, appointment, true)?;

        // Store the appointment itself
        self.store_appointment(appointment)?;

        Ok(())
    }

    /// Loads non finalized appointments from the database for a given tower based on a status flag.
    ///
    /// This is meant to be used only for pending and invalid appointments, if the method is called for
    /// accepted appointment, an empty collection will be returned.
    fn load_appointments(&self, tower_id: TowerId, status: AppointmentStatus) -> Vec<Appointment> {
        // Return early for accepted appointments
        if matches!(status, AppointmentStatus::Accepted) {
            return Vec::new();
        }

        self.list_keys(get_appointment_namespace(status))
            .iter()
            .filter(|key| key.starts_with(&tower_id.to_string()))
            .filter_map(|key| {
                // Extract and parse locator from key
                key.split(':')
                    .nth(1)
                    .and_then(|hex_str| hex::decode(hex_str).ok())
                    .and_then(|bytes| Locator::from_slice(&bytes).ok())
                    .and_then(|locator| self.load_appointment(locator))
            })
            .collect()
    }

    /// Stores a misbehaving proof into the database.
    ///
    /// A misbehaving proof is proof that the tower has signed an appointment using a key different
    /// than the one advertised to the user when they registered.
    fn store_misbehaving_proof(
        &mut self,
        tower_id: TowerId,
        proof: &MisbehaviorProof,
    ) -> Result<(), PersisterError> {
        // Store the appointment receipt
        self.store_item(
            KeySpace::appointment_receipt(tower_id, proof.locator),
            &proof.appointment_receipt,
            true,
        )?;

        // Store the misbehavior proof
        self.store_item(KeySpace::misbehaving_proof(tower_id), proof, true)
    }

    fn appointment_exists(&self, locator: Locator) -> bool {
        let key_space = KeySpace::appointment(locator);

        self.load_item::<Appointment>(&key_space, true).is_some()
    }

    fn appointment_receipt_exists(&self, locator: Locator, tower_id: TowerId) -> bool {
        let key_space = KeySpace::appointment_receipt(tower_id, locator);

        self.load_item::<AppointmentReceipt>(&key_space, true)
            .is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::mock_kv::MemoryStore;

    use teos_common::test_utils::{
        generate_random_appointment, get_random_registration_receipt, get_random_user_id,
        get_registration_receipt_from_previous,
    };

    impl KVStorage {
        fn exists_misbehaving_proof(&self, tower_id: TowerId) -> bool {
            self.load_item::<MisbehaviorProof>(&KeySpace::misbehaving_proof(tower_id), true)
                .is_some()
        }
    }

    fn create_test_kv_storage() -> KVStorage {
        let store = MemoryStore::new().into_dyn_store();
        let sk = vec![0u8; 32]; // Test secret key
        KVStorage::new(store, sk).unwrap()
    }

    #[test]
    fn test_store_load_tower_record() {
        let mut storage = create_test_kv_storage();

        // In order to add a tower record we need to associated registration receipt.
        let tower_id = get_random_user_id();
        let net_addr = "talaia.watch";
        let receipt = get_random_registration_receipt();

        let tower_info = TowerInfo::new(
            net_addr.to_owned(),
            receipt.available_slots(),
            receipt.subscription_start(),
            receipt.subscription_expiry(),
            HashMap::new(),
            Vec::new(),
            Vec::new(),
        );

        // Check the loaded data matches the in memory data
        let serialized = bincode::serialize(&tower_info).unwrap();

        let deserialized: TowerInfo = bincode::deserialize(&serialized).unwrap();
        assert_eq!(tower_info, deserialized);

        storage
            .store_tower_record(tower_id, net_addr, &receipt)
            .unwrap();

        let loaded = storage.load_tower_record(tower_id).unwrap();
        assert_eq!(loaded, tower_info);

        let loaded_receipt = storage
            .load_registration_receipt(tower_id, receipt.user_id())
            .unwrap();
        assert_eq!(loaded_receipt, receipt);
    }

    #[test]
    fn test_load_registration_receipt() {
        let mut storage = create_test_kv_storage();

        // Registration receipts are stored alongside tower records when the register command is called
        let tower_id = get_random_user_id();
        let net_addr = "talaia.watch";
        let receipt = get_random_registration_receipt();

        // Check the receipt was stored
        storage
            .store_tower_record(tower_id, net_addr, &receipt)
            .unwrap();
        assert_eq!(
            storage
                .load_registration_receipt(tower_id, receipt.user_id())
                .unwrap(),
            receipt
        );

        // Add another receipt for the same tower with a higher expiry and check this last one is loaded
        let middle_receipt = get_registration_receipt_from_previous(&receipt);
        let latest_receipt = get_registration_receipt_from_previous(&middle_receipt);

        storage
            .store_tower_record(tower_id, net_addr, &latest_receipt)
            .unwrap();
        assert_eq!(
            storage
                .load_registration_receipt(tower_id, latest_receipt.user_id())
                .unwrap(),
            latest_receipt
        );

        // Add a final one with a lower expiry and check the last is still loaded
        storage
            .store_tower_record(tower_id, net_addr, &middle_receipt)
            .unwrap();
        assert_eq!(
            storage
                .load_registration_receipt(tower_id, latest_receipt.user_id())
                .unwrap(),
            latest_receipt
        );
    }

    #[test]
    fn test_load_same_registration_receipt() {
        let mut storage = create_test_kv_storage();

        // Registration receipts are stored alongside tower records when the register command is called
        let tower_id = get_random_user_id();
        let net_addr = "talaia.watch";
        let receipt = get_random_registration_receipt();

        // Store it once
        storage
            .store_tower_record(tower_id, net_addr, &receipt)
            .unwrap();
        assert_eq!(
            storage
                .load_registration_receipt(tower_id, receipt.user_id())
                .unwrap(),
            receipt
        );

        // // Store the same again, this should fail due to UNIQUE PK constrains.
        // // Notice store_tower_record is guarded against this by WTClient::add_update_tower though.
        // let err = storage.store_tower_record(tower_id, net_addr, &receipt).unwrap_err();
        // assert_eq!(
        //     err,
        //     PersisterError::StoreError(format!("tower_id: {tower_id} already exists"))
        // );
    }

    #[test]
    fn test_load_nonexistent_tower_record() {
        let storage = create_test_kv_storage();

        // If the tower does not exists, `load_tower` will fail.
        let tower_id = get_random_user_id();
        assert!(storage.load_tower_record(tower_id).is_none());
    }

    #[test]
    fn test_store_load_towers() {
        let mut storage = create_test_kv_storage();
        let mut towers = HashMap::new();

        // In order to add a tower record we need to associated registration receipt.
        for _ in 0..10 {
            let tower_id = get_random_user_id();
            let net_addr = "talaia.watch";
            let mut receipt = get_random_registration_receipt();
            storage
                .store_tower_record(tower_id, net_addr, &receipt)
                .unwrap();

            // Add not only one registration receipt to test if the tower retrieves the one with furthest expiry date.
            for _ in 0..10 {
                receipt = get_registration_receipt_from_previous(&receipt);
                storage
                    .store_tower_record(tower_id, net_addr, &receipt)
                    .unwrap();
            }

            towers.insert(
                tower_id,
                TowerSummary::new(
                    net_addr.to_owned(),
                    receipt.available_slots(),
                    receipt.subscription_start(),
                    receipt.subscription_expiry(),
                ),
            );
        }

        assert_eq!(storage.load_towers(), towers);
    }

    #[test]
    fn test_load_towers_empty() {
        // If there are no towers in the database, `load_towers` should return an empty map.
        let storage = create_test_kv_storage();
        assert_eq!(storage.load_towers(), HashMap::new());
    }

    #[test]
    fn test_remove_tower_record() {
        let mut storage = create_test_kv_storage();

        let tower_id = get_random_user_id();
        let net_addr = "talaia.watch";
        let receipt = get_random_registration_receipt();
        storage
            .store_tower_record(tower_id, net_addr, &receipt)
            .unwrap();

        assert!(matches!(storage.remove_tower_record(tower_id), Ok(())));
        assert_eq!(storage.load_towers(), HashMap::new());
    }

    #[test]
    fn test_remove_tower_record_inexistent() {
        let storage = create_test_kv_storage();
        let tower_id = get_random_user_id();
        let err = storage.remove_tower_record(tower_id).unwrap_err();
        assert_eq!(
            err,
            PersisterError::StoreError(format!("removing: {}", tower_id))
        );
    }

    #[test]
    fn test_store_load_appointment_receipts() {
        let mut storage = create_test_kv_storage();

        // In order to add a tower record we need to associated registration receipt.
        let tower_id = get_random_user_id();
        let net_addr = "talaia.watch";

        let receipt = get_random_registration_receipt();
        let mut tower_summary = TowerSummary::new(
            net_addr.to_owned(),
            receipt.available_slots(),
            receipt.subscription_start(),
            receipt.subscription_expiry(),
        );
        storage
            .store_tower_record(tower_id, net_addr, &receipt)
            .unwrap();

        // Add some appointment receipts and check they match
        let mut receipts = HashMap::new();
        for _ in 0..5 {
            let appointment = generate_random_appointment(None);
            let user_signature = "user_signature";
            let appointment_receipt = AppointmentReceipt::with_signature(
                user_signature.to_owned(),
                42,
                "tower_signature".to_owned(),
            );

            tower_summary.available_slots -= 1;

            storage
                .store_appointment_receipt(
                    tower_id,
                    appointment.locator,
                    tower_summary.available_slots,
                    &appointment_receipt,
                )
                .unwrap();
            receipts.insert(
                appointment.locator,
                appointment_receipt.signature().unwrap(),
            );
        }

        assert_eq!(storage.load_appointment_receipts(tower_id), receipts);
    }

    #[test]
    fn test_load_appointment_receipt() {
        let mut storage = create_test_kv_storage();
        let tower_id = get_random_user_id();
        let appointment = generate_random_appointment(None);

        // If there is no appointment receipt for the given (locator, tower_id) pair, Error::NotFound is returned
        // Try first with both being unknown
        assert!(storage
            .load_appointment_receipt(tower_id, appointment.locator)
            .is_none());

        // Add the tower but not the appointment and try again
        let net_addr = "talaia.watch";
        let receipt = get_random_registration_receipt();
        storage
            .store_tower_record(tower_id, net_addr, &receipt)
            .unwrap();

        assert!(storage
            .load_appointment_receipt(tower_id, appointment.locator)
            .is_none());

        // Add both
        let tower_summary = TowerSummary::new(
            net_addr.to_owned(),
            receipt.available_slots(),
            receipt.subscription_start(),
            receipt.subscription_expiry(),
        );
        let appointment_receipt = AppointmentReceipt::with_signature(
            "user_signature".to_owned(),
            42,
            "tower_signature".to_owned(),
        );
        storage
            .store_appointment_receipt(
                tower_id,
                appointment.locator,
                tower_summary.available_slots,
                &appointment_receipt,
            )
            .unwrap();

        assert_eq!(
            storage
                .load_appointment_receipt(tower_id, appointment.locator)
                .unwrap(),
            appointment_receipt
        );
    }

    #[test]
    fn test_load_appointment_locators() {
        // `load_appointment_locators` is used to load locators from either `appointment_receipts`, `pending_appointments` or `invalid_appointments`
        let mut storage = create_test_kv_storage();

        // We first need to add a tower record to the database so we can add some associated data.
        let tower_id = get_random_user_id();
        let net_addr = "talaia.watch";

        let receipt = get_random_registration_receipt();
        let tower_summary = TowerSummary::new(
            net_addr.to_owned(),
            receipt.available_slots(),
            receipt.subscription_start(),
            receipt.subscription_expiry(),
        );
        storage
            .store_tower_record(tower_id, net_addr, &receipt)
            .unwrap();

        // Create all types of appointments and store them in the db.
        let user_signature = "user_signature";
        let mut receipts = HashSet::new();
        let mut pending_appointments = HashSet::new();
        let mut invalid_appointments = HashSet::new();
        for _ in 0..5 {
            let appointment = generate_random_appointment(None);
            let appointment_receipt = AppointmentReceipt::with_signature(
                user_signature.to_owned(),
                42,
                "tower_signature".to_owned(),
            );
            let pending_appointment = generate_random_appointment(None);
            let invalid_appointment = generate_random_appointment(None);

            storage
                .store_appointment_receipt(
                    tower_id,
                    appointment.locator,
                    tower_summary.available_slots,
                    &appointment_receipt,
                )
                .unwrap();
            storage
                .store_pending_appointment(tower_id, &pending_appointment)
                .unwrap();
            storage
                .store_invalid_appointment(tower_id, &invalid_appointment)
                .unwrap();

            receipts.insert(appointment.locator);
            pending_appointments.insert(pending_appointment.locator);
            invalid_appointments.insert(invalid_appointment.locator);
        }

        // Pull data from the db and check it matches the expected data
        assert_eq!(
            storage.load_appointment_locators(tower_id, AppointmentStatus::Accepted),
            receipts
        );
        assert_eq!(
            storage.load_appointment_locators(tower_id, AppointmentStatus::Pending),
            pending_appointments
        );
        assert_eq!(
            storage.load_appointment_locators(tower_id, AppointmentStatus::Invalid),
            invalid_appointments
        );
    }

    #[test]
    fn test_store_load_appointment() {
        let mut storage = create_test_kv_storage();

        let appointment = generate_random_appointment(None);
        storage.store_appointment(&appointment).unwrap();

        let loaded_appointment = storage.load_appointment(appointment.locator);
        assert_eq!(appointment, loaded_appointment.unwrap());
    }

    #[test]
    fn test_store_load_appointment_inexistent() {
        let storage = create_test_kv_storage();

        let locator = generate_random_appointment(None).locator;
        let loaded_appointment = storage.load_appointment(locator);
        assert!(loaded_appointment.is_none());
    }

    #[test]
    fn test_store_pending_appointment() {
        let mut storage = create_test_kv_storage();

        // In order to add a tower record we need to associated registration receipt.
        let tower_id = get_random_user_id();
        let net_addr = "talaia.watch";

        let receipt = get_random_registration_receipt();
        let mut tower_summary = TowerSummary::new(
            net_addr.to_owned(),
            receipt.available_slots(),
            receipt.subscription_start(),
            receipt.subscription_expiry(),
        )
        .with_status(TowerStatus::TemporaryUnreachable);

        storage
            .store_tower_record(tower_id, net_addr, &receipt)
            .unwrap();

        // Add some pending appointments and check they match
        for _ in 0..5 {
            let appointment = generate_random_appointment(None);

            tower_summary
                .pending_appointments
                .insert(appointment.locator);

            storage
                .store_pending_appointment(tower_id, &appointment)
                .unwrap();
            assert_eq!(
                TowerSummary::from(storage.load_tower_record(tower_id).unwrap()),
                tower_summary
            );
        }
    }

    #[test]
    fn test_store_pending_appointment_twice() {
        let mut storage = create_test_kv_storage();

        // In order to add a tower record we need to associated registration receipt.
        let tower_id_1 = get_random_user_id();
        let tower_id_2 = get_random_user_id();
        let net_addr = "talaia.watch";

        let receipt = get_random_registration_receipt();
        storage
            .store_tower_record(tower_id_1, net_addr, &receipt)
            .unwrap();
        storage
            .store_tower_record(tower_id_2, net_addr, &receipt)
            .unwrap();

        // If the same appointment is stored twice (by different towers) it should go through
        // Since the appointment data will be stored only once and this will create two references
        let appointment = generate_random_appointment(None);
        storage
            .store_pending_appointment(tower_id_1, &appointment)
            .unwrap();
        storage
            .store_pending_appointment(tower_id_2, &appointment)
            .unwrap();

        // If this is called twice with for the same tower it will fail, since two identical references
        // can not exist. This is intended behavior and should not happen
        assert!(storage
            .store_pending_appointment(tower_id_2, &appointment)
            .is_err());
    }

    #[test]
    fn test_delete_pending_appointment() {
        let mut storage = create_test_kv_storage();

        // In order to add a tower record we need to associated registration receipt.
        let tower_id = get_random_user_id();
        let net_addr = "talaia.watch";

        let receipt = get_random_registration_receipt();
        storage
            .store_tower_record(tower_id, net_addr, &receipt)
            .unwrap();

        // Add a single one, remove it later
        let appointment = generate_random_appointment(None);
        storage
            .store_pending_appointment(tower_id, &appointment)
            .unwrap();
        assert!(storage
            .delete_pending_appointment(tower_id, appointment.locator)
            .is_ok());

        // The appointment should be completely gone
        assert!(!storage
            .load_appointment_locators(tower_id, AppointmentStatus::Pending)
            .contains(&appointment.locator));

        assert!(!storage.appointment_exists(appointment.locator));

        // Try again with more than one reference
        let another_tower_id = get_random_user_id();
        storage
            .store_tower_record(another_tower_id, net_addr, &receipt)
            .unwrap();

        // Add two
        storage
            .store_pending_appointment(tower_id, &appointment)
            .unwrap();
        storage
            .store_pending_appointment(another_tower_id, &appointment)
            .unwrap();
        // Delete one
        assert!(storage
            .delete_pending_appointment(tower_id, appointment.locator)
            .is_ok());
        // Check
        assert!(!storage
            .load_appointment_locators(tower_id, AppointmentStatus::Pending)
            .contains(&appointment.locator));
        assert!(storage
            .load_appointment_locators(another_tower_id, AppointmentStatus::Pending)
            .contains(&appointment.locator));
        assert!(storage.appointment_exists(appointment.locator));

        // Add an invalid reference and check again
        storage
            .store_invalid_appointment(tower_id, &appointment)
            .unwrap();
        assert!(storage
            .delete_pending_appointment(another_tower_id, appointment.locator)
            .is_ok());
        assert!(!storage
            .load_appointment_locators(another_tower_id, AppointmentStatus::Pending)
            .contains(&appointment.locator));
        assert!(storage
            .load_appointment_locators(tower_id, AppointmentStatus::Invalid)
            .contains(&appointment.locator));
        assert!(storage.appointment_exists(appointment.locator));
    }

    #[test]
    fn test_store_invalid_appointment() {
        let mut storage = create_test_kv_storage();

        // In order to add a tower record we need to associated registration receipt.
        let tower_id = get_random_user_id();
        let net_addr = "talaia.watch";

        let receipt = get_random_registration_receipt();
        let mut tower_summary = TowerSummary::new(
            net_addr.to_owned(),
            receipt.available_slots(),
            receipt.subscription_start(),
            receipt.subscription_expiry(),
        );
        storage
            .store_tower_record(tower_id, net_addr, &receipt)
            .unwrap();

        // Add some invalid appointments and check they match
        for _ in 0..5 {
            let appointment = generate_random_appointment(None);

            tower_summary
                .invalid_appointments
                .insert(appointment.locator);

            storage
                .store_invalid_appointment(tower_id, &appointment)
                .unwrap();
            assert_eq!(
                TowerSummary::from(storage.load_tower_record(tower_id).unwrap()),
                tower_summary
            );
        }
    }

    #[test]
    fn test_store_invalid_appointment_twice() {
        let mut storage = create_test_kv_storage();

        // In order to add a tower record we need to associated registration receipt.
        let tower_id_1 = get_random_user_id();
        let tower_id_2 = get_random_user_id();
        let net_addr = "talaia.watch";

        let receipt = get_random_registration_receipt();
        storage
            .store_tower_record(tower_id_1, net_addr, &receipt)
            .unwrap();
        storage
            .store_tower_record(tower_id_2, net_addr, &receipt)
            .unwrap();

        // Same as with pending appointments. Two references from different towers is allowed
        let appointment = generate_random_appointment(None);
        storage
            .store_invalid_appointment(tower_id_1, &appointment)
            .unwrap();
        storage
            .store_invalid_appointment(tower_id_2, &appointment)
            .unwrap();

        // Two references from the same tower is not.
        assert!(storage
            .store_invalid_appointment(tower_id_2, &appointment)
            .is_err());
    }

    #[test]
    fn test_store_load_misbehaving_proof() {
        let mut storage = create_test_kv_storage();

        // In order to add a tower record we need to associated registration receipt.
        let tower_id = get_random_user_id();
        let net_addr = "talaia.watch";

        let receipt = get_random_registration_receipt();
        let tower_summary = TowerSummary::new(
            net_addr.to_owned(),
            receipt.available_slots(),
            receipt.subscription_start(),
            receipt.subscription_expiry(),
        );
        storage
            .store_tower_record(tower_id, net_addr, &receipt)
            .unwrap();
        assert_eq!(
            TowerSummary::from(storage.load_tower_record(tower_id).unwrap()),
            tower_summary
        );

        // Store a misbehaving proof and load it back
        let appointment = generate_random_appointment(None);
        let appointment_receipt = AppointmentReceipt::with_signature(
            "user_signature".to_owned(),
            42,
            "tower_signature".to_owned(),
        );

        let proof = MisbehaviorProof::new(
            appointment.locator,
            appointment_receipt,
            get_random_user_id(),
        );

        storage.store_misbehaving_proof(tower_id, &proof).unwrap();
        assert_eq!(storage.load_misbehaving_proof(tower_id).unwrap(), proof);
    }

    #[test]
    fn test_store_load_non_existing_misbehaving_proof() {
        let storage = create_test_kv_storage();
        assert!(storage
            .load_misbehaving_proof(get_random_user_id())
            .is_none());
    }

    #[test]
    fn test_store_exists_misbehaving_proof() {
        let mut storage = create_test_kv_storage();

        // In order to add a tower record we need to associated registration receipt.
        let tower_id = get_random_user_id();
        let net_addr = "talaia.watch";

        let receipt = get_random_registration_receipt();
        let tower_summary = TowerSummary::new(
            net_addr.to_owned(),
            receipt.available_slots(),
            receipt.subscription_start(),
            receipt.subscription_expiry(),
        );
        storage
            .store_tower_record(tower_id, net_addr, &receipt)
            .unwrap();
        assert_eq!(
            TowerSummary::from(storage.load_tower_record(tower_id).unwrap()),
            tower_summary
        );

        // // Store a misbehaving proof check
        let appointment = generate_random_appointment(None);
        let appointment_receipt = AppointmentReceipt::with_signature(
            "user_signature".to_owned(),
            42,
            "tower_signature".to_owned(),
        );

        let proof = MisbehaviorProof::new(
            appointment.locator,
            appointment_receipt,
            get_random_user_id(),
        );

        storage.store_misbehaving_proof(tower_id, &proof).unwrap();
        assert!(storage.exists_misbehaving_proof(tower_id));
    }

    #[test]
    fn test_exists_misbehaving_proof_false() {
        let storage = create_test_kv_storage();
        assert!(!storage.exists_misbehaving_proof(get_random_user_id()));
    }
}
