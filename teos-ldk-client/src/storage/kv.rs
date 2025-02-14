use std::collections::{HashMap, HashSet};
// use chacha20poly1305::aead::{Aead};
use std::sync::Arc;

use crate::storage::persister::{Persister, PersisterError};
// use bitcoin::secp256k1::SecretKey;
use lightning::io::Error as DBError;

use lightning::util::persist::KVStore;
use teos_common::appointment::{Appointment, Locator};
use teos_common::receipts::{AppointmentReceipt, RegistrationReceipt};
use teos_common::{TowerId, UserId};
// use teos_common::cryptography;

// use chacha20poly1305::aead::{Aead, NewAead};
// use rand::distributions::Uniform;
// use rand::Rng;

// use bitcoin::consensus;
// use bitcoin::secp256k1::{Error, PublicKey, Secp256k1, SecretKey};
// use bitcoin::{Transaction, Txid};
// use lightning::util::message_signing;

impl From<DBError> for PersisterError {
    fn from(error: DBError) -> Self {
        PersisterError::Other(error.to_string())
    }
}

use crate::{AppointmentStatus, MisbehaviorProof, TowerInfo, TowerSummary};

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
const NS_AVAILABLE_SLOTS: &str = "available_slots";

pub type DynStore = dyn KVStore + Sync + Send;

/// Enum representing the possible errors when decrypting an encrypted blob.
#[derive(Debug)]
pub enum DecryptingError {
    AED(chacha20poly1305::aead::Error),
    Encode(bitcoin::consensus::encode::Error),
}

pub struct KVStorage {
    store: Arc<DynStore>,
    sk: Vec<u8>,
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

// Implement methods to convert TowerInfo to vec<u8> and vice versa

impl KVStorage {
    pub fn new(store: Arc<DynStore>, sk: Vec<u8>) -> Result<Self, PersisterError> {
        Ok(KVStorage { store, sk })
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
        let key = make_key(&[&tower_id.to_string()]);

        if let Ok(existing) = self.store.read(PRIMARY_NAMESPACE, NS_TOWER_RECORDS, &key) {
            let decrypted = decrypt(&existing, &self.sk).unwrap();
            let existing_tower_info: TowerInfo = bincode::deserialize(&decrypted).unwrap();
            if existing_tower_info.subscription_expiry > receipt.subscription_expiry() {
                return Ok(());
            }
        };

        let tower_info = TowerInfo::new(
            net_addr.to_string(),
            receipt.available_slots(),
            receipt.subscription_start(),
            receipt.subscription_expiry(),
            HashMap::new(),
            Vec::new(),
            Vec::new(),
        );

        let tower_info = bincode::serialize(&tower_info)
            .map_err(|e| PersisterError::Other(format!("Serialization error: {}", e)))?;

        let encrypted = encrypt(&tower_info, &self.sk).unwrap();

        self.store
            .write(PRIMARY_NAMESPACE, NS_TOWER_RECORDS, &key, &encrypted)
            .map_err(|e| PersisterError::StoreError(e.to_string()))
            .unwrap();

        let registration_receipt = bincode::serialize(&receipt)
            .map_err(|e| PersisterError::Other(format!("Serialization error: {}", e)))?;

        let encrypted = encrypt(&registration_receipt, &self.sk).unwrap();

        self.store
            .write(
                PRIMARY_NAMESPACE,
                NS_AVAILABLE_SLOTS,
                &key,
                receipt.available_slots().to_be_bytes().as_ref(),
            )
            .map_err(|e| PersisterError::StoreError(e.to_string()))
            .unwrap();

        match self.store.write(
            PRIMARY_NAMESPACE,
            NS_REGISTRATION_RECEIPTS,
            &key,
            &encrypted,
        ) {
            Ok(_) => Ok(()),
            Err(e) => {
                self.remove_tower_record(tower_id).unwrap();
                Err(PersisterError::StoreError(e.to_string()))
            }
        }
    }

    /// Loads a tower record from the database.
    ///
    /// Tower records are composed from the tower information and the appointment data. The latter is split in:
    /// accepted appointments (represented by appointment receipts), pending appointments and invalid appointments.
    /// In the case that the tower has misbehaved, then a misbehaving proof is also attached to the record.
    fn load_tower_record(&self, tower_id: TowerId) -> Option<TowerInfo> {
        let key = make_key(&[&tower_id.to_string()]);
        let value = match self.store.read(PRIMARY_NAMESPACE, NS_TOWER_RECORDS, &key) {
            Ok(v) => v,
            Err(_) => return None,
        };

        let decrypted = decrypt(&value, &self.sk).unwrap();
        let mut tower_info: TowerInfo = bincode::deserialize(&decrypted).ok()?;

        // TODO:
        // tower_info.appointments = self.load_appointment_receipts(tower_id);
        // tower_info.pending_appointments =
        //     self.load_appointments(tower_id, AppointmentStatus::Pending);
        // tower_info.invalid_appointments =
        //     self.load_appointments(tower_id, AppointmentStatus::Invalid);
        tower_info.available_slots =
            match self.store.read(PRIMARY_NAMESPACE, NS_AVAILABLE_SLOTS, &key) {
                Ok(bytes) if bytes.len() >= 4 => {
                    let mut buf = [0u8; 4];
                    buf.copy_from_slice(&bytes[0..4]);
                    u32::from_be_bytes(buf)
                }
                _ => 0,
            };

        Some(tower_info)
    }

    /// Removes a tower record from the database.
    ///
    /// This triggers a cascade deletion of all related data, such as appointments, appointment receipts, etc. As long as there is a single
    /// reference to them.
    fn remove_tower_record(&self, tower_id: TowerId) -> Result<(), PersisterError> {
        let key = make_key(&[&tower_id.to_string()]);
        self.store
            .remove(PRIMARY_NAMESPACE, NS_TOWER_RECORDS, &key, true)
            .map_err(|e| PersisterError::NotFound(format!("tower_id: {tower_id}")))
    }

    /// Loads all tower records from the database.
    ///
    /// Returns a key value pair with the tower id as key and the tower summary as value.
    fn load_towers(&self) -> HashMap<TowerId, TowerSummary> {
        let mut towers = HashMap::new();
        let keys = self
            .store
            .list(PRIMARY_NAMESPACE, NS_TOWER_RECORDS)
            .unwrap();

        for key in keys {
            let tower_id = key.split(":").next().unwrap().parse().unwrap();
            let tower_info = self.load_tower_record(tower_id).unwrap();
            towers.insert(tower_id, TowerSummary::from(tower_info));
        }

        towers
    }

    /// Loads the latest registration receipt for a given tower.
    ///
    /// Latests is determined by the one with the `subscription_expiry` further into the future.
    fn load_registration_receipt(
        &self,
        tower_id: TowerId,
        user_id: UserId,
    ) -> Option<RegistrationReceipt> {
        let key = make_key(&[&tower_id.to_string()]);

        match self
            .store
            .read(PRIMARY_NAMESPACE, NS_REGISTRATION_RECEIPTS, &key)
        {
            Ok(value) => {
                let decrypted = decrypt(&value, &self.sk).unwrap();
                let registration_receipt: RegistrationReceipt =
                    bincode::deserialize(&decrypted).unwrap();
                Some(RegistrationReceipt::with_signature(
                    user_id,
                    registration_receipt.available_slots(),
                    registration_receipt.subscription_start(),
                    registration_receipt.subscription_expiry(),
                    registration_receipt.signature().unwrap(),
                ))
            }
            Err(_) => None,
        }
    }

    /// Stores an appointments receipt into the database representing an appointment accepted by a given tower.
    fn store_appointment_receipt(
        &mut self,
        tower_id: TowerId,
        locator: Locator,
        available_slots: u32,
        receipt: &AppointmentReceipt,
    ) -> Result<(), PersisterError> {
        let tower_namespace = format!("{}:{}", NS_APPOINTMENT_RECEIPTS, tower_id);
        let key = locator.to_string();

        let encrypted = encrypt(&bincode::serialize(receipt).unwrap(), &self.sk).unwrap();

        self.store
            .write(PRIMARY_NAMESPACE, &tower_namespace, &key, &encrypted)
            .map_err(|e| PersisterError::StoreError(e.to_string()))
            .unwrap();

        // Update the tower's available_slots
        let slots_key = make_key(&[&tower_id.to_string()]);
        self.store
            .write(
                PRIMARY_NAMESPACE,
                NS_AVAILABLE_SLOTS,
                &slots_key,
                available_slots.to_be_bytes().as_ref(),
            )
            .map_err(|e| PersisterError::StoreError(e.to_string()))
            .unwrap();

        Ok(())
    }

    /// Loads a given appointment receipt of a given tower from the database.
    fn load_appointment_receipt(
        &self,
        tower_id: TowerId,
        locator: Locator,
    ) -> Option<AppointmentReceipt> {
        let tower_namespace = format!("{}:{}", NS_APPOINTMENT_RECEIPTS, tower_id);
        let key = locator.to_string();

        match self.store.read(PRIMARY_NAMESPACE, &tower_namespace, &key) {
            Ok(value) => {
                let decrypted = decrypt(&value, &self.sk).unwrap();
                Some(bincode::deserialize(&decrypted).unwrap())
            }
            Err(_) => None,
        }
    }

    /// Loads the appointment receipts associated to a given tower.
    ///
    /// TODO: Currently this is only loading a summary of the receipt, if we need to really load all the information
    /// for any reason this method may need to be renamed.
    fn load_appointment_receipts(&self, tower_id: TowerId) -> HashMap<Locator, String> {
        let mut receipts = HashMap::new();
        let tower_namespace = format!("{}:{}", NS_APPOINTMENT_RECEIPTS, tower_id);

        let keys = self
            .store
            .list(PRIMARY_NAMESPACE, &tower_namespace)
            .unwrap();

        // Get all keys in the tower-specific namespace
        for key in keys {
            // Key is just the locator string
            let hex_encoded_string = key;
            let locator =
                match Locator::from_slice(hex::decode(&hex_encoded_string).unwrap().as_slice()) {
                    Ok(l) => l,
                    Err(s) => {
                        panic!("Error deserializing locator: {}", s);
                    }
                };
            // Try to read and decrypt the receipt
            let receipt = self.load_appointment_receipt(tower_id, locator).unwrap();
            if let Some(signature) = receipt.signature() {
                receipts.insert(locator, signature);
            }
        }

        receipts
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
        let mut result = HashSet::new();

        let appointment_namespace = get_appointment_namespace(status);

        let tower_namespace = format!("{}:{}", appointment_namespace, tower_id);

        let locators = self
            .store
            .list(PRIMARY_NAMESPACE, &tower_namespace)
            .map_err(|e| PersisterError::StoreError(e.to_string()))
            .unwrap();

        for locator in locators {
            result.insert(Locator::from_slice(hex::decode(&locator).unwrap().as_slice()).unwrap());
        }

        result
    }

    /// Loads an appointment from the database.
    fn load_appointment(&self, locator: Locator) -> Option<Appointment> {
        // primary namespace: "watchtower"
        // secondary namespance: "appointment_receipt"
        // key: <locator>
        todo!();
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
        let tower_namespace = format!("{}:{}", NS_PENDING_APPOINTMENTS, tower_id);
        let key = appointment.locator.to_string();

        let encrypted = encrypt(&bincode::serialize(appointment).unwrap(), &self.sk).unwrap();

        self.store
            .write(PRIMARY_NAMESPACE, &tower_namespace, &key, &encrypted)
            .map_err(|e| PersisterError::StoreError(e.to_string()))
            .unwrap();

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
        // let key = make_key(&[&tower_id.to_string(), &locator.to_string()]);
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
    fn store_invalid_appointment(
        &mut self,
        tower_id: TowerId,
        appointment: &Appointment,
    ) -> Result<(), PersisterError> {
        let tower_namespace = format!("{}:{}", NS_INVALID_APPOINTMENTS, tower_id);
        let key = appointment.locator.to_string();

        let encrypted = encrypt(&bincode::serialize(appointment).unwrap(), &self.sk).unwrap();

        self.store
            .write(PRIMARY_NAMESPACE, &tower_namespace, &key, &encrypted)
            .map_err(|e| PersisterError::StoreError(e.to_string()))
            .unwrap();

        Ok(())
    }

    /// Loads non finalized appointments from the database for a given tower based on a status flag.
    ///
    /// This is meant to be used only for pending and invalid appointments, if the method is called for
    /// accepted appointment, an empty collection will be returned.
    fn load_appointments(&self, tower_id: TowerId, status: AppointmentStatus) -> Vec<Appointment> {
        // let key = make_key(&[&tower_id.to_string()]);
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
    fn store_misbehaving_proof(
        &mut self,
        tower_id: TowerId,
        proof: &MisbehaviorProof,
    ) -> Result<(), PersisterError> {
        // let key = make_key(&[&tower_id.to_string()]);
        // primary namespace: "watchtower"
        // secondary namespance: "misbehaving_proof"
        // key: ?
        // value: ?
        todo!();
    }

    fn appointment_exists(&self, locator: Locator) -> bool {
        todo!();
    }

    fn appointment_receipt_exists(&self, locator: Locator, tower_id: TowerId) -> bool {
        todo!();
    }
}

/// Encrypts a given message under a given secret using `chacha20poly1305`.
///
/// The key material used is:
/// - The dispute txid as encryption key.
/// - `[0; 12]` as IV.
///
/// The message to be encrypted is expected to be the penalty transaction.
fn encrypt(message: &Vec<u8>, secret: &Vec<u8>) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
    // // Defaults is [0; 12]
    // let nonce = Nonce::default();
    // let k = sha256::Hash::hash(secret);
    // let key = Key::from_slice(k.as_byte_array());
    //
    // let cypher = ChaCha20Poly1305::new(key);
    //
    // cypher.encrypt(&nonce, message.to_vec().as_ref())
    Ok(message.clone())
}

/// Decrypts an encrypted blob of data using `chacha20poly1305` and a given secret.
///
/// The key material used is:
/// - The dispute txid as decryption key.
/// - `[0; 12]` as IV.
///
///  The result is expected to be a penalty transaction.
fn decrypt(
    encrypted_blob: &[u8],
    secret: &Vec<u8>,
) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
    // // Defaults is [0; 12]
    // let nonce = Nonce::default();
    // let k = sha256::Hash::hash(secret);
    // let key = Key::from_slice(k.as_byte_array());
    //
    // let cypher = ChaCha20Poly1305::new(key);
    //
    // cypher.decrypt(&nonce, encrypted_blob.as_ref())
    Ok(encrypted_blob.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStore;

    use teos_common::test_utils::{
        generate_random_appointment, get_random_registration_receipt, get_random_user_id,
        get_registration_receipt_from_previous,
    };

    fn create_test_storage() -> KVStorage {
        let store = MemoryStore::new().into_dyn_store();
        let sk = vec![0u8; 32]; // Test secret key
        KVStorage::new(store, sk).unwrap()
    }

    #[test]
    fn test_store_load_tower_record() {
        let mut storage = create_test_storage();

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
        let mut storage = create_test_storage();

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
        let mut storage = create_test_storage();

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
        let storage = create_test_storage();

        // If the tower does not exists, `load_tower` will fail.
        let tower_id = get_random_user_id();
        assert!(storage.load_tower_record(tower_id).is_none());
    }

    #[test]
    fn test_store_load_towers() {
        let mut storage = create_test_storage();
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
        let storage = create_test_storage();
        assert_eq!(storage.load_towers(), HashMap::new());
    }

    #[test]
    fn test_remove_tower_record() {
        let mut storage = create_test_storage();

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
        let storage = create_test_storage();
        let tower_id = get_random_user_id();
        let err = storage.remove_tower_record(tower_id).unwrap_err();
        assert_eq!(
            err,
            PersisterError::NotFound(format!("tower_id: {tower_id}"))
        );
    }

    #[test]
    fn test_store_load_appointment_receipts() {
        let mut storage = create_test_storage();

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
        let mut storage = create_test_storage();
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
        let mut storage = create_test_storage();

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

    // #[test]
    // fn test_store_load_appointment() {
    //     let mut dbm = DBM::in_memory().unwrap();
    //
    //     let appointment = generate_random_appointment(None);
    //     let tx = dbm.get_mut_connection().transaction().unwrap();
    //     DBM::store_appointment(&tx, &appointment).unwrap();
    //     tx.commit().unwrap();
    //
    //     let loaded_appointment = dbm.load_appointment(appointment.locator);
    //     assert_eq!(appointment, loaded_appointment.unwrap());
    // }
    //
    // #[test]
    // fn test_store_load_appointment_inexistent() {
    //     let dbm = DBM::in_memory().unwrap();
    //
    //     let locator = generate_random_appointment(None).locator;
    //     let loaded_appointment = dbm.load_appointment(locator);
    //     assert!(loaded_appointment.is_none());
    // }
    //
    // #[test]
    // fn test_store_pending_appointment() {
    //     let mut dbm = DBM::in_memory().unwrap();
    //
    //     // In order to add a tower record we need to associated registration receipt.
    //     let tower_id = get_random_user_id();
    //     let net_addr = "talaia.watch";
    //
    //     let receipt = get_random_registration_receipt();
    //     let mut tower_summary = TowerSummary::new(
    //         net_addr.to_owned(),
    //         receipt.available_slots(),
    //         receipt.subscription_start(),
    //         receipt.subscription_expiry(),
    //     )
    //     .with_status(TowerStatus::TemporaryUnreachable);
    //     dbm.store_tower_record(tower_id, net_addr, &receipt)
    //         .unwrap();
    //
    //     // Add some pending appointments and check they match
    //     for _ in 0..5 {
    //         let appointment = generate_random_appointment(None);
    //
    //         tower_summary
    //             .pending_appointments
    //             .insert(appointment.locator);
    //
    //         dbm.store_pending_appointment(tower_id, &appointment)
    //             .unwrap();
    //         assert_eq!(
    //             TowerSummary::from(dbm.load_tower_record(tower_id).unwrap()),
    //             tower_summary
    //         );
    //     }
    // }
    //
    // #[test]
    // fn test_store_pending_appointment_twice() {
    //     let mut dbm = DBM::in_memory().unwrap();
    //
    //     // In order to add a tower record we need to associated registration receipt.
    //     let tower_id_1 = get_random_user_id();
    //     let tower_id_2 = get_random_user_id();
    //     let net_addr = "talaia.watch";
    //
    //     let receipt = get_random_registration_receipt();
    //     dbm.store_tower_record(tower_id_1, net_addr, &receipt)
    //         .unwrap();
    //     dbm.store_tower_record(tower_id_2, net_addr, &receipt)
    //         .unwrap();
    //
    //     // If the same appointment is stored twice (by different towers) it should go through
    //     // Since the appointment data will be stored only once and this will create two references
    //     let appointment = generate_random_appointment(None);
    //     dbm.store_pending_appointment(tower_id_1, &appointment)
    //         .unwrap();
    //     dbm.store_pending_appointment(tower_id_2, &appointment)
    //         .unwrap();
    //
    //     // If this is called twice with for the same tower it will fail, since two identical references
    //     // can not exist. This is intended behavior and should not happen
    //     assert!(dbm
    //         .store_pending_appointment(tower_id_2, &appointment)
    //         .is_err());
    // }
    //
    // #[test]
    // fn test_delete_pending_appointment() {
    //     let mut dbm = DBM::in_memory().unwrap();
    //
    //     // In order to add a tower record we need to associated registration receipt.
    //     let tower_id = get_random_user_id();
    //     let net_addr = "talaia.watch";
    //
    //     let receipt = get_random_registration_receipt();
    //     dbm.store_tower_record(tower_id, net_addr, &receipt)
    //         .unwrap();
    //
    //     // Add a single one, remove it later
    //     let appointment = generate_random_appointment(None);
    //     dbm.store_pending_appointment(tower_id, &appointment)
    //         .unwrap();
    //     assert!(dbm
    //         .delete_pending_appointment(tower_id, appointment.locator)
    //         .is_ok());
    //
    //     // The appointment should be completely gone
    //     assert!(!dbm
    //         .load_appointment_locators(tower_id, AppointmentStatus::Pending)
    //         .contains(&appointment.locator));
    //     // assert!(!dbm.appointment_exists(appointment.locator));
    //
    //     // Try again with more than one reference
    //     let another_tower_id = get_random_user_id();
    //     dbm.store_tower_record(another_tower_id, net_addr, &receipt)
    //         .unwrap();
    //
    //     // Add two
    //     dbm.store_pending_appointment(tower_id, &appointment)
    //         .unwrap();
    //     dbm.store_pending_appointment(another_tower_id, &appointment)
    //         .unwrap();
    //     // Delete one
    //     assert!(dbm
    //         .delete_pending_appointment(tower_id, appointment.locator)
    //         .is_ok());
    //     // Check
    //     assert!(!dbm
    //         .load_appointment_locators(tower_id, AppointmentStatus::Pending)
    //         .contains(&appointment.locator));
    //     assert!(dbm
    //         .load_appointment_locators(another_tower_id, AppointmentStatus::Pending)
    //         .contains(&appointment.locator));
    //     // assert!(dbm.appointment_exists(appointment.locator));
    //
    //     // Add an invalid reference and check again
    //     dbm.store_invalid_appointment(tower_id, &appointment)
    //         .unwrap();
    //     assert!(dbm
    //         .delete_pending_appointment(another_tower_id, appointment.locator)
    //         .is_ok());
    //     assert!(!dbm
    //         .load_appointment_locators(another_tower_id, AppointmentStatus::Pending)
    //         .contains(&appointment.locator));
    //     assert!(dbm
    //         .load_appointment_locators(tower_id, AppointmentStatus::Invalid)
    //         .contains(&appointment.locator));
    //     // assert!(dbm.appointment_exists(appointment.locator));
    // }
    //
    // #[test]
    // fn test_store_invalid_appointment() {
    //     let mut dbm = DBM::in_memory().unwrap();
    //
    //     // In order to add a tower record we need to associated registration receipt.
    //     let tower_id = get_random_user_id();
    //     let net_addr = "talaia.watch";
    //
    //     let receipt = get_random_registration_receipt();
    //     let mut tower_summary = TowerSummary::new(
    //         net_addr.to_owned(),
    //         receipt.available_slots(),
    //         receipt.subscription_start(),
    //         receipt.subscription_expiry(),
    //     );
    //     dbm.store_tower_record(tower_id, net_addr, &receipt)
    //         .unwrap();
    //
    //     // Add some invalid appointments and check they match
    //     for _ in 0..5 {
    //         let appointment = generate_random_appointment(None);
    //
    //         tower_summary
    //             .invalid_appointments
    //             .insert(appointment.locator);
    //
    //         dbm.store_invalid_appointment(tower_id, &appointment)
    //             .unwrap();
    //         assert_eq!(
    //             TowerSummary::from(dbm.load_tower_record(tower_id).unwrap()),
    //             tower_summary
    //         );
    //     }
    // }
    //
    // #[test]
    // fn test_store_invalid_appointment_twice() {
    //     let mut dbm = DBM::in_memory().unwrap();
    //
    //     // In order to add a tower record we need to associated registration receipt.
    //     let tower_id_1 = get_random_user_id();
    //     let tower_id_2 = get_random_user_id();
    //     let net_addr = "talaia.watch";
    //
    //     let receipt = get_random_registration_receipt();
    //     dbm.store_tower_record(tower_id_1, net_addr, &receipt)
    //         .unwrap();
    //     dbm.store_tower_record(tower_id_2, net_addr, &receipt)
    //         .unwrap();
    //
    //     // Same as with pending appointments. Two references from different towers is allowed
    //     let appointment = generate_random_appointment(None);
    //     dbm.store_invalid_appointment(tower_id_1, &appointment)
    //         .unwrap();
    //     dbm.store_invalid_appointment(tower_id_2, &appointment)
    //         .unwrap();
    //
    //     // Two references from the same tower is not.
    //     assert!(dbm
    //         .store_invalid_appointment(tower_id_2, &appointment)
    //         .is_err());
    // }
    //
    // #[test]
    // fn test_store_load_misbehaving_proof() {
    //     let mut dbm = DBM::in_memory().unwrap();
    //
    //     // In order to add a tower record we need to associated registration receipt.
    //     let tower_id = get_random_user_id();
    //     let net_addr = "talaia.watch";
    //
    //     let receipt = get_random_registration_receipt();
    //     let tower_summary = TowerSummary::new(
    //         net_addr.to_owned(),
    //         receipt.available_slots(),
    //         receipt.subscription_start(),
    //         receipt.subscription_expiry(),
    //     );
    //     dbm.store_tower_record(tower_id, net_addr, &receipt)
    //         .unwrap();
    //     assert_eq!(
    //         TowerSummary::from(dbm.load_tower_record(tower_id).unwrap()),
    //         tower_summary
    //     );
    //
    //     // Store a misbehaving proof and load it back
    //     let appointment = generate_random_appointment(None);
    //     let appointment_receipt = AppointmentReceipt::with_signature(
    //         "user_signature".to_owned(),
    //         42,
    //         "tower_signature".to_owned(),
    //     );
    //
    //     let proof = MisbehaviorProof::new(
    //         appointment.locator,
    //         appointment_receipt,
    //         get_random_user_id(),
    //     );
    //
    //     dbm.store_misbehaving_proof(tower_id, &proof).unwrap();
    //     assert_eq!(dbm.load_misbehaving_proof(tower_id).unwrap(), proof);
    // }
    //
    // #[test]
    // fn test_store_load_non_existing_misbehaving_proof() {
    //     let dbm = DBM::in_memory().unwrap();
    //     assert!(dbm.load_misbehaving_proof(get_random_user_id()).is_none());
    // }
    //
    // #[test]
    // fn test_store_exists_misbehaving_proof() {
    //     let mut dbm = DBM::in_memory().unwrap();
    //
    //     // In order to add a tower record we need to associated registration receipt.
    //     let tower_id = get_random_user_id();
    //     let net_addr = "talaia.watch";
    //
    //     let receipt = get_random_registration_receipt();
    //     let tower_summary = TowerSummary::new(
    //         net_addr.to_owned(),
    //         receipt.available_slots(),
    //         receipt.subscription_start(),
    //         receipt.subscription_expiry(),
    //     );
    //     dbm.store_tower_record(tower_id, net_addr, &receipt)
    //         .unwrap();
    //     assert_eq!(
    //         TowerSummary::from(dbm.load_tower_record(tower_id).unwrap()),
    //         tower_summary
    //     );
    //
    //     // // Store a misbehaving proof check
    //     let appointment = generate_random_appointment(None);
    //     let appointment_receipt = AppointmentReceipt::with_signature(
    //         "user_signature".to_owned(),
    //         42,
    //         "tower_signature".to_owned(),
    //     );
    //
    //     let proof = MisbehaviorProof::new(
    //         appointment.locator,
    //         appointment_receipt,
    //         get_random_user_id(),
    //     );
    //
    //     dbm.store_misbehaving_proof(tower_id, &proof).unwrap();
    //     assert!(dbm.exists_misbehaving_proof(tower_id));
    // }
    //
    // #[test]
    // fn test_exists_misbehaving_proof_false() {
    //     let dbm = DBM::in_memory().unwrap();
    //     assert!(!dbm.exists_misbehaving_proof(get_random_user_id()));
    // }
}
