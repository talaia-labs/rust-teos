use std::collections::{HashMap, HashSet};
use std::fmt;

use teos_common::appointment::{Appointment, Locator};
use teos_common::receipts::{AppointmentReceipt, RegistrationReceipt};
use teos_common::{TowerId, UserId};

use crate::{AppointmentStatus, MisbehaviorProof, TowerInfo, TowerSummary};

/// A general storage error type that can be used across different storage implementations
#[derive(Debug)]
pub enum StorageError {
    /// Error when storing data
    StoreError(String),
    /// Error when retrieving data
    RetrievalError(String),
    /// Error when data is not found
    NotFound(String),
    /// Any other storage-related error
    Other(String),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::StoreError(msg) => write!(f, "Storage store error: {}", msg),
            StorageError::RetrievalError(msg) => write!(f, "Storage retrieval error: {}", msg),
            StorageError::NotFound(msg) => write!(f, "Data not found: {}", msg),
            StorageError::Other(msg) => write!(f, "Storage error: {}", msg),
        }
    }
}

impl std::error::Error for StorageError {}

/// Trait defining the interface for database operations
pub trait Persister {
    /// Stores a tower record into the database alongside the corresponding registration receipt.
    ///
    /// This function MUST be guarded against inserting duplicate (tower_id, subscription_expiry) pairs.
    /// This is currently done in WTClient::add_update_tower.
    fn store_tower_record(
        &mut self,
        tower_id: TowerId,
        net_addr: &str,
        receipt: &RegistrationReceipt,
    ) -> Result<(), StorageError>;

    /// Loads a tower record from the database.
    ///
    /// Tower records are composed from the tower information and the appointment data. The latter is split in:
    /// accepted appointments (represented by appointment receipts), pending appointments and invalid appointments.
    /// In the case that the tower has misbehaved, then a misbehaving proof is also attached to the record.
    fn load_tower_record(&self, tower_id: TowerId) -> Option<TowerInfo>;

    /// Loads the latest registration receipt for a given tower.
    ///
    /// Latests is determined by the one with the `subscription_expiry` further into the future.
    fn load_registration_receipt(
        &self,
        tower_id: TowerId,
        user_id: UserId,
    ) -> Option<RegistrationReceipt>;

    /// Removes a tower record from the database.
    ///
    /// This triggers a cascade deletion of all related data, such as appointments, appointment receipts, etc. As long as there is a single
    /// reference to them.
    fn remove_tower_record(&self, tower_id: TowerId) -> Result<(), StorageError>;

    /// Loads all tower records from the database.
    fn load_towers(&self) -> HashMap<TowerId, TowerSummary>;

    /// Stores an appointments receipt into the database representing an appointment accepted by a given tower.
    fn store_appointment_receipt(
        &mut self,
        tower_id: TowerId,
        locator: Locator,
        available_slots: u32,
        receipt: &AppointmentReceipt,
    ) -> Result<(), StorageError>;

    /// Loads a given appointment receipt of a given tower from the database.
    fn load_appointment_receipt(
        &self,
        tower_id: TowerId,
        locator: Locator,
    ) -> Option<AppointmentReceipt>;

    /// Loads the appointment receipts associated to a given tower.
    ///
    /// TODO: Currently this is only loading a summary of the receipt, if we need to really load all the information
    /// for any reason this method may need to be renamed.
    fn load_appointment_receipts(&self, tower_id: TowerId) -> HashMap<Locator, String>;

    /// Loads a collection of locators from the database entry associated to a given tower.
    ///
    /// The loaded locators can be loaded either from appointment_receipts, pending_appointments or invalid_appointments
    ///  depending on `status`.
    fn load_appointment_locators(
        &self,
        tower_id: TowerId,
        status: AppointmentStatus,
    ) -> HashSet<Locator>;

    /// Loads an appointment from the database.
    fn load_appointment(&self, locator: Locator) -> Option<Appointment>;

    /// Stores a pending appointment into the database.
    ///
    /// A pending appointment is an appointment that was sent to a tower when it was unreachable.
    /// This data is stored so it can be resent once the tower comes back online.
    /// Internally calls [Self::store_appointment].
    fn store_pending_appointment(
        &mut self,
        tower_id: TowerId,
        appointment: &Appointment,
    ) -> Result<(), StorageError>;

    /// Removes a pending appointment from the database.
    ///
    /// If the pending appointment is the only instance of the appointment, the appointment will also be deleted form the appointments table.
    fn delete_pending_appointment(
        &mut self,
        tower_id: TowerId,
        locator: Locator,
    ) -> Result<(), StorageError>;

    /// Stores an invalid appointment into the database.
    ///
    /// An invalid appointment is an appointment that was rejected by the tower.
    /// Storing this data may allow us to see what was the issue and send the data later on.
    /// Internally calls [Self::store_appointment].
    fn store_invalid_appointment(
        &mut self,
        tower_id: TowerId,
        appointment: &Appointment,
    ) -> Result<(), StorageError>;

    /// Loads non finalized appointments from the database for a given tower based on a status flag.
    ///
    /// This is meant to be used only for pending and invalid appointments, if the method is called for
    /// accepted appointment, an empty collection will be returned.
    fn load_appointments(
        &self,
        tower_id: TowerId,
        status: AppointmentStatus,
    ) -> Vec<Appointment>;

    /// Stores a misbehaving proof into the database.
    ///
    /// A misbehaving proof is proof that the tower has signed an appointment using a key different
    /// than the one advertised to the user when they registered.
    fn store_misbehaving_proof(
        &mut self,
        tower_id: TowerId,
        proof: &MisbehaviorProof,
    ) -> Result<(), StorageError>;
}
