use teos_common::appointment::Locator;
use teos_common::TowerId;

use crate::AppointmentStatus;

/// Namespace constants for the storage system
pub mod constants {
    /// Primary namespace for all watchtower-related data
    pub const PRIMARY: &str = "watchtower";

    /// Secondary namespace constants
    pub mod secondary {
        pub const TOWER_RECORDS: &str = "tower_records";
        pub const REGISTRATION_RECEIPTS: &str = "registration_receipts";
        pub const APPOINTMENT_RECEIPTS: &str = "appointment_receipts";
        pub const APPOINTMENTS: &str = "appointments";
        pub const PENDING_APPOINTMENTS: &str = "appointments_pending";
        pub const INVALID_APPOINTMENTS: &str = "appointments_invalid";
        pub const MISBEHAVIOR_PROOFS: &str = "misbehavior_proofs";
        pub const AVAILABLE_SLOTS: &str = "available_slots";
    }
}

use constants::secondary::*;
use constants::*;

/// Gets the appropriate namespace based on appointment status
pub(crate) fn get_appointment_namespace(status: AppointmentStatus) -> NameSpace {
    match status {
        AppointmentStatus::Accepted => NameSpace::appointment_receipts(),
        AppointmentStatus::Pending => NameSpace::pending_appointments(),
        AppointmentStatus::Invalid => NameSpace::invalid_appointments(),
    }
}

/// Represents a namespace in the storage system
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct NameSpace {
    primary_namespace: String,
    secondary_namespace: String,
}

impl NameSpace {
    /// Returns the primary namespace
    pub fn primary(&self) -> &str {
        &self.primary_namespace
    }

    /// Returns the secondary namespace  
    pub fn secondary(&self) -> &str {
        &self.secondary_namespace
    }
}

impl NameSpace {
    /// Creates a KeySpace from this namespace
    pub fn with_key(&self, key: impl Into<String>) -> KeySpace {
        KeySpace::new(self.clone(), key)
    }

    /// Creates a new NameSpace instance
    fn new(secondary_namespace: impl Into<String>) -> Self {
        Self {
            primary_namespace: PRIMARY.to_string(),
            secondary_namespace: secondary_namespace.into(),
        }
    }

    /// Creates a new NameSpace instance with a formatted secondary namespace
    fn new_formatted(
        secondary_namespace: impl std::fmt::Display,
        id: impl std::fmt::Display,
    ) -> Self {
        Self::new(format!("{}:{}", secondary_namespace, id))
    }

    pub fn registration_receipts(tower_id: TowerId) -> Self {
        Self::new_formatted(REGISTRATION_RECEIPTS, tower_id)
    }

    pub fn pending_appointments() -> Self {
        Self::new(PENDING_APPOINTMENTS)
    }

    pub fn invalid_appointments() -> Self {
        Self::new(INVALID_APPOINTMENTS)
    }

    pub fn appointment_receipts() -> Self {
        Self::new(APPOINTMENT_RECEIPTS)
    }

    pub fn tower_records() -> Self {
        Self::new(TOWER_RECORDS)
    }
}

/// Represents a complete key space in the storage system
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct KeySpace {
    namespace: NameSpace,
    key: String,
}

impl KeySpace {
    /// Returns a reference to the namespace
    pub fn namespace(&self) -> &NameSpace {
        &self.namespace
    }

    /// Returns a reference to the key
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Creates a new KeySpace instance
    fn new(namespace: NameSpace, key: impl Into<String>) -> Self {
        Self {
            namespace,
            key: key.into(),
        }
    }

    /// Creates a new KeySpace instance with a formatted key
    fn new_with_formatted_key(
        secondary_namespace: impl Into<String>,
        id1: impl std::fmt::Display,
        id2: impl std::fmt::Display,
    ) -> Self {
        NameSpace::new(secondary_namespace).with_key(format!("{}:{}", id1, id2))
    }

    pub fn tower(tower_id: TowerId) -> Self {
        Self::new(NameSpace::tower_records(), tower_id.to_string())
    }

    pub fn appointment(locator: Locator) -> Self {
        Self::new(NameSpace::new(APPOINTMENTS), locator.to_string())
    }

    pub fn misbehaving_proof(tower_id: TowerId) -> Self {
        NameSpace::new(MISBEHAVIOR_PROOFS).with_key(tower_id.to_string())
    }

    pub fn registration_receipt(tower_id: TowerId, subscription_expiry: u32) -> Self {
        NameSpace::registration_receipts(tower_id).with_key(subscription_expiry.to_string())
    }

    pub fn appointment_receipt(tower_id: TowerId, locator: Locator) -> Self {
        Self::new_with_formatted_key(APPOINTMENT_RECEIPTS, tower_id, locator)
    }

    pub fn pending_appointment(tower_id: TowerId, locator: Locator) -> Self {
        Self::new_with_formatted_key(PENDING_APPOINTMENTS, tower_id, locator)
    }

    pub fn invalid_appointment(tower_id: TowerId, locator: Locator) -> Self {
        Self::new_with_formatted_key(INVALID_APPOINTMENTS, tower_id, locator)
    }

    pub fn available_slots(tower_id: TowerId) -> Self {
        NameSpace::new(AVAILABLE_SLOTS).with_key(tower_id.to_string())
    }
}
