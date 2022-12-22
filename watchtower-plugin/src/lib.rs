use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::Serialize;

use teos_common::appointment::{Appointment, Locator};
use teos_common::receipts::AppointmentReceipt;
use teos_common::TowerId;

pub mod convert;
pub mod dbm;
pub mod net;
pub mod retrier;
mod ser;
pub mod wt_client;

#[cfg(test)]
mod test_utils;

/// The status the tower can be found at.
#[derive(Clone, Serialize, PartialEq, Eq, Copy, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TowerStatus {
    Reachable,
    TemporaryUnreachable,
    Unreachable,
    SubscriptionError,
    Misbehaving,
}

/// The status an appointment can be at.
pub enum AppointmentStatus {
    Accepted,
    Pending,
    Invalid,
}

/// Errors related to updating a subscription
#[derive(Debug, PartialEq, Eq)]
pub enum SubscriptionError {
    Expiry,
    Slots,
}

impl SubscriptionError {
    /// Whether the error is related to the expiry time or not.
    pub fn is_expiry(&self) -> bool {
        *self == SubscriptionError::Expiry
    }
}

impl fmt::Display for TowerStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                TowerStatus::Reachable => "reachable",
                TowerStatus::TemporaryUnreachable => "temporary unreachable",
                TowerStatus::Unreachable => "unreachable",
                TowerStatus::SubscriptionError => "subscription error",
                TowerStatus::Misbehaving => "misbehaving",
            }
        )
    }
}

impl TowerStatus {
    /// Whether the tower is reachable or not.
    pub fn is_reachable(&self) -> bool {
        *self == TowerStatus::Reachable
    }

    /// Whether the tower is unreachable or not.
    pub fn is_temporary_unreachable(&self) -> bool {
        *self == TowerStatus::TemporaryUnreachable
    }

    /// Whether the tower is unreachable or not.
    pub fn is_unreachable(&self) -> bool {
        *self == TowerStatus::Unreachable
    }

    /// Whether the tower is misbehaving or not.
    pub fn is_misbehaving(&self) -> bool {
        *self == TowerStatus::Misbehaving
    }

    /// Whether there is a subscription issue with the tower.
    pub fn is_subscription_error(&self) -> bool {
        *self == TowerStatus::SubscriptionError
    }

    /// Whether the tower can be manually retried
    pub fn is_retryable(&self) -> bool {
        self.is_unreachable() || self.is_subscription_error()
    }
}

/// Summarized data associated with a given tower.
#[derive(Clone, Serialize, Debug, PartialEq, Eq)]
pub struct TowerSummary {
    pub net_addr: String,
    pub available_slots: u32,
    subscription_start: u32,
    pub subscription_expiry: u32,
    pub status: TowerStatus,
    #[serde(serialize_with = "teos_common::ser::serialize_locators")]
    pub pending_appointments: HashSet<Locator>,
    #[serde(serialize_with = "teos_common::ser::serialize_locators")]
    pub invalid_appointments: HashSet<Locator>,
}

impl TowerSummary {
    /// Creates a new [TowerSummary] instance.
    pub fn new(
        net_addr: String,
        available_slots: u32,
        subscription_start: u32,
        subscription_expiry: u32,
    ) -> Self {
        Self {
            net_addr,
            available_slots,
            subscription_start,
            subscription_expiry,
            status: TowerStatus::Reachable,
            pending_appointments: HashSet::new(),
            invalid_appointments: HashSet::new(),
        }
    }

    /// Creates a new instance with some associated appointment data.
    pub fn with_appointments(
        net_addr: String,
        available_slots: u32,
        subscription_start: u32,
        subscription_expiry: u32,
        pending_appointments: HashSet<Locator>,
        invalid_appointments: HashSet<Locator>,
    ) -> Self {
        Self {
            net_addr,
            available_slots,
            subscription_start,
            subscription_expiry,
            status: TowerStatus::Reachable,
            pending_appointments,
            invalid_appointments,
        }
    }

    /// Creates a new instance using the existing info but updating the status.
    pub fn with_status(mut self, status: TowerStatus) -> Self {
        self.status = status;
        self
    }

    /// Updates the main information about the summary while preserving the appointment maps.
    pub fn udpate(
        &mut self,
        net_addr: String,
        available_slots: u32,
        subscription_start: u32,
        subscription_expiry: u32,
    ) {
        self.net_addr = net_addr;
        self.available_slots = available_slots;
        self.subscription_start = subscription_start;
        self.subscription_expiry = subscription_expiry;
    }
}

impl From<TowerInfo> for TowerSummary {
    fn from(info: TowerInfo) -> Self {
        TowerSummary::with_appointments(
            info.net_addr,
            info.available_slots,
            info.subscription_start,
            info.subscription_expiry,
            info.pending_appointments
                .iter()
                .map(|a| a.locator)
                .collect(),
            info.invalid_appointments
                .iter()
                .map(|a| a.locator)
                .collect(),
        )
        .with_status(info.status)
    }
}

/// Summarized data associated with a given tower.
#[derive(Clone, Serialize, Debug, PartialEq, Eq)]
pub struct TowerInfo {
    pub net_addr: String,
    pub available_slots: u32,
    pub subscription_start: u32,
    pub subscription_expiry: u32,
    pub status: TowerStatus,
    #[serde(serialize_with = "crate::ser::serialize_receipts")]
    pub appointments: HashMap<Locator, String>,
    #[serde(serialize_with = "crate::ser::serialize_appointments")]
    pub pending_appointments: Vec<Appointment>,
    #[serde(serialize_with = "crate::ser::serialize_appointments")]
    pub invalid_appointments: Vec<Appointment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub misbehaving_proof: Option<MisbehaviorProof>,
}

impl TowerInfo {
    /// Creates a new [TowerInfo] instance.
    pub fn new(
        net_addr: String,
        available_slots: u32,
        subscription_start: u32,
        subscription_expiry: u32,
        appointments: HashMap<Locator, String>,
        pending_appointments: Vec<Appointment>,
        invalid_appointments: Vec<Appointment>,
    ) -> Self {
        Self {
            net_addr,
            available_slots,
            subscription_start,
            subscription_expiry,
            status: TowerStatus::Reachable,
            appointments,
            pending_appointments,
            invalid_appointments,
            misbehaving_proof: None,
        }
    }

    /// Creates a new instance using the existing info but updating the status.
    pub fn with_status(mut self, status: TowerStatus) -> Self {
        self.status = status;
        self
    }

    /// Sets the misbehaving proof of a tower.
    pub fn set_misbehaving_proof(&mut self, proof: MisbehaviorProof) {
        self.misbehaving_proof = Some(proof);
    }
}

/// A misbehaving proof. Contains proof of a tower replying with a public key different from the advertised one.
#[derive(Clone, Serialize, Debug, PartialEq, Eq)]
pub struct MisbehaviorProof {
    #[serde(with = "hex::serde")]
    pub locator: Locator,
    pub appointment_receipt: AppointmentReceipt,
    pub recovered_id: TowerId,
}

impl MisbehaviorProof {
    /// Creates a new [MisbehavingProof] instance.
    pub fn new(
        locator: Locator,
        appointment_receipt: AppointmentReceipt,
        recovered_id: TowerId,
    ) -> Self {
        Self {
            locator,
            appointment_receipt,
            recovered_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATUSES: [TowerStatus; 5] = [
        TowerStatus::Reachable,
        TowerStatus::TemporaryUnreachable,
        TowerStatus::Unreachable,
        TowerStatus::SubscriptionError,
        TowerStatus::Misbehaving,
    ];

    const AVAILABLE_SLOTS: u32 = 21;
    const SUBSCRIPTION_START: u32 = 100;
    const SUBSCRIPTION_EXPIRY: u32 = SUBSCRIPTION_START + 42;

    mod tower_status {
        use super::*;
        use TowerStatus::*;

        #[test]
        fn test_is_reachable() {
            for status in STATUSES {
                if status == Reachable {
                    assert!(status.is_reachable())
                } else {
                    assert!(!status.is_reachable());
                }
            }
        }

        #[test]
        fn test_is_temporary_reachable() {
            for status in STATUSES {
                if status == TemporaryUnreachable {
                    assert!(status.is_temporary_unreachable())
                } else {
                    assert!(!status.is_temporary_unreachable());
                }
            }
        }

        #[test]
        fn test_is_unreachable() {
            for status in STATUSES {
                if status == Unreachable {
                    assert!(status.is_unreachable())
                } else {
                    assert!(!status.is_unreachable());
                }
            }
        }

        #[test]
        fn test_is_misbehaving() {
            for status in STATUSES {
                if status == Misbehaving {
                    assert!(status.is_misbehaving())
                } else {
                    assert!(!status.is_misbehaving());
                }
            }
        }

        #[test]
        fn test_is_subscription_error() {
            for status in STATUSES {
                if status == SubscriptionError {
                    assert!(status.is_subscription_error())
                } else {
                    assert!(!status.is_subscription_error());
                }
            }
        }

        #[test]
        fn test_is_retryable() {
            for status in STATUSES {
                if status == Unreachable || status == SubscriptionError {
                    assert!(status.is_retryable())
                } else {
                    assert!(!status.is_retryable());
                }
            }
        }
    }

    mod tower_summary {
        use super::*;

        use std::iter::FromIterator;

        use teos_common::test_utils::generate_random_appointment;

        #[test]
        fn test_new() {
            let net_addr: String = "addr".to_owned();

            let tower_summary = TowerSummary::new(
                net_addr.clone(),
                AVAILABLE_SLOTS,
                SUBSCRIPTION_START,
                SUBSCRIPTION_EXPIRY,
            );
            assert_eq!(
                tower_summary,
                TowerSummary {
                    net_addr,
                    available_slots: AVAILABLE_SLOTS,
                    subscription_start: SUBSCRIPTION_START,
                    subscription_expiry: SUBSCRIPTION_EXPIRY,
                    status: TowerStatus::Reachable,
                    pending_appointments: HashSet::new(),
                    invalid_appointments: HashSet::new(),
                },
            );
        }

        #[test]
        fn test_with_appointments() {
            let net_addr: String = "addr".to_owned();

            let pending_appointments =
                HashSet::from_iter([generate_random_appointment(None).locator]);
            let invalid_appointments =
                HashSet::from_iter([generate_random_appointment(None).locator]);

            let tower_summary = TowerSummary::with_appointments(
                net_addr.clone(),
                AVAILABLE_SLOTS,
                SUBSCRIPTION_START,
                SUBSCRIPTION_EXPIRY,
                pending_appointments.clone(),
                invalid_appointments.clone(),
            );
            assert_eq!(
                tower_summary,
                TowerSummary {
                    net_addr,
                    available_slots: AVAILABLE_SLOTS,
                    subscription_start: SUBSCRIPTION_START,
                    subscription_expiry: SUBSCRIPTION_EXPIRY,
                    status: TowerStatus::Reachable,
                    pending_appointments,
                    invalid_appointments,
                },
            );
        }

        #[test]
        fn test_with_status() {
            let mut tower_summary = TowerSummary::new(
                "addr".to_owned(),
                AVAILABLE_SLOTS,
                SUBSCRIPTION_START,
                SUBSCRIPTION_EXPIRY,
            );

            let unreachable_tower = tower_summary.clone().with_status(TowerStatus::Unreachable);
            tower_summary.status = TowerStatus::Unreachable;
            assert_eq!(unreachable_tower, tower_summary);
        }
    }

    mod tower_info {
        use super::*;

        use teos_common::test_utils::{generate_random_appointment, get_random_user_id};

        impl TowerInfo {
            pub fn empty(
                net_addr: String,
                available_slots: u32,
                subscription_start: u32,
                subscription_expiry: u32,
            ) -> Self {
                TowerInfo::new(
                    net_addr,
                    available_slots,
                    subscription_start,
                    subscription_expiry,
                    HashMap::new(),
                    Vec::new(),
                    Vec::new(),
                )
            }
        }

        #[test]
        fn test_new() {
            let tower_info = TowerInfo::new(
                "addr".to_owned(),
                AVAILABLE_SLOTS,
                SUBSCRIPTION_START,
                SUBSCRIPTION_EXPIRY,
                HashMap::new(),
                Vec::new(),
                Vec::new(),
            );

            assert!(tower_info.status.is_reachable());
            assert!(tower_info.misbehaving_proof.is_none());
        }

        #[test]
        fn test_with_status() {
            let mut tower_info = TowerInfo::empty(
                "addr".to_owned(),
                AVAILABLE_SLOTS,
                SUBSCRIPTION_START,
                SUBSCRIPTION_EXPIRY,
            );

            let unreachable_tower = tower_info.clone().with_status(TowerStatus::Unreachable);
            tower_info.status = TowerStatus::Unreachable;
            assert_eq!(unreachable_tower, tower_info);
        }

        #[test]
        fn test_set_misbehaving_proof() {
            let mut tower_info = TowerInfo::empty(
                "addr".to_owned(),
                AVAILABLE_SLOTS,
                SUBSCRIPTION_START,
                SUBSCRIPTION_EXPIRY,
            );
            assert_eq!(tower_info.misbehaving_proof, None);

            let appointment_receipt = AppointmentReceipt::with_signature(
                "user_signature".to_owned(),
                SUBSCRIPTION_START + 1,
                "tower_signature".to_owned(),
            );
            let proof = MisbehaviorProof::new(
                generate_random_appointment(None).locator,
                appointment_receipt,
                get_random_user_id(),
            );

            tower_info.set_misbehaving_proof(proof.clone());
            assert_eq!(tower_info.misbehaving_proof, Some(proof));
        }
    }
}
