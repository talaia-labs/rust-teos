//! A module that implements useful gRPC messages to lightning message conversions.

use super::messages::*;
use crate::appointment::Locator;
use crate::constants::ENCRYPTED_BLOB_MAX_SIZE;
use crate::protos as msgs;

use bitcoin::hashes::Hash;
use bitcoin::Txid;

/// Conversions from individual messages to tower messages.
mod msg_to_tower_msg {
    use super::*;
    macro_rules! impl_from_msg {
        ($msg: ident) => {
            impl From<$msg> for TowerMessage {
                fn from(m: $msg) -> TowerMessage {
                    TowerMessage::$msg(m)
                }
            }
        };
    }

    impl_from_msg!(Register);
    impl_from_msg!(SubscriptionDetails);
    impl_from_msg!(AddUpdateAppointment);
    impl_from_msg!(AppointmentAccepted);
    impl_from_msg!(AppointmentRejected);
    impl_from_msg!(GetAppointment);
    impl_from_msg!(AppointmentData);
    impl_from_msg!(TrackerData);
    impl_from_msg!(AppointmentNotFound);
    impl_from_msg!(GetSubscriptionInfo);
    impl_from_msg!(SubscriptionInfo);
}

// FIXME: There are a lot of `unwrap()`s in these conversions. We assume that the gRPC interface won't send invalid data.
// If the conversion panics this would crash the lightning server.

/// Conversion from user requests to gRPC requests.
/// These are used by the tower when routing lightning requests to its internal gRPC server.
mod msg_to_grpc {
    use super::*;
    impl From<Register> for msgs::RegisterRequest {
        fn from(r: Register) -> Self {
            msgs::RegisterRequest {
                user_id: r.pubkey.to_vec(),
            }
        }
    }

    impl From<AddUpdateAppointment> for msgs::AddAppointmentRequest {
        fn from(r: AddUpdateAppointment) -> Self {
            let appointment = msgs::Appointment {
                locator: r.locator.to_vec(),
                encrypted_blob: r.encrypted_blob,
                to_self_delay: r.to_self_delay.unwrap_or(42),
            };

            msgs::AddAppointmentRequest {
                appointment: Some(appointment),
                signature: r.signature,
            }
        }
    }

    impl From<GetAppointment> for msgs::GetAppointmentRequest {
        fn from(r: GetAppointment) -> Self {
            msgs::GetAppointmentRequest {
                locator: r.locator.to_vec(),
                signature: r.signature,
            }
        }
    }

    impl From<GetSubscriptionInfo> for msgs::GetSubscriptionInfoRequest {
        fn from(r: GetSubscriptionInfo) -> Self {
            msgs::GetSubscriptionInfoRequest {
                signature: r.signature,
            }
        }
    }
}

/// Conversion from gRPC responses to tower responses.
/// These are used by the tower when parsing internal gRPC server's responses.
mod grpc_to_tower_msg {
    use super::*;
    impl From<msgs::RegisterResponse> for TowerMessage {
        fn from(r: msgs::RegisterResponse) -> Self {
            SubscriptionDetails {
                appointment_max_size: ENCRYPTED_BLOB_MAX_SIZE as u16,
                start_block: r.subscription_start,
                amount_msat: None,
                invoice: None,
                signature: Some(r.subscription_signature),
            }
            .into()
        }
    }

    impl From<msgs::AddAppointmentResponse> for TowerMessage {
        fn from(r: msgs::AddAppointmentResponse) -> Self {
            AppointmentAccepted {
                locator: Locator::from_slice(&r.locator).unwrap(),
                start_block: r.start_block,
                receipt_signature: Some(r.signature),
            }
            .into()
        }
    }

    impl From<msgs::GetAppointmentResponse> for TowerMessage {
        fn from(r: msgs::GetAppointmentResponse) -> Self {
            match r.appointment_data.unwrap().appointment_data.unwrap() {
                msgs::appointment_data::AppointmentData::Appointment(a) => AppointmentData {
                    locator: Locator::from_slice(&a.locator).unwrap(),
                    encrypted_blob: a.encrypted_blob,
                }
                .into(),
                msgs::appointment_data::AppointmentData::Tracker(t) => TrackerData {
                    dispute_txid: Txid::from_slice(&t.dispute_txid).unwrap(),
                    penalty_txid: Txid::from_slice(&t.penalty_txid).unwrap(),
                    penalty_rawtx: t.penalty_rawtx,
                }
                .into(),
            }
        }
    }

    impl From<msgs::GetSubscriptionInfoResponse> for TowerMessage {
        fn from(r: msgs::GetSubscriptionInfoResponse) -> Self {
            SubscriptionInfo {
                available_slots: r.available_slots,
                subscription_expiry: r.subscription_expiry,
                locators: r
                    .locators
                    .into_iter()
                    .map(|l| Locator::from_slice(&l).unwrap())
                    .collect(),
            }
            .into()
        }
    }
}
