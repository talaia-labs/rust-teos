//! Watchtower custom lightning messages that implement LDK's [`Readable`] & [`Writeable`] traits.
//!
//! [`Readable`]: lightning::util::ser::Readable

use crate::appointment::Locator;
use crate::lightning::ser_macros::{impl_writeable_msg, set_msg_type};
use bitcoin::secp256k1::PublicKey;
use bitcoin::Txid;
use lightning::io::Error;
use lightning::ln::wire;
use lightning::util::ser::{Writeable, Writer};

// Re-exporting this for other crates to use.
pub use crate::lightning::ser_utils::Type;

/// The register message sent by the user to subscribe for the watching service.
#[derive(Debug)]
pub struct Register {
    pub pubkey: PublicKey,
    pub appointment_slots: u32,
    pub subscription_period: u32,
}

/// The subscription details message that is sent to the user after registering or toping up.
/// This message is the response to the register message.
#[derive(Debug)]
pub struct SubscriptionDetails {
    pub appointment_max_size: u16,
    pub start_block: u32,
    pub amount_msat: u32,
    // Optional TLV.
    pub invoice: Option<String>,
    pub signature: Option<String>,
}

/// The add/update appointment message sent by the user.
#[derive(Debug)]
pub struct AddUpdateAppointment {
    pub locator: Locator,
    // NOTE: LDK will prefix varying size fields (e.g. vectors and strings) with their length.
    pub encrypted_blob: Vec<u8>,
    pub signature: String,
    // Optional TLV.
    pub to_self_delay: Option<u64>,
}

/// The appointment accepted message that is sent after an accepted add/update appointment message.
#[derive(Debug)]
pub struct AppointmentAccepted {
    pub locator: Locator,
    pub start_block: u32,
    // Optional TLV.
    pub receipt_signature: Option<String>,
}

/// The appointment rejected message that is sent if an add/update appointment message was rejected.
#[derive(Debug)]
pub struct AppointmentRejected {
    pub locator: Locator,
    pub rcode: u16,
    pub reason: String,
}

/// The get appointment message sent by the user to retrieve a previously sent appointment from the tower.
#[derive(Debug)]
pub struct GetAppointment {
    pub locator: Locator,
    pub signature: String,
}

/// The appointment data message sent by the tower after a get appointment message.
#[derive(Debug)]
pub struct AppointmentData {
    pub locator: Locator,
    pub encrypted_blob: Vec<u8>,
}

/// The tracker data message sent by the tower when the requested appointment has been acted upon.
#[derive(Debug)]
pub struct TrackerData {
    pub dispute_txid: Txid,
    pub penalty_txid: Txid,
    pub penalty_rawtx: Vec<u8>,
}

/// The appointment not found message sent by the tower in response to a get appointment message
/// whose locator didn't match any known appointment.
#[derive(Debug)]
pub struct AppointmentNotFound {
    pub locator: Locator,
}

/// The get subscription info message (a TEOS custom message, not a bolt13 one).
#[derive(Debug)]
pub struct GetSubscriptionInfo {
    pub signature: String,
}

/// The subscription info message sent by the tower in response to get subscription info message.
#[derive(Debug)]
pub struct SubscriptionInfo {
    pub available_slots: u32,
    pub subscription_expiry: u32,
    // Sent as a TLV. Defaults to an empty vector.
    pub locators: Vec<Locator>,
}

impl_writeable_msg!(Register, {
    pubkey,
    appointment_slots,
    subscription_period
}, {});

impl_writeable_msg!(SubscriptionDetails, {
    appointment_max_size,
    start_block,
    amount_msat,
}, {
    // Use `opt_str` and not `opt` to avoid writing a length prefix for strings
    // since it's already written in the length part of the TLV.
    (1, invoice, opt_str),
    (3, signature, opt_str),
});

impl_writeable_msg!(AddUpdateAppointment, {
    locator,
    encrypted_blob,
    signature,
}, {
    (1, to_self_delay, opt),
});

impl_writeable_msg!(AppointmentAccepted, {
    locator,
    start_block,
}, {
    // Use `opt_str` and not `opt` to avoid writing a length prefix for strings
    // since it's already written in the length part of the TLV.
    (1, receipt_signature, opt_str),
});

impl_writeable_msg!(AppointmentRejected, {
    locator,
    rcode,
    reason,
}, {});

impl_writeable_msg!(GetAppointment, {
    locator,
    signature,
}, {});

impl_writeable_msg!(AppointmentData, {
    locator,
    encrypted_blob,
}, {});

impl_writeable_msg!(TrackerData, {
    dispute_txid,
    penalty_txid,
    penalty_rawtx,
}, {});

impl_writeable_msg!(AppointmentNotFound, {
    locator,
}, {});

impl_writeable_msg!(GetSubscriptionInfo, {
    signature,
}, {});

impl_writeable_msg!(SubscriptionInfo, {
    available_slots,
    subscription_expiry,
}, {
    (1, locators, vec)
});

set_msg_type!(Register, 48848);
set_msg_type!(SubscriptionDetails, 48850);
set_msg_type!(AddUpdateAppointment, 48852);
set_msg_type!(AppointmentAccepted, 48854);
set_msg_type!(AppointmentRejected, 48856);
set_msg_type!(GetAppointment, 48858);
set_msg_type!(AppointmentData, 48860);
set_msg_type!(TrackerData, 48862);
set_msg_type!(AppointmentNotFound, 48864);
// Let these messages get odd types since they are auxiliary messages.
set_msg_type!(GetSubscriptionInfo, 48865);
set_msg_type!(SubscriptionInfo, 48867);

#[derive(Debug)]
pub enum TowerMessage {
    // Register messages
    Register(Register),
    SubscriptionDetails(SubscriptionDetails),
    // Appointment submission messages
    AddUpdateAppointment(AddUpdateAppointment),
    AppointmentAccepted(AppointmentAccepted),
    AppointmentRejected(AppointmentRejected),
    // Appointment fetching messages
    GetAppointment(GetAppointment),
    AppointmentData(AppointmentData),
    TrackerData(TrackerData),
    AppointmentNotFound(AppointmentNotFound),
    // User subscription messages
    GetSubscriptionInfo(GetSubscriptionInfo),
    SubscriptionInfo(SubscriptionInfo),
}

impl wire::Type for TowerMessage {
    fn type_id(&self) -> u16 {
        match self {
            TowerMessage::Register(..) => Register::TYPE,
            TowerMessage::SubscriptionDetails(..) => SubscriptionDetails::TYPE,
            TowerMessage::AddUpdateAppointment(..) => AddUpdateAppointment::TYPE,
            TowerMessage::AppointmentAccepted(..) => AppointmentAccepted::TYPE,
            TowerMessage::AppointmentRejected(..) => AppointmentRejected::TYPE,
            TowerMessage::GetAppointment(..) => GetAppointment::TYPE,
            TowerMessage::AppointmentData(..) => AppointmentData::TYPE,
            TowerMessage::TrackerData(..) => TrackerData::TYPE,
            TowerMessage::AppointmentNotFound(..) => AppointmentNotFound::TYPE,
            TowerMessage::GetSubscriptionInfo(..) => GetSubscriptionInfo::TYPE,
            TowerMessage::SubscriptionInfo(..) => SubscriptionInfo::TYPE,
        }
    }
}

impl Writeable for TowerMessage {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
        match self {
            TowerMessage::Register(msg) => msg.write(writer),
            TowerMessage::SubscriptionDetails(msg) => msg.write(writer),
            TowerMessage::AddUpdateAppointment(msg) => msg.write(writer),
            TowerMessage::AppointmentAccepted(msg) => msg.write(writer),
            TowerMessage::AppointmentRejected(msg) => msg.write(writer),
            TowerMessage::GetAppointment(msg) => msg.write(writer),
            TowerMessage::AppointmentData(msg) => msg.write(writer),
            TowerMessage::TrackerData(msg) => msg.write(writer),
            TowerMessage::AppointmentNotFound(msg) => msg.write(writer),
            TowerMessage::GetSubscriptionInfo(msg) => msg.write(writer),
            TowerMessage::SubscriptionInfo(msg) => msg.write(writer),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptography::{get_random_bytes, get_random_keypair};
    use crate::lightning::ser_utils::{get_random_locator, get_random_txid, TestVecWriter};
    use lightning::io::Cursor;
    use lightning::util::ser::{Readable, Writeable};
    use std::cmp::PartialEq;
    use std::fmt::Debug;
    use std::iter::FromIterator;

    fn test_msg<T: Debug + Readable + Writeable + PartialEq>(msg: T) {
        // Get a writer and write the message to it.
        let mut stream = TestVecWriter(Vec::new());
        msg.write(&mut stream).ok().unwrap();
        // Create a reader out of the written buffer.
        let mut stream = Cursor::new(stream.0);
        let read_msg: T = Readable::read(&mut stream).ok().unwrap();
        // Assert the serialized then deserialized message is the same as the original one.
        assert_eq!(msg, read_msg);
    }

    #[test]
    fn test_tower_messages_empty_tlvs() {
        test_msg(Register {
            pubkey: get_random_keypair().1,
            appointment_slots: 4300,
            subscription_period: 4032,
        });
        test_msg(SubscriptionDetails {
            appointment_max_size: 3032,
            start_block: 358943,
            amount_msat: 41893,
            invoice: None,
            signature: None,
        });
        test_msg(AddUpdateAppointment {
            locator: get_random_locator(),
            encrypted_blob: get_random_bytes(542),
            signature: String::from("sign: locator || encrypted_blob || to_self_delay?"),
            to_self_delay: None,
        });
        test_msg(AppointmentAccepted {
            locator: get_random_locator(),
            start_block: 500310,
            receipt_signature: None,
        });
        test_msg(AppointmentRejected {
            locator: get_random_locator(),
            rcode: 539,
            reason: String::from("You have no more slots. 😢🥺💔"),
        });
        test_msg(GetAppointment {
            locator: get_random_locator(),
            signature: String::from("this is my signature. and is real."),
        });
        test_msg(AppointmentData {
            locator: get_random_locator(),
            encrypted_blob: get_random_bytes(678),
        });
        test_msg(TrackerData {
            dispute_txid: get_random_txid(),
            penalty_txid: get_random_txid(),
            penalty_rawtx: get_random_bytes(432),
        });
        test_msg(AppointmentNotFound {
            locator: get_random_locator(),
        });
        test_msg(GetSubscriptionInfo {
            signature: String::from("sign: get subscription info"),
        });
        test_msg(SubscriptionInfo {
            available_slots: 429,
            subscription_expiry: 1093,
            locators: Vec::new(),
        });
    }

    #[test]
    fn test_tower_message_with_tlvs() {
        test_msg(SubscriptionDetails {
            appointment_max_size: 4498,
            start_block: 4934503,
            amount_msat: 891431,
            invoice: Some(String::from(
                "lnbc100p1psj9jhxdqud3jxktt5w46x7unfv9kz6mn0v3jsnp4q0d3p2sfluzdx45...",
            )),
            signature: Some(String::from(
                "sign: user_pubkey || appointment_max_size || start_block || amount_msat || invoice_id?",
            )),
        });
        test_msg(AddUpdateAppointment {
            locator: get_random_locator(),
            encrypted_blob: get_random_bytes(542),
            signature: String::from("sign: locator || encrypted_blob || to_self_delay?"),
            to_self_delay: Some(56),
        });
        test_msg(AppointmentAccepted {
            locator: get_random_locator(),
            start_block: 500310,
            receipt_signature: Some(String::from("sign: user_signature || start_block")),
        });
        test_msg(SubscriptionInfo {
            available_slots: 429,
            subscription_expiry: 1093,
            locators: Vec::from_iter((0..10).map(|_| get_random_locator())),
        });
    }
}
