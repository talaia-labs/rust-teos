use bitcoin::consensus::encode;
use bitcoin::Transaction;
#[cfg(feature = "accountable")]
use teos_common::appointment::{Appointment, Locator, Locators};
#[cfg(not(feature = "accountable"))]
use teos_common::appointment::{Appointment, Locators};
use hex::FromHex;
use serde::{de, ser::SerializeMap, Deserializer, Serialize, Serializer};
#[cfg(feature = "accountable")]
use std::collections::HashMap;

pub fn deserialize_tx<'de, D>(deserializer: D) -> Result<Transaction, D::Error>
where
    D: Deserializer<'de>,
{
    struct TransactionVisitor;

    impl<'de> de::Visitor<'de> for TransactionVisitor {
        type Value = Transaction;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a hex string containing the transaction")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let tx = encode::deserialize(
                &Vec::from_hex(v).map_err(|_| E::custom("transaction is not hex encoded"))?,
            )
            .map_err(|_| E::custom("transaction cannot be deserialized"))?;
            Ok(tx)
        }
    }

    deserializer.deserialize_any(TransactionVisitor)
}

#[cfg(feature = "accountable")]
pub fn serialize_receipts<S>(hm: &HashMap<Locator, String>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut map = s.serialize_map(Some(hm.len()))?;
    for (locator, sig) in hm {
        map.serialize_entry(&hex::encode(locator), sig)?;
    }
    map.end()
}

#[derive(Serialize)]
struct AppointmentInners {
    encrypted_blob: String,
    to_self_delay: u32,
}

#[cfg(feature = "accountable")]
struct LocatorInners {
    arg1: String,
    arg2: u32,
}

pub fn serialize_appointments<S>(v: &Vec<Appointment>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut map = s.serialize_map(Some(v.len()))?;
    for a in v {
        map.serialize_entry(
            &hex::encode(a.locator),
            &AppointmentInners {
                encrypted_blob: hex::encode(&a.encrypted_blob),
                to_self_delay: a.to_self_delay,
            },
        )?;
    }
    map.end()
}

pub fn serialize_locators<S>(v: &Vec<Locators>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut map = s.serialize_map(Some(v.len()))?;
    for a in v {
        map.serialize_entry(&hex::encode(a.locator), "None")?;
    }
    map.end()
}
