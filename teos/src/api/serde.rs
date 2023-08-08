use crate::protos as msgs;

use teos_common::net::AddressType;

impl msgs::NetworkAddress {
    pub fn from_ipv4(address: String, port: u16) -> Self {
        Self {
            address_type: AddressType::IpV4 as i32,
            address,
            port: port as u32,
        }
    }

    pub fn from_torv3(address: String, port: u16) -> Self {
        Self {
            address_type: AddressType::TorV3 as i32,
            address,
            port: port as u32,
        }
    }
}

pub mod serde_address_type {
    use serde::de::{self, Deserializer};
    use serde::Serializer;
    use std::str::FromStr;

    use super::AddressType;

    pub fn serialize<S>(status: &i32, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&AddressType::from(*status).to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<i32, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StatusVisitor;

        impl<'de> de::Visitor<'de> for StatusVisitor {
            type Value = i32;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string containing the address type")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let status = AddressType::from_str(v)
                    .map_err(|_| E::custom("given address type is unknown"))?;
                Ok(status as i32)
            }
        }

        deserializer.deserialize_any(StatusVisitor)
    }
}
