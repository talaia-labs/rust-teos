pub mod http;
pub mod internal;
pub mod tor;

pub mod serde_status {
    use serde::de::{self, Deserializer};
    use serde::ser::Serializer;
    use std::str::FromStr;

    use teos_common::appointment::AppointmentStatus;

    pub fn serialize<S>(status: &i32, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&AppointmentStatus::from(*status).to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<i32, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StatusVisitor;

        impl<'de> de::Visitor<'de> for StatusVisitor {
            type Value = i32;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string containing the status")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let status = AppointmentStatus::from_str(v)
                    .map_err(|_| E::custom("given status is unknown"))?;
                Ok(status as i32)
            }
        }

        deserializer.deserialize_any(StatusVisitor)
    }
}
