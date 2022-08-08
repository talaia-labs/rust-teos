use std::collections::HashSet;

use serde::{ser::SerializeSeq, Serializer};

use crate::appointment::Locator;

pub fn serialize_locators<S>(hs: &HashSet<Locator>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut seq = s.serialize_seq(Some(hs.len()))?;
    for element in hs.iter() {
        seq.serialize_element(&hex::encode(element))?;
    }
    seq.end()
}

pub mod serde_be {
    use super::*;
    use serde::de::{self, Deserializer};

    pub fn serialize<S>(v: &[u8], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut v = v.to_owned();
        v.reverse();
        hex::serialize(v, s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BEVisitor;

        impl<'de> de::Visitor<'de> for BEVisitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a hex encoded string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let mut v =
                    hex::decode(v).map_err(|_| E::custom("cannot deserialize the given value"))?;
                v.reverse();
                Ok(v)
            }
        }

        deserializer.deserialize_any(BEVisitor)
    }
}

pub mod serde_vec_bytes {
    use super::*;
    use serde::de::{self, Deserializer, SeqAccess};

    pub fn serialize<S>(v: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = s.serialize_seq(Some(v.len()))?;
        for element in v.iter() {
            seq.serialize_element(&hex::encode(element))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct VecVisitor;

        impl<'de> de::Visitor<'de> for VecVisitor {
            type Value = Vec<Vec<u8>>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a hex encoded string")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut result = Vec::new();
                while let Some(v) = seq.next_element::<String>()? {
                    result
                        .push(hex::decode(v).map_err(|_| {
                            de::Error::custom("cannot deserialize the given value")
                        })?);
                }

                Ok(result)
            }
        }

        deserializer.deserialize_any(VecVisitor)
    }
}

pub mod serde_status {
    use super::*;
    use serde::de::{self, Deserializer};
    use std::str::FromStr;

    use crate::appointment::AppointmentStatus;

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
