use bitcoin::secp256k1::PublicKey;
use serde::de::{self, SeqAccess, Unexpected, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

pub mod appointment;
pub mod constants;
pub mod cryptography;
pub mod receipts;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct UserId(pub PublicKey);

struct UserIdVisitor;

impl Serialize for UserId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0.serialize())
    }
}

impl<'de> Visitor<'de> for UserIdVisitor {
    type Value = UserId;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a 33-byte long array or sequence")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        match PublicKey::from_slice(v) {
            Ok(pk) => Ok(UserId(pk)),
            Err(_) => Err(de::Error::invalid_value(Unexpected::Bytes(v), &self)),
        }
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut vec = Vec::new();

        while let Some(elem) = seq.next_element()? {
            vec.push(elem);
        }

        match PublicKey::from_slice(&vec) {
            Ok(pk) => Ok(UserId(pk)),
            Err(_) => Err(de::Error::invalid_value(Unexpected::Seq, &self)),
        }
    }
}

impl<'de> Deserialize<'de> for UserId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(UserIdVisitor)
    }
}
