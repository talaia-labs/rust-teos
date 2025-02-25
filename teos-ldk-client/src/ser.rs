use bitcoin::consensus::encode;
use bitcoin::Transaction;

use hex::FromHex;
use serde::{de, Deserializer};

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
