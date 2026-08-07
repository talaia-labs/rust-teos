//! Logic to build teos appointments from ldk-server justice transactions.
//!
//! teos appointments encrypt the *penalty* (justice) transaction under a key derived
//! from the dispute (commitment) txid, and are identified by a locator consisting of
//! the first 16 bytes of that txid.
//!
//! In v1, ldk-server exports justice transactions with `signed = false` and empty
//! `justice_tx` bytes (only `commitment_txid` and `commitment_number` are real, as
//! locator sources). [build_appointment] therefore only builds appointments from
//! signed, non-empty entries; the caller is expected to track *all* commitment
//! txids in its local database so the later transition to signed entries is
//! detected as new state.

use bitcoin::consensus;
use bitcoin::hashes::hex::FromHex;
use bitcoin::{Transaction, Txid};

use teos_common::appointment::{Appointment, Locator};
use teos_common::cryptography;

use crate::proto::JusticeTransaction;

/// Whether a justice transaction carries everything needed to build an appointment.
pub fn is_appointment_ready(justice: &JusticeTransaction) -> bool {
    justice.signed && !justice.justice_tx.is_empty()
}

/// Builds a teos [Appointment] from a [JusticeTransaction] exported by ldk-server.
///
/// Returns `None` (logging at debug level) if the entry is not signed yet or carries
/// no transaction bytes, and (at warn level) if the entry is malformed. This is the
/// single place that needs to change if ldk-server's export format evolves.
pub fn build_appointment(justice: &JusticeTransaction, to_self_delay: u32) -> Option<Appointment> {
    if !is_appointment_ready(justice) {
        log::debug!(
            "Skipping justice transaction for commitment {}: not signed or empty justice tx",
            justice.commitment_txid
        );
        return None;
    }

    let dispute_txid = match Txid::from_hex(&justice.commitment_txid) {
        Ok(txid) => txid,
        Err(e) => {
            log::warn!(
                "Cannot build appointment: invalid commitment txid {} ({e})",
                justice.commitment_txid
            );
            return None;
        }
    };

    let justice_tx: Transaction = match consensus::deserialize(&justice.justice_tx) {
        Ok(tx) => tx,
        Err(e) => {
            log::warn!(
                "Cannot build appointment: cannot deserialize justice tx for commitment {} ({e})",
                justice.commitment_txid
            );
            return None;
        }
    };

    // The encryption key is sha256(dispute_txid) with nonce [0; 12],
    // as per `teos_common::cryptography::encrypt`.
    let encrypted_blob = match cryptography::encrypt(&justice_tx, &dispute_txid) {
        Ok(blob) => blob,
        Err(e) => {
            log::warn!(
                "Cannot build appointment: encryption failed for commitment {} ({e})",
                justice.commitment_txid
            );
            return None;
        }
    };

    Some(Appointment::new(
        Locator::new(dispute_txid),
        encrypted_blob,
        to_self_delay,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) const HEX_TX: &str = "010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff54038e830a1b4d696e656420627920416e74506f6f6c373432c2005b005e7a0ae3fabe6d6d7841cd582ead8ea5dd8e3de1173cae6fcd2a53c7362ebb7fb6f815604fe07cbe0200000000000000ac0e060005f90000ffffffff04d9476026000000001976a91411dbe48cc6b617f9c6adaf4d9ed5f625b1c7cb5988ac0000000000000000266a24aa21a9ed7248c6efddd8d99bfddd7f499f0b915bffa8253003cc934df1ff14a81301e2340000000000000000266a24b9e11b6d7054937e13f39529d6ad7e685e9dd4efa426f247d5f5a5bed58cdddb2d0fa60100000000000000002b6a2952534b424c4f434b3a054a68aa5368740e8b3e3c67bce45619c2cfd07d4d4f0936a5612d2d0034fa0a0120000000000000000000000000000000000000000000000000000000000000000000000000";
    pub(crate) const HEX_TXID: &str =
        "d6ac4a5e61657c4c604dcde855a1db74ec6b3e54f32695d72c5e11c7761ea1b4";

    pub(crate) fn signed_justice() -> JusticeTransaction {
        JusticeTransaction {
            commitment_txid: HEX_TXID.to_owned(),
            commitment_number: 42,
            to_local_value_sats: 100_000,
            justice_tx: Vec::from_hex(HEX_TX).unwrap(),
            signed: true,
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // The blob of an appointment must decrypt back to the justice transaction
        // under the same key (sha256(dispute_txid)) the tower would derive from the
        // dispute txid found on-chain.
        let tx: Transaction = consensus::deserialize(&Vec::from_hex(HEX_TX).unwrap()).unwrap();
        let txid = Txid::from_hex(HEX_TXID).unwrap();

        let encrypted_blob = cryptography::encrypt(&tx, &txid).unwrap();
        assert_eq!(cryptography::decrypt(&encrypted_blob, &txid).unwrap(), tx);
    }

    #[test]
    fn test_locator_from_txid() {
        // The locator is the first 16 bytes of the txid (internal byte order).
        // Since `Txid`'s hex display is byte-reversed w.r.t. the internal order,
        // the locator hex is the byte-reversed tail (last 16 bytes) of the txid hex.
        let txid = Txid::from_hex(HEX_TXID).unwrap();
        let locator = Locator::new(txid);
        assert_eq!(locator.to_vec(), txid[..16].to_vec());
        assert_eq!(locator.to_string(), "b4a11e76c7115e2cd79526f3543e6bec");
    }

    #[test]
    fn test_build_appointment_from_signed_entry() {
        let appointment = build_appointment(&signed_justice(), 144).unwrap();

        let txid = Txid::from_hex(HEX_TXID).unwrap();
        let tx: Transaction = consensus::deserialize(&Vec::from_hex(HEX_TX).unwrap()).unwrap();
        assert_eq!(appointment.locator, Locator::new(txid));
        assert_eq!(appointment.to_self_delay, 144);
        assert_eq!(
            cryptography::decrypt(&appointment.encrypted_blob, &txid).unwrap(),
            tx
        );
    }

    #[test]
    fn test_unsigned_and_empty_entries_are_skipped() {
        // Unsigned entry with empty justice tx: the v1 ldk-server export format.
        let unsigned = JusticeTransaction {
            commitment_txid: HEX_TXID.to_owned(),
            commitment_number: 42,
            to_local_value_sats: 100_000,
            justice_tx: Vec::new(),
            signed: false,
        };
        assert!(build_appointment(&unsigned, 144).is_none());

        // Signed but empty: still not buildable.
        let signed_empty = JusticeTransaction {
            justice_tx: Vec::new(),
            signed: true,
            ..unsigned.clone()
        };
        assert!(build_appointment(&signed_empty, 144).is_none());

        // Unsigned but with tx bytes: not buildable either (the tower would receive
        // a transaction that cannot be broadcast).
        let unsigned_nonempty = JusticeTransaction {
            signed: false,
            ..signed_justice()
        };
        assert!(build_appointment(&unsigned_nonempty, 144).is_none());

        // Signed and non-empty, but malformed tx bytes.
        let malformed = JusticeTransaction {
            justice_tx: vec![0xde, 0xad, 0xbe, 0xef],
            signed: true,
            ..unsigned
        };
        assert!(build_appointment(&malformed, 144).is_none());
    }
}
