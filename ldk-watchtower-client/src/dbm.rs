//! SQLite-backed persistence for the watchtower client.
//!
//! Mirrors the patterns of `watchtower-plugin/src/dbm.rs`. The database is the
//! pending queue: every exported commitment state is tracked here, so no
//! appointment is ever lost across restarts.
//!
//! State machine for tracked commitment states (`justice_states.status`):
//! - `seen`:    commitment txid tracked, but no signed justice tx available yet.
//! - `pending`: a signed justice tx is available; the appointment still needs to
//!              be (re-)sent to the tower (e.g. after a connection failure or a restart).
//! - `sent`:    the tower accepted the appointment (receipt stored).
//! - `invalid`: the tower permanently rejected the appointment, or it misbehaved.

use std::path::Path;

use rusqlite::{params, Connection, Error};

use bitcoin::secp256k1::SecretKey;

use teos_common::receipts::{AppointmentReceipt, RegistrationReceipt};
use teos_common::{TowerId, UserId};

use crate::tower::MisbehaviorProof;

const TABLES: [&str; 5] = [
    "CREATE TABLE IF NOT EXISTS keys (
        id INTEGER PRIMARY KEY,
        key BLOB NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS registration_receipts (
        tower_id TEXT PRIMARY KEY,
        available_slots INT NOT NULL,
        subscription_start INT NOT NULL,
        subscription_expiry INT NOT NULL,
        signature TEXT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS justice_states (
        commitment_txid TEXT PRIMARY KEY,
        user_channel_id TEXT NOT NULL,
        commitment_number INT NOT NULL,
        to_local_value_sats INT NOT NULL,
        to_self_delay INT NOT NULL,
        justice_tx BLOB NOT NULL,
        status TEXT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS appointment_receipts (
        locator TEXT PRIMARY KEY,
        user_signature TEXT NOT NULL,
        start_block INT NOT NULL,
        signature TEXT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS misbehaving_proofs (
        tower_id TEXT PRIMARY KEY,
        locator TEXT NOT NULL,
        appointment_receipt TEXT NOT NULL,
        recovered_id TEXT NOT NULL
    )",
];

/// The status of a tracked commitment state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateStatus {
    Seen,
    Pending,
    Sent,
    Invalid,
}

impl std::fmt::Display for StateStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            StateStatus::Seen => "seen",
            StateStatus::Pending => "pending",
            StateStatus::Sent => "sent",
            StateStatus::Invalid => "invalid",
        };
        write!(f, "{s}")
    }
}

impl std::str::FromStr for StateStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "seen" => Ok(StateStatus::Seen),
            "pending" => Ok(StateStatus::Pending),
            "sent" => Ok(StateStatus::Sent),
            "invalid" => Ok(StateStatus::Invalid),
            _ => Err(format!("Unknown status: {s}")),
        }
    }
}

/// A tracked justice transaction, as persisted in the database.
#[derive(Clone, Debug)]
pub struct TrackedJustice {
    pub commitment_txid: String,
    pub user_channel_id: String,
    pub commitment_number: u64,
    pub to_local_value_sats: u64,
    pub to_self_delay: u32,
    pub justice_tx: Vec<u8>,
    pub status: StateStatus,
}

pub struct DBM {
    connection: Connection,
}

impl DBM {
    pub fn new(db_path: &Path) -> Result<Self, Error> {
        let connection = Connection::open(db_path)?;
        for table in TABLES.iter() {
            connection.execute(table, [])?;
        }
        Ok(DBM { connection })
    }

    #[cfg(test)]
    pub fn in_memory() -> Result<Self, Error> {
        let connection = Connection::open_in_memory()?;
        for table in TABLES.iter() {
            connection.execute(table, [])?;
        }
        Ok(DBM { connection })
    }

    /// Stores the client secret key used to sign appointments (single row).
    pub fn store_client_key(&self, sk: &SecretKey) -> Result<(), Error> {
        self.connection.execute(
            "INSERT OR REPLACE INTO keys (id, key) VALUES (0, ?1)",
            params![sk.secret_bytes().to_vec()],
        )?;
        Ok(())
    }

    /// Loads the client secret key, if any was stored.
    pub fn load_client_key(&self) -> Option<SecretKey> {
        self.connection
            .query_row("SELECT key FROM keys WHERE id = 0", [], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .ok()
            .and_then(|bytes| SecretKey::from_slice(&bytes).ok())
    }

    /// Stores (or replaces) the registration receipt for a tower.
    pub fn store_registration_receipt(
        &self,
        tower_id: TowerId,
        receipt: &RegistrationReceipt,
    ) -> Result<(), Error> {
        self.connection.execute(
            "INSERT OR REPLACE INTO registration_receipts
                (tower_id, available_slots, subscription_start, subscription_expiry, signature)
            VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                tower_id.to_string(),
                receipt.available_slots(),
                receipt.subscription_start(),
                receipt.subscription_expiry(),
                receipt.signature().unwrap_or_default(),
            ],
        )?;
        Ok(())
    }

    /// Loads the registration receipt for a tower, if any.
    pub fn load_registration_receipt(
        &self,
        tower_id: TowerId,
        user_id: UserId,
    ) -> Option<RegistrationReceipt> {
        self.connection
            .query_row(
                "SELECT available_slots, subscription_start, subscription_expiry, signature
                 FROM registration_receipts WHERE tower_id = ?1",
                params![tower_id.to_string()],
                |row| {
                    Ok(RegistrationReceipt::with_signature(
                        user_id,
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                    ))
                },
            )
            .ok()
    }

    /// Tracks a justice transaction in the database.
    ///
    /// Returns the status the state is left in. A state that was already `sent` or
    /// `invalid` is never downgraded; a state transitioning from `seen` (or new)
    /// with signed justice tx data becomes `pending`.
    pub fn track_justice(&self, justice: &TrackedJustice) -> Result<StateStatus, Error> {
        match self.load_justice(&justice.commitment_txid)? {
            Some(existing) => {
                if matches!(existing.status, StateStatus::Sent | StateStatus::Invalid) {
                    return Ok(existing.status);
                }
                // Upgrade a `seen` state to `pending` once signed data is available.
                let status = if justice.justice_tx.is_empty() {
                    existing.status
                } else {
                    StateStatus::Pending
                };
                self.connection.execute(
                    "UPDATE justice_states SET user_channel_id = ?2, commitment_number = ?3,
                        to_local_value_sats = ?4, to_self_delay = ?5, justice_tx = ?6, status = ?7
                     WHERE commitment_txid = ?1",
                    params![
                        justice.commitment_txid,
                        justice.user_channel_id,
                        justice.commitment_number,
                        justice.to_local_value_sats,
                        justice.to_self_delay,
                        if justice.justice_tx.is_empty() {
                            existing.justice_tx
                        } else {
                            justice.justice_tx.clone()
                        },
                        status.to_string(),
                    ],
                )?;
                Ok(status)
            }
            None => {
                let status = if justice.justice_tx.is_empty() {
                    StateStatus::Seen
                } else {
                    StateStatus::Pending
                };
                self.connection.execute(
                    "INSERT INTO justice_states
                        (commitment_txid, user_channel_id, commitment_number, to_local_value_sats,
                         to_self_delay, justice_tx, status)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        justice.commitment_txid,
                        justice.user_channel_id,
                        justice.commitment_number,
                        justice.to_local_value_sats,
                        justice.to_self_delay,
                        justice.justice_tx,
                        status.to_string(),
                    ],
                )?;
                Ok(status)
            }
        }
    }

    /// Loads a tracked justice transaction by commitment txid.
    pub fn load_justice(&self, commitment_txid: &str) -> Result<Option<TrackedJustice>, Error> {
        let mut stmt = self.connection.prepare(
            "SELECT commitment_txid, user_channel_id, commitment_number, to_local_value_sats,
                    to_self_delay, justice_tx, status
             FROM justice_states WHERE commitment_txid = ?1",
        )?;
        let mut rows = stmt.query(params![commitment_txid])?;
        match rows.next()? {
            Some(row) => {
                let status: String = row.get(6)?;
                Ok(Some(TrackedJustice {
                    commitment_txid: row.get(0)?,
                    user_channel_id: row.get(1)?,
                    commitment_number: row.get(2)?,
                    to_local_value_sats: row.get(3)?,
                    to_self_delay: row.get(4)?,
                    justice_tx: row.get(5)?,
                    status: status.parse().unwrap_or(StateStatus::Seen),
                }))
            }
            None => Ok(None),
        }
    }

    /// Loads all states awaiting (re-)delivery to the tower.
    pub fn load_pending_justices(&self) -> Result<Vec<TrackedJustice>, Error> {
        let mut stmt = self.connection.prepare(
            "SELECT commitment_txid, user_channel_id, commitment_number, to_local_value_sats,
                    to_self_delay, justice_tx, status
             FROM justice_states WHERE status = 'pending'",
        )?;
        let mut rows = stmt.query([])?;
        let mut result = Vec::new();
        while let Some(row) = rows.next()? {
            let status: String = row.get(6)?;
            result.push(TrackedJustice {
                commitment_txid: row.get(0)?,
                user_channel_id: row.get(1)?,
                commitment_number: row.get(2)?,
                to_local_value_sats: row.get(3)?,
                to_self_delay: row.get(4)?,
                justice_tx: row.get(5)?,
                status: status.parse().unwrap_or(StateStatus::Pending),
            });
        }
        Ok(result)
    }

    /// Sets the status of a tracked state.
    pub fn set_justice_status(
        &self,
        commitment_txid: &str,
        status: StateStatus,
    ) -> Result<(), Error> {
        self.connection.execute(
            "UPDATE justice_states SET status = ?2 WHERE commitment_txid = ?1",
            params![commitment_txid, status.to_string()],
        )?;
        Ok(())
    }

    /// Stores the receipt issued by the tower for an accepted appointment.
    pub fn store_appointment_receipt(
        &self,
        locator: &str,
        receipt: &AppointmentReceipt,
    ) -> Result<(), Error> {
        self.connection.execute(
            "INSERT OR REPLACE INTO appointment_receipts (locator, user_signature, start_block, signature)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                locator,
                receipt.user_signature(),
                receipt.start_block(),
                receipt.signature().unwrap_or_default(),
            ],
        )?;
        Ok(())
    }

    /// Stores proof that a tower signed a receipt with a key not matching its tower id.
    pub fn store_misbehaving_proof(
        &self,
        tower_id: TowerId,
        proof: &MisbehaviorProof,
    ) -> Result<(), Error> {
        self.connection.execute(
            "INSERT OR REPLACE INTO misbehaving_proofs (tower_id, locator, appointment_receipt, recovered_id)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                tower_id.to_string(),
                proof.locator.to_string(),
                serde_json::to_string(&proof.appointment_receipt).unwrap(),
                proof.recovered_id.to_string(),
            ],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tracked(txid: &str, justice_tx: Vec<u8>) -> TrackedJustice {
        TrackedJustice {
            commitment_txid: txid.to_owned(),
            user_channel_id: "abcd".to_owned(),
            commitment_number: 42,
            to_local_value_sats: 100_000,
            to_self_delay: 144,
            justice_tx,
            status: StateStatus::Seen,
        }
    }

    #[test]
    fn test_track_justice_transitions() {
        let dbm = DBM::in_memory().unwrap();
        let txid = "d6ac4a5e61657c4c604dcde855a1db74ec6b3e54f32695d72c5e11c7761ea1b4";

        // Unsigned (empty justice tx) entries are tracked as `seen`.
        let status = dbm.track_justice(&tracked(txid, Vec::new())).unwrap();
        assert_eq!(status, StateStatus::Seen);

        // The transition to a signed entry (justice tx bytes present) is detected
        // as new state: the entry becomes `pending`.
        let status = dbm.track_justice(&tracked(txid, vec![1, 2, 3])).unwrap();
        assert_eq!(status, StateStatus::Pending);
        assert_eq!(dbm.load_pending_justices().unwrap().len(), 1);
        assert_eq!(
            dbm.load_justice(txid).unwrap().unwrap().justice_tx,
            vec![1, 2, 3]
        );

        // Once sent, re-tracking the same state does not downgrade it.
        dbm.set_justice_status(txid, StateStatus::Sent).unwrap();
        let status = dbm.track_justice(&tracked(txid, vec![1, 2, 3])).unwrap();
        assert_eq!(status, StateStatus::Sent);
        assert!(dbm.load_pending_justices().unwrap().is_empty());
    }

    #[test]
    fn test_client_key_roundtrip() {
        let dbm = DBM::in_memory().unwrap();
        assert!(dbm.load_client_key().is_none());
        let sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
        dbm.store_client_key(&sk).unwrap();
        assert_eq!(dbm.load_client_key().unwrap(), sk);
    }
}
