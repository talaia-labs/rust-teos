//! Logic related to the database manager (DBM), component in charge of persisting data on disk.
//!

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::str::FromStr;

use rusqlite::ffi::{SQLITE_CONSTRAINT_FOREIGNKEY, SQLITE_CONSTRAINT_PRIMARYKEY};
use rusqlite::limits::Limit;
use rusqlite::{params, params_from_iter, Connection, Error as SqliteError, ErrorCode, Params};

use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::SecretKey;
use bitcoin::util::psbt::serialize::Serialize;
use bitcoin::{BlockHash, Transaction};

use teos_common::appointment::{Appointment, Locator};
use teos_common::constants::ENCRYPTED_BLOB_MAX_SIZE;
use teos_common::UserId;

use crate::extended_appointment::{compute_appointment_slots, ExtendedAppointment, UUID};
use crate::gatekeeper::UserInfo;
use crate::responder::TransactionTracker;
use crate::watcher::Breach;

/// Packs the errors than can raise when interacting with the underlying database.
#[derive(Debug)]
pub enum Error {
    AlreadyExists,
    MissingForeignKey,
    NotFound,
    Unknown(SqliteError),
}

/// Identifies the tower component for those who store similar data into the database.
#[derive(Clone)]
pub enum Component {
    Watcher,
    Responder,
}

/// Component in charge of interacting with the underlying database.
///
/// Currently works for `SQLite`. `PostgreSQL` should also be added in the future.
pub struct DBM {
    /// The underlying database connection.
    connection: Connection,
}

impl DBM {
    /// Creates a new [DBM] instance.
    pub fn new(db_path: PathBuf) -> Result<Self, SqliteError> {
        let connection = Connection::open(db_path)?;
        connection.execute("PRAGMA foreign_keys=1;", [])?;
        let mut dbm = Self { connection };
        dbm.create_tables()?;

        Ok(dbm)
    }

    /// Creates the database tables if not present.
    ///
    /// The database consists of the following tables:
    /// - users
    /// - appointments
    /// - trackers
    /// - last_known_block
    /// - keys
    fn create_tables(&mut self) -> Result<(), SqliteError> {
        let tx = self.connection.transaction().unwrap();
        tx.execute(
            "CREATE TABLE IF NOT EXISTS users (
                    user_id INT PRIMARY KEY,
                    available_slots INT NOT NULL,
                    subscription_expiry INT NOT NULL
                )",
            [],
        )?;
        tx.execute(
            "CREATE TABLE IF NOT EXISTS appointments (
                UUID INT PRIMARY KEY,
                locator INT NOT NULL,
                encrypted_blob BLOB NOT NULL,
                to_self_delay INT NOT NULL,
                user_signature BLOB NOT NULL,
                start_block INT NOT NULL,
                user_id INT NOT NULL,
                FOREIGN KEY(user_id)
                    REFERENCES users(user_id)
                    ON DELETE CASCADE
            )",
            [],
        )?;
        tx.execute(
            "CREATE TABLE IF NOT EXISTS trackers (
                UUID INT PRIMARY KEY,
                dispute_tx BLOB NOT NULL,
                penalty_tx BLOB NOT NULL,
                FOREIGN KEY(UUID)
                    REFERENCES appointments(UUID)
                    ON DELETE CASCADE
            )",
            [],
        )?;
        tx.execute(
            "CREATE TABLE IF NOT EXISTS last_known_block (
                id INT PRIMARY KEY,
                block_hash INT NOT NULL
            )",
            [],
        )?;

        tx.execute(
            "CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key INT NOT NULL
            )",
            [],
        )?;
        tx.commit()
    }

    /// Generic method to store data into the database.
    fn store_data<P: Params>(&self, query: &str, params: P) -> Result<(), Error> {
        match self.connection.execute(query, params) {
            Ok(_) => Ok(()),
            Err(e) => match e {
                SqliteError::SqliteFailure(ie, _) => match ie.code {
                    ErrorCode::ConstraintViolation => match ie.extended_code {
                        SQLITE_CONSTRAINT_FOREIGNKEY => Err(Error::MissingForeignKey),
                        SQLITE_CONSTRAINT_PRIMARYKEY => Err(Error::AlreadyExists),
                        _ => Err(Error::Unknown(e)),
                    },
                    _ => Err(Error::Unknown(e)),
                },
                _ => Err(Error::Unknown(e)),
            },
        }
    }

    /// Generic method to remove data from the database.
    fn remove_data<P: Params>(&self, query: &str, params: P) -> Result<(), Error> {
        match self.connection.execute(query, params).unwrap() {
            0 => Err(Error::NotFound),
            _ => Ok(()),
        }
    }

    /// Generic method to update data from the database.
    fn update_data<P: Params>(&self, query: &str, params: P) -> Result<(), Error> {
        // Updating data is fundamentally the same as deleting it in terms of interface.
        // A query is sent and either no row is modified or some rows are
        self.remove_data(query, params)
    }

    /// Stores a user ([UserInfo]) into the database.
    pub(crate) fn store_user(&self, user_id: UserId, user_info: &UserInfo) -> Result<(), Error> {
        let query =
            "INSERT INTO users (user_id, available_slots, subscription_expiry) VALUES (?1, ?2, ?3)";

        match self.store_data(
            query,
            params![
                user_id.serialize(),
                user_info.available_slots,
                user_info.subscription_expiry,
            ],
        ) {
            Ok(x) => {
                log::debug!("User successfully stored: {}", user_id);
                Ok(x)
            }
            Err(e) => {
                log::error!("Couldn't store user: {}. Error: {:?}", user_id, e);
                Err(e)
            }
        }
    }

    /// Updates an existing user ([UserInfo]) in the database.
    pub(crate) fn update_user(&self, user_id: UserId, user_info: &UserInfo) {
        let query =
            "UPDATE users SET available_slots=(?1), subscription_expiry=(?2) WHERE user_id=(?3)";
        match self.update_data(
            query,
            params![
                user_info.available_slots,
                user_info.subscription_expiry,
                user_id.serialize(),
            ],
        ) {
            Ok(_) => {
                log::debug!("User's info successfully updated: {}", user_id);
            }
            Err(_) => {
                log::error!("User not found, data cannot be updated: {}", user_id);
            }
        }
    }

    /// Loads the associated appointments ([Appointment]) of a given user ([UserInfo]).
    pub(crate) fn load_user_appointments(&self, user_id: UserId) -> HashMap<UUID, u32> {
        let mut stmt = self
            .connection
            .prepare("SELECT UUID, encrypted_blob FROM appointments WHERE user_id=(?)")
            .unwrap();
        let mut rows = stmt.query([user_id.serialize()]).unwrap();

        let mut appointments = HashMap::new();
        while let Ok(Some(inner_row)) = rows.next() {
            let raw_uuid: Vec<u8> = inner_row.get(0).unwrap();
            let uuid = UUID::deserialize(&raw_uuid[0..20]).unwrap();
            let e_blob: Vec<u8> = inner_row.get(1).unwrap();

            appointments.insert(
                uuid,
                compute_appointment_slots(e_blob.len(), ENCRYPTED_BLOB_MAX_SIZE),
            );
        }

        appointments
    }

    /// Loads all users from the database.
    pub(crate) fn load_all_users(&self) -> HashMap<UserId, UserInfo> {
        let mut users = HashMap::new();
        let mut stmt = self.connection.prepare("SELECT * FROM users").unwrap();
        let mut rows = stmt.query([]).unwrap();

        while let Ok(Some(row)) = rows.next() {
            let raw_userid: Vec<u8> = row.get(0).unwrap();
            let user_id = UserId::deserialize(&raw_userid).unwrap();
            let slots = row.get(1).unwrap();
            let expiry = row.get(2).unwrap();

            users.insert(
                user_id,
                UserInfo::with_appointments(slots, expiry, self.load_user_appointments(user_id)),
            );
        }

        users
    }

    /// Removes some users from the database in batch.
    pub(crate) fn batch_remove_users(&mut self, users: &HashSet<UserId>) -> usize {
        let limit = self.connection.limit(Limit::SQLITE_LIMIT_VARIABLE_NUMBER) as usize;
        let tx = self.connection.transaction().unwrap();
        let iter = users
            .iter()
            .map(|uuid| uuid.serialize())
            .collect::<Vec<Vec<u8>>>();

        for chunk in iter.chunks(limit) {
            let query = "DELETE FROM users WHERE user_id IN ".to_owned();
            let placeholders = format!("(?{})", (", ?").repeat(chunk.len() - 1));

            match tx.execute(
                &format!("{}{}", query, placeholders),
                params_from_iter(chunk),
            ) {
                Ok(_) => log::debug!("Users deletion added to db transaction"),
                Err(e) => log::error!("Couldn't add deletion query to transaction. Error: {:?}", e),
            }
        }

        match tx.commit() {
            Ok(_) => log::debug!("Users successfully deleted"),
            Err(e) => log::error!("Couldn't delete users. Error: {:?}", e),
        }

        (users.len() as f64 / limit as f64).ceil() as usize
    }

    /// Stores an [Appointment] into the database.
    pub(crate) fn store_appointment(
        &self,
        uuid: UUID,
        appointment: &ExtendedAppointment,
    ) -> Result<(), Error> {
        let query = "INSERT INTO appointments (UUID, locator, encrypted_blob, to_self_delay, user_signature, start_block, user_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";
        match self.store_data(
            query,
            params![
                uuid.serialize(),
                appointment.locator().serialize(),
                appointment.encrypted_blob(),
                appointment.to_self_delay(),
                appointment.user_signature,
                appointment.start_block,
                appointment.user_id.serialize(),
            ],
        ) {
            Ok(x) => {
                log::debug!("Appointment successfully stored: {}", uuid);
                Ok(x)
            }
            Err(e) => {
                log::error!("Couldn't store appointment: {}. Error: {:?}", uuid, e);
                Err(e)
            }
        }
    }

    /// Updates an existing [Appointment] in the database.
    pub(crate) fn update_appointment(&self, uuid: UUID, appointment: &ExtendedAppointment) {
        // DISCUSS: Check what fields we'd like to make updatable. e_blob and signature are the obvious, to_self_delay and start_block may not be necessary (or even risky)
        let query =
            "UPDATE appointments SET encrypted_blob=(?1), to_self_delay=(?2), user_signature=(?3), start_block=(?4) WHERE UUID=(?5)";
        match self.update_data(
            query,
            params![
                appointment.encrypted_blob(),
                appointment.to_self_delay(),
                appointment.user_signature,
                appointment.start_block,
                uuid.serialize(),
            ],
        ) {
            Ok(_) => {
                log::debug!("Appointment successfully updated: {}", uuid);
            }
            Err(_) => {
                log::error!("Appointment not found, data cannot be updated: {}", uuid);
            }
        }
    }

    /// Loads an [Appointment] from the database.
    pub(crate) fn load_appointment(&self, uuid: UUID) -> Result<ExtendedAppointment, Error> {
        let key = uuid.serialize();
        let mut stmt = self
            .connection
            .prepare("SELECT * FROM appointments WHERE UUID=(?)")
            .unwrap();

        stmt.query_row([key], |row| {
            let raw_locator: Vec<u8> = row.get(1).unwrap();
            let locator = Locator::deserialize(&raw_locator).unwrap();
            let raw_userid: Vec<u8> = row.get(6).unwrap();
            let user_id = UserId::deserialize(&raw_userid).unwrap();

            let appointment = Appointment::new(locator, row.get(2).unwrap(), row.get(3).unwrap());
            Ok(ExtendedAppointment::new(
                appointment,
                user_id,
                row.get(4).unwrap(),
                row.get(5).unwrap(),
            ))
        })
        .map_err(|_| Error::NotFound)
    }

    /// Loads all appointments from the database.
    pub(crate) fn load_all_appointments(&self) -> HashMap<UUID, ExtendedAppointment> {
        let mut appointments = HashMap::new();
        let mut stmt = self
            .connection
            .prepare("SELECT * FROM appointments as a LEFT JOIN trackers as t ON a.UUID=t.UUID WHERE t.UUID IS NULL")
            .unwrap();
        let mut rows = stmt.query([]).unwrap();

        while let Ok(Some(row)) = rows.next() {
            let raw_uuid: Vec<u8> = row.get(0).unwrap();
            let uuid = UUID::deserialize(&raw_uuid[0..20]).unwrap();
            let raw_locator: Vec<u8> = row.get(1).unwrap();
            let locator = Locator::deserialize(&raw_locator).unwrap();
            let raw_userid: Vec<u8> = row.get(6).unwrap();
            let user_id = UserId::deserialize(&raw_userid).unwrap();

            let appointment = Appointment::new(locator, row.get(2).unwrap(), row.get(3).unwrap());

            appointments.insert(
                uuid,
                ExtendedAppointment::new(
                    appointment,
                    user_id,
                    row.get(4).unwrap(),
                    row.get(5).unwrap(),
                ),
            );
        }

        appointments
    }

    /// Removes an [Appointment] from the database.
    pub(crate) fn remove_appointment(&self, uuid: UUID) {
        let query = "DELETE FROM appointments WHERE UUID=(?)";
        match self.remove_data(query, params![uuid.serialize()]) {
            Ok(_) => {
                log::debug!("Appointment successfully removed: {}", uuid);
            }
            Err(_) => {
                log::error!("Appointment not found, data cannot be removed: {}", uuid);
            }
        }
    }

    /// Removes some appointments from the database in batch and updates the associated users giving back
    /// the freed appointment slots
    pub(crate) fn batch_remove_appointments(
        &mut self,
        appointments: &HashSet<UUID>,
        updated_users: &HashMap<UserId, UserInfo>,
    ) -> usize {
        let limit = self.connection.limit(Limit::SQLITE_LIMIT_VARIABLE_NUMBER) as usize;
        let tx = self.connection.transaction().unwrap();
        let iter = appointments
            .iter()
            .map(|uuid| uuid.serialize())
            .collect::<Vec<Vec<u8>>>();

        for chunk in iter.chunks(limit) {
            let query = "DELETE FROM appointments WHERE UUID IN ".to_owned();
            let placeholders = format!("(?{})", (", ?").repeat(chunk.len() - 1));

            match tx.execute(
                &format!("{}{}", query, placeholders),
                params_from_iter(chunk),
            ) {
                Ok(_) => log::debug!("Appointments deletion added to db transaction"),
                Err(e) => log::error!("Couldn't add deletion query to transaction. Error: {:?}", e),
            }
        }

        for (id, info) in updated_users.iter() {
            let query = "UPDATE users SET available_slots=(?1) WHERE user_id=(?2)";
            match tx.execute(query, params![info.available_slots, id.serialize(),]) {
                Ok(_) => log::debug!("User update added to db transaction"),
                Err(e) => log::error!("Couldn't add update query to transaction. Error: {:?}", e),
            };
        }

        match tx.commit() {
            Ok(_) => log::debug!("Appointments successfully deleted"),
            Err(e) => log::error!("Couldn't delete appointments. Error: {:?}", e),
        }

        (appointments.len() as f64 / limit as f64).ceil() as usize
    }

    /// Stores a [TransactionTracker] into the database.
    pub(crate) fn store_tracker(
        &self,
        uuid: UUID,
        tracker: &TransactionTracker,
    ) -> Result<(), Error> {
        let query = "INSERT INTO trackers (UUID, dispute_tx, penalty_tx) VALUES (?1, ?2, ?3)";
        match self.store_data(
            query,
            params![
                uuid.serialize(),
                tracker.dispute_tx.serialize(),
                tracker.penalty_tx.serialize(),
            ],
        ) {
            Ok(x) => {
                log::debug!("Tracker successfully stored: {}", uuid);
                Ok(x)
            }
            Err(e) => {
                log::error!("Couldn't store tracker: {}. Error: {:?}", uuid, e);
                Err(e)
            }
        }
    }

    /// Loads a [TransactionTracker] from the database.
    pub(crate) fn load_tracker(&self, uuid: UUID) -> Result<TransactionTracker, Error> {
        let key = uuid.serialize();
        let mut stmt = self.connection.prepare(
            "SELECT t.*, a.locator, a.user_id FROM trackers as t INNER JOIN appointments as a ON t.UUID=a.UUID WHERE t.UUID=(?)").unwrap();

        stmt.query_row([key], |row| {
            let raw_dispute_tx: Vec<u8> = row.get(1).unwrap();
            let dispute_tx = deserialize::<Transaction>(&raw_dispute_tx).unwrap();
            let raw_penalty_tx: Vec<u8> = row.get(2).unwrap();
            let penalty_tx = deserialize::<Transaction>(&raw_penalty_tx).unwrap();
            let raw_locator: Vec<u8> = row.get(3).unwrap();
            let locator = Locator::deserialize(&raw_locator).unwrap();
            let raw_userid: Vec<u8> = row.get(4).unwrap();
            let user_id = UserId::deserialize(&raw_userid).unwrap();

            Ok(TransactionTracker {
                locator,
                dispute_tx,
                penalty_tx,
                user_id,
            })
        })
        .map_err(|_| Error::NotFound)
    }

    /// Loads all trackers from the database.
    pub(crate) fn load_all_trackers(&self) -> HashMap<UUID, TransactionTracker> {
        let mut trackers = HashMap::new();
        let mut stmt = self
            .connection
            .prepare("SELECT t.*, a.locator, a.user_id FROM trackers as t INNER JOIN appointments as a ON t.UUID=a.UUID")
            .unwrap();
        let mut rows = stmt.query([]).unwrap();

        while let Ok(Some(row)) = rows.next() {
            let raw_uuid: Vec<u8> = row.get(0).unwrap();
            let uuid = UUID::deserialize(&raw_uuid[0..20]).unwrap();
            let raw_dispute_tx: Vec<u8> = row.get(1).unwrap();
            let dispute_tx = deserialize::<Transaction>(&raw_dispute_tx).unwrap();
            let raw_penalty_tx: Vec<u8> = row.get(2).unwrap();
            let penalty_tx = deserialize::<Transaction>(&raw_penalty_tx).unwrap();
            let raw_locator: Vec<u8> = row.get(3).unwrap();
            let locator = Locator::deserialize(&raw_locator).unwrap();
            let raw_userid: Vec<u8> = row.get(4).unwrap();
            let user_id = UserId::deserialize(&raw_userid).unwrap();

            trackers.insert(
                uuid,
                TransactionTracker::new(Breach::new(locator, dispute_tx, penalty_tx), user_id),
            );
        }

        trackers
    }

    /// Stores the last known block of a given [Component] into the database.
    fn store_last_known_block(
        &self,
        block_hash: &BlockHash,
        component: Component,
    ) -> Result<(), Error> {
        let query = "INSERT OR REPLACE INTO last_known_block (id, block_hash) VALUES (?1, ?2)";
        let id = match component {
            Component::Watcher => 0,
            Component::Responder => 1,
        };

        self.store_data(query, params![id, block_hash.to_vec()])
    }

    /// Stores the last known block by the [Watcher](crate::watcher::Watcher) into the database.
    pub(crate) fn store_last_known_block_watcher(&self, block_hash: &BlockHash) {
        match self.store_last_known_block(block_hash, Component::Watcher) {
            Ok(_) => log::debug!(
                "Watcher's last known block successfully stored: {}",
                block_hash
            ),
            Err(e) => log::error!(
                "Couldn't store watcher's last known block: {}. Error: {:?}",
                block_hash,
                e
            ),
        }
    }

    /// Stores the last known block by the [Responder](crate::responder::Responder) into the database.
    pub(crate) fn store_last_known_block_responder(&self, block_hash: &BlockHash) {
        match self.store_last_known_block(block_hash, Component::Responder) {
            Ok(_) => log::debug!(
                "Responder's last known block successfully stored: {}",
                block_hash
            ),
            Err(e) => log::error!(
                "Couldn't store responder's last known block: {}. Error: {:?}",
                block_hash,
                e
            ),
        }
    }

    /// Loads the last known block of a [Component] from the database.
    fn load_last_known_block(&self, component: Component) -> Result<BlockHash, Error> {
        let mut stmt = self
            .connection
            .prepare("SELECT block_hash FROM last_known_block WHERE id=?1")
            .unwrap();

        let id = match component {
            Component::Watcher => 0,
            Component::Responder => 1,
        };

        stmt.query_row([id], |row| {
            let raw_hash: Vec<u8> = row.get(0).unwrap();
            Ok(BlockHash::from_slice(&raw_hash).unwrap())
        })
        .map_err(|_| Error::NotFound)
    }

    /// Loads the last known block by the [Watcher](crate::watcher::Watcher) from the database.
    pub(crate) fn load_last_known_block_watcher(&self) -> Result<BlockHash, Error> {
        self.load_last_known_block(Component::Watcher)
    }

    /// Loads the last known block by the [Responder](crate::responder::Responder) from the database.
    pub(crate) fn load_last_known_block_responder(&self) -> Result<BlockHash, Error> {
        self.load_last_known_block(Component::Responder)
    }

    /// Stores the tower secret key into the database.
    ///
    /// When a new key is generated, old keys are not overwritten but are not retrievable from the API either.
    pub fn store_tower_key(&self, sk: &SecretKey) -> Result<(), Error> {
        let query = "INSERT INTO keys (key) VALUES (?)";
        self.store_data(query, params![sk.to_string()])
    }

    /// Loads the last known tower secret key from the database.
    ///
    /// Loads the key with higher id from the database. Old keys are not overwritten just in case a recovery is needed,
    /// but they are not accessible from the API either.
    pub fn load_tower_key(&self) -> Result<SecretKey, Error> {
        let mut stmt = self
            .connection
            .prepare(
                "SELECT key FROM keys WHERE id = (SELECT seq FROM sqlite_sequence WHERE name=(?))",
            )
            .unwrap();

        stmt.query_row(["keys"], |row| {
            let sk: String = row.get(0).unwrap();
            Ok(SecretKey::from_str(&sk).unwrap())
        })
        .map_err(|_| Error::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_utils::{
        generate_dummy_appointment, generate_dummy_appointment_with_user, generate_uuid,
        get_random_tracker, get_random_user_id,
    };
    use std::iter::FromIterator;
    use teos_common::cryptography::get_random_bytes;

    impl DBM {
        pub(crate) fn in_memory() -> Result<Self, SqliteError> {
            let connection = Connection::open_in_memory()?;
            connection.execute("PRAGMA foreign_keys=1;", [])?;
            let dbm = Self { connection };
            dbm.create_tables()?;

            Ok(dbm)
        }

        pub(crate) fn load_user(&self, user_id: UserId) -> Result<UserInfo, Error> {
            let key = user_id.serialize();
            let mut stmt = self
                .connection
                .prepare("SELECT available_slots, subscription_expiry FROM users WHERE user_id=(?)")
                .unwrap();
            let user = stmt
                .query_row([&key], |row| {
                    let slots = row.get(0).unwrap();
                    let expiry = row.get(1).unwrap();
                    Ok(UserInfo::with_appointments(
                        slots,
                        expiry,
                        self.load_user_appointments(user_id),
                    ))
                })
                .map_err(|_| Error::NotFound)?;

            Ok(user)
        }
    }

    #[test]
    fn test_create_tables() {
        let connection = Connection::open_in_memory().unwrap();
        let dbm = DBM { connection };
        dbm.create_tables().unwrap();
    }

    #[test]
    fn test_store_load_user() {
        let dbm = DBM::in_memory().unwrap();

        let user_id = get_random_user_id();
        let mut user = UserInfo::new(21, 42);

        assert!(matches!(dbm.store_user(user_id, &user), Ok { .. }));
        assert_eq!(dbm.load_user(user_id).unwrap(), user);

        // User info should be updatable but only via the update_user method
        user = UserInfo::new(42, 21);
        assert!(matches!(
            dbm.store_user(user_id, &user),
            Err(Error::AlreadyExists)
        ));
    }

    #[test]
    fn test_store_load_user_with_appointments() {
        let dbm = DBM::in_memory().unwrap();

        let user_id = get_random_user_id();
        let mut user = UserInfo::new(21, 42);

        dbm.store_user(user_id, &user).unwrap();

        // Add some appointments to the user
        for _ in 0..10 {
            let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
            dbm.store_appointment(uuid, &appointment).unwrap();
            user.appointments.insert(uuid, 1);
        }

        // Check both loading the whole user info or only the associated appointments
        assert_eq!(dbm.load_user(user_id).unwrap(), user);
        assert_eq!(dbm.load_user_appointments(user_id), user.appointments);
    }

    #[test]
    fn test_load_nonexistent_user() {
        let dbm = DBM::in_memory().unwrap();

        let user_id = get_random_user_id();
        assert!(matches!(dbm.load_user(user_id), Err(Error::NotFound)));
    }

    #[test]
    fn test_update_user() {
        let dbm = DBM::in_memory().unwrap();

        let user_id = get_random_user_id();
        let mut user = UserInfo::new(21, 42);

        dbm.store_user(user_id, &user).unwrap();
        assert_eq!(dbm.load_user(user_id).unwrap(), user);

        user.available_slots *= 2;
        dbm.update_user(user_id, &user);
        assert_eq!(dbm.load_user(user_id).unwrap(), user);
    }

    #[test]
    fn test_load_all_users() {
        let dbm = DBM::in_memory().unwrap();
        let mut users = HashMap::new();

        for i in 1..11 {
            let user_id = get_random_user_id();
            let user = UserInfo::new(i, i * 2);
            users.insert(user_id, user.clone());
            dbm.store_user(user_id, &user).unwrap();

            // Add appointments to some of the users
            if i % 2 == 0 {
                let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
                dbm.store_appointment(uuid, &appointment).unwrap();
                users
                    .get_mut(&user_id)
                    .unwrap()
                    .appointments
                    .insert(uuid, 1);
            }
        }

        assert_eq!(dbm.load_all_users(), users);
    }

    #[test]
    fn test_batch_remove_users() {
        let mut dbm = DBM::in_memory().unwrap();

        // Set a limit value for the maximum number of variables in SQLite so we can
        // test splitting big queries into chunks.
        let limit = 10;
        dbm.connection
            .set_limit(Limit::SQLITE_LIMIT_VARIABLE_NUMBER, limit);

        let mut to_be_deleted = HashSet::new();
        let mut rest = HashSet::new();
        for i in 1..100 {
            let user_id = get_random_user_id();
            let user = UserInfo::new(21, 42);
            dbm.store_user(user_id, &user).unwrap();

            if i % 2 == 0 {
                to_be_deleted.insert(user_id);
            } else {
                rest.insert(user_id);
            }
        }

        // Check that the db transaction had 5 (100/2*10) queries on it
        assert_eq!(dbm.batch_remove_users(&to_be_deleted), 5);
        // Check user data was deleted
        assert_eq!(
            rest,
            dbm.load_all_users()
                .keys()
                .cloned()
                .collect::<HashSet<UserId>>()
        );
    }

    #[test]
    fn test_batch_remove_users_cascade() {
        // Test that removing users cascade deleted appointments and trackers
        let mut dbm = DBM::in_memory().unwrap();
        let uuid = generate_uuid();
        let appointment = generate_dummy_appointment(None);
        let tracker = get_random_tracker(appointment.user_id);

        // Add the user and link an appointment (this is usually done once the appointment)
        // is added after the user creation, but for the test purpose it can be done all at once.
        let info = UserInfo::new(21, 42);
        dbm.store_user(appointment.user_id, &info).unwrap();

        // Appointment only
        assert!(matches!(
            dbm.store_appointment(uuid, &appointment.clone()),
            Ok { .. }
        ));

        dbm.batch_remove_users(&HashSet::from_iter(vec![appointment.user_id]));
        assert!(matches!(
            dbm.load_user(appointment.user_id),
            Err(Error::NotFound)
        ));
        assert!(matches!(dbm.load_appointment(uuid), Err(Error::NotFound)));

        // Appointment + Tracker
        dbm.store_user(appointment.user_id, &info).unwrap();
        assert!(matches!(
            dbm.store_appointment(uuid, &appointment.clone()),
            Ok { .. }
        ));
        assert!(matches!(
            dbm.store_tracker(uuid, &tracker.clone()),
            Ok { .. }
        ));

        dbm.batch_remove_users(&HashSet::from_iter(vec![appointment.user_id]));
        assert!(matches!(
            dbm.load_user(appointment.user_id),
            Err(Error::NotFound)
        ));
        assert!(matches!(dbm.load_appointment(uuid), Err(Error::NotFound)));
        assert!(matches!(dbm.load_tracker(uuid), Err(Error::NotFound)));
    }

    #[test]
    fn test_batch_remove_nonexistent_users() {
        let mut dbm = DBM::in_memory().unwrap();
        let users = (0..10)
            .map(|_| get_random_user_id())
            .collect::<HashSet<UserId>>();

        // Test it does not fail even if the user does not exist (it will log though)
        dbm.batch_remove_users(&users);
    }

    #[test]
    fn test_store_load_appointment() {
        let dbm = DBM::in_memory().unwrap();

        // In order to add an appointment we need the associated user to be present
        let user_id = get_random_user_id();
        let user = UserInfo::new(21, 42);
        dbm.store_user(user_id, &user).unwrap();

        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);

        assert!(matches!(
            dbm.store_appointment(uuid, &appointment),
            Ok { .. }
        ));
        assert_eq!(dbm.load_appointment(uuid).unwrap(), appointment);

        // Appointment info should be updatable but only via the update_appointment method
        assert!(matches!(
            dbm.store_appointment(uuid, &appointment),
            Err(Error::AlreadyExists)
        ));
    }

    #[test]
    fn test_store_appointment_missing_user() {
        let dbm = DBM::in_memory().unwrap();

        let uuid = generate_uuid();
        let appointment = generate_dummy_appointment(None);

        assert!(matches!(
            dbm.store_appointment(uuid, &appointment),
            Err(Error::MissingForeignKey)
        ));
        assert!(matches!(dbm.load_tracker(uuid), Err(Error::NotFound)));
    }

    #[test]
    fn test_load_nonexistent_appointment() {
        let dbm = DBM::in_memory().unwrap();

        let uuid = generate_uuid();
        assert!(matches!(dbm.load_appointment(uuid), Err(Error::NotFound)));
    }

    #[test]
    fn test_update_appointment() {
        let dbm = DBM::in_memory().unwrap();

        let user_id = get_random_user_id();
        let user = UserInfo::new(21, 42);
        dbm.store_user(user_id, &user).unwrap();

        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        assert!(matches!(
            dbm.store_appointment(uuid, &appointment),
            Ok { .. }
        ));

        // Modify the appointment and update it
        let mut modified_appointment = appointment.clone();
        modified_appointment.inner.encrypted_blob.reverse();

        // Not all fields are updatable, create another appointment modifying fields that cannot be
        let mut another_modified_appointment = modified_appointment.clone();
        another_modified_appointment.user_id = get_random_user_id();

        // Check how only the modifiable fields have been updated
        dbm.update_appointment(uuid, &another_modified_appointment);
        assert_eq!(dbm.load_appointment(uuid).unwrap(), modified_appointment);
        assert_ne!(
            dbm.load_appointment(uuid).unwrap(),
            another_modified_appointment
        );
    }

    #[test]
    fn test_load_all_appointments() {
        let dbm = DBM::in_memory().unwrap();
        let mut appointments = HashMap::new();

        for i in 1..11 {
            let user_id = get_random_user_id();
            let user = UserInfo::new(i, i * 2);
            dbm.store_user(user_id, &user).unwrap();

            let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
            dbm.store_appointment(uuid, &appointment).unwrap();
            appointments.insert(uuid, appointment);
        }

        assert_eq!(dbm.load_all_appointments(), appointments);

        // If an appointment has an associated tracker, it should not be loaded since it is seen
        // as a triggered appointment
        let user_id = get_random_user_id();
        let user = UserInfo::new(21, 42);
        dbm.store_user(user_id, &user).unwrap();

        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        dbm.store_appointment(uuid, &appointment).unwrap();

        let mut tracker = get_random_tracker(user_id);
        tracker.locator = appointment.locator();
        dbm.store_tracker(uuid, &tracker).unwrap();

        // We should get all the appointments back except from the triggered one
        assert_eq!(dbm.load_all_appointments(), appointments);
    }

    #[test]
    fn test_batch_remove_appointments() {
        let mut dbm = DBM::in_memory().unwrap();

        // Set a limit value for the maximum number of variables in SQLite so we can
        // test splitting big queries into chunks.
        let limit = 10;
        dbm.connection
            .set_limit(Limit::SQLITE_LIMIT_VARIABLE_NUMBER, limit);

        let user_id = get_random_user_id();
        let mut user = UserInfo::new(500, 42);
        dbm.store_user(user_id, &user).unwrap();

        let mut rest = HashSet::new();
        for i in 1..6 {
            let mut to_be_deleted = HashSet::new();
            for j in 0..limit * 2 * i {
                let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
                dbm.store_appointment(uuid, &appointment).unwrap();

                if j % 2 == 0 {
                    to_be_deleted.insert(uuid);
                } else {
                    rest.insert(uuid);
                }
            }

            // When the appointment are deleted, the user will get back slots based on the deleted data.
            // Here we can just make a number up to make sure it matches.
            user.available_slots = i as u32;
            let updated_users = HashMap::from_iter([(user_id, user.clone())]);

            // Check that the db transaction had i queries on it
            assert_eq!(
                dbm.batch_remove_appointments(&to_be_deleted, &updated_users),
                i as usize
            );
            // Check appointment data was deleted and users properly updated
            assert_eq!(
                rest,
                dbm.load_all_appointments()
                    .keys()
                    .cloned()
                    .collect::<HashSet<UUID>>()
            );
            assert_eq!(
                dbm.load_user(user_id).unwrap().available_slots,
                user.available_slots
            );
        }
    }

    #[test]
    fn test_batch_remove_appointments_cascade() {
        let mut dbm = DBM::in_memory().unwrap();
        let uuid = generate_uuid();
        let appointment = generate_dummy_appointment(None);
        let tracker = get_random_tracker(appointment.user_id);

        let info = UserInfo::new(21, 42);

        // Add the user b/c of FK restrictions
        dbm.store_user(appointment.user_id, &info).unwrap();

        // Appointment only
        assert!(matches!(
            dbm.store_appointment(uuid, &appointment.clone()),
            Ok { .. }
        ));

        dbm.batch_remove_appointments(
            &HashSet::from_iter(vec![uuid]),
            &HashMap::from_iter([(appointment.user_id, info.clone())]),
        );
        assert!(matches!(dbm.load_appointment(uuid), Err(Error::NotFound)));

        // Appointment + Tracker
        assert!(matches!(
            dbm.store_appointment(uuid, &appointment.clone()),
            Ok { .. }
        ));
        assert!(matches!(
            dbm.store_tracker(uuid, &tracker.clone()),
            Ok { .. }
        ));

        dbm.batch_remove_appointments(
            &HashSet::from_iter(vec![uuid]),
            &HashMap::from_iter([(appointment.user_id, info)]),
        );
        assert!(matches!(dbm.load_appointment(uuid), Err(Error::NotFound)));
        assert!(matches!(dbm.load_tracker(uuid), Err(Error::NotFound)));
    }

    #[test]
    fn test_batch_remove_nonexistent_appointments() {
        let mut dbm = DBM::in_memory().unwrap();
        let appointments = (0..10).map(|_| generate_uuid()).collect::<HashSet<UUID>>();

        // Test it does not fail even if the user does not exist (it will log though)
        dbm.batch_remove_appointments(&appointments, &HashMap::new());
    }

    #[test]
    fn test_store_load_tracker() {
        let dbm = DBM::in_memory().unwrap();

        // In order to add a tracker we need the associated appointment to be present (which
        // at the same time requires an associated user to be present)
        let user_id = get_random_user_id();
        let user = UserInfo::new(21, 42);
        dbm.store_user(user_id, &user).unwrap();

        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        dbm.store_appointment(uuid, &appointment).unwrap();

        let mut tracker = get_random_tracker(user_id);
        // Set the locator to match between appointment and tracker
        tracker.locator = appointment.locator();

        assert!(matches!(dbm.store_tracker(uuid, &tracker), Ok { .. }));
        assert_eq!(dbm.load_tracker(uuid).unwrap(), tracker);
    }

    #[test]
    fn test_store_duplicate_tracker() {
        let dbm = DBM::in_memory().unwrap();

        let user_id = get_random_user_id();
        let user = UserInfo::new(21, 42);
        dbm.store_user(user_id, &user).unwrap();

        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        dbm.store_appointment(uuid, &appointment).unwrap();

        let mut tracker = get_random_tracker(user_id);
        tracker.locator = appointment.locator();
        assert!(matches!(dbm.store_tracker(uuid, &tracker), Ok { .. }));

        // Try to store it again, but it shouldn't go through
        assert!(matches!(
            dbm.store_tracker(uuid, &tracker),
            Err(Error::AlreadyExists)
        ));
    }

    #[test]
    fn test_store_tracker_missing_appointment() {
        let dbm = DBM::in_memory().unwrap();

        let uuid = generate_uuid();
        let user_id = get_random_user_id();
        let tracker = get_random_tracker(user_id);

        assert!(matches!(
            dbm.store_tracker(uuid, &tracker),
            Err(Error::MissingForeignKey)
        ));
    }

    #[test]
    fn test_load_nonexistent_tracker() {
        let dbm = DBM::in_memory().unwrap();

        let uuid = generate_uuid();
        assert!(matches!(dbm.load_tracker(uuid), Err(Error::NotFound)));
    }

    #[test]
    fn test_load_all_trackers() {
        let dbm = DBM::in_memory().unwrap();
        let mut trackers = HashMap::new();

        for i in 1..11 {
            let user_id = get_random_user_id();
            let user = UserInfo::new(i, i * 2);
            dbm.store_user(user_id, &user).unwrap();

            let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
            dbm.store_appointment(uuid, &appointment).unwrap();

            let mut tracker = get_random_tracker(user_id);
            tracker.locator = appointment.locator();
            dbm.store_tracker(uuid, &tracker).unwrap();
            trackers.insert(uuid, tracker);
        }

        assert_eq!(dbm.load_all_trackers(), trackers);
    }

    #[test]
    fn test_store_load_last_known_block() {
        let dbm = DBM::in_memory().unwrap();

        for component in [Component::Watcher, Component::Responder] {
            let mut block_hash = BlockHash::from_slice(&get_random_bytes(32)).unwrap();
            dbm.store_last_known_block(&block_hash, component.clone())
                .unwrap();
            assert_eq!(
                dbm.load_last_known_block(component.clone()).unwrap(),
                block_hash
            );

            // Update with a new hash to check it can be done
            block_hash = BlockHash::from_slice(&get_random_bytes(32)).unwrap();
            dbm.store_last_known_block(&block_hash, component.clone())
                .unwrap();
            assert_eq!(dbm.load_last_known_block(component).unwrap(), block_hash);
        }
    }

    #[test]
    fn test_store_load_nonexistent_last_known_block() {
        let dbm = DBM::in_memory().unwrap();

        for component in [Component::Watcher, Component::Responder] {
            assert!(matches!(
                dbm.load_last_known_block(component.clone()),
                Err(Error::NotFound)
            ));
        }
    }

    #[test]
    fn test_store_load_last_known_block_watcher() {
        let dbm = DBM::in_memory().unwrap();

        let mut block_hash = BlockHash::from_slice(&get_random_bytes(32)).unwrap();
        dbm.store_last_known_block_watcher(&block_hash);
        assert_eq!(dbm.load_last_known_block_watcher().unwrap(), block_hash);

        // Update with a new hash to check it can be done
        block_hash = BlockHash::from_slice(&get_random_bytes(32)).unwrap();
        dbm.store_last_known_block_watcher(&block_hash);
        assert_eq!(dbm.load_last_known_block_watcher().unwrap(), block_hash);

        // Check that the Responder's entry is unaffected
        assert!(matches!(
            dbm.load_last_known_block_responder(),
            Err(Error::NotFound)
        ));
    }

    #[test]
    fn test_store_load_last_known_block_responder() {
        let dbm = DBM::in_memory().unwrap();

        let mut block_hash = BlockHash::from_slice(&get_random_bytes(32)).unwrap();
        dbm.store_last_known_block_responder(&block_hash);
        assert_eq!(dbm.load_last_known_block_responder().unwrap(), block_hash);

        // Update with a new hash to check it can be done
        block_hash = BlockHash::from_slice(&get_random_bytes(32)).unwrap();
        dbm.store_last_known_block_responder(&block_hash);
        assert_eq!(dbm.load_last_known_block_responder().unwrap(), block_hash);

        // Check that the Watcher's entry is unaffected
        assert!(matches!(
            dbm.load_last_known_block_watcher(),
            Err(Error::NotFound)
        ));
    }
}
