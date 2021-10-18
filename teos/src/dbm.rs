use std::collections::HashMap;
use std::convert::TryInto;

use bitcoin::hashes::Hash;
use rusqlite::ErrorCode;
use rusqlite::{params, Connection, Error as SqliteError, Params};

use bitcoin::consensus::deserialize;
use bitcoin::util::psbt::serialize::Serialize;
use bitcoin::{BlockHash, Transaction};

use teos_common::appointment::{Appointment, Locator};
use teos_common::constants::ENCRYPTED_BLOB_MAX_SIZE;
use teos_common::UserId;

use crate::extended_appointment::{compute_appointment_slots, ExtendedAppointment, UUID};
use crate::gatekeeper::UserInfo;
use crate::responder::TransactionTracker;
use crate::watcher::Breach;

#[derive(Debug)]
pub enum Error {
    AlreadyExists,
    MissingForeignKey,
    NotFound,
    Unknown(SqliteError),
}

#[derive(Clone)]
pub enum Component {
    Watcher,
    Responder,
}

pub struct DBM {
    connection: Connection,
}

impl DBM {
    pub fn new(db_path: &str) -> Result<Self, SqliteError> {
        let connection = Connection::open(db_path)?;
        connection.execute("PRAGMA foreign_keys=1;", [])?;
        let dbm = Self { connection };
        dbm.create_tables()?;

        Ok(dbm)
    }

    fn create_tables(&self) -> Result<(), SqliteError> {
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS users (
                    user_id INT PRIMARY KEY,
                    available_slots INT NOT NULL,
                    subscription_expiry INT NOT NULL
                )",
            [],
        )?;
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS appointments (
                UUID INT PRIMARY KEY,
                locator INT NOT NULL,
                encrypted_blob BLOB NOT NULL,
                to_self_delay INT NOT NULL,
                user_signature BLOB NOT NULL,
                start_block INT NOT NULL,
                user_id INT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(user_id)
            )",
            [],
        )?;
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS trackers (
                UUID INT PRIMARY KEY,
                dispute_tx BLOB NOT NULL,
                penalty_tx BLOB NOT NULL,
                FOREIGN KEY(UUID) REFERENCES appointments(UUID)
            )",
            [],
        )?;
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS last_known_block (
                id INT PRIMARY KEY,
                block_hash INT NOT NULL
            )",
            [],
        )?;
        Ok(())
    }

    fn store_data<P: Params>(&self, query: &str, params: P) -> Result<(), Error> {
        match self.connection.execute(query, params) {
            Ok(_) => Ok(()),
            Err(e) => match e {
                SqliteError::SqliteFailure(ie, _) => match ie.code {
                    ErrorCode::ConstraintViolation => match ie.extended_code {
                        // FIXME: I don't like having to use hardcoded values here but I haven't found
                        // a way to use data from rusqlite::ffi since it's not public
                        787 => Err(Error::MissingForeignKey),
                        1555 => Err(Error::AlreadyExists),
                        _ => Err(Error::Unknown(e)),
                    },
                    _ => Err(Error::Unknown(e)),
                },
                _ => Err(Error::Unknown(e)),
            },
        }
    }

    fn store_user(&self, user_id: UserId, user_info: UserInfo) -> Result<(), Error> {
        let query =
            "INSERT INTO users (user_id, available_slots, subscription_expiry) VALUES (?1, ?2, ?3)";

        self.store_data(
            query,
            params![
                user_id.serialize(),
                user_info.available_slots,
                user_info.subscription_expiry,
            ],
        )
    }

    // DISCUSS: This could be implemented with an INNER JOIN query, but the logic will be more complex given each row
    // will have the user info replicated. Consider whether it makes sense to change it.
    fn load_user(&self, user_id: UserId) -> Result<UserInfo, Error> {
        let key = user_id.serialize();
        let mut stmt = self
            .connection
            .prepare("SELECT available_slots, subscription_expiry FROM users WHERE user_id=(?)")
            .unwrap();
        let mut user = stmt
            .query_row([key.clone()], |row| {
                let slots = row.get(0).unwrap();
                let expiry = row.get(1).unwrap();
                Ok(UserInfo::new(slots, expiry))
            })
            .map_err(|_| Error::NotFound)?;

        // Loads the associated appointments if found
        let mut stmt = self
            .connection
            .prepare("SELECT uuid, encrypted_blob FROM appointments WHERE user_id=(?)")
            .unwrap();
        let mut rows = stmt.query([key]).unwrap();

        let mut appointments = HashMap::new();
        while let Ok(Some(inner_row)) = rows.next() {
            let raw_uuid: Vec<u8> = inner_row.get(0).unwrap();
            let uuid = UUID(raw_uuid[0..20].try_into().unwrap());
            let e_blob: Vec<u8> = inner_row.get(1).unwrap();

            appointments.insert(
                uuid,
                compute_appointment_slots(e_blob.len(), ENCRYPTED_BLOB_MAX_SIZE),
            );
        }

        if !appointments.is_empty() {
            user.appointments = appointments;
        }

        Ok(user)
    }

    fn load_all_users(&self) -> HashMap<UserId, UserInfo> {
        let mut users = HashMap::new();
        let mut stmt = self.connection.prepare("SELECT * FROM users").unwrap();
        let mut rows = stmt.query([]).unwrap();

        while let Ok(Some(row)) = rows.next() {
            let raw_userid: Vec<u8> = row.get(0).unwrap();
            let user_id = UserId::deserialize(&raw_userid).unwrap();
            let slots = row.get(1).unwrap();
            let expiry = row.get(2).unwrap();

            users.insert(user_id, UserInfo::new(slots, expiry));
        }

        users
    }

    fn store_appointment(&self, uuid: UUID, appointment: ExtendedAppointment) -> Result<(), Error> {
        let query = "INSERT INTO appointments (uuid, locator, encrypted_blob, to_self_delay, user_signature, start_block, user_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";
        self.store_data(
            query,
            params![
                uuid.serialize(),
                appointment.inner.locator.serialize(),
                appointment.inner.encrypted_blob,
                appointment.inner.to_self_delay,
                appointment.user_signature,
                appointment.start_block,
                appointment.user_id.serialize(),
            ],
        )
    }

    fn load_appointment(&self, uuid: UUID) -> Result<ExtendedAppointment, Error> {
        let key = uuid.serialize();
        let mut stmt = self
            .connection
            .prepare("SELECT * FROM appointments WHERE UUID=(?)")
            .unwrap();

        stmt.query_row([key], |row| {
            let raw_locator: Vec<u8> = row.get(1).unwrap();
            let locator: [u8; 16] = raw_locator[0..16].try_into().unwrap();
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

    fn load_all_appointments(&self) -> HashMap<UUID, ExtendedAppointment> {
        let mut appointments = HashMap::new();
        let mut stmt = self
            .connection
            .prepare("SELECT * FROM appointments")
            .unwrap();
        let mut rows = stmt.query([]).unwrap();

        while let Ok(Some(row)) = rows.next() {
            let raw_uuid: Vec<u8> = row.get(0).unwrap();
            let uuid = UUID(raw_uuid[0..20].try_into().unwrap());
            let raw_locator: Vec<u8> = row.get(1).unwrap();
            let locator: [u8; 16] = raw_locator[0..16].try_into().unwrap();
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

    fn store_tracker(&self, uuid: UUID, tracker: TransactionTracker) -> Result<(), Error> {
        let query = "INSERT INTO trackers (uuid, dispute_tx, penalty_tx) VALUES (?1, ?2, ?3)";
        self.store_data(
            query,
            params![
                uuid.serialize(),
                tracker.dispute_tx.serialize(),
                tracker.penalty_tx.serialize(),
            ],
        )
    }

    fn load_tracker(&self, uuid: UUID) -> Result<TransactionTracker, Error> {
        let key = uuid.serialize();
        let mut stmt = self.connection.prepare(
            "SELECT t.*, a.locator, a.user_id FROM trackers as t INNER JOIN appointments as a ON t.UUID=a.UUID WHERE t.UUID=(?)").unwrap();

        stmt.query_row([key], |row| {
            let raw_dispute_tx: Vec<u8> = row.get(1).unwrap();
            let dispute_tx: Transaction = deserialize(&raw_dispute_tx).unwrap();
            let raw_penalty_tx: Vec<u8> = row.get(2).unwrap();
            let penalty_tx: Transaction = deserialize(&raw_penalty_tx).unwrap();
            let raw_locator: Vec<u8> = row.get(3).unwrap();
            let locator = Locator::deserialize(raw_locator).unwrap();
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

    fn load_all_trackers(&self) -> HashMap<UUID, TransactionTracker> {
        let mut trackers = HashMap::new();
        let mut stmt = self
            .connection
            .prepare("SELECT t.*, a.locator, a.user_id FROM trackers as t INNER JOIN appointments as a ON t.UUID=a.UUID")
            .unwrap();
        let mut rows = stmt.query([]).unwrap();

        while let Ok(Some(row)) = rows.next() {
            let raw_uuid: Vec<u8> = row.get(0).unwrap();
            let uuid = UUID(raw_uuid[0..20].try_into().unwrap());
            let raw_dispute_tx: Vec<u8> = row.get(1).unwrap();
            let dispute_tx: Transaction = deserialize(&raw_dispute_tx).unwrap();
            let raw_penalty_tx: Vec<u8> = row.get(2).unwrap();
            let penalty_tx: Transaction = deserialize(&raw_penalty_tx).unwrap();
            let raw_locator: Vec<u8> = row.get(3).unwrap();
            let locator = Locator::deserialize(raw_locator).unwrap();
            let raw_userid: Vec<u8> = row.get(4).unwrap();
            let user_id = UserId::deserialize(&raw_userid).unwrap();

            trackers.insert(
                uuid,
                TransactionTracker::new(Breach::new(locator, dispute_tx, penalty_tx), user_id),
            );
        }

        trackers
    }

    fn store_last_known_block(
        &self,
        block_hash: BlockHash,
        component: Component,
    ) -> Result<(), Error> {
        let query = "INSERT OR REPLACE INTO last_known_block (id, block_hash) VALUES (?1, ?2)";
        let id = match component {
            Component::Watcher => 0,
            Component::Responder => 1,
        };

        self.store_data(query, params![id, block_hash.to_vec()])
    }
    fn store_last_known_block_watcher(&self, block_hash: BlockHash) -> Result<(), Error> {
        self.store_last_known_block(block_hash, Component::Watcher)
    }

    fn store_last_known_block_responder(&self, block_hash: BlockHash) -> Result<(), Error> {
        self.store_last_known_block(block_hash, Component::Responder)
    }

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
    fn load_last_known_block_watcher(&self) -> Result<BlockHash, Error> {
        self.load_last_known_block(Component::Watcher)
    }

    fn load_last_known_block_responder(&self) -> Result<BlockHash, Error> {
        self.load_last_known_block(Component::Responder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gatekeeper::UserInfo;
    use crate::test_utils::{
        generate_dummy_appointment, generate_uuid, get_random_bytes, get_random_tracker,
        get_random_user_id,
    };

    impl DBM {
        fn in_memory() -> Result<Self, SqliteError> {
            let connection = Connection::open_in_memory()?;
            connection.execute("PRAGMA foreign_keys=1;", [])?;
            let dbm = Self { connection };
            dbm.create_tables()?;

            Ok(dbm)
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
        let user = UserInfo::new(21, 42);

        dbm.store_user(user_id, user.clone()).unwrap();
        assert_eq!(dbm.load_user(user_id).unwrap(), user);
    }

    #[test]
    fn test_store_load_user_with_appointments() {
        let dbm = DBM::in_memory().unwrap();

        let user_id = get_random_user_id();
        let mut user = UserInfo::new(21, 42);

        dbm.store_user(user_id, user.clone()).unwrap();

        // Add some appointments to the user
        for _ in 0..10 {
            let uuid = generate_uuid();
            let mut appointment = generate_dummy_appointment(None);
            appointment.user_id = user_id;

            dbm.store_appointment(uuid, appointment).unwrap();
            user.appointments.insert(uuid, 1);
        }

        assert_eq!(dbm.load_user(user_id).unwrap(), user);
    }

    #[test]
    fn test_store_duplicate_user() {
        let dbm = DBM::in_memory().unwrap();

        let user_id = get_random_user_id();
        let user = UserInfo::new(21, 42);
        dbm.store_user(user_id, user.clone()).unwrap();

        assert!(matches!(
            dbm.store_user(user_id, user.clone()),
            Err(Error::AlreadyExists)
        ));
    }

    #[test]
    fn test_load_nonexistent_user() {
        let dbm = DBM::in_memory().unwrap();

        let user_id = get_random_user_id();
        assert!(matches!(dbm.load_user(user_id), Err(Error::NotFound)));
    }

    #[test]
    fn test_load_all_users() {
        let dbm = DBM::in_memory().unwrap();
        let mut users = HashMap::new();

        for i in 1..11 {
            let user_id = get_random_user_id();
            let user = UserInfo::new(i, i * 2);
            users.insert(user_id, user.clone());
            dbm.store_user(user_id, user).unwrap();
        }

        assert_eq!(dbm.load_all_users(), users);
    }

    #[test]
    fn test_store_load_appointment() {
        let dbm = DBM::in_memory().unwrap();

        // In order to add an appointment we need the associated user to be present
        let user_id = get_random_user_id();
        let user = UserInfo::new(21, 42);
        dbm.store_user(user_id, user).unwrap();

        let uuid = generate_uuid();
        let mut appointment = generate_dummy_appointment(None);
        appointment.user_id = user_id;

        dbm.store_appointment(uuid, appointment.clone()).unwrap();
        assert_eq!(dbm.load_appointment(uuid).unwrap(), appointment);
    }

    #[test]
    fn test_store_duplicate_appointment() {
        let dbm = DBM::in_memory().unwrap();

        let user_id = get_random_user_id();
        let user = UserInfo::new(21, 42);
        dbm.store_user(user_id, user).unwrap();

        let uuid = generate_uuid();
        let mut appointment = generate_dummy_appointment(None);
        appointment.user_id = user_id;

        dbm.store_appointment(uuid, appointment.clone()).unwrap();
        assert!(matches!(
            dbm.store_appointment(uuid, appointment.clone()),
            Err(Error::AlreadyExists)
        ));
    }

    #[test]
    fn test_store_appointment_missing_user() {
        let dbm = DBM::in_memory().unwrap();

        let uuid = generate_uuid();
        let appointment = generate_dummy_appointment(None);

        assert!(matches!(
            dbm.store_appointment(uuid, appointment.clone()),
            Err(Error::MissingForeignKey)
        ));
    }

    #[test]
    fn test_load_nonexistent_appointment() {
        let dbm = DBM::in_memory().unwrap();

        let uuid = generate_uuid();
        assert!(matches!(dbm.load_appointment(uuid), Err(Error::NotFound)));
    }

    #[test]
    fn test_load_all_appointments() {
        let dbm = DBM::in_memory().unwrap();
        let mut appointments = HashMap::new();

        for i in 1..11 {
            let user_id = get_random_user_id();
            let user = UserInfo::new(i, i * 2);
            dbm.store_user(user_id, user).unwrap();

            let uuid = generate_uuid();
            let mut appointment = generate_dummy_appointment(None);
            appointment.user_id = user_id;

            dbm.store_appointment(uuid, appointment.clone()).unwrap();
            appointments.insert(uuid, appointment);
        }

        assert_eq!(dbm.load_all_appointments(), appointments);
    }

    #[test]
    fn test_store_load_tracker() {
        let dbm = DBM::in_memory().unwrap();

        // In order to add a tracker we need the associated appointment to be present (which
        // at the same time requires an associated user to be present)
        let user_id = get_random_user_id();
        let user = UserInfo::new(21, 42);
        dbm.store_user(user_id, user).unwrap();

        let uuid = generate_uuid();
        let mut appointment = generate_dummy_appointment(None);
        appointment.user_id = user_id;
        dbm.store_appointment(uuid, appointment.clone()).unwrap();

        let mut tracker = get_random_tracker(user_id);
        // Set the locator to match between appointment and tracker
        tracker.locator = appointment.inner.locator.clone();

        dbm.store_tracker(uuid, tracker.clone()).unwrap();
        assert_eq!(dbm.load_tracker(uuid).unwrap(), tracker);
    }

    #[test]
    fn test_store_duplicate_tracker() {
        let dbm = DBM::in_memory().unwrap();

        let user_id = get_random_user_id();
        let user = UserInfo::new(21, 42);
        dbm.store_user(user_id, user).unwrap();

        let uuid = generate_uuid();
        let mut appointment = generate_dummy_appointment(None);
        appointment.user_id = user_id;
        dbm.store_appointment(uuid, appointment.clone()).unwrap();

        let mut tracker = get_random_tracker(user_id);
        tracker.locator = appointment.inner.locator.clone();

        dbm.store_tracker(uuid, tracker.clone()).unwrap();
        assert!(matches!(
            dbm.store_tracker(uuid, tracker),
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
            dbm.store_tracker(uuid, tracker.clone()),
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
            dbm.store_user(user_id, user).unwrap();

            let uuid = generate_uuid();
            let mut appointment = generate_dummy_appointment(None);
            appointment.user_id = user_id;
            dbm.store_appointment(uuid, appointment.clone()).unwrap();

            let mut tracker = get_random_tracker(user_id);
            tracker.locator = appointment.inner.locator.clone();
            dbm.store_tracker(uuid, tracker.clone()).unwrap();
            trackers.insert(uuid, tracker);
        }

        assert_eq!(dbm.load_all_trackers(), trackers);
    }

    #[test]
    fn store_load_last_known_block() {
        let dbm = DBM::in_memory().unwrap();

        for component in [Component::Watcher, Component::Responder] {
            let mut block_hash = BlockHash::from_slice(&get_random_bytes(32)).unwrap();
            dbm.store_last_known_block(block_hash, component.clone())
                .unwrap();
            assert_eq!(
                dbm.load_last_known_block(component.clone()).unwrap(),
                block_hash
            );

            // Update with a new hash to check it can be done
            block_hash = BlockHash::from_slice(&get_random_bytes(32)).unwrap();
            dbm.store_last_known_block(block_hash, component.clone())
                .unwrap();
            assert_eq!(dbm.load_last_known_block(component).unwrap(), block_hash);
        }
    }

    #[test]
    fn store_load_nonexistent_last_known_block() {
        let dbm = DBM::in_memory().unwrap();

        for component in [Component::Watcher, Component::Responder] {
            assert!(matches!(
                dbm.load_last_known_block(component.clone()),
                Err(Error::NotFound)
            ));
        }
    }

    #[test]
    fn store_load_last_known_block_watcher() {
        let dbm = DBM::in_memory().unwrap();

        let mut block_hash = BlockHash::from_slice(&get_random_bytes(32)).unwrap();
        dbm.store_last_known_block_watcher(block_hash).unwrap();
        assert_eq!(dbm.load_last_known_block_watcher().unwrap(), block_hash);

        // Update with a new hash to check it can be done
        block_hash = BlockHash::from_slice(&get_random_bytes(32)).unwrap();
        dbm.store_last_known_block_watcher(block_hash).unwrap();
        assert_eq!(dbm.load_last_known_block_watcher().unwrap(), block_hash);

        // Check that the Responder's entry is unaffected
        assert!(matches!(
            dbm.load_last_known_block_responder(),
            Err(Error::NotFound)
        ));
    }

    #[test]
    fn store_load_last_known_block_responder() {
        let dbm = DBM::in_memory().unwrap();

        let mut block_hash = BlockHash::from_slice(&get_random_bytes(32)).unwrap();
        dbm.store_last_known_block_responder(block_hash).unwrap();
        assert_eq!(dbm.load_last_known_block_responder().unwrap(), block_hash);

        // Update with a new hash to check it can be done
        block_hash = BlockHash::from_slice(&get_random_bytes(32)).unwrap();
        dbm.store_last_known_block_responder(block_hash).unwrap();
        assert_eq!(dbm.load_last_known_block_responder().unwrap(), block_hash);

        // Check that the Watcher's entry is unaffected
        assert!(matches!(
            dbm.load_last_known_block_watcher(),
            Err(Error::NotFound)
        ));
    }
}
