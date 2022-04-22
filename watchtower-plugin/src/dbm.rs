use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;
use std::path::PathBuf;
use std::str::FromStr;

use rusqlite::{params, Connection, Error as SqliteError};

use bitcoin::secp256k1::SecretKey;

use teos_common::appointment::{Appointment, Locator};
use teos_common::dbm::{DatabaseConnection, DatabaseManager, Error};
use teos_common::receipts::{AppointmentReceipt, RegistrationReceipt};
use teos_common::TowerId;

use crate::{AppointmentStatus, MisbehaviorProof, TowerInfo, TowerStatus, TowerSummary};

const TABLES: [&str; 8] = [
    "CREATE TABLE IF NOT EXISTS towers (
    tower_id INT PRIMARY KEY,
    net_addr TEXT NOT NULL,
    available_slots INT NOT NULL,
    subscription_expiry INT NOT NULL
)",
    "CREATE TABLE IF NOT EXISTS appointments (
    locator INT PRIMARY KEY,
    encrypted_blob BLOB,
    to_self_delay INT
)",
    "CREATE TABLE IF NOT EXISTS pending_appointments (
    locator INT NOT NULL,
    tower_id INT NOT NULL,
    PRIMARY KEY (locator, tower_id),
    FOREIGN KEY(locator)
        REFERENCES appointments(locator)
        ON DELETE CASCADE
    FOREIGN KEY(tower_id)
        REFERENCES towers(tower_id)
        ON DELETE CASCADE
)",
    "CREATE TABLE IF NOT EXISTS invalid_appointments (
    locator INT NOT NULL,
    tower_id INT NOT NULL,
    PRIMARY KEY (locator, tower_id),
    FOREIGN KEY(locator)
        REFERENCES appointments(locator)
        ON DELETE CASCADE
    FOREIGN KEY(tower_id)
        REFERENCES towers(tower_id)
        ON DELETE CASCADE
)",
    "CREATE TABLE IF NOT EXISTS registration_receipts (
    tower_id INT PRIMARY KEY,
    available_slots INT NOT NULL,
    subscription_expiry INT NOT NULL,
    signature BLOB NOT NULL,
    FOREIGN KEY(tower_id)
        REFERENCES towers(tower_id)
        ON DELETE CASCADE
)",
    "CREATE TABLE IF NOT EXISTS appointment_receipts (
    locator INT NOT NULL,
    tower_id INT NOT NULL,
    start_block INT NOT NULL,
    user_signature BLOB NOT NULL,
    tower_signature BLOB NOT NULL,
    PRIMARY KEY (locator, tower_id),
    FOREIGN KEY(tower_id)
        REFERENCES towers(tower_id)
        ON DELETE CASCADE
)",
    "CREATE TABLE IF NOT EXISTS misbehaving_proofs (
    tower_id INT PRIMARY KEY,
    locator INT NOT NULL,
    recovered_id INT NOT NULL,
    FOREIGN KEY(locator, tower_id)
        REFERENCES appointment_receipts(locator, tower_id)
        ON DELETE CASCADE
)",
    "CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key INT NOT NULL
)",
];

/// Component in charge of interacting with the underlying database.
///
/// Currently works for `SQLite`. `PostgreSQL` should also be added in the future.
#[derive(Debug)]
pub struct DBM {
    /// The underlying database connection.
    connection: Connection,
}

impl DatabaseConnection for DBM {
    fn get_connection(&self) -> &Connection {
        &self.connection
    }

    fn get_mut_connection(&mut self) -> &mut Connection {
        &mut self.connection
    }
}

impl DBM {
    /// Creates a new [DBM] instance.
    pub fn new(db_path: &PathBuf) -> Result<Self, SqliteError> {
        let connection = Connection::open(db_path)?;
        connection.execute("PRAGMA foreign_keys=1;", [])?;
        let mut dbm = Self { connection };
        dbm.create_tables(Vec::from_iter(TABLES))?;

        Ok(dbm)
    }

    /// Stores the client secret key into the database.
    ///
    /// When a new key is generated, old keys are not overwritten but are not retrievable from the API either.
    pub fn store_client_key(&self, sk: &SecretKey) -> Result<(), Error> {
        let query = "INSERT INTO keys (key) VALUES (?)";
        self.store_data(query, params![sk.to_string()])
    }

    /// Loads the last known client secret key from the database.
    ///
    /// Loads the key with higher id from the database. Old keys are not overwritten just in case a recovery is needed,
    /// but they are not accessible from the API either.
    pub fn load_client_key(&self) -> Result<SecretKey, Error> {
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

    /// Stores a tower record into the database.
    pub fn store_tower_record(
        &self,
        tower_id: TowerId,
        net_addr: &str,
        receipt: &RegistrationReceipt,
    ) -> Result<(), Error> {
        let query =
            "INSERT OR REPLACE INTO towers (tower_id, net_addr, available_slots, subscription_expiry) VALUES (?1, ?2, ?3, ?4)";
        self.store_data(
            query,
            params![
                tower_id.to_vec(),
                net_addr,
                receipt.available_slots(),
                receipt.subscription_expiry()
            ],
        )
    }

    /// Loads a tower record from the database.
    ///
    /// Tower records are composed from the tower information and the appointment data. The latter is split in:
    /// accepted appointments (represented by appointment receipts), pending appointments and invalid appointments.
    /// In the case that the tower has misbehaved, then a misbehaving proof is also attached to the record.
    pub fn load_tower_record(&self, tower_id: TowerId) -> Result<TowerInfo, Error> {
        let mut stmt = self
        .connection
        .prepare("SELECT net_addr, available_slots, subscription_expiry FROM towers WHERE tower_id = ?")
        .unwrap();

        let mut tower = stmt
            .query_row([tower_id.to_vec()], |row| {
                let net_addr: String = row.get(0).unwrap();
                let available_slots: u32 = row.get(1).unwrap();
                let subscription_expiry: u32 = row.get(2).unwrap();
                Ok(TowerInfo::new(
                    net_addr,
                    available_slots,
                    subscription_expiry,
                    self.load_appointment_receipts(tower_id),
                    self.load_appointments(tower_id, AppointmentStatus::Pending),
                    self.load_appointments(tower_id, AppointmentStatus::Invalid),
                ))
            })
            .map_err(|_| Error::NotFound)?;

        if let Ok(proof) = self.load_misbehaving_proof(tower_id) {
            tower.status = TowerStatus::Misbehaving;
            tower.set_misbehaving_proof(proof);
        }

        Ok(tower)
    }

    /// Loads all tower records from the database.
    pub fn load_towers(&self) -> HashMap<TowerId, TowerSummary> {
        let mut towers = HashMap::new();
        let mut stmt = self.connection.prepare("SELECT * FROM towers").unwrap();
        let mut rows = stmt.query([]).unwrap();

        while let Ok(Some(row)) = rows.next() {
            let raw_towerid: Vec<u8> = row.get(0).unwrap();
            let tower_id = TowerId::from_slice(&raw_towerid).unwrap();
            let net_addr: String = row.get(1).unwrap();
            let available_slots: u32 = row.get(2).unwrap();
            let subscription_expiry: u32 = row.get(3).unwrap();

            let mut tower = TowerSummary::with_appointments(
                net_addr,
                available_slots,
                subscription_expiry,
                self.load_appointment_locators(tower_id, AppointmentStatus::Pending),
                self.load_appointment_locators(tower_id, AppointmentStatus::Invalid),
            );

            if self.exists_misbehaving_proof(tower_id) {
                tower.status = TowerStatus::Misbehaving;
            }

            towers.insert(tower_id, tower);
        }

        towers
    }

    /// Stores an appointments receipt into the database representing an appointment accepted by a given tower.
    pub fn store_appointment_receipt(
        &mut self,
        tower_id: TowerId,
        locator: Locator,
        available_slots: u32,
        receipt: &AppointmentReceipt,
    ) -> Result<(), SqliteError> {
        let tx = self.get_mut_connection().transaction().unwrap();
        tx.execute(
            "INSERT INTO appointment_receipts (locator, tower_id, start_block, user_signature, tower_signature) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                locator.to_vec(),
                tower_id.to_vec(),
                receipt.start_block(),
                receipt.user_signature(),
                receipt.signature()
            ],
        )?;
        tx.execute(
            "UPDATE towers SET available_slots=?1 WHERE tower_id=?2",
            params![available_slots, tower_id.to_vec()],
        )?;
        tx.commit()
    }

    /// Loads the appointment receipts associated to a given tower
    ///
    /// TODO: Currently this is only loading a summary of the receipt, if we need to really load all the information
    /// for any reason this method may need to be renamed.
    pub fn load_appointment_receipts(&self, tower_id: TowerId) -> HashMap<Locator, String> {
        let mut receipts = HashMap::new();
        let mut stmt = self
            .connection
            .prepare("SELECT locator, tower_signature FROM appointment_receipts WHERE tower_id = ?")
            .unwrap();
        let mut rows = stmt.query([tower_id.to_vec()]).unwrap();

        while let Ok(Some(row)) = rows.next() {
            let locator = Locator::from_slice(&row.get::<_, Vec<u8>>(0).unwrap()).unwrap();
            let signature = row.get::<_, String>(1).unwrap();

            receipts.insert(locator, signature);
        }

        receipts
    }

    /// Loads a collection of locators from the database entry associated to a given tower.
    ///
    /// The loaded locators can be loaded either from appointment_receipts, pending_appointments or invalid_appointments
    ///  depending on `status`.
    fn load_appointment_locators(
        &self,
        tower_id: TowerId,
        status: AppointmentStatus,
    ) -> HashSet<Locator> {
        let status = match status {
            AppointmentStatus::Accepted => "appointment_receipts",
            AppointmentStatus::Pending => "pending_appointments",
            AppointmentStatus::Invalid => "invalid_appointments",
        };
        let mut appointments = HashSet::new();
        // TODO: Can this be prepared instead of formatted (using ?1 seems to fail)?
        let mut stmt = self
            .connection
            .prepare(&format!(
                "SELECT locator FROM {} WHERE tower_id = ?",
                status
            ))
            .unwrap();

        let mut rows = stmt.query(params![tower_id.to_vec()]).unwrap();
        while let Ok(Some(inner_row)) = rows.next() {
            appointments
                .insert(Locator::from_slice(&inner_row.get::<_, Vec<u8>>(0).unwrap()).unwrap());
        }

        appointments
    }

    /// Stores an appointment into the database.
    ///
    /// Appointments are only stored as a whole when they are pending or invalid.
    /// Accepted appointments are simplified in the form of an appointment receipt.
    fn store_appointment(
        tx: &rusqlite::Transaction,
        appointment: &Appointment,
    ) -> Result<usize, SqliteError> {
        tx.execute(
            "INSERT INTO appointments (locator, encrypted_blob, to_self_delay) VALUES (?1, ?2, ?3)",
            params![
                appointment.locator.to_vec(),
                appointment.encrypted_blob,
                appointment.to_self_delay
            ],
        )
    }

    /// Stores a pending appointment into the database.
    ///
    /// A pending appointment is an appointment that was sent to a tower when it was unreachable.
    /// This data is stored so it can be resent once the tower comes back online.
    /// Internally calls [Self::store_appointment].
    pub fn store_pending_appointment(
        &mut self,
        tower_id: TowerId,
        appointment: &Appointment,
    ) -> Result<(), SqliteError> {
        let tx = self.get_mut_connection().transaction().unwrap();

        Self::store_appointment(&tx, appointment)?;
        tx.execute(
            "INSERT INTO pending_appointments (locator, tower_id) VALUES (?1, ?2)",
            params![appointment.locator.to_vec(), tower_id.to_vec(),],
        )?;

        tx.commit()
    }

    /// Stores an invalid appointment into the database.
    ///
    /// An invalid appointment is an appointment that was rejected by the tower.
    /// Storing this data may allow us to see what was the issue and send the data later on.
    /// Internally calls [Self::store_appointment].
    pub fn store_invalid_appointment(
        &mut self,
        tower_id: TowerId,
        appointment: &Appointment,
    ) -> Result<(), SqliteError> {
        let tx = self.get_mut_connection().transaction().unwrap();

        Self::store_appointment(&tx, appointment)?;
        tx.execute(
            "INSERT INTO invalid_appointments (locator, tower_id) VALUES (?1, ?2)",
            params![appointment.locator.to_vec(), tower_id.to_vec(),],
        )?;

        tx.commit()
    }

    /// Loads non finalized appointments from the database for a given tower based on a status flag.
    ///
    /// This is meant to be used only for pending and invalid appointments, if the method is called for
    /// accepted appointment, an empty collection will be returned.
    pub fn load_appointments(
        &self,
        tower_id: TowerId,
        status: AppointmentStatus,
    ) -> Vec<Appointment> {
        let table = match status {
            AppointmentStatus::Accepted => return Vec::new(),
            AppointmentStatus::Pending => "pending_appointments",
            AppointmentStatus::Invalid => "invalid_appointments",
        };

        let mut appointments = Vec::new();
        let mut stmt = self
            .connection
            .prepare(&format!("SELECT * FROM appointments as a, {} as t WHERE a.locator = t.locator AND t.tower_id = ?", table))
            .unwrap();
        let mut rows = stmt.query([tower_id.to_vec()]).unwrap();

        while let Ok(Some(row)) = rows.next() {
            let locator = Locator::from_slice(&row.get::<_, Vec<u8>>(0).unwrap()).unwrap();
            let encrypted_blob = row.get::<_, Vec<u8>>(1).unwrap();
            let to_self_delay = row.get::<_, u32>(2).unwrap();

            appointments.push(Appointment::new(locator, encrypted_blob, to_self_delay));
        }

        appointments
    }

    /// Stores a misbehaving proof into the database.
    ///
    /// A misbehaving proof is proof that the tower has signed an appointment using a key different
    /// than the one advertised to the user when they registered.
    pub fn store_misbehaving_proof(
        &mut self,
        tower_id: TowerId,
        proof: &MisbehaviorProof,
    ) -> Result<(), SqliteError> {
        let tx = self.get_mut_connection().transaction().unwrap();
        tx.execute(
            "INSERT INTO appointment_receipts (tower_id, locator, start_block, user_signature, tower_signature) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                tower_id.to_vec(),
                proof.locator.to_vec(),
                proof.appointment_receipt.start_block(),
                proof.appointment_receipt.user_signature(),
                proof.appointment_receipt.signature()
            ],
        )?;
        tx.execute(
            "INSERT INTO misbehaving_proofs (tower_id, locator, recovered_id) VALUES (?1, ?2, ?3)",
            params![
                tower_id.to_vec(),
                proof.locator.to_vec(),
                proof.recovered_id.to_vec()
            ],
        )?;

        tx.commit()
    }

    /// Loads the misbehaving proof for a given tower from the database (if found).
    fn load_misbehaving_proof(&self, tower_id: TowerId) -> Result<MisbehaviorProof, Error> {
        let mut misbehaving_stmt = self
            .connection
            .prepare("SELECT locator, recovered_id FROM misbehaving_proofs WHERE tower_id = ?")
            .unwrap();

        misbehaving_stmt
            .query_row([tower_id.to_vec()], |row| {
                let locator = Locator::from_slice(&row.get::<_, Vec<u8>>(0).unwrap()).unwrap();
                let recovered_id = TowerId::from_slice(&row.get::<_, Vec<u8>>(1).unwrap()).unwrap();
                Ok((locator, recovered_id))
            })
            .map(|(locator, recovered_id)| {
                let mut receipt_stmt = self
                .connection
                .prepare(
                    "SELECT start_block, user_signature, tower_signature FROM appointment_receipts WHERE locator = ?1 AND tower_id = ?2",
                )
                .unwrap();
                let receipt = receipt_stmt
                    .query_row([locator.to_vec(), tower_id.to_vec()], |row| {
                        let start_block = row.get::<_, u32>(0).unwrap();
                        let user_signature = row.get::<_, String>(1).unwrap();
                        let tower_signature = row.get::<_, String>(2).unwrap();
                        Ok(AppointmentReceipt::with_signature(
                            user_signature,
                            start_block,
                            tower_signature,
                        ))
                    })
                    .unwrap();
                MisbehaviorProof::new(locator, receipt, recovered_id)
        }).map_err(|_| Error::NotFound)
    }

    /// Checks whether a misbehaving proof exists for a given tower.
    fn exists_misbehaving_proof(&self, tower_id: TowerId) -> bool {
        let mut misbehaving_stmt = self
            .connection
            .prepare("SELECT tower_id FROM misbehaving_proofs WHERE tower_id = ?")
            .unwrap();
        misbehaving_stmt.exists([tower_id.to_vec()]).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use teos_common::test_utils::{
        generate_random_appointment, get_random_registration_receipt, get_random_user_id,
    };

    impl DBM {
        pub(crate) fn in_memory() -> Result<Self, SqliteError> {
            let connection = Connection::open_in_memory()?;
            connection.execute("PRAGMA foreign_keys=1;", [])?;
            let mut dbm = Self { connection };
            dbm.create_tables(Vec::from_iter(TABLES))?;

            Ok(dbm)
        }
    }

    #[test]
    fn test_create_tables() {
        let connection = Connection::open_in_memory().unwrap();
        let mut dbm = DBM { connection };
        dbm.create_tables(Vec::from_iter(TABLES)).unwrap();
    }

    #[test]
    fn test_store_load_tower_record() {
        let dbm = DBM::in_memory().unwrap();

        // In order to add a tower record we need to associated registration receipt.
        let tower_id = get_random_user_id();
        let net_addr = "talaia.watch";

        let receipt = get_random_registration_receipt();
        let tower_info = TowerInfo::new(
            net_addr.into(),
            receipt.available_slots(),
            receipt.subscription_expiry(),
            HashMap::new(),
            Vec::new(),
            Vec::new(),
        );

        // Check the loaded data matches the in memory data
        dbm.store_tower_record(tower_id, net_addr, &receipt)
            .unwrap();
        assert_eq!(dbm.load_tower_record(tower_id).unwrap(), tower_info);
    }

    #[test]
    fn test_load_nonexistent_tower_record() {
        let dbm = DBM::in_memory().unwrap();

        // If the tower does not exists, `load_tower` will fail.
        let tower_id = get_random_user_id();
        assert!(matches!(
            dbm.load_tower_record(tower_id),
            Err(Error::NotFound)
        ));
    }

    #[test]
    fn test_store_load_towers() {
        let dbm = DBM::in_memory().unwrap();
        let mut towers = HashMap::new();

        // In order to add a tower record we need to associated registration receipt.
        for _ in 0..5 {
            let tower_id = get_random_user_id();
            let net_addr = "talaia.watch";

            let receipt = get_random_registration_receipt();
            towers.insert(
                tower_id,
                TowerSummary::new(
                    net_addr.into(),
                    receipt.available_slots(),
                    receipt.subscription_expiry(),
                ),
            );

            dbm.store_tower_record(tower_id, net_addr, &receipt)
                .unwrap();
        }

        assert_eq!(dbm.load_towers(), towers);
    }

    #[test]
    fn test_load_towers_empty() {
        // If there are no towers in the database, `load_towers` should return an empty map.
        let dbm = DBM::in_memory().unwrap();
        assert_eq!(dbm.load_towers(), HashMap::new());
    }

    #[test]
    fn test_store_load_appointment_receipts() {
        let mut dbm = DBM::in_memory().unwrap();

        // In order to add a tower record we need to associated registration receipt.
        let tower_id = get_random_user_id();
        let net_addr = "talaia.watch";

        let receipt = get_random_registration_receipt();
        let mut tower_summary = TowerSummary::new(
            net_addr.into(),
            receipt.available_slots(),
            receipt.subscription_expiry(),
        );
        dbm.store_tower_record(tower_id, net_addr, &receipt)
            .unwrap();

        // Add some appointment receipts and check they match
        let mut receipts = HashMap::new();
        for _ in 0..5 {
            let appointment = generate_random_appointment(None);
            let user_signature = "user_signature";
            let appointment_receipt = AppointmentReceipt::with_signature(
                user_signature.into(),
                42,
                "tower_signature".into(),
            );

            tower_summary.available_slots -= 1;

            dbm.store_appointment_receipt(
                tower_id,
                appointment.locator,
                tower_summary.available_slots,
                &appointment_receipt,
            )
            .unwrap();
            receipts.insert(
                appointment.locator,
                appointment_receipt.signature().unwrap(),
            );
        }

        assert_eq!(dbm.load_appointment_receipts(tower_id), receipts);
    }

    #[test]
    fn test_load_appointment_locators() {
        // `load_appointment_locators` is used to load locators from either `appointment_receipts`, `pending_appointments` or `invalid_appointments`
        let mut dbm = DBM::in_memory().unwrap();

        // We first need to add a tower record to the database so we can add some associated data.
        let tower_id = get_random_user_id();
        let net_addr = "talaia.watch";

        let receipt = get_random_registration_receipt();
        let tower_summary = TowerSummary::new(
            net_addr.into(),
            receipt.available_slots(),
            receipt.subscription_expiry(),
        );
        dbm.store_tower_record(tower_id, net_addr, &receipt)
            .unwrap();

        // Create all types of appointments and store them in the db.
        let user_signature = "user_signature";
        let mut receipts = HashSet::new();
        let mut pending_appointments = HashSet::new();
        let mut invalid_appointments = HashSet::new();
        for _ in 0..5 {
            let appointment = generate_random_appointment(None);
            let appointment_receipt = AppointmentReceipt::with_signature(
                user_signature.into(),
                42,
                "tower_signature".into(),
            );
            let pending_appointment = generate_random_appointment(None);
            let invalid_appointment = generate_random_appointment(None);

            dbm.store_appointment_receipt(
                tower_id,
                appointment.locator,
                tower_summary.available_slots,
                &appointment_receipt,
            )
            .unwrap();
            dbm.store_pending_appointment(tower_id, &pending_appointment)
                .unwrap();
            dbm.store_invalid_appointment(tower_id, &invalid_appointment)
                .unwrap();

            receipts.insert(appointment.locator);
            pending_appointments.insert(pending_appointment.locator);
            invalid_appointments.insert(invalid_appointment.locator);
        }

        // Pull data from the db and check it matches the expected data
        assert_eq!(
            dbm.load_appointment_locators(tower_id, AppointmentStatus::Accepted),
            receipts
        );
        assert_eq!(
            dbm.load_appointment_locators(tower_id, AppointmentStatus::Pending),
            pending_appointments
        );
        assert_eq!(
            dbm.load_appointment_locators(tower_id, AppointmentStatus::Invalid),
            invalid_appointments
        );
    }

    // `store_appointments` is implicitly tested by `store_pending_appointment` and `store_invalid_appointment`

    #[test]
    fn test_store_pending_appointment() {
        let mut dbm = DBM::in_memory().unwrap();

        // In order to add a tower record we need to associated registration receipt.
        let tower_id = get_random_user_id();
        let net_addr = "talaia.watch";

        let receipt = get_random_registration_receipt();
        let mut tower_summary = TowerSummary::new(
            net_addr.into(),
            receipt.available_slots(),
            receipt.subscription_expiry(),
        );
        dbm.store_tower_record(tower_id, net_addr, &receipt)
            .unwrap();

        // Add some pending appointments and check they match
        for _ in 0..5 {
            let appointment = generate_random_appointment(None);

            tower_summary
                .pending_appointments
                .insert(appointment.locator);

            dbm.store_pending_appointment(tower_id, &appointment)
                .unwrap();
            assert_eq!(
                TowerSummary::from(dbm.load_tower_record(tower_id).unwrap()),
                tower_summary
            );
        }
    }

    #[test]
    fn test_store_invalid_appointment() {
        let mut dbm = DBM::in_memory().unwrap();

        // In order to add a tower record we need to associated registration receipt.
        let tower_id = get_random_user_id();
        let net_addr = "talaia.watch";

        let receipt = get_random_registration_receipt();
        let mut tower_summary = TowerSummary::new(
            net_addr.into(),
            receipt.available_slots(),
            receipt.subscription_expiry(),
        );
        dbm.store_tower_record(tower_id, net_addr, &receipt)
            .unwrap();

        // Add some invalid appointments and check they match
        for _ in 0..5 {
            let appointment = generate_random_appointment(None);

            tower_summary
                .invalid_appointments
                .insert(appointment.locator);

            dbm.store_invalid_appointment(tower_id, &appointment)
                .unwrap();
            assert_eq!(
                TowerSummary::from(dbm.load_tower_record(tower_id).unwrap()),
                tower_summary
            );
        }
    }

    #[test]
    fn test_store_load_misbehaving_proof() {
        let mut dbm = DBM::in_memory().unwrap();

        // In order to add a tower record we need to associated registration receipt.
        let tower_id = get_random_user_id();
        let net_addr = "talaia.watch";

        let receipt = get_random_registration_receipt();
        let tower_summary = TowerSummary::new(
            net_addr.into(),
            receipt.available_slots(),
            receipt.subscription_expiry(),
        );
        dbm.store_tower_record(tower_id, net_addr, &receipt)
            .unwrap();
        assert_eq!(
            TowerSummary::from(dbm.load_tower_record(tower_id).unwrap()),
            tower_summary
        );

        // Store a misbehaving proof and load it back
        let appointment = generate_random_appointment(None);
        let appointment_receipt = AppointmentReceipt::with_signature(
            "user_signature".into(),
            42,
            "tower_signature".into(),
        );

        let proof = MisbehaviorProof::new(
            appointment.locator,
            appointment_receipt,
            get_random_user_id(),
        );

        dbm.store_misbehaving_proof(tower_id, &proof).unwrap();
        assert_eq!(dbm.load_misbehaving_proof(tower_id).unwrap(), proof);
    }

    #[test]
    fn test_store_load_non_existing_misbehaving_proof() {
        let dbm = DBM::in_memory().unwrap();
        assert!(matches!(
            dbm.load_misbehaving_proof(get_random_user_id()),
            Err(Error::NotFound)
        ));
    }

    #[test]
    fn test_store_exists_misbehaving_proof() {
        let mut dbm = DBM::in_memory().unwrap();

        // In order to add a tower record we need to associated registration receipt.
        let tower_id = get_random_user_id();
        let net_addr = "talaia.watch";

        let receipt = get_random_registration_receipt();
        let tower_summary = TowerSummary::new(
            net_addr.into(),
            receipt.available_slots(),
            receipt.subscription_expiry(),
        );
        dbm.store_tower_record(tower_id, net_addr, &receipt)
            .unwrap();
        assert_eq!(
            TowerSummary::from(dbm.load_tower_record(tower_id).unwrap()),
            tower_summary
        );

        // // Store a misbehaving proof check
        let appointment = generate_random_appointment(None);
        let appointment_receipt = AppointmentReceipt::with_signature(
            "user_signature".into(),
            42,
            "tower_signature".into(),
        );

        let proof = MisbehaviorProof::new(
            appointment.locator,
            appointment_receipt,
            get_random_user_id(),
        );

        dbm.store_misbehaving_proof(tower_id, &proof).unwrap();
        assert!(dbm.exists_misbehaving_proof(tower_id));
    }

    #[test]
    fn test_exists_misbehaving_proof_false() {
        let dbm = DBM::in_memory().unwrap();
        assert!(!dbm.exists_misbehaving_proof(get_random_user_id()));
    }
}
