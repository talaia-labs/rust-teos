//! Logic related to the tower database manager (DBM), component in charge of persisting data on disk.
#![allow(dead_code)]

use std::collections::HashMap;
use std::str::FromStr;

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::SecretKey;
use bitcoin::{consensus, BlockHash};
use sqlx::any::{install_drivers, AnyRow};
use sqlx::{AnyPool, Error, Row};

use teos_common::appointment::{Appointment, Locator};
use teos_common::UserId;

use crate::extended_appointment::{ExtendedAppointment, UUID};
use crate::gatekeeper::UserInfo;
use crate::responder::{ConfirmationStatus, PenaltySummary, TransactionTracker};
use crate::watcher::Breach;

#[cfg(not(test))]
/// The maximum number of bind variables per SQL query.
/// `32766` for SQLite & `65535` for PostgreSQL. Picking `32766` for both since it's big enough already.
const SQL_VARIABLE_LIMIT: usize = 32766;
#[cfg(test)]
/// The maximum number of bind variables per SQL query. Set to `10` for testing.
const SQL_VARIABLE_LIMIT: usize = 10;

/// Checks if the database type (`$db_type`) matches with the connection string (`$connection_string`).
/// If the connection string matches the database type, this macro does:
/// - Try to install the driver for the passed database type.
/// - Try to connect to the database.
/// - Try to run the migrations specified in `$migrations_path`.
/// - Return [Ok(DBM)] if everything succeeds, [Err(String)] otherwise explaining the error.
macro_rules! return_db_if_matching {
    ($connection_string:expr, $db_type:tt, $migrations_path:literal) => {
        if $connection_string.starts_with(concat!(stringify!($db_type), ":")) {
            install_drivers(&[sqlx::$db_type::any::DRIVER])
                // Just log the warning but try to connect anyways. `install_drivers` might fail if the driver is already installed.
                .map_err(|e| log::error!("Failed to install database drivers for {}: {e}", stringify!($db_type)))
                .ok();
            let pool = AnyPool::connect($connection_string)
                .await
                .map_err(|e| format!("Couldn't connect to {}: {e}", $connection_string))?;
            sqlx::migrate!($migrations_path)
                .run(&pool)
                .await
                .map_err(|e| format!("Failed to run database migrations: {e}"))?;
            return Ok(Self { pool });
        }
    }
}

/// Component in charge of interacting with the underlying database.
#[derive(Debug)]
pub struct DBM {
    // TODO: Add MySQL support. The queries used right now isn't MySQL-compatible.
    pool: AnyPool,
}

impl DBM {
    /// Creates a new [DBM] instance.
    pub async fn new(connection_string: &str) -> Result<Self, String> {
        #[cfg(not(any(feature = "sqlite", feature = "postgres")))]
        compile_error!("Can't compile with no database drivers.");

        // Note that sqlx initiates `PRAGMA foreign_keys = ON` connections by default.
        #[cfg(feature = "sqlite")]
        return_db_if_matching!(connection_string, sqlite, "migrations/sqlite");

        #[cfg(feature = "postgres")]
        return_db_if_matching!(connection_string, postgres, "migrations/postgres");

        let supported_dbs = vec![
            #[cfg(feature = "sqlite")]
            "SQLite",
            #[cfg(feature = "postgres")]
            "PostgreSQL",
        ];

        Err(format!(
            "The database connection string ({connection_string}) is invalid or isn't supported. Supported databases are: {supported_dbs:?}."
        ))
    }

    /// Stores a user ([UserInfo]) into the database.
    pub(crate) async fn store_user(
        &self,
        user_id: UserId,
        user_info: &UserInfo,
    ) -> Result<(), Error> {
        let sql = "INSERT INTO users (user_id, available_slots, subscription_start, subscription_expiry) VALUES ($1, $2, $3, $4)";
        sqlx::query(sql)
            .bind(user_id.to_vec())
            .bind(user_info.available_slots as i64)
            .bind(user_info.subscription_start as i64)
            .bind(user_info.subscription_expiry as i64)
            .execute(&self.pool)
            .await
            .map(|_| ())
    }

    /// Updates an existing user ([UserInfo]) in the database.
    pub(crate) async fn update_user(
        &self,
        user_id: UserId,
        user_info: &UserInfo,
    ) -> Result<(), Error> {
        let sql = "UPDATE users SET available_slots=($1), subscription_start=($2), subscription_expiry=($3) WHERE user_id=($4)";
        let updated_rows = sqlx::query(sql)
            .bind(user_info.available_slots as i64)
            .bind(user_info.subscription_start as i64)
            .bind(user_info.subscription_expiry as i64)
            .bind(user_id.to_vec())
            .execute(&self.pool)
            .await?
            .rows_affected();

        (updated_rows != 0).then_some(()).ok_or(Error::RowNotFound)
    }

    /// Loads the associated locators ([Locator]) of a given user ([UserId]).
    pub(crate) async fn load_user_locators(&self, user_id: UserId) -> Vec<Locator> {
        sqlx::query("SELECT locator FROM appointments WHERE user_id=($1)")
            .bind(user_id.to_vec())
            .map(|row: AnyRow| Locator::from_slice(row.get("locator")).unwrap())
            .fetch_all(&self.pool)
            .await
            .unwrap()
    }

    /// Loads all users from the database.
    pub(crate) async fn load_all_users(&self) -> HashMap<UserId, UserInfo> {
        sqlx::query(
            "SELECT user_id, available_slots, subscription_start, subscription_expiry FROM users",
        )
        .map(|row: AnyRow| {
            (
                UserId::from_slice(row.get("user_id")).unwrap(),
                UserInfo::new(
                    row.get::<i64, _>("available_slots") as u32,
                    row.get::<i64, _>("subscription_start") as u32,
                    row.get::<i64, _>("subscription_expiry") as u32,
                ),
            )
        })
        .fetch_all(&self.pool)
        .await
        .unwrap()
        .into_iter()
        .collect()
    }

    /// Removes some users from the database in batch.
    pub(crate) async fn batch_remove_users(&self, users: Vec<UserId>) -> usize {
        let users: Vec<_> = users.iter().map(|uuid| uuid.to_vec()).collect();

        for chunk in users.chunks(SQL_VARIABLE_LIMIT) {
            let str_indices: Vec<_> = (1..=chunk.len()).map(|i| i.to_string()).collect();
            let placeholders = format!("${}", str_indices.join(", $"));
            let sql = format!("DELETE FROM users WHERE user_id IN ({placeholders})");
            let mut query = sqlx::query(&sql);
            for user_id in chunk {
                query = query.bind(user_id);
            }
            query.execute(&self.pool).await.unwrap();
        }

        (users.len() as f64 / SQL_VARIABLE_LIMIT as f64).ceil() as usize
    }

    /// Get the number of stored appointments.
    pub(crate) async fn get_appointments_count(&self) -> usize {
        let sql = "SELECT COUNT(*) FROM appointments as a LEFT JOIN trackers as t ON a.UUID=t.UUID WHERE t.UUID IS NULL";
        sqlx::query(sql)
            .map(|row: AnyRow| row.get::<i64, _>(0) as usize)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    /// Get the number of stored trackers.
    pub(crate) async fn get_trackers_count(&self) -> usize {
        sqlx::query("SELECT COUNT(*) FROM trackers")
            .map(|row: AnyRow| row.get::<i64, _>(0) as usize)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    /// Stores an [Appointment] into the database.
    pub(crate) async fn store_appointment(
        &self,
        uuid: UUID,
        appointment: &ExtendedAppointment,
    ) -> Result<(), Error> {
        let sql = "INSERT INTO appointments (UUID, locator, encrypted_blob, to_self_delay, user_signature, start_block, user_id) VALUES ($1, $2, $3, $4, $5, $6, $7)";
        sqlx::query(sql)
            .bind(uuid.to_vec())
            .bind(appointment.locator().to_vec())
            .bind(appointment.encrypted_blob())
            .bind(appointment.to_self_delay() as i64)
            .bind(&appointment.user_signature)
            .bind(appointment.start_block as i64)
            .bind(appointment.user_id.to_vec())
            .execute(&self.pool)
            .await
            .map(|_| ())
    }

    /// Updates an existing [Appointment] in the database.
    pub(crate) async fn update_appointment(
        &self,
        uuid: UUID,
        appointment: &ExtendedAppointment,
    ) -> Result<(), Error> {
        // DISCUSS: Check what fields we'd like to make updatable. e_blob and signature are the obvious, to_self_delay and start_block may not be necessary (or even risky)
        let sql = "UPDATE appointments SET encrypted_blob=($1), to_self_delay=($2), user_signature=($3), start_block=($4) WHERE UUID=($5)";
        let updated_rows = sqlx::query(sql)
            .bind(appointment.encrypted_blob())
            .bind(appointment.to_self_delay() as i64)
            .bind(&appointment.user_signature)
            .bind(appointment.start_block as i64)
            .bind(uuid.to_vec())
            .execute(&self.pool)
            .await?
            .rows_affected();

        (updated_rows != 0).then_some(()).ok_or(Error::RowNotFound)
    }

    /// Loads an [Appointment] from the database.
    pub(crate) async fn load_appointment(&self, uuid: UUID) -> Option<ExtendedAppointment> {
        let sql = "SELECT locator, encrypted_blob, to_self_delay, user_id, user_signature, start_block FROM appointments WHERE UUID=($1)";
        sqlx::query(sql)
            .bind(uuid.to_vec())
            .map(|row: AnyRow| {
                ExtendedAppointment::new(
                    Appointment::new(
                        Locator::from_slice(row.get("locator")).unwrap(),
                        row.get("encrypted_blob"),
                        row.get::<i64, _>("to_self_delay") as u32,
                    ),
                    UserId::from_slice(row.get("user_id")).unwrap(),
                    row.get("user_signature"),
                    row.get::<i64, _>("start_block") as u32,
                )
            })
            .fetch_one(&self.pool)
            .await
            .ok()
    }

    /// Check if an appointment with `uuid` exists.
    pub(crate) async fn appointment_exists(&self, uuid: UUID) -> bool {
        sqlx::query("SELECT UUID FROM appointments WHERE UUID=($1)")
            .bind(uuid.to_vec())
            .fetch_one(&self.pool)
            .await
            .is_ok()
    }

    /// Loads appointments from the database. If a locator is given, this method loads only the appointments
    /// matching this locator. If no locator is given, all the appointments in the database would be returned.
    pub(crate) async fn load_appointments(
        &self,
        locator: Option<Locator>,
    ) -> HashMap<UUID, ExtendedAppointment> {
        let mut sql = "SELECT a.UUID, a.locator, a.encrypted_blob, a.to_self_delay, a.user_id, a.user_signature, a.start_block FROM appointments as a LEFT JOIN trackers as t ON a.UUID=t.UUID WHERE t.UUID IS NULL".to_string();

        // If a locator was passed, filter based on it.
        let query = if let Some(locator) = locator {
            sql.push_str(" AND a.locator=($1)");
            sqlx::query(&sql).bind(locator.to_vec())
        } else {
            sqlx::query(&sql)
        };

        query
            .map(|row: AnyRow| {
                (
                    UUID::from_slice(row.get(0)).unwrap(),
                    ExtendedAppointment::new(
                        Appointment::new(
                            Locator::from_slice(row.get(1)).unwrap(),
                            row.get(2),
                            row.get::<i64, _>(3) as u32,
                        ),
                        UserId::from_slice(row.get(4)).unwrap(),
                        row.get(5),
                        row.get::<i64, _>(6) as u32,
                    ),
                )
            })
            .fetch_all(&self.pool)
            .await
            .unwrap()
            .into_iter()
            .collect()
    }

    /// Gets the length of an appointment (the length of `appointment.encrypted_blob`).
    pub(crate) async fn get_appointment_length(&self, uuid: UUID) -> Result<usize, Error> {
        sqlx::query("SELECT length(encrypted_blob) FROM appointments WHERE UUID=($1)")
            .bind(uuid.to_vec())
            .map(|row: AnyRow| row.get::<i64, _>(0) as usize)
            .fetch_one(&self.pool)
            .await
    }

    /// Gets the [`UserId`] of the owner of the appointment along with the appointment
    /// length (same as [DBM::get_appointment_length]) for `uuid`.
    pub(crate) async fn get_appointment_user_and_length(
        &self,
        uuid: UUID,
    ) -> Result<(UserId, usize), Error> {
        sqlx::query("SELECT user_id, length(encrypted_blob) FROM appointments WHERE UUID=($1)")
            .bind(uuid.to_vec())
            .map(|row: AnyRow| {
                (
                    UserId::from_slice(row.get("user_id")).unwrap(),
                    row.get::<i64, _>(1) as usize,
                )
            })
            .fetch_one(&self.pool)
            .await
    }

    /// Removes an [Appointment] from the database.
    pub(crate) async fn remove_appointment(&self, uuid: UUID) {
        if let Err(e) = sqlx::query("DELETE FROM appointments WHERE UUID=($1)")
            .bind(uuid.to_vec())
            .execute(&self.pool)
            .await
        {
            log::error!("Failed to remove appointment ({uuid}) due to: {e}")
        }
    }

    /// Removes some appointments from the database in batch and updates the associated users
    /// (giving back freed appointment slots) in one transaction so that the deletion and the
    /// update is atomic.
    pub(crate) async fn batch_remove_appointments(
        &self,
        appointments: Vec<UUID>,
        updated_users: HashMap<UserId, UserInfo>,
    ) -> usize {
        let uuids: Vec<_> = appointments.iter().map(|uuid| uuid.to_vec()).collect();
        let mut tx = self.pool.begin().await.unwrap();

        for chunk in uuids.chunks(SQL_VARIABLE_LIMIT) {
            let str_indices: Vec<_> = (1..=chunk.len()).map(|i| i.to_string()).collect();
            let placeholders = format!("${}", str_indices.join(", $"));
            let sql = format!("DELETE FROM appointments WHERE UUID IN ({placeholders})");
            let mut query = sqlx::query(&sql);
            for uuid in chunk {
                query = query.bind(uuid);
            }
            query.execute(&mut *tx).await.unwrap();
        }

        for (user_id, info) in updated_users.iter() {
            sqlx::query("UPDATE users SET available_slots=($1) WHERE user_id=($2)")
                .bind(info.available_slots as i64)
                .bind(user_id.to_vec())
                .execute(&mut *tx)
                .await
                .unwrap();
        }

        if let Err(e) = tx.commit().await {
            log::error!("Failed to remove appointments in batch: {e}")
        }

        (uuids.len() as f64 / SQL_VARIABLE_LIMIT as f64).ceil() as usize
    }

    /// Loads the [`UUID`]s of appointments triggered by `locator`.
    pub(crate) async fn load_uuids(&self, locator: Locator) -> Vec<UUID> {
        sqlx::query("SELECT UUID from appointments WHERE locator=($1)")
            .bind(locator.to_vec())
            // NOTE: For some reason, indexing using the string "UUID" fails on PostgreSQL.
            // Using numerical index for interoperability with SQLite.
            .map(|row: AnyRow| UUID::from_slice(row.get(0)).unwrap())
            .fetch_all(&self.pool)
            .await
            .unwrap()
    }

    /// Filters the given set of [`Locator`]s by including only the ones which trigger any of our stored appointments.
    pub(crate) async fn batch_check_locators_exist(&self, locators: Vec<&Locator>) -> Vec<Locator> {
        let mut registered_locators = Vec::new();
        let locators: Vec<_> = locators.iter().map(|l| l.to_vec()).collect();

        for chunk in locators.chunks(SQL_VARIABLE_LIMIT) {
            let str_indices: Vec<_> = (1..=chunk.len()).map(|i| i.to_string()).collect();
            let placeholders = format!("${}", str_indices.join(", $"));
            let sql = format!("SELECT locator FROM appointments WHERE locator IN ({placeholders})");
            let mut query = sqlx::query(&sql);
            for locator in chunk {
                query = query.bind(locator);
            }
            registered_locators.extend(
                query
                    .map(|row: AnyRow| Locator::from_slice(row.get("locator")).unwrap())
                    .fetch_all(&self.pool)
                    .await
                    .unwrap(),
            )
        }

        registered_locators
    }

    /// Stores a [TransactionTracker] into the database.
    pub(crate) async fn store_tracker(
        &self,
        uuid: UUID,
        tracker: &TransactionTracker,
    ) -> Result<(), Error> {
        let (height, confirmed) = tracker
            .status
            .to_db_data()
            .ok_or(Error::Decode("Tracker status isn't storable".into()))?;
        let sql = "INSERT INTO trackers (UUID, dispute_tx, penalty_tx, height, confirmed) VALUES ($1, $2, $3, $4, $5)";
        sqlx::query(sql)
            .bind(uuid.to_vec())
            .bind(consensus::serialize(&tracker.dispute_tx))
            .bind(consensus::serialize(&tracker.penalty_tx))
            .bind(height as i64)
            .bind(confirmed as i64)
            .execute(&self.pool)
            .await
            .map(|_| ())
    }

    /// Updates the tracker status in the database.
    ///
    /// The only updatable fields are `height` and `confirmed`.
    pub(crate) async fn update_tracker_status(
        &self,
        uuid: UUID,
        status: &ConfirmationStatus,
    ) -> Result<(), Error> {
        let (height, confirmed) = status
            .to_db_data()
            .ok_or(Error::Decode("Tracker status isn't storable".into()))?;
        let updated_rows =
            sqlx::query("UPDATE trackers SET height=($1), confirmed=($2) WHERE UUID=($3)")
                .bind(height as i64)
                .bind(confirmed as i64)
                .bind(uuid.to_vec())
                .execute(&self.pool)
                .await?
                .rows_affected();

        (updated_rows != 0).then_some(()).ok_or(Error::RowNotFound)
    }

    /// Loads a [TransactionTracker] from the database.
    pub(crate) async fn load_tracker(&self, uuid: UUID) -> Option<TransactionTracker> {
        let sql = "SELECT t.dispute_tx, t.penalty_tx, a.user_id, t.height, t.confirmed FROM trackers as t INNER JOIN appointments as a ON t.UUID=a.UUID WHERE t.UUID=($1)";
        sqlx::query(sql)
            .bind(uuid.to_vec())
            .map(|row: AnyRow| {
                TransactionTracker::new(
                    Breach::new(
                        consensus::deserialize(row.get(0)).unwrap(),
                        consensus::deserialize(row.get(1)).unwrap(),
                    ),
                    UserId::from_slice(row.get(2)).unwrap(),
                    ConfirmationStatus::from_db_data(
                        row.get::<i64, _>(3) as u32,
                        row.get::<i64, _>(4) != 0,
                    ),
                )
            })
            .fetch_one(&self.pool)
            .await
            .ok()
    }

    /// Check if a tracker with `uuid` exists.
    pub(crate) async fn tracker_exists(&self, uuid: UUID) -> bool {
        sqlx::query("SELECT UUID FROM trackers WHERE UUID=($1)")
            .bind(uuid.to_vec())
            .fetch_one(&self.pool)
            .await
            .is_ok()
    }

    /// Loads trackers from the database. If a locator is given, this method loads only the trackers
    /// matching this locator. If no locator is given, all the trackers in the database would be returned.
    pub(crate) async fn load_trackers(
        &self,
        locator: Option<Locator>,
    ) -> HashMap<UUID, TransactionTracker> {
        let mut sql = "SELECT t.UUID, t.dispute_tx, t.penalty_tx, a.user_id, t.height, t.confirmed FROM trackers as t INNER JOIN appointments as a ON t.UUID=a.UUID".to_string();

        // If a locator was passed, filter based on it.
        let query = if let Some(locator) = locator {
            sql.push_str(" WHERE a.locator=($1)");
            sqlx::query(&sql).bind(locator.to_vec())
        } else {
            sqlx::query(&sql)
        };

        query
            .map(|row: AnyRow| {
                (
                    UUID::from_slice(row.get(0)).unwrap(),
                    TransactionTracker::new(
                        Breach::new(
                            consensus::deserialize(row.get(1)).unwrap(),
                            consensus::deserialize(row.get(2)).unwrap(),
                        ),
                        UserId::from_slice(row.get(3)).unwrap(),
                        ConfirmationStatus::from_db_data(
                            row.get::<i64, _>(4) as u32,
                            row.get::<i64, _>(5) != 0,
                        ),
                    ),
                )
            })
            .fetch_all(&self.pool)
            .await
            .unwrap()
            .into_iter()
            .collect()
    }

    /// Loads trackers with the given confirmation status.
    ///
    /// Note that for [`ConfirmationStatus::InMempoolSince(height)`] variant, this pulls trackers
    /// with `h <= height` and not just `h = height`.
    pub(crate) async fn load_trackers_with_confirmation_status(
        &self,
        status: ConfirmationStatus,
    ) -> Result<Vec<UUID>, Error> {
        let (height, confirmed) = status
            .to_db_data()
            .ok_or(Error::Decode("Tracker status isn't storable".into()))?;

        sqlx::query(&format!(
            "SELECT UUID FROM trackers WHERE confirmed=($1) AND height{}($2)",
            if confirmed { "=" } else { "<=" }
        ))
        .bind(confirmed as i64)
        .bind(height as i64)
        .map(|row: AnyRow| UUID::from_slice(row.get(0)).unwrap())
        .fetch_all(&self.pool)
        .await
    }

    /// Loads the transaction IDs of all the penalties and their status from the database.
    pub(crate) async fn load_penalties_summaries(&self) -> HashMap<UUID, PenaltySummary> {
        let sql = "SELECT t.UUID, t.penalty_tx, t.height, t.confirmed FROM trackers as t INNER JOIN appointments as a ON t.UUID=a.UUID";
        sqlx::query(sql)
            .map(|row: AnyRow| {
                (
                    UUID::from_slice(row.get(0)).unwrap(),
                    PenaltySummary::new(
                        consensus::deserialize::<bitcoin::Transaction>(row.get(1))
                            .unwrap()
                            .txid(),
                        ConfirmationStatus::from_db_data(
                            row.get::<i64, _>(2) as u32,
                            row.get::<i64, _>(3) != 0,
                        ),
                    ),
                )
            })
            .fetch_all(&self.pool)
            .await
            .unwrap()
            .into_iter()
            .collect()
    }

    /// Stores the last known block into the database.
    pub(crate) async fn store_last_known_block(&self, block_hash: &BlockHash) -> Result<(), Error> {
        let sql = "INSERT INTO last_known_block (id, block_hash) VALUES (0, $1) ON CONFLICT (id) DO UPDATE SET block_hash = excluded.block_hash";
        sqlx::query(sql)
            .bind(block_hash.to_vec())
            .execute(&self.pool)
            .await
            .map(|_| ())
    }

    /// Loads the last known block from the database.
    pub async fn load_last_known_block(&self) -> Option<BlockHash> {
        sqlx::query("SELECT block_hash FROM last_known_block WHERE id=0")
            .map(|row: AnyRow| BlockHash::from_slice(row.get("block_hash")).unwrap())
            .fetch_one(&self.pool)
            .await
            .ok()
    }

    /// Stores the tower secret key into the database.
    ///
    /// When a new key is generated, old keys are not overwritten but are not retrievable from the API either.
    pub async fn store_tower_key(&self, sk: &SecretKey) -> Result<(), Error> {
        sqlx::query("INSERT INTO keys (secret_key) VALUES ($1)")
            .bind(sk.display_secret().to_string())
            .execute(&self.pool)
            .await
            .map(|_| ())
    }

    /// Loads the last known tower secret key from the database.
    ///
    /// Loads the key with higher id from the database. Old keys are not overwritten just in case a recovery is needed,
    /// but they are not accessible from the API either.
    pub async fn load_tower_key(&self) -> Option<SecretKey> {
        sqlx::query("SELECT secret_key FROM keys WHERE id = (SELECT MAX(id) from keys)")
            .map(|row: AnyRow| SecretKey::from_str(row.get("secret_key")).unwrap())
            .fetch_one(&self.pool)
            .await
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashSet;
    use std::iter::FromIterator;

    use teos_common::cryptography::{get_random_bytes, get_random_keypair};
    use teos_common::test_utils::{get_random_locator, get_random_user_id};

    use crate::rpc_errors;
    use crate::test_utils::{
        generate_dummy_appointment, generate_dummy_appointment_with_user, generate_uuid,
        get_random_tracker, get_random_tx, AVAILABLE_SLOTS, SUBSCRIPTION_EXPIRY,
        SUBSCRIPTION_START,
    };

    impl DBM {
        #[cfg(feature = "sqlite")]
        async fn memory() -> Self {
            use sqlx::any::AnyPoolOptions;
            install_drivers(&[sqlx::sqlite::any::DRIVER]).ok();
            let pool = AnyPoolOptions::new()
                // Each new connection actually creates a brand new DB: https://github.com/launchbadge/sqlx/issues/2510
                // So make sure the pool doesn't create more than one connection.
                .max_connections(1)
                .connect("sqlite::memory:")
                .await
                .unwrap();
            sqlx::migrate!("migrations/sqlite")
                .run(&pool)
                .await
                .unwrap();
            Self { pool }
        }

        #[cfg(feature = "postgres")]
        async fn postgres() -> Self {
            let dbm = async {
                return_db_if_matching!(
                    "postgres://user:pass@localhost/teos",
                    postgres,
                    "migrations/postgres"
                );
                Err("Unreachable (the macro above will always match)".to_string())
            }
            .await
            .unwrap();
            // The DBM could have been used in a previous test, so make sure it is clear.
            dbm.clear_db().await;
            dbm
        }

        /// Clears all the DB tables. To be used to emulate starting a brand new database.
        async fn clear_db(&self) {
            let tables_to_clear = [
                "users",
                "appointments",
                "trackers",
                "last_known_block",
                "keys",
            ];
            for table in tables_to_clear {
                sqlx::query(&format!("DELETE FROM {table}"))
                    .execute(&self.pool)
                    .await
                    .unwrap();
            }
        }

        #[allow(unreachable_code)]
        /// Returns a new [DBM], preferring sqlite over postgres if available.
        pub(crate) async fn test_db() -> Self {
            #[cfg(feature = "sqlite")]
            return Self::memory().await;

            // WARNING: When running the tests on PostgreSQL set the environment variable RUST_TEST_THREADS=1.
            // Otherwise tests will run on parallel and contaminate the database.
            #[cfg(feature = "postgres")]
            return Self::postgres().await;

            panic!("No database driver available. Make sure you compile with sqlite and/or postgres features enabled.")
        }

        pub(crate) async fn load_user(&self, user_id: UserId) -> Option<UserInfo> {
            let sql = "SELECT available_slots, subscription_start, subscription_expiry FROM users WHERE user_id=($1)";
            sqlx::query(sql)
                .bind(user_id.to_vec())
                .map(|row: AnyRow| {
                    UserInfo::new(
                        row.get::<i64, _>("available_slots") as u32,
                        row.get::<i64, _>("subscription_start") as u32,
                        row.get::<i64, _>("subscription_expiry") as u32,
                    )
                })
                .fetch_one(&self.pool)
                .await
                .ok()
        }
    }

    #[tokio::test]
    async fn test_store_user() {
        let dbm = DBM::test_db().await;

        let user_id = get_random_user_id();
        let user_info = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);

        assert!(dbm.load_user(user_id).await.is_none());

        dbm.store_user(user_id, &user_info).await.unwrap();
        assert_eq!(dbm.load_user(user_id).await, Some(user_info));

        // Store an existing user should error (should use update_user).
        dbm.store_user(user_id, &user_info).await.unwrap_err();
    }

    #[tokio::test]
    async fn test_update_user() {
        let dbm = DBM::test_db().await;

        let user_id = get_random_user_id();
        let mut user_info = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);

        dbm.store_user(user_id, &user_info).await.unwrap();

        user_info.available_slots *= 2;
        dbm.update_user(user_id, &user_info).await.unwrap();
        assert_eq!(dbm.load_user(user_id).await, Some(user_info));
    }

    #[tokio::test]
    async fn test_load_user_locators() {
        let dbm = DBM::test_db().await;

        let user_id = get_random_user_id();
        let user_info = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);
        dbm.store_user(user_id, &user_info).await.unwrap();

        let mut locators = HashSet::new();

        // Add some appointments to the user
        for _ in 0..10 {
            let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
            dbm.store_appointment(uuid, &appointment).await.unwrap();
            locators.insert(appointment.locator());
        }

        assert_eq!(dbm.load_user(user_id).await, Some(user_info));
        assert_eq!(
            HashSet::from_iter(dbm.load_user_locators(user_id).await),
            locators
        );
    }

    #[tokio::test]
    async fn test_load_all_users() {
        let dbm = DBM::test_db().await;
        let mut users = HashMap::new();

        for i in 1..11 {
            let user_id = get_random_user_id();
            let user_info = UserInfo::new(
                AVAILABLE_SLOTS + i,
                SUBSCRIPTION_START + i,
                SUBSCRIPTION_EXPIRY + i,
            );
            users.insert(user_id, user_info);
            dbm.store_user(user_id, &user_info).await.unwrap();
        }

        assert_eq!(dbm.load_all_users().await, users);
    }

    #[tokio::test]
    async fn test_batch_remove_users() {
        let dbm = DBM::test_db().await;

        let mut to_be_deleted = Vec::new();
        let mut rest = HashSet::new();

        for i in 0..SQL_VARIABLE_LIMIT * 3 {
            let user_id = get_random_user_id();
            let user = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);
            dbm.store_user(user_id, &user).await.unwrap();

            if i % 2 == 0 {
                to_be_deleted.push(user_id);
            } else {
                rest.insert(user_id);
            }
        }

        // SQL_VARIABLE_LIMIT is 10 for tests,
        // Check that deletion had `ceil(10 * 3 / 2) / 10` (2) queries on it
        assert_eq!(dbm.batch_remove_users(to_be_deleted).await, 2);

        // Check user data was deleted
        assert_eq!(rest, dbm.load_all_users().await.keys().cloned().collect());
    }

    #[tokio::test]
    async fn test_batch_remove_users_cascade() {
        // Test that removing users cascade deleted appointments and trackers
        let dbm = DBM::test_db().await;
        let uuid = generate_uuid();
        let appointment = generate_dummy_appointment(None);
        // The confirmation status doesn't really matter here, it can be any of {ConfirmedIn, InMempoolSince}.
        let tracker = get_random_tracker(appointment.user_id, ConfirmationStatus::ConfirmedIn(100));

        // Add the user and link an appointment (this is usually done once the appointment)
        // is added after the user creation, but for the test purpose it can be done all at once.
        let info = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);
        dbm.store_user(appointment.user_id, &info).await.unwrap();

        // Appointment only
        dbm.store_appointment(uuid, &appointment).await.unwrap();

        dbm.batch_remove_users(vec![appointment.user_id]).await;
        assert!(dbm.load_user(appointment.user_id).await.is_none());
        assert!(dbm.load_appointment(uuid).await.is_none());

        // Appointment + Tracker
        dbm.store_user(appointment.user_id, &info).await.unwrap();
        dbm.store_appointment(uuid, &appointment).await.unwrap();
        dbm.store_tracker(uuid, &tracker).await.unwrap();

        dbm.batch_remove_users(vec![appointment.user_id]).await;
        assert!(dbm.load_user(appointment.user_id).await.is_none());
        assert!(dbm.load_appointment(uuid).await.is_none());
        assert!(dbm.load_tracker(uuid).await.is_none());
    }

    #[tokio::test]
    async fn test_batch_remove_nonexistent_users() {
        let dbm = DBM::test_db().await;
        let users = (0..10).map(|_| get_random_user_id()).collect();

        // Test it does not fail even if the user does not exist
        dbm.batch_remove_users(users).await;
    }

    #[tokio::test]
    async fn test_get_appointments_trackers_count() {
        let dbm = DBM::test_db().await;
        let n_users = 100;
        let n_app_per_user = 4;
        let n_trk_per_user = 6;

        for _ in 0..n_users {
            let user_id = get_random_user_id();
            let user = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);
            dbm.store_user(user_id, &user).await.unwrap();

            // These are un-triggered appointments.
            for _ in 0..n_app_per_user {
                let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
                dbm.store_appointment(uuid, &appointment).await.unwrap();
            }

            // And these are triggered ones (trackers).
            for _ in 0..n_trk_per_user {
                let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
                dbm.store_appointment(uuid, &appointment).await.unwrap();
                let tracker = get_random_tracker(user_id, ConfirmationStatus::ConfirmedIn(42));
                dbm.store_tracker(uuid, &tracker).await.unwrap();
            }
        }

        assert_eq!(dbm.get_appointments_count().await, n_users * n_app_per_user);
        assert_eq!(dbm.get_trackers_count().await, n_users * n_trk_per_user);
    }

    #[tokio::test]
    async fn test_store_load_appointment() {
        let dbm = DBM::test_db().await;

        // In order to add an appointment we need the associated user to be present
        let user_id = get_random_user_id();
        let user = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);
        dbm.store_user(user_id, &user).await.unwrap();

        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);

        dbm.store_appointment(uuid, &appointment).await.unwrap();

        assert_eq!(dbm.load_appointment(uuid).await.unwrap(), appointment);

        // Appointment info should be updatable but only via the update_appointment method
        assert!(dbm
            .store_appointment(uuid, &appointment)
            .await
            .unwrap_err()
            .into_database_error()
            .unwrap()
            .is_unique_violation())
    }

    #[tokio::test]
    async fn test_store_appointment_missing_user() {
        let dbm = DBM::test_db().await;

        let uuid = generate_uuid();
        let appointment = generate_dummy_appointment(None);

        assert!(dbm
            .store_appointment(uuid, &appointment)
            .await
            .unwrap_err()
            .into_database_error()
            .unwrap()
            .is_foreign_key_violation());
        assert!((dbm.load_tracker(uuid).await.is_none()));
    }

    #[tokio::test]
    async fn test_update_appointment() {
        let dbm = DBM::test_db().await;

        let user_id = get_random_user_id();
        let user = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);
        dbm.store_user(user_id, &user).await.unwrap();

        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        dbm.store_appointment(uuid, &appointment).await.unwrap();

        // Modify the appointment and update it
        let mut modified_appointment = appointment;
        modified_appointment.inner.encrypted_blob.reverse();

        // Not all fields are updatable, create another appointment modifying fields that cannot be
        let mut another_modified_appointment = modified_appointment.clone();
        another_modified_appointment.user_id = get_random_user_id();

        // Check how only the modifiable fields have been updated
        dbm.update_appointment(uuid, &another_modified_appointment)
            .await
            .unwrap();
        assert_eq!(
            dbm.load_appointment(uuid).await.unwrap(),
            modified_appointment
        );
        assert_ne!(
            dbm.load_appointment(uuid).await.unwrap(),
            another_modified_appointment
        );
    }

    #[tokio::test]
    async fn test_load_nonexistent_appointment() {
        let dbm = DBM::test_db().await;

        let uuid = generate_uuid();
        assert!(dbm.load_appointment(uuid).await.is_none());
    }

    #[tokio::test]
    async fn test_appointment_exists() {
        let dbm = DBM::test_db().await;

        let user_id = get_random_user_id();
        let user = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);
        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);

        assert!(!dbm.appointment_exists(uuid).await);

        dbm.store_user(user_id, &user).await.unwrap();
        dbm.store_appointment(uuid, &appointment).await.unwrap();

        assert!(dbm.appointment_exists(uuid).await);
    }

    #[tokio::test]
    async fn test_get_appointment_length() {
        let dbm = DBM::test_db().await;

        let user_id = get_random_user_id();
        let user = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);
        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);

        dbm.store_user(user_id, &user).await.unwrap();
        dbm.store_appointment(uuid, &appointment).await.unwrap();

        assert_eq!(
            dbm.get_appointment_length(uuid).await.unwrap(),
            appointment.inner.encrypted_blob.len()
        );
        assert!(matches!(
            dbm.get_appointment_length(generate_uuid()).await,
            Err(Error::RowNotFound)
        ));
    }

    #[tokio::test]
    async fn test_get_appointment_user_and_length() {
        let dbm = DBM::test_db().await;

        let user_id = get_random_user_id();
        let user = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);
        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);

        dbm.store_user(user_id, &user).await.unwrap();
        dbm.store_appointment(uuid, &appointment).await.unwrap();

        assert_eq!(
            dbm.get_appointment_user_and_length(uuid).await.unwrap(),
            (user_id, appointment.encrypted_blob().len())
        );
        assert!(matches!(
            dbm.get_appointment_user_and_length(generate_uuid()).await,
            Err(Error::RowNotFound)
        ));
    }

    #[tokio::test]
    async fn test_load_all_appointments() {
        let dbm = DBM::test_db().await;
        let mut appointments = HashMap::new();

        for i in 1..11 {
            let user_id = get_random_user_id();
            let user = UserInfo::new(
                AVAILABLE_SLOTS + i,
                SUBSCRIPTION_START + i,
                SUBSCRIPTION_EXPIRY + i,
            );
            dbm.store_user(user_id, &user).await.unwrap();

            let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
            dbm.store_appointment(uuid, &appointment).await.unwrap();
            appointments.insert(uuid, appointment);
        }

        assert_eq!(dbm.load_appointments(None).await, appointments);

        // If an appointment has an associated tracker, it should not be loaded since it is seen
        // as a triggered appointment
        let user_id = get_random_user_id();
        let user = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);
        dbm.store_user(user_id, &user).await.unwrap();

        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        dbm.store_appointment(uuid, &appointment).await.unwrap();

        // The confirmation status doesn't really matter here, it can be any of {ConfirmedIn, InMempoolSince}.
        let tracker = get_random_tracker(user_id, ConfirmationStatus::InMempoolSince(100));
        dbm.store_tracker(uuid, &tracker).await.unwrap();

        // We should get all the appointments back except from the triggered one
        assert_eq!(dbm.load_appointments(None).await, appointments);
    }

    #[tokio::test]
    async fn test_load_appointments_with_locator() {
        let dbm = DBM::test_db().await;
        let mut appointments = HashMap::new();
        let dispute_tx = get_random_tx();
        let dispute_txid = dispute_tx.txid();
        let locator = Locator::new(dispute_txid);

        for i in 1..11 {
            let user_id = get_random_user_id();
            let user = UserInfo::new(
                AVAILABLE_SLOTS + i,
                SUBSCRIPTION_START + i,
                SUBSCRIPTION_EXPIRY + i,
            );
            dbm.store_user(user_id, &user).await.unwrap();

            // Let some appointments belong to a specific dispute tx and some with random ones.
            // We will use the locator for that dispute tx to query these appointments.
            if i % 2 == 0 {
                let (uuid, appointment) =
                    generate_dummy_appointment_with_user(user_id, Some(&dispute_txid));
                dbm.store_appointment(uuid, &appointment).await.unwrap();
                // Store the appointments made using our dispute tx.
                appointments.insert(uuid, appointment);
            } else {
                let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
                dbm.store_appointment(uuid, &appointment).await.unwrap();
            }
        }

        // Validate that no other appointments than the ones with our locator are returned.
        assert_eq!(dbm.load_appointments(Some(locator)).await, appointments);

        // If an appointment has an associated tracker, it should not be loaded since it is seen
        // as a triggered appointment
        let user_id = get_random_user_id();
        let user = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);
        dbm.store_user(user_id, &user).await.unwrap();

        // Generate an appointment for our dispute tx, thus it gets the same locator as the ones generated above.
        let (uuid, appointment) =
            generate_dummy_appointment_with_user(user_id, Some(&dispute_txid));
        dbm.store_appointment(uuid, &appointment).await.unwrap();

        // The confirmation status doesn't really matter here, it can be any of {ConfirmedIn, InMempoolSince}.
        let tracker = get_random_tracker(user_id, ConfirmationStatus::InMempoolSince(100));
        dbm.store_tracker(uuid, &tracker).await.unwrap();

        // We should get all the appointments matching our locator back except from the triggered one
        assert_eq!(dbm.load_appointments(Some(locator)).await, appointments);
    }

    #[tokio::test]
    async fn test_remove_appointment() {
        let dbm = DBM::test_db().await;

        let user_id = get_random_user_id();
        let user = UserInfo::new(
            AVAILABLE_SLOTS + 123,
            SUBSCRIPTION_START,
            SUBSCRIPTION_EXPIRY,
        );
        dbm.store_user(user_id, &user).await.unwrap();

        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        dbm.store_appointment(uuid, &appointment).await.unwrap();

        dbm.remove_appointment(uuid).await;
        assert!(!dbm.appointment_exists(uuid).await)
    }

    #[tokio::test]
    async fn test_batch_remove_appointments() {
        let dbm = DBM::test_db().await;

        let user_id = get_random_user_id();
        let mut user = UserInfo::new(
            AVAILABLE_SLOTS + 123,
            SUBSCRIPTION_START,
            SUBSCRIPTION_EXPIRY,
        );
        dbm.store_user(user_id, &user).await.unwrap();

        let mut rest = HashSet::new();
        for i in 1..6 {
            let mut to_be_deleted = Vec::new();
            for j in 0..SQL_VARIABLE_LIMIT * 2 * i {
                let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
                dbm.store_appointment(uuid, &appointment).await.unwrap();

                if j % 2 == 0 {
                    to_be_deleted.push(uuid);
                } else {
                    rest.insert(uuid);
                }
            }

            // When the appointment are deleted, the user will get back slots based on the deleted data.
            // Here we can just make a number up to make sure it matches.
            user.available_slots = i as u32;
            let updated_users = HashMap::from_iter([(user_id, user)]);

            // Check that the db transaction had i queries on it
            assert_eq!(
                dbm.batch_remove_appointments(to_be_deleted, updated_users)
                    .await,
                i
            );
            // Check appointment data was deleted and users properly updated
            assert_eq!(
                rest,
                dbm.load_appointments(None).await.keys().cloned().collect()
            );
            assert_eq!(
                dbm.load_user(user_id).await.unwrap().available_slots,
                user.available_slots
            );
        }
    }

    #[tokio::test]
    async fn test_batch_remove_appointments_cascade() {
        let dbm = DBM::test_db().await;
        let uuid = generate_uuid();
        let appointment = generate_dummy_appointment(None);
        // The confirmation status doesn't really matter here, it can be any of {ConfirmedIn, InMempoolSince}.
        let tracker = get_random_tracker(appointment.user_id, ConfirmationStatus::ConfirmedIn(21));

        let info = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);

        // Add the user b/c of FK restrictions
        dbm.store_user(appointment.user_id, &info).await.unwrap();

        println!("{}", appointment.inner.to_self_delay);
        // Appointment only
        dbm.store_appointment(uuid, &appointment).await.unwrap();

        dbm.batch_remove_appointments(
            vec![uuid],
            HashMap::from_iter([(appointment.user_id, info)]),
        )
        .await;
        assert!(dbm.load_appointment(uuid).await.is_none());

        // Appointment + Tracker
        dbm.store_appointment(uuid, &appointment).await.unwrap();
        dbm.store_tracker(uuid, &tracker).await.unwrap();

        dbm.batch_remove_appointments(
            vec![uuid],
            HashMap::from_iter([(appointment.user_id, info)]),
        )
        .await;
        assert!(dbm.load_appointment(uuid).await.is_none());
        assert!(dbm.load_tracker(uuid).await.is_none());
    }

    #[tokio::test]
    async fn test_batch_remove_nonexistent_appointments() {
        let dbm = DBM::test_db().await;
        let appointments = (0..10).map(|_| generate_uuid()).collect();

        // Test it does not fail even if the user does not exist
        dbm.batch_remove_appointments(appointments, HashMap::new())
            .await;
    }

    #[tokio::test]
    async fn test_load_uuids() {
        let dbm = DBM::test_db().await;

        let user = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);
        let dispute_tx = get_random_tx();
        let dispute_txid = dispute_tx.txid();
        let mut uuids = HashSet::new();

        // Add ten appointments triggered by the same locator.
        for _ in 0..10 {
            let user_id = get_random_user_id();
            dbm.store_user(user_id, &user).await.unwrap();

            let (uuid, appointment) =
                generate_dummy_appointment_with_user(user_id, Some(&dispute_txid));
            dbm.store_appointment(uuid, &appointment).await.unwrap();

            uuids.insert(uuid);
        }

        // Add ten more appointments triggered by different locators.
        for _ in 0..10 {
            let user_id = get_random_user_id();
            dbm.store_user(user_id, &user).await.unwrap();

            let dispute_txid = get_random_tx().txid();
            let (uuid, appointment) =
                generate_dummy_appointment_with_user(user_id, Some(&dispute_txid));
            dbm.store_appointment(uuid, &appointment).await.unwrap();
        }

        assert_eq!(
            HashSet::from_iter(dbm.load_uuids(Locator::new(dispute_txid)).await),
            uuids
        );
    }

    #[tokio::test]
    async fn test_batch_check_locators_exist() {
        let dbm = DBM::test_db().await;
        // Generate `n_app` appointments which we will store in the DB.
        let n_app = 100;
        let appointments: Vec<_> = (0..n_app)
            .map(|_| generate_dummy_appointment(None))
            .collect();

        // Register all the users beforehand.
        for user_id in appointments.iter().map(|a| a.user_id) {
            let user = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);
            dbm.store_user(user_id, &user).await.unwrap();
        }

        // Store all the `n_app` appointments.
        for appointment in appointments.iter() {
            dbm.store_appointment(appointment.uuid(), appointment)
                .await
                .unwrap();
        }

        // Select `n_app / 5` locators as if they appeared in a new block.
        let known_locators: HashSet<_> = appointments
            .iter()
            .take(n_app / 5)
            .map(|a| a.locator())
            .collect();
        // And extra `n_app / 5` unknown locators.
        let unknown_locators: HashSet<_> = (0..n_app / 5).map(|_| get_random_locator()).collect();
        let all_locators = known_locators
            .iter()
            .chain(unknown_locators.iter())
            .collect();

        assert_eq!(
            HashSet::from_iter(dbm.batch_check_locators_exist(all_locators).await),
            known_locators
        );
    }

    #[tokio::test]
    async fn test_store_load_tracker() {
        let dbm = DBM::test_db().await;

        // In order to add a tracker we need the associated appointment to be present (which
        // at the same time requires an associated user to be present)
        let user_id = get_random_user_id();
        let user = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);
        dbm.store_user(user_id, &user).await.unwrap();

        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        dbm.store_appointment(uuid, &appointment).await.unwrap();

        // The confirmation status doesn't really matter here, it can be any of {ConfirmedIn, InMempoolSince}.
        let tracker = get_random_tracker(user_id, ConfirmationStatus::ConfirmedIn(21));
        dbm.store_tracker(uuid, &tracker).await.unwrap();
        assert_eq!(dbm.load_tracker(uuid).await.unwrap(), tracker);
    }

    #[tokio::test]
    async fn test_store_duplicate_tracker() {
        let dbm = DBM::test_db().await;

        let user_id = get_random_user_id();
        let user = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);
        dbm.store_user(user_id, &user).await.unwrap();

        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        dbm.store_appointment(uuid, &appointment).await.unwrap();

        // The confirmation status doesn't really matter here, it can be any of {ConfirmedIn, InMempoolSince}.
        let tracker = get_random_tracker(user_id, ConfirmationStatus::InMempoolSince(42));
        dbm.store_tracker(uuid, &tracker).await.unwrap();

        // Try to store it again, but it shouldn't go through
        assert!(dbm
            .store_tracker(uuid, &tracker)
            .await
            .unwrap_err()
            .into_database_error()
            .unwrap()
            .is_unique_violation());
    }

    #[tokio::test]
    async fn test_store_tracker_missing_appointment() {
        let dbm = DBM::test_db().await;

        let uuid = generate_uuid();
        let user_id = get_random_user_id();

        // The confirmation status doesn't really matter here, it can be any of {ConfirmedIn, InMempoolSince}.
        let tracker = get_random_tracker(user_id, ConfirmationStatus::InMempoolSince(42));

        // Try to store the tracker with no appointment for it
        assert!(dbm
            .store_tracker(uuid, &tracker)
            .await
            .unwrap_err()
            .into_database_error()
            .unwrap()
            .is_foreign_key_violation())
    }

    #[tokio::test]
    async fn test_update_tracker_status() {
        let dbm = DBM::test_db().await;

        let user_id = get_random_user_id();
        let user = UserInfo::new(AVAILABLE_SLOTS, SUBSCRIPTION_START, SUBSCRIPTION_EXPIRY);
        dbm.store_user(user_id, &user).await.unwrap();

        let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
        dbm.store_appointment(uuid, &appointment).await.unwrap();

        let tracker = get_random_tracker(user_id, ConfirmationStatus::InMempoolSince(42));
        dbm.store_tracker(uuid, &tracker).await.unwrap();

        // Update the status and check if it's actually updated.
        dbm.update_tracker_status(uuid, &ConfirmationStatus::ConfirmedIn(100))
            .await
            .unwrap();
        assert_eq!(
            dbm.load_tracker(uuid).await.unwrap().status,
            ConfirmationStatus::ConfirmedIn(100)
        );

        // Rejected status doesn't have a persistent DB representation.
        assert!(matches!(
            dbm.update_tracker_status(
                uuid,
                &ConfirmationStatus::Rejected(rpc_errors::RPC_VERIFY_REJECTED)
            )
            .await,
            Err(Error::Decode(..))
        ));
    }

    #[tokio::test]
    async fn test_load_nonexistent_tracker() {
        let dbm = DBM::test_db().await;

        let uuid = generate_uuid();
        assert!(dbm.load_tracker(uuid).await.is_none());
    }

    #[tokio::test]
    async fn test_load_all_trackers() {
        let dbm = DBM::test_db().await;
        let mut trackers = HashMap::new();

        for i in 1..11 {
            let user_id = get_random_user_id();
            let user = UserInfo::new(
                AVAILABLE_SLOTS + i,
                SUBSCRIPTION_START + i,
                SUBSCRIPTION_EXPIRY + i,
            );
            dbm.store_user(user_id, &user).await.unwrap();

            let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
            dbm.store_appointment(uuid, &appointment).await.unwrap();

            // The confirmation status doesn't really matter here, it can be any of {ConfirmedIn, InMempoolSince}.
            let tracker = get_random_tracker(user_id, ConfirmationStatus::InMempoolSince(42));
            dbm.store_tracker(uuid, &tracker).await.unwrap();
            trackers.insert(uuid, tracker);
        }

        assert_eq!(dbm.load_trackers(None).await, trackers);
    }

    #[tokio::test]
    async fn test_load_trackers_with_locator() {
        let dbm = DBM::test_db().await;
        let mut trackers = HashMap::new();
        let dispute_tx = get_random_tx();
        let dispute_txid = dispute_tx.txid();
        let locator = Locator::new(dispute_txid);
        let status = ConfirmationStatus::InMempoolSince(42);

        for i in 1..11 {
            let user_id = get_random_user_id();
            let user = UserInfo::new(
                AVAILABLE_SLOTS + i,
                SUBSCRIPTION_START + i,
                SUBSCRIPTION_EXPIRY + i,
            );
            dbm.store_user(user_id, &user).await.unwrap();
            let tracker = get_random_tracker(user_id, status);

            // Let some trackers belong to our dispute tx and some belong to random ones.
            let (uuid, appointment) = if i % 2 == 0 {
                let (uuid, app) =
                    generate_dummy_appointment_with_user(user_id, Some(&dispute_txid));
                // Store the trackers of appointments made with our dispute tx.
                trackers.insert(uuid, tracker.clone());
                (uuid, app)
            } else {
                generate_dummy_appointment_with_user(user_id, None)
            };
            dbm.store_appointment(uuid, &appointment).await.unwrap();
            dbm.store_tracker(uuid, &tracker).await.unwrap();
        }

        assert_eq!(dbm.load_trackers(Some(locator)).await, trackers);
    }

    #[tokio::test]
    async fn test_load_trackers_with_confirmation_status_in_mempool() {
        let dbm = DBM::test_db().await;
        let n_trackers = 100;
        let mut tracker_statuses = HashMap::new();

        // Store a bunch of trackers.
        for i in 0..n_trackers {
            let user_id = get_random_user_id();
            let user = UserInfo::new(
                AVAILABLE_SLOTS + i,
                SUBSCRIPTION_START + i,
                SUBSCRIPTION_EXPIRY + i,
            );
            dbm.store_user(user_id, &user).await.unwrap();

            let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
            dbm.store_appointment(uuid, &appointment).await.unwrap();

            // Some trackers confirmed and some aren't.
            let status = if i % 2 == 0 {
                ConfirmationStatus::InMempoolSince(i)
            } else {
                ConfirmationStatus::ConfirmedIn(i)
            };

            let tracker = get_random_tracker(user_id, status);
            dbm.store_tracker(uuid, &tracker).await.unwrap();
            tracker_statuses.insert(uuid, status);
        }

        for i in 0..n_trackers + 10 {
            let in_mempool_since_i: HashSet<UUID> = tracker_statuses
                .iter()
                .filter_map(|(&uuid, &status)| {
                    if let ConfirmationStatus::InMempoolSince(x) = status {
                        // If a tracker was in mempool since x, then it's also in mempool since x + 1, x + 2, etc...
                        return (x <= i).then_some(uuid);
                    }
                    None
                })
                .collect();
            assert_eq!(
                HashSet::from_iter(
                    dbm.load_trackers_with_confirmation_status(ConfirmationStatus::InMempoolSince(
                        i
                    ))
                    .await
                    .unwrap()
                ),
                in_mempool_since_i,
            );
        }
    }

    #[tokio::test]
    async fn test_load_trackers_with_confirmation_status_confirmed() {
        let dbm = DBM::test_db().await;
        let n_blocks = 100;
        let n_trackers = 30;
        let mut tracker_statuses = HashMap::new();

        // Loop over a bunch of blocks.
        for i in 0..n_blocks {
            // Store a bunch of trackers in each block.
            for j in 0..n_trackers {
                let user_id = get_random_user_id();
                let user = UserInfo::new(
                    AVAILABLE_SLOTS + i,
                    SUBSCRIPTION_START + i,
                    SUBSCRIPTION_EXPIRY + i,
                );
                dbm.store_user(user_id, &user).await.unwrap();

                let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
                dbm.store_appointment(uuid, &appointment).await.unwrap();

                // Some trackers confirmed and some aren't.
                let status = if j % 2 == 0 {
                    ConfirmationStatus::InMempoolSince(i)
                } else {
                    ConfirmationStatus::ConfirmedIn(i)
                };

                let tracker = get_random_tracker(user_id, status);
                dbm.store_tracker(uuid, &tracker).await.unwrap();
                tracker_statuses.insert(uuid, status);
            }
        }

        for i in 0..n_blocks + 10 {
            let confirmed_in_i: HashSet<UUID> = tracker_statuses
                .iter()
                .filter_map(|(&uuid, &status)| {
                    if let ConfirmationStatus::ConfirmedIn(x) = status {
                        return (x == i).then_some(uuid);
                    }
                    None
                })
                .collect();
            assert_eq!(
                HashSet::from_iter(
                    dbm.load_trackers_with_confirmation_status(ConfirmationStatus::ConfirmedIn(i))
                        .await
                        .unwrap()
                ),
                confirmed_in_i,
            );
        }
    }

    #[tokio::test]
    async fn test_load_trackers_with_confirmation_status_bad_status() {
        let dbm = DBM::test_db().await;

        assert!(matches!(
            dbm.load_trackers_with_confirmation_status(ConfirmationStatus::Rejected(
                rpc_errors::RPC_VERIFY_REJECTED
            ))
            .await,
            Err(Error::Decode(..))
        ));
        assert!(matches!(
            dbm.load_trackers_with_confirmation_status(ConfirmationStatus::IrrevocablyResolved)
                .await,
            Err(Error::Decode(..))
        ));
    }

    #[tokio::test]
    async fn test_load_penalties_summaries() {
        let dbm = DBM::test_db().await;
        let n_trackers = 100;
        let mut penalties_summaries = HashMap::new();

        for i in 0..n_trackers {
            let user_id = get_random_user_id();
            let user = UserInfo::new(
                AVAILABLE_SLOTS + i,
                SUBSCRIPTION_START + i,
                SUBSCRIPTION_EXPIRY + i,
            );
            dbm.store_user(user_id, &user).await.unwrap();

            let (uuid, appointment) = generate_dummy_appointment_with_user(user_id, None);
            dbm.store_appointment(uuid, &appointment).await.unwrap();

            let status = if i % 2 == 0 {
                ConfirmationStatus::InMempoolSince(i)
            } else {
                ConfirmationStatus::ConfirmedIn(i)
            };

            let tracker = get_random_tracker(user_id, status);
            dbm.store_tracker(uuid, &tracker).await.unwrap();

            penalties_summaries
                .insert(uuid, PenaltySummary::new(tracker.penalty_tx.txid(), status));
        }

        assert_eq!(dbm.load_penalties_summaries().await, penalties_summaries);
    }

    #[tokio::test]
    async fn test_store_load_last_known_block() {
        let dbm = DBM::test_db().await;

        let mut block_hash = BlockHash::from_slice(&get_random_bytes(32)).unwrap();
        dbm.store_last_known_block(&block_hash).await.unwrap();
        assert_eq!(dbm.load_last_known_block().await.unwrap(), block_hash);

        // Update with a new hash to check it can be done
        block_hash = BlockHash::from_slice(&get_random_bytes(32)).unwrap();
        dbm.store_last_known_block(&block_hash).await.unwrap();
        assert_eq!(dbm.load_last_known_block().await.unwrap(), block_hash);
    }

    #[tokio::test]
    async fn test_store_load_nonexistent_last_known_block() {
        let dbm = DBM::test_db().await;

        assert!(dbm.load_last_known_block().await.is_none());
    }

    #[tokio::test]
    async fn test_store_load_tower_key() {
        let dbm = DBM::test_db().await;

        assert!(dbm.load_tower_key().await.is_none());
        for _ in 0..7 {
            let sk = get_random_keypair().0;
            dbm.store_tower_key(&sk).await.unwrap();
            assert_eq!(dbm.load_tower_key().await.unwrap(), sk);
        }
    }
}
