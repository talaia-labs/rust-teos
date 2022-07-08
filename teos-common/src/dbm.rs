//! Logic related to a common database manager, component in charge of persisting data on disk. This is the base of more complex managers
//! that can be used by both clients and towers.
//!

use rusqlite::ffi::{SQLITE_CONSTRAINT_FOREIGNKEY, SQLITE_CONSTRAINT_PRIMARYKEY};
use rusqlite::{Connection, Error as SqliteError, ErrorCode, Params};

/// Packs the errors than can raise when interacting with the underlying database.
#[derive(Debug)]
pub enum Error {
    AlreadyExists,
    MissingForeignKey,
    MissingField,
    NotFound,
    Unknown(SqliteError),
}

pub trait DatabaseConnection {
    fn get_connection(&self) -> &Connection;
    fn get_mut_connection(&mut self) -> &mut Connection;
}

pub trait DatabaseManager: Sized {
    fn create_tables(&mut self, tables: Vec<&str>) -> Result<(), SqliteError>;
    fn store_data<P: Params>(&self, query: &str, params: P) -> Result<(), Error>;
    fn remove_data<P: Params>(&self, query: &str, params: P) -> Result<(), Error>;
    fn update_data<P: Params>(&self, query: &str, params: P) -> Result<(), Error>;
}

impl<T: DatabaseConnection> DatabaseManager for T {
    /// Creates the database tables if not present.
    fn create_tables(&mut self, tables: Vec<&str>) -> Result<(), SqliteError> {
        let tx = self.get_mut_connection().transaction().unwrap();
        for table in tables.iter() {
            tx.execute(table, [])?;
        }
        tx.commit()
    }

    /// Generic method to store data into the database.
    fn store_data<P: Params>(&self, query: &str, params: P) -> Result<(), Error> {
        match self.get_connection().execute(query, params) {
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
        match self.get_connection().execute(query, params).unwrap() {
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
}
