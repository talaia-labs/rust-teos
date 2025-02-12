pub mod persister;

mod sql_storage;
use std::path::PathBuf;

pub use crate::storage::persister::{Persister, PersisterError};

use sql_storage::DBM;

#[cfg(feature = "kv")]
mod kv;
#[cfg(feature = "kv")]
pub use kv::DBError;
#[cfg(feature = "kv")]
pub(crate) use kv::Storage;

#[cfg(test)]
#[cfg(feature = "kv")]
mod memory_store;
#[cfg(test)]
#[cfg(feature = "kv")]
pub use memory_store::MemoryStore;

pub fn create_storage(
    config: StorageConfig,
) -> Result<Box<dyn persister::Persister>, PersisterError> {
    match config.storage_type {
        StorageType::SQL => match DBM::new(&config.db_path.expect("db_path must be specificed")) {
            Ok(storage) => Ok(Box::new(storage)),
            Err(e) => Err(PersisterError::Other(format!(
                "Error creating storage: {}",
                e
            ))),
        },
        _ => {
            panic!("Unsupported persistence type");
        }
    }
}

pub struct StorageConfig {
    pub storage_type: StorageType,
    pub db_path: Option<PathBuf>,
}

pub enum StorageType {
    SQL,
    KV,
}
