pub mod persister;

mod sql_storage;
use std::path::PathBuf;
use std::sync::Arc;

pub use crate::storage::persister::{Persister, PersisterError};

use sql_storage::DBM;

mod kv;
use kv::{DynStore, KVStorage};

#[cfg(test)]
mod memory_store;

#[cfg(test)]
pub use memory_store::MemoryStore;

pub fn create_storage(
    config: StorageConfig,
) -> Result<Box<dyn persister::Persister>, PersisterError> {
    match config {
        StorageConfig::SQL { db_path } => match DBM::new(&db_path) {
            Ok(storage) => Ok(Box::new(storage)),
            Err(e) => Err(PersisterError::Other(format!(
                "Error creating storage: {}",
                e
            ))),
        },
        StorageConfig::KV { kv_store, sk } => match KVStorage::new(kv_store, sk) {
            Ok(storage) => Ok(Box::new(storage)),
            Err(e) => Err(PersisterError::Other(format!(
                "Error creating storage: {}",
                e
            ))),
        },
    }
}

pub enum StorageConfig {
    SQL {
        db_path: PathBuf,
    },
    KV {
        kv_store: Arc<DynStore>,
        sk: Vec<u8>,
    },
}

#[cfg(test)]
fn create_test_kv_storage() -> KVStorage {
    let store = MemoryStore::new().into_dyn_store();
    let sk = vec![0u8; 32]; // Test secret key
    KVStorage::new(store, sk).unwrap()
}

