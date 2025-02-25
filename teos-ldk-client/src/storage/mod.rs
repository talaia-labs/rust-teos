pub mod persister;

use std::sync::Arc;

pub use crate::storage::persister::{Persister, PersisterError};

mod kv;
use kv::{DynStore, KVStorage};

mod encryption;
mod namespace;

#[cfg(test)]
pub mod memory_store;

#[cfg(test)]
pub use memory_store::MemoryStore;

pub fn create_storage(
    config: StorageConfig,
) -> Result<Box<dyn persister::Persister>, PersisterError> {
    match config {
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
