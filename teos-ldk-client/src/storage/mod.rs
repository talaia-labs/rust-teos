pub mod persister;

pub use crate::storage::persister::{Persister, PersisterError};

mod encryption;
mod kv;
mod namespace;

#[cfg(test)]
pub mod mock_kv;

#[cfg(test)]
pub use mock_kv::MemoryStore;

#[cfg(test)]
pub fn create_storage(
    kv_store: Arc<DynStore>,
    sk: Vec<u8>,
) -> Result<Box<dyn persister::Persister>, PersisterError> {
    match KVStorage::new(kv_store, sk) {
        Ok(storage) => Ok(Box::new(storage)),
        Err(e) => Err(PersisterError::Other(format!(
            "Error creating storage: {}",
            e
        ))),
    }
}

#[cfg(test)]
use std::sync::Arc;

#[cfg(test)]
use kv::{DynStore, KVStorage};
