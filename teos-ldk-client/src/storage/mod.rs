pub mod persister;

mod sql_storage;
pub use sql_storage::DBM as Storage;

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
