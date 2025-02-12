pub mod persister;

#[cfg(all(not(feature = "sqlite"), not(feature = "kv")))]
compile_error!(
    "No storage backend enabled. Please enable one of the following features: sqlite, kv"
);

#[cfg(all(feature = "sqlite", feature = "kv"))]
compile_error!("Only one of 'sqlite' or 'kv' features can be enabled");

#[cfg(feature = "sqlite")]
mod dbm;
// #[cfg(feature = "sqlite")]
// pub use dbm::DBError;
#[cfg(feature = "sqlite")]
pub use dbm::DBM as Storage;

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
