//! Shared constant values.

// LN general nomenclature
/// Number of blocks required to consider a transaction irrevocable.
pub const IRREVOCABLY_RESOLVED: u32 = 100;

// Temporary constants, may be changed
/// Maximum size of encrypted blobs in appointments.
pub const ENCRYPTED_BLOB_MAX_SIZE: usize = 2048;
/// Size of the outdated users cache.
// FIXME: this may not fit here.
pub const OUTDATED_USERS_CACHE_SIZE_BLOCKS: usize = 10;
