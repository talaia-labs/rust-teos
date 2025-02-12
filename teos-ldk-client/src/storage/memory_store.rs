use lightning::io::Error as DBError;
use lightning::util::persist::KVStore;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// In-memory key-value store implementation for testing
#[derive(Clone, Debug)]
pub struct MemoryStore {
    data: Arc<Mutex<HashMap<String, HashMap<String, Vec<u8>>>>>,
}

impl MemoryStore {
    /// Creates a new empty MemoryStore
    pub fn new() -> Self {
        MemoryStore {
            data: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Creates the composite key used for storage
    fn make_key(namespace: &str, key: &str) -> String {
        format!("{}:{}", namespace, key)
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl KVStore for MemoryStore {
    fn read(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
    ) -> Result<Vec<u8>, DBError> {
        let data = self
            .data
            .lock()
            .map_err(|_| DBError::new(bitcoin::io::ErrorKind::AddrInUse, "Lock poisoned"))?;

        let namespace = Self::make_key(primary_namespace, secondary_namespace);
        data.get(&namespace)
            .and_then(|ns| ns.get(key))
            .cloned()
            .ok_or_else(|| DBError::new(bitcoin::io::ErrorKind::NotFound, "Key not found"))
    }

    fn write(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
        value: &[u8],
    ) -> Result<(), DBError> {
        let mut data = self
            .data
            .lock()
            .map_err(|_| DBError::new(bitcoin::io::ErrorKind::AddrInUse, "Lock poisoned"))?;

        let namespace = Self::make_key(primary_namespace, secondary_namespace);
        let ns_map = data.entry(namespace).or_default();
        ns_map.insert(key.to_string(), value.to_vec());

        Ok(())
    }

    fn remove(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
        _lazy: bool,
    ) -> Result<(), DBError> {
        let mut data = self
            .data
            .lock()
            .map_err(|_| DBError::new(bitcoin::io::ErrorKind::AddrInUse, "Lock poisoned"))?;

        let namespace = Self::make_key(primary_namespace, secondary_namespace);
        if let Some(ns_map) = data.get_mut(&namespace) {
            ns_map.remove(key);
            Ok(())
        } else {
            Err(DBError::new(
                bitcoin::io::ErrorKind::NotFound,
                "Key not found",
            ))
        }
    }

    fn list(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
    ) -> Result<Vec<String>, DBError> {
        let data = self
            .data
            .lock()
            .map_err(|_| DBError::new(bitcoin::io::ErrorKind::AddrInUse, "Lock poisoned"))?;

        let namespace = Self::make_key(primary_namespace, secondary_namespace);
        let res = data
            .get(&namespace)
            .map(|ns_map| ns_map.keys().cloned().collect())
            .unwrap();

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_operations() {
        let store = MemoryStore::new();

        // Test write and read
        store
            .write("primary", "secondary", "key1", b"value1")
            .unwrap();
        assert_eq!(
            store.read("primary", "secondary", "key1").unwrap(),
            b"value1"
        );

        // Test remove
        store.remove("primary", "secondary", "key1", false).unwrap();
        assert!(store.read("primary", "secondary", "key1").is_err());

        // Test list
        store
            .write("primary", "secondary", "key1", b"value1")
            .unwrap();
        store
            .write("primary", "secondary", "key2", b"value2")
            .unwrap();
        let keys = store.list("primary", "secondary").unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"key1".to_string()));
        assert!(keys.contains(&"key2".to_string()));
    }

    #[test]
    fn test_namespacing() {
        let store = MemoryStore::new();

        // Write same key to different namespaces
        store
            .write("primary1", "secondary1", "key", b"value1")
            .unwrap();
        store
            .write("primary1", "secondary2", "key", b"value2")
            .unwrap();
        store
            .write("primary2", "secondary1", "key", b"value3")
            .unwrap();

        // Verify they don't interfere
        assert_eq!(
            store.read("primary1", "secondary1", "key").unwrap(),
            b"value1"
        );
        assert_eq!(
            store.read("primary1", "secondary2", "key").unwrap(),
            b"value2"
        );
        assert_eq!(
            store.read("primary2", "secondary1", "key").unwrap(),
            b"value3"
        );
    }
}
