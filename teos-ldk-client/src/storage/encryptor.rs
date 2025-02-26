use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};

use bitcoin::hashes::{sha256, Hash};

/// A struct handling encryption and decryption using ChaCha20Poly1305
pub(crate) struct Encryptor {
    cipher: ChaCha20Poly1305,
    nonce: Nonce,
}

impl Encryptor {
    /// Creates a new Encryptor instance with the given secret
    ///
    /// # Arguments
    /// * `secret` - The secret used to derive the encryption key
    pub fn new(secret: &[u8]) -> Self {
        let key_hash = sha256::Hash::hash(secret);
        let key = Key::from_slice(key_hash.as_byte_array());

        Self {
            cipher: ChaCha20Poly1305::new(key),
            nonce: Nonce::default(), // [0; 12]
        }
    }

    /// Encrypts a given message using the initialized cipher
    ///
    /// # Arguments
    /// * `message` - The message to encrypt (expected to be a penalty transaction)
    ///
    /// # Returns
    /// The encrypted message or an encryption error
    pub fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
        self.cipher.encrypt(&self.nonce, message)
    }

    /// Decrypts an encrypted blob using the initialized cipher
    ///
    /// # Arguments
    /// * `encrypted_blob` - The encrypted data to decrypt
    ///
    /// # Returns
    /// The decrypted message (expected to be a penalty transaction) or a decryption error
    pub fn decrypt(&self, encrypted_blob: &[u8]) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
        self.cipher.decrypt(&self.nonce, encrypted_blob)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption() {
        let secret = b"test_secret";
        let message = b"Hello, World!";

        let encryptor = Encryptor::new(secret);

        let encrypted = encryptor.encrypt(message).unwrap();
        let decrypted = encryptor.decrypt(&encrypted).unwrap();

        assert_eq!(message.to_vec(), decrypted);
    }
}
