use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};

use bitcoin::hashes::{sha256, Hash};

/// Encrypts a given message under a given secret using `chacha20poly1305`.
///
/// The key material used is:
/// - The dispute txid as encryption key.
/// - `[0; 12]` as IV.
///
/// The message to be encrypted is expected to be the penalty transaction.
pub(crate) fn encrypt(
    message: &[u8],
    secret: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
    // Create nonce [0; 12]
    let nonce = Nonce::default();

    // Hash the secret to create the encryption key
    let key_hash = sha256::Hash::hash(secret);
    let key = Key::from_slice(key_hash.as_byte_array());

    // Create cipher instance
    let cipher = ChaCha20Poly1305::new(key);
    // Encrypt the message
    cipher.encrypt(&nonce, message)
}

/// Decrypts an encrypted blob of data using `chacha20poly1305` and a given secret.
///
/// The key material used is:
/// - The dispute txid as decryption key.
/// - `[0; 12]` as IV.
///
///  The result is expected to be a penalty transaction.
pub(crate) fn decrypt(
    encrypted_blob: &[u8],
    secret: &Vec<u8>,
) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
    // Defaults is [0; 12]
    let nonce = Nonce::default();
    let k = sha256::Hash::hash(secret);
    let key = Key::from_slice(k.as_byte_array());

    let cypher = ChaCha20Poly1305::new(key);

    cypher.decrypt(&nonce, encrypted_blob.as_ref())
}
