use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Error, PublicKey, SecretKey};
use bitcoin::util::psbt::serialize::{Deserialize, Serialize};
use bitcoin::{Transaction, Txid};
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use lightning::util::message_signing;

/// Enum representing the possible errors when decrypting an encrypted blob.
#[derive(Debug)]
pub enum DecryptingError {
    AED(chacha20poly1305::aead::Error),
    Encode(bitcoin::consensus::encode::Error),
}

/// Shadows message_signing::sign.
pub fn sign(msg: &[u8], sk: SecretKey) -> Result<String, Error> {
    message_signing::sign(msg, sk)
}

/// Shadows message_signing::verify.
pub fn verify(msg: &[u8], sig: &str, pk: PublicKey) -> bool {
    match message_signing::recover_pk(msg, sig) {
        Ok(x) => x == pk,
        Err(_) => false,
    }
}

/// Shadows message_signing::recover_pk.
pub fn recover_pk(msg: &[u8], sig: &str) -> Result<PublicKey, Error> {
    message_signing::recover_pk(msg, sig)
}

/// Encrypts a given message (the penalty transaction) under a given secret (the dispute txid) using chacha20poly1305 with [0; 12] as IV.
pub fn encrypt(
    message: &Transaction,
    secret: &Txid,
) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
    // Defaults is [0; 12]
    let nonce = Nonce::default();
    let _k = sha256::Hash::hash(&secret);
    let key = Key::from_slice(&_k);

    let cypher = ChaCha20Poly1305::new(key);
    cypher.encrypt(&nonce, message.serialize().as_ref())
}

/// Decrypts an encrypted blob of data using a given secret (the dispute txid) using chacha20poly1305 with [0; 12] as IV. The result is expected to
/// be a penalty transaction.
pub fn decrypt(encrypted_blob: &Vec<u8>, secret: &Txid) -> Result<Transaction, DecryptingError> {
    // Defaults is [0; 12]
    let nonce = Nonce::default();
    let _k = sha256::Hash::hash(&secret);
    let key = Key::from_slice(&_k);

    let cypher = ChaCha20Poly1305::new(key);

    match cypher.decrypt(&nonce, encrypted_blob.as_ref()) {
        Ok(tx_bytes) => match Transaction::deserialize(&tx_bytes) {
            Ok(tx) => Ok(tx),
            Err(e) => Err(DecryptingError::Encode(e)),
        },
        Err(e) => Err(DecryptingError::AED(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{hashes::hex::FromHex, util::psbt::serialize::Deserialize};

    #[test]
    fn test_encrypt() {
        let expected_enc = Vec::from_hex("8ad4fafde8c4e1d7fdb2f0f27756b81d48bc48c54695e0e6508f5e3969bd780a88b9c97821fe7aa9b8b5cce3a12eef4f63eccb99059a69dae5f67f45b472e070d01ea223930465ceb31abe0720aa8a529e2adc4a8b84f10fc7c3789e545ee5da87674d48cb4105cb09b150c81b27565e719ce6af2ed86db1d90525acff317c49f39e2c1f6863a0b63a3f6233588b17b3b7bdcd24404db7acfab3f4e63d4b91a3be3afda6955524b1650772df8f84def35e7cdc520d17c8571920284d67795b33563c5683bcba6d3d6f17b5479cd366059fe108955769c7d5f31dc29f722bceced7b73ab9af03a4e3b4e3198a25dadea04cfc384548183d25831ead01b433a9c16951834f7d5c7f04ce95eca3dae0f71e2d19d7adfb8641743a9d4f586f40a48f05c4517f7170357b3bfb4035da25e17ec4e06a8a6f6f2df04dafe38b4222e7648ac387978ba35fb96358b9da745fe9d3c71cdd5b349bce8363d5fc5d98809b93e1e021cf61c31c1b288e68bb62a653").unwrap();

        let tx_bytes = Vec::from_hex("010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff54038e830a1b4d696e656420627920416e74506f6f6c373432c2005b005e7a0ae3fabe6d6d7841cd582ead8ea5dd8e3de1173cae6fcd2a53c7362ebb7fb6f815604fe07cbe0200000000000000ac0e060005f90000ffffffff04d9476026000000001976a91411dbe48cc6b617f9c6adaf4d9ed5f625b1c7cb5988ac0000000000000000266a24aa21a9ed7248c6efddd8d99bfddd7f499f0b915bffa8253003cc934df1ff14a81301e2340000000000000000266a24b9e11b6d7054937e13f39529d6ad7e685e9dd4efa426f247d5f5a5bed58cdddb2d0fa60100000000000000002b6a2952534b424c4f434b3a054a68aa5368740e8b3e3c67bce45619c2cfd07d4d4f0936a5612d2d0034fa0a0120000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let tx = Transaction::deserialize(&tx_bytes).unwrap();
        // FIXME: What endianness should be used for txid (was it BE?)
        // d6ac4a5e61657c4c604dcde855a1db74ec6b3e54f32695d72c5e11c7761ea1b4
        let txid =
            Txid::from_hex("b4a11e76c7115e2cd79526f3543e6bec74dba155e8cd4d604c7c65615e4aacd6")
                .unwrap();

        assert_eq!(encrypt(&tx, &txid).unwrap(), expected_enc);
    }

    #[test]
    fn test_decrypt() {
        let expected_tx = Transaction::deserialize(&Vec::from_hex("010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff54038e830a1b4d696e656420627920416e74506f6f6c373432c2005b005e7a0ae3fabe6d6d7841cd582ead8ea5dd8e3de1173cae6fcd2a53c7362ebb7fb6f815604fe07cbe0200000000000000ac0e060005f90000ffffffff04d9476026000000001976a91411dbe48cc6b617f9c6adaf4d9ed5f625b1c7cb5988ac0000000000000000266a24aa21a9ed7248c6efddd8d99bfddd7f499f0b915bffa8253003cc934df1ff14a81301e2340000000000000000266a24b9e11b6d7054937e13f39529d6ad7e685e9dd4efa426f247d5f5a5bed58cdddb2d0fa60100000000000000002b6a2952534b424c4f434b3a054a68aa5368740e8b3e3c67bce45619c2cfd07d4d4f0936a5612d2d0034fa0a0120000000000000000000000000000000000000000000000000000000000000000000000000").unwrap()).unwrap();

        let encrypted_blob = Vec::from_hex("8ad4fafde8c4e1d7fdb2f0f27756b81d48bc48c54695e0e6508f5e3969bd780a88b9c97821fe7aa9b8b5cce3a12eef4f63eccb99059a69dae5f67f45b472e070d01ea223930465ceb31abe0720aa8a529e2adc4a8b84f10fc7c3789e545ee5da87674d48cb4105cb09b150c81b27565e719ce6af2ed86db1d90525acff317c49f39e2c1f6863a0b63a3f6233588b17b3b7bdcd24404db7acfab3f4e63d4b91a3be3afda6955524b1650772df8f84def35e7cdc520d17c8571920284d67795b33563c5683bcba6d3d6f17b5479cd366059fe108955769c7d5f31dc29f722bceced7b73ab9af03a4e3b4e3198a25dadea04cfc384548183d25831ead01b433a9c16951834f7d5c7f04ce95eca3dae0f71e2d19d7adfb8641743a9d4f586f40a48f05c4517f7170357b3bfb4035da25e17ec4e06a8a6f6f2df04dafe38b4222e7648ac387978ba35fb96358b9da745fe9d3c71cdd5b349bce8363d5fc5d98809b93e1e021cf61c31c1b288e68bb62a653").unwrap();
        // FIXME: What endianness should be used for txid (was it BE?)
        // d6ac4a5e61657c4c604dcde855a1db74ec6b3e54f32695d72c5e11c7761ea1b4
        let txid =
            Txid::from_hex("b4a11e76c7115e2cd79526f3543e6bec74dba155e8cd4d604c7c65615e4aacd6")
                .unwrap();

        assert_eq!(decrypt(&&encrypted_blob, &txid).unwrap(), expected_tx);
    }
}
