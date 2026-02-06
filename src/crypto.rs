use chacha20poly1305::{
    KeyInit,
    aead::{Aead, Nonce, Payload, generic_array::GenericArray},
};
use thiserror::Error;

/// Key for the `ChaCha20Poly1305` and `XChaCha20Poly1305` AEAD algorithms used for encryption
pub type Key = [u8; 32];

pub const MAC_BYTES: usize = 16;

#[derive(Debug, Error)]
pub enum EncryptError {
    #[error("invalid input/output buffers given")]
    BufferSizeMismatch,

    #[error("internal encryption failure")]
    Failed,
}

/// Generates a new random private key.
pub fn generate_key() -> Key {
    let mut key = Key::default();

    random_bytes(&mut key);

    key
}

pub fn random_bytes(out: &mut [u8]) {
    getrandom::fill(out).unwrap();
}

pub fn encode<T: Aead + KeyInit>(
    out: &mut [u8],
    data: &[u8],
    additional_data: Option<&[u8]>,
    nonce: &Nonce<T>,
    key: &Key,
) -> Result<usize, EncryptError> {
    if out.len() < data.len() + MAC_BYTES {
        return Err(EncryptError::BufferSizeMismatch);
    }

    let key = GenericArray::from_slice(key);

    let payload = Payload {
        msg: data,
        aad: additional_data.unwrap_or_default(),
    };

    match T::new(key).encrypt(nonce, payload) {
        Ok(cipher_text) => {
            out[0..cipher_text.len()].copy_from_slice(&cipher_text);
            Ok(cipher_text.len())
        }
        Err(_) => Err(EncryptError::Failed),
    }
}

pub fn decode<T: Aead + KeyInit>(
    out: &mut [u8],
    data: &[u8],
    additional_data: Option<&[u8]>,
    nonce: &Nonce<T>,
    key: &Key,
) -> Result<usize, EncryptError> {
    if out.len() < data.len() - MAC_BYTES {
        return Err(EncryptError::BufferSizeMismatch);
    }

    let key = GenericArray::from_slice(key);

    let payload = Payload {
        msg: data,
        aad: additional_data.unwrap_or_default(),
    };

    match T::new(key).decrypt(nonce, payload) {
        Ok(plain_text) => {
            out[0..plain_text.len()].copy_from_slice(&plain_text);
            Ok(plain_text.len())
        }
        Err(_) => Err(EncryptError::Failed),
    }
}
