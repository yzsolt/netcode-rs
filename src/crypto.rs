use crate::common::*;

use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::{Aead, NewAead, Nonce, Payload};

use std::io;

pub const NETCODE_ENCRYPT_EXTA_BYTES: usize = 16;

#[derive(Debug)]
pub enum EncryptError {
    InvalidPublicKeySize,
    BufferSizeMismatch,
    IO(io::Error),
    Failed,
}

impl From<io::Error> for EncryptError {
    fn from(err: io::Error) -> Self {
        EncryptError::IO(err)
    }
}

/// Generates a new random private key.
pub fn generate_key() -> [u8; NETCODE_KEY_BYTES] {
    let mut key: [u8; NETCODE_KEY_BYTES] = [0; NETCODE_KEY_BYTES];

    random_bytes(&mut key);

    key
}

pub fn random_bytes(out: &mut [u8]) {
    getrandom::getrandom(out).unwrap();
}

pub fn encode<T: Aead + NewAead>(
    out: &mut [u8],
    data: &[u8],
    additional_data: Option<&[u8]>,
    nonce: &Nonce::<T::NonceSize>,
    key: &[u8; NETCODE_KEY_BYTES],
) -> Result<usize, EncryptError> {
    if key.len() != NETCODE_KEY_BYTES {
        return Err(EncryptError::InvalidPublicKeySize);
    }

    if out.len() < data.len() + NETCODE_ENCRYPT_EXTA_BYTES {
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
        Err(_) => {
            Err(EncryptError::Failed)
        }
    }
}

pub fn decode<T: Aead + NewAead>(
    out: &mut [u8],
    data: &[u8],
    additional_data: Option<&[u8]>,
    nonce: &Nonce::<T::NonceSize>,
    key: &[u8; NETCODE_KEY_BYTES],
) -> Result<usize, EncryptError> {
    if key.len() != NETCODE_KEY_BYTES {
        return Err(EncryptError::InvalidPublicKeySize);
    }

    if out.len() < data.len() - NETCODE_ENCRYPT_EXTA_BYTES {
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
        Err(_) => {
            Err(EncryptError::Failed)
        }
    }
}
