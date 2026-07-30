//! Authenticated encryption. Two suites, one interface.

use crate::error::{Error, Result};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Suite {
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Suite {
    pub fn name(&self) -> &'static str {
        match self {
            Suite::Aes256Gcm => "AES-256-GCM",
            Suite::ChaCha20Poly1305 => "ChaCha20-Poly1305",
        }
    }
}

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

pub fn seal(suite: Suite, key: &[u8; 32], nonce: &[u8; NONCE_LEN], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
    // `Nonce` and `Key` are both `hybrid_array::Array`, and `&Array<T, N>`
    // converts from `&[T; N]` — a fixed-size reference, checked at compile time.
    // The 0.10 spelling went through `from_slice`, which took `&[u8]` and
    // panicked on a length mismatch; these arrays are already the right length
    // by their types, so the fallible step is simply gone rather than handled.
    let payload = Payload { msg: pt, aad };
    match suite {
        Suite::Aes256Gcm => Aes256Gcm::new(key.into())
            .encrypt(nonce.into(), payload)
            .map_err(|_| Error::Aead),
        Suite::ChaCha20Poly1305 => ChaCha20Poly1305::new(key.into())
            .encrypt(nonce.into(), payload)
            .map_err(|_| Error::Aead),
    }
}

pub fn open(suite: Suite, key: &[u8; 32], nonce: &[u8; NONCE_LEN], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    let payload = Payload { msg: ct, aad };
    match suite {
        Suite::Aes256Gcm => Aes256Gcm::new(key.into())
            .decrypt(nonce.into(), payload)
            .map_err(|_| Error::Aead),
        Suite::ChaCha20Poly1305 => ChaCha20Poly1305::new(key.into())
            .decrypt(nonce.into(), payload)
            .map_err(|_| Error::Aead),
    }
}
