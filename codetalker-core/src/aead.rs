//! Authenticated encryption. Two suites, one interface.

use crate::error::{Error, Result};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
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
    let n = Nonce::from_slice(nonce);
    let payload = Payload { msg: pt, aad };
    match suite {
        Suite::Aes256Gcm => Aes256Gcm::new(key.into())
            .encrypt(n, payload)
            .map_err(|_| Error::Aead),
        Suite::ChaCha20Poly1305 => {
            use chacha20poly1305::aead::Aead as _;
            use chacha20poly1305::aead::KeyInit as _;
            let c = ChaCha20Poly1305::new(key.as_slice().into());
            c.encrypt(
                chacha20poly1305::Nonce::from_slice(nonce),
                chacha20poly1305::aead::Payload { msg: pt, aad },
            )
            .map_err(|_| Error::Aead)
        }
    }
}

pub fn open(suite: Suite, key: &[u8; 32], nonce: &[u8; NONCE_LEN], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    let n = Nonce::from_slice(nonce);
    let payload = Payload { msg: ct, aad };
    match suite {
        Suite::Aes256Gcm => Aes256Gcm::new(key.into())
            .decrypt(n, payload)
            .map_err(|_| Error::Aead),
        Suite::ChaCha20Poly1305 => {
            use chacha20poly1305::aead::Aead as _;
            use chacha20poly1305::aead::KeyInit as _;
            let c = ChaCha20Poly1305::new(key.as_slice().into());
            c.decrypt(
                chacha20poly1305::Nonce::from_slice(nonce),
                chacha20poly1305::aead::Payload { msg: ct, aad },
            )
            .map_err(|_| Error::Aead)
        }
    }
}
