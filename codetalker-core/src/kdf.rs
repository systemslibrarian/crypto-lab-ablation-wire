//! HKDF-SHA256 extract-and-expand.

use crate::error::{Error, Result};
use hkdf::Hkdf;
use sha2::Sha256;

pub const SALT: &[u8] = b"code-talker/v1";

/// Derive `N` bytes of keying material from a shared secret.
pub fn derive(ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    let hk = Hkdf::<Sha256>::new(Some(SALT), ikm);
    hk.expand(info, out).map_err(|_| Error::Kdf)
}

/// Derive with an explicit salt. Used by the RFC 5869 known-answer tests.
pub fn derive_with_salt(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    hk.expand(info, out).map_err(|_| Error::Kdf)
}

/// Expose the extract step so tests can check the PRK against published vectors.
pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(&prk);
    out
}
