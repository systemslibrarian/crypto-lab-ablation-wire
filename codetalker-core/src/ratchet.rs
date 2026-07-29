//! Symmetric-key ratchet.
//!
//! Deliberately *not* called a Double Ratchet: there is no DH ratchet here, so
//! this provides forward secrecy but not post-compromise security. Naming it
//! honestly matters more than naming it impressively.
//!
//! Each message key is derived from the current chain key, then the chain key
//! is advanced irreversibly. Compromising the chain at message N reveals
//! messages N onward and nothing before it.

use crate::error::Result;
use crate::kdf;
use zeroize::Zeroize;

pub struct Chain {
    ck: [u8; 32],
    pub n: u32,
}

impl Drop for Chain {
    fn drop(&mut self) {
        self.ck.zeroize();
    }
}

impl Chain {
    pub fn new(root: [u8; 32]) -> Self {
        Chain { ck: root, n: 0 }
    }

    /// Derive the next message key and advance the chain.
    ///
    /// Deliberately not an `Iterator`. Key derivation is fallible, and a chain
    /// has no end to signal — `Iterator` would have to swallow the error or
    /// report exhaustion that never happens. The name matches the ratchet
    /// vocabulary, so it stays.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<[u8; 32]> {
        let mut mk = [0u8; 32];
        kdf::derive(&self.ck, b"ratchet/mk", &mut mk)?;

        let mut next_ck = [0u8; 32];
        kdf::derive(&self.ck, b"ratchet/ck", &mut next_ck)?;

        self.ck.zeroize();
        self.ck = next_ck;
        self.n += 1;
        Ok(mk)
    }

    /// Message key without advancing. Models a channel with no ratchet, where
    /// one key covers every message ever sent.
    pub fn static_key(&self) -> Result<[u8; 32]> {
        let mut mk = [0u8; 32];
        kdf::derive(&self.ck, b"ratchet/mk", &mut mk)?;
        Ok(mk)
    }
}
